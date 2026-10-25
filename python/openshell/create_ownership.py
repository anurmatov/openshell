# SPDX-License-Identifier: Apache-2.0

"""Curated request-bound receipts and explicit metadata fences, never Create replay."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from ._proto import datamodel_pb2, openshell_pb2, openshell_pb2_grpc
from .create_fingerprint import CreateOwnershipKey
from .errors import _error_mapping_channel

if TYPE_CHECKING:
    import grpc

    from .sandbox import SandboxClient

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_INVALID = "invalid Create ownership receipt"


class CreateReceiptState(IntEnum):
    PENDING = 1
    SUCCEEDED = 2
    AMBIGUOUS = 3
    NO_RESOURCE = 4
    EXPIRED = 5
    NOT_FOUND_AS_OF_READ = 6
    UNSUPPORTED_COVERAGE = 7
    ABANDONED = 8
    FENCED_PENDING = 9


class CreateEffectState(IntEnum):
    NOT_STARTED = 1
    RESOURCE_COMMITTED = 2
    DRIVER_STARTED = 3
    OWNER_TERMINAL = 4


@dataclass(frozen=True)
class OwnershipTimestamp:
    """Exact wire seconds/nanoseconds, without datetime microsecond truncation."""

    seconds: int
    nanos: int


@dataclass(frozen=True)
class CreateOwnershipBinding:
    claim_incarnation_id: str
    sandbox_id: str
    initial_resource_version: int
    current_resource_version: int | None
    current_state: str
    effect_state: CreateEffectState
    binding_revision: int


@dataclass(frozen=True)
class CreateOwnershipReceipt:
    """Complete describes the Create result, never runtime or broker absence."""

    state: CreateReceiptState
    request_id: str
    fingerprint: bytes
    schema_digest: str
    revision: int
    created_at: OwnershipTimestamp | None
    completed_at: OwnershipTimestamp | None
    expires_at: OwnershipTimestamp | None
    coverage_epoch: str
    bindings: tuple[CreateOwnershipBinding, ...]
    complete: bool
    fence_revision: int
    admission_closed: bool
    reason_code: str


def _uuid(value: str) -> bool:
    return (
        isinstance(value, str)
        and _UUID.fullmatch(value) is not None
        and value != "00000000-0000-0000-0000-000000000000"
    )


def _freeze(
    workspace: str, key: CreateOwnershipKey, expected: str | None
) -> CreateOwnershipKey:
    if (
        not isinstance(workspace, str)
        or not workspace
        or workspace.strip() != workspace
        or workspace == "*"
        or not _uuid(key.request_id)
        or not isinstance(key.fingerprint, (bytes, bytearray, memoryview))
        or not isinstance(key.schema_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", key.schema_digest) is None
        or (expected is not None and not _uuid(expected))
    ):
        raise ValueError("named workspace and canonical original Create key required")
    fingerprint = bytes(key.fingerprint)
    if len(fingerprint) != 32:
        raise ValueError("named workspace and canonical original Create key required")
    return CreateOwnershipKey(key.request_id, fingerprint, key.schema_digest)


def _decode(r, key: CreateOwnershipKey, expected: str | None) -> CreateOwnershipReceipt:
    if (
        r is None
        or r.request_id != key.request_id
        or bytes(r.fingerprint) != key.fingerprint
        or r.fingerprint_schema_digest != key.schema_digest
        or not 1 <= r.receipt_state <= 9
        or len(r.bindings) > 16
        or not r.coverage_epoch
    ):
        raise ValueError(_INVALID)
    state = CreateReceiptState(r.receipt_state)
    completed = r.HasField("completed_at")
    if (
        (r.complete and state not in (2, 4, 8))
        or (
            state == 8
            and (not r.admission_closed or r.fence_revision == 0 or r.bindings)
        )
        or (state == 9 and (not r.admission_closed or r.fence_revision == 0))
        or (state == 4 and (not r.admission_closed or not completed or r.bindings))
        or (state in (2, 5) and (not completed or len(r.bindings) != 1))
        or (
            state not in (6, 7)
            and (r.receipt_revision == 0 or not r.HasField("created_at"))
        )
    ):
        raise ValueError(_INVALID)

    def timestamp(name):
        if not r.HasField(name):
            return None
        value = getattr(r, name)
        if (
            not -62135596800 <= value.seconds <= 253402300799
            or not 0 <= value.nanos < 1_000_000_000
        ):
            raise ValueError(_INVALID)
        return OwnershipTimestamp(value.seconds, value.nanos)

    bindings = []
    seen = set()
    matched = expected is None or state in (6, 7)
    for b in r.bindings:
        current = (
            b.current_resource_version
            if b.HasField("current_resource_version")
            else None
        )
        if (
            not _uuid(b.sandbox_id)
            or not _uuid(b.claim_incarnation_id)
            or b.initial_resource_version == 0
            or b.binding_revision == 0
            or current == 0
            or not 1 <= b.effect_state <= 4
            or b.sandbox_id in seen
            or (b.effect_state == 4) != completed
        ):
            raise ValueError(_INVALID)
        seen.add(b.sandbox_id)
        matched = matched or b.sandbox_id == expected
        bindings.append(
            CreateOwnershipBinding(
                b.claim_incarnation_id,
                b.sandbox_id,
                b.initial_resource_version,
                current,
                b.current_state,
                CreateEffectState(b.effect_state),
                b.binding_revision,
            )
        )
    if not matched:
        raise ValueError(_INVALID)
    return CreateOwnershipReceipt(
        state,
        r.request_id,
        bytes(r.fingerprint),
        r.fingerprint_schema_digest,
        r.receipt_revision,
        timestamp("created_at"),
        timestamp("completed_at"),
        timestamp("expires_at"),
        r.coverage_epoch,
        tuple(bindings),
        r.complete,
        r.fence_revision,
        r.admission_closed,
        r.reason_code,
    )


class CreateOwnershipClient:
    """Reuse a caller-owned authenticated channel without owning its lifecycle.

    Supply a channel without mutation-retry policies/interceptors. Each invocation
    probes Health and sends its RPC once, without automatic retry or fallback.
    Discovery cannot close a subsequent downgrade race; the server must enforce
    the contract. Cancellation/transport failure never authorizes a Create resend.
    """

    def __init__(self, channel: grpc.Channel, *, timeout: float = 30.0) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive")
        self._channel = channel
        self._stub = openshell_pb2_grpc.OpenShellStub(_error_mapping_channel(channel))
        self._timeout = timeout

    @classmethod
    def from_sandbox_client(cls, client: SandboxClient) -> CreateOwnershipClient:
        """Retain the existing channel's TLS/bearer authentication and per-RPC timeout."""
        return cls(client._channel, timeout=client._timeout)

    def _require_capability(self) -> None:
        health = self._stub.Health(openshell_pb2.HealthRequest(), timeout=self._timeout)
        if "sandbox-create-ownership-v1" not in health.capabilities:
            raise ValueError("gateway capability sandbox-create-ownership-v1 required")

    def get(
        self,
        workspace: str,
        key: CreateOwnershipKey,
        *,
        expected_sandbox_id: str | None = None,
    ) -> CreateOwnershipReceipt:
        """Send one SELECT-only receipt read; missing/expired evidence never fences."""
        original = _freeze(workspace, key, expected_sandbox_id)
        self._require_capability()
        request = openshell_pb2.GetSandboxCreateReceiptRequest(
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=workspace),
            request_id=original.request_id,
            payload_fingerprint=original.fingerprint,
            fingerprint_schema_digest=original.schema_digest,
        )
        if expected_sandbox_id is not None:
            request.expected_sandbox_id = expected_sandbox_id
        return _decode(
            self._stub.GetSandboxCreateReceipt(request, timeout=self._timeout),
            original,
            expected_sandbox_id,
        )

    def fence(self, workspace: str, key: CreateOwnershipKey) -> CreateOwnershipReceipt:
        """Explicit metadata mutation, not cancellation or runtime absence.

        A lost reply is an error, not retry permission. Use get for readback.
        """
        original = _freeze(workspace, key, None)
        self._require_capability()
        response = self._stub.FenceSandboxCreate(
            openshell_pb2.FenceSandboxCreateRequest(
                workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=workspace),
                request_id=original.request_id,
                payload_fingerprint=original.fingerprint,
                fingerprint_schema_digest=original.schema_digest,
            ),
            timeout=self._timeout,
        )
        result = _decode(
            response.receipt if response.HasField("receipt") else None, original, None
        )
        if not result.admission_closed or result.fence_revision == 0:
            raise ValueError("Create fence was not confirmed closed")
        return result
