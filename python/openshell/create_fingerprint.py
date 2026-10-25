# SPDX-License-Identifier: Apache-2.0

"""Canonical original Create keys, separate from legacy replay hashing."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from google.protobuf import (
    descriptor_pb2,
    descriptor_pool,
    json_format,
    message_factory,
)

_ERROR = "canonical Create fingerprint unavailable or schema mismatch"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class CreateOwnershipKey:
    """Original request identity, not replacement authority or runtime proof."""

    request_id: str
    fingerprint: bytes
    schema_digest: str


def create_ownership_key_from_request(
    original_wire: bytes | bytearray, expected_schema_digest: str
) -> CreateOwnershipKey:
    """Project exact original binary Create without sending any RPC.

    Clear only request_id on a decoded copy, never the audited flag. The expected
    digest is pinned by the qualified release's canonical vector manifest, not an
    arbitrary endpoint response. Unknown binary fields do not enter ProtoJSON.
    """
    try:
        if len(original_wire) > 4 * 1024 * 1024:
            raise ValueError(_ERROR)
        wire = bytes(original_wire)
        if len(wire) > 4 * 1024 * 1024:
            raise ValueError(_ERROR)
        descriptor = Path(__file__).with_name("create_descriptor.bin").read_bytes()
        digest = hashlib.sha256(descriptor).hexdigest()
        if digest != expected_schema_digest:
            raise ValueError(_ERROR)
        pool = _descriptor_pool(descriptor)
        cls = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("openshell.v1.CreateSandboxRequest")
        )
        request = cls.FromString(wire)
        request_id = request.request_id
        if (
            not _UUID.fullmatch(request_id)
            or request_id == "00000000-0000-0000-0000-000000000000"
        ):
            raise ValueError(_ERROR)
        request.ClearField("request_id")
        projected = json_format.MessageToDict(request, descriptor_pool=pool)
        canonical = _canonical_json(projected).encode("utf-8")
        return CreateOwnershipKey(
            request_id, hashlib.sha256(canonical).digest(), digest
        )
    except Exception:
        # Never disclose protobuf parse diagnostics, payload values or file paths.
        raise ValueError(_ERROR) from None


def _descriptor_pool(descriptor: bytes | None = None) -> descriptor_pool.DescriptorPool:
    if descriptor is None:
        descriptor = Path(__file__).with_name("create_descriptor.bin").read_bytes()
    compiled = descriptor_pb2.FileDescriptorSet.FromString(descriptor)
    files = {file.name: file for file in compiled.file}
    pool = descriptor_pool.DescriptorPool()
    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name not in files or name in active:
            raise ValueError(_ERROR)
        active.add(name)
        file = files[name]
        for dependency in file.dependency:
            visit(dependency)
        # Load dependency order without replacing or normalizing the raw closure
        # bytes whose SHA identifies the canonical release projection.
        pool.AddSerializedFile(file.SerializeToString())
        active.remove(name)
        visited.add(name)

    visit("openshell.proto")
    return pool


def _number(value: int | float) -> str:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(_ERROR)
    if number == 0:
        return "0"
    # CPython's shortest round-trip digits; JCS uses ECMAScript's fixed/exponent
    # windows and no exponent zero padding, independently checked by vectors.
    shortest = repr(number)
    if 1e-6 <= abs(number) < 1e21:
        fixed = format(Decimal(shortest), "f")
        return fixed.rstrip("0").rstrip(".") if "." in fixed else fixed
    mantissa, exponent = shortest.lower().split("e")
    if mantissa.endswith(".0"):
        mantissa = mantissa[:-2]
    power = int(exponent)
    return mantissa + "e" + ("+" if power >= 0 else "") + str(power)


def _canonical_json(value, depth=0) -> str:
    if depth > 128:
        raise ValueError(_ERROR)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        try:
            value.encode("utf-8")  # Reject lone surrogates, never normalize text.
        except UnicodeError:
            raise ValueError(_ERROR) from None
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return (
            "[" + ",".join(_canonical_json(item, depth + 1) for item in value) + "]"
        )
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError(_ERROR)
        try:
            keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        except UnicodeError:
            raise ValueError(_ERROR) from None
        return (
            "{"
            + ",".join(
                _canonical_json(key, depth + 1)
                + ":"
                + _canonical_json(value[key], depth + 1)
                for key in keys
            )
            + "}"
        )
    raise ValueError(_ERROR)
