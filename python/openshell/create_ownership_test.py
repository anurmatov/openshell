# SPDX-License-Identifier: Apache-2.0
"""Curated receipt/fence calls over the actual generated gRPC channel."""

import json
from concurrent import futures
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import grpc
import pytest
from google.protobuf import json_format

from openshell import (
    CreateOwnershipClient,
    CreateOwnershipKey,
    SandboxClient,
    create_ownership_key_from_request,
)
from openshell._proto import openshell_pb2 as pb

REQUEST = "11111111-1111-4111-8111-111111111111"
SANDBOX = "22222222-2222-4222-8222-222222222222"
CLAIM = "33333333-3333-4333-8333-333333333333"


def key():
    return CreateOwnershipKey(REQUEST, bytes([7]) * 32, "a" * 64)


def receipt():
    value = pb.GetSandboxCreateReceiptResponse(
        receipt_state=2, request_id=REQUEST, fingerprint=key().fingerprint,
        fingerprint_schema_digest=key().schema_digest, receipt_revision=1,
        coverage_epoch="epoch-a", complete=True,
        bindings=[pb.CreateOwnershipBinding(claim_incarnation_id=CLAIM,
            sandbox_id=SANDBOX, initial_resource_version=1,
            current_resource_version=2, effect_state=4, binding_revision=1)],
    )
    value.created_at.seconds = 1
    value.completed_at.seconds = 2
    return value


@pytest.fixture
def connection():
    state = SimpleNamespace(capable=True, health=0, reads=[], fences=[], auth=[], deadlines=[],
                            response=receipt(), code=None, mutate=None)
    def health(_request, context):
        state.health += 1
        state.deadlines.append(context.time_remaining())
        state.auth.append(dict(context.invocation_metadata()).get("authorization"))
        if state.mutate:
            state.mutate()
        return pb.HealthResponse(capabilities=["sandbox-create-ownership-v1"] if state.capable else [])
    def read(request, context):
        state.reads.append(request)
        state.deadlines.append(context.time_remaining())
        state.auth.append(dict(context.invocation_metadata()).get("authorization"))
        if state.code:
            context.abort(state.code, "synthetic refusal")
        return state.response
    def fence(request, context):
        state.fences.append(request)
        if state.code:
            context.abort(state.code, "synthetic ambiguous reply")
        return pb.FenceSandboxCreateResponse(receipt=state.response)
    methods = {}
    for name, handler, request_type, response_type in [
        ("Health", health, pb.HealthRequest, pb.HealthResponse),
        ("GetSandboxCreateReceipt", read, pb.GetSandboxCreateReceiptRequest, pb.GetSandboxCreateReceiptResponse),
        ("FenceSandboxCreate", fence, pb.FenceSandboxCreateRequest, pb.FenceSandboxCreateResponse),
    ]:
        methods[name] = grpc.unary_unary_rpc_method_handler(handler,
            request_deserializer=request_type.FromString,
            response_serializer=response_type.SerializeToString)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("openshell.v1.OpenShell", methods),))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    with SandboxClient(f"127.0.0.1:{port}", timeout=2, bearer_token="owned-synthetic") as client:
        try:
            yield CreateOwnershipClient.from_sandbox_client(client), state
        finally:
            server.stop(0).wait()


def test_generated_read_preserves_original_key_identity_and_fresh_auth(connection):
    client, state = connection
    result = client.get("workspace-a", key(), expected_sandbox_id=SANDBOX)
    assert result.state == 2 and result.bindings[0].sandbox_id == SANDBOX
    request, = state.reads
    assert request.workspace_scope.workspace == "workspace-a"
    assert request.request_id == REQUEST
    assert request.payload_fingerprint == key().fingerprint
    assert request.expected_sandbox_id == SANDBOX
    assert state.health == 1 and state.fences == []
    assert state.auth == ["Bearer owned-synthetic", "Bearer owned-synthetic"]
    assert len(state.deadlines) == 2
    assert all(0 < deadline <= 2.1 for deadline in state.deadlines)
    with pytest.raises(FrozenInstanceError):
        result.complete = False


def test_capability_rechecked_each_call_without_downgrade(connection):
    client, state = connection
    client.get("workspace-a", key())
    state.capable = False
    for call in [lambda: client.get("workspace-a", key()), lambda: client.fence("workspace-a", key())]:
        with pytest.raises(ValueError, match="capability"):
            call()
    assert state.health == 3 and len(state.reads) == 1 and not state.fences


@pytest.mark.parametrize("workspace", ["", "*", " workspace-a"])
def test_invalid_workspace_makes_no_rpc(connection, workspace):
    client, state = connection
    with pytest.raises(ValueError):
        client.get(workspace, key())
    assert state.health == 0 and not state.reads and not state.fences


@pytest.mark.parametrize("fault", [
    "unknown", "wrong-id", "fingerprint", "schema", "epoch", "zero-revision",
    "timestamp", "nonterminal", "false-nonterminal", "duplicate",
    "zero-initial", "zero-current", "foreign-sandbox", "abandoned",
    "fenced", "complete-pending", "too-many", "missing-created",
])
def test_contradictory_reply_refused_through_public_get(connection, fault):
    client, state = connection
    r = state.response
    if fault == "unknown":
        r.receipt_state = 99
    if fault == "wrong-id":
        r.request_id = SANDBOX
    if fault == "fingerprint":
        r.fingerprint = bytes(32)
    if fault == "schema":
        r.fingerprint_schema_digest = "b" * 64
    if fault == "epoch":
        r.coverage_epoch = ""
    if fault == "zero-revision":
        r.receipt_revision = 0
    if fault == "timestamp":
        r.created_at.nanos = 1_000_000_000
    if fault in ("nonterminal", "false-nonterminal"):
        r.bindings[0].effect_state = 1
    if fault == "false-nonterminal":
        r.complete = False
    if fault == "duplicate":
        r.bindings.append(r.bindings[0])
    if fault == "zero-initial":
        r.bindings[0].initial_resource_version = 0
    if fault == "zero-current":
        r.bindings[0].current_resource_version = 0
    if fault == "foreign-sandbox":
        r.bindings[0].sandbox_id = CLAIM
    if fault == "abandoned":
        r.receipt_state = 8
        del r.bindings[:]
    if fault == "fenced":
        r.receipt_state = 9
        r.complete = False
    if fault == "complete-pending":
        r.receipt_state = 1
    if fault == "too-many":
        for _ in range(16):
            r.bindings.append(r.bindings[0])
    if fault == "missing-created":
        r.ClearField("created_at")
    with pytest.raises(ValueError, match="invalid Create ownership receipt"):
        client.get("workspace-a", key(), expected_sandbox_id=SANDBOX)
    assert len(state.reads) == 1 and not state.fences


@pytest.mark.parametrize("state_value", [1, 3, 5, 6, 7, 9])
def test_incomplete_states_do_not_trigger_another_operation(connection, state_value):
    client, state = connection
    state.response.receipt_state = state_value
    state.response.complete = False
    if state_value != 5:
        del state.response.bindings[:]
    if state_value == 9:
        state.response.admission_closed = True
        state.response.fence_revision = 1
    result = client.get("workspace-a", key())
    assert result.state == state_value and not result.complete
    assert len(state.reads) == 1 and not state.fences


def test_explicit_fence_requires_confirmed_closure_and_is_not_retried(connection):
    client, state = connection
    state.response.receipt_state = 8
    state.response.admission_closed = True
    state.response.fence_revision = 1
    del state.response.bindings[:]
    assert client.fence("workspace-a", key()).state == 8
    assert len(state.fences) == 1 and not state.reads
    state.code = grpc.StatusCode.UNAVAILABLE
    with pytest.raises(grpc.RpcError):
        client.fence("workspace-a", key())
    assert len(state.fences) == 2  # one RPC per explicit invocation, never a retry


def test_unconfirmed_fence_refuses_success(connection):
    client, state = connection
    with pytest.raises(ValueError, match="not confirmed closed"):
        client.fence("workspace-a", key())
    assert len(state.fences) == 1


def test_input_and_output_buffers_are_independent(connection):
    client, state = connection
    original = bytearray([7] * 32)
    mutable_key = CreateOwnershipKey(REQUEST, original, "a" * 64)
    state.mutate = lambda: original.__setitem__(slice(None), bytes(32))
    result = client.get("workspace-a", mutable_key)
    assert state.reads[0].payload_fingerprint == bytes([7]) * 32
    state.response.fingerprint = bytes(32)
    assert result.fingerprint == bytes([7]) * 32
    assert isinstance(result.bindings, tuple)


def test_exact_uint64_and_nanosecond_fields(connection):
    client, state = connection
    state.response.receipt_revision = 2**64 - 1
    state.response.bindings[0].initial_resource_version = 2**64 - 1
    state.response.created_at.seconds = -62135596800
    state.response.created_at.nanos = 999999999
    result = client.get("workspace-a", key())
    assert result.revision == 2**64 - 1
    assert result.bindings[0].initial_resource_version == 2**64 - 1
    assert result.created_at.seconds == -62135596800 and result.created_at.nanos == 999999999


def test_invalid_keys_make_no_rpc(connection):
    client, state = connection
    for bad in [
        CreateOwnershipKey("same-name", bytes(32), "a" * 64),
        CreateOwnershipKey(REQUEST, bytes(31), "a" * 64),
        CreateOwnershipKey(REQUEST, bytes(32), "A" * 64),
    ]:
        with pytest.raises(ValueError):
            client.get("workspace-a", bad)
    with pytest.raises(ValueError):
        client.get("workspace-a", key(), expected_sandbox_id="same-name")
    assert state.health == 0


def test_invalid_timeout_refuses_before_health(connection):
    client, state = connection
    for value in [0, -1, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            CreateOwnershipClient(client._channel, timeout=value)
    assert state.health == 0

# The public canonical builder feeds the actual generated receipt request.
# The stand-in does not qualify server storage/authorization or a live gateway.

VECTORS = json.loads((Path(__file__).parents[2] / "proto/create_fingerprint.v1.json").read_text())


@pytest.mark.parametrize("vector", [
    v for v in VECTORS["vectors"] if v["message_type"] == "openshell.v1.CreateSandboxRequest"
], ids=lambda v: v["name"])
def test_public_canonical_key_reaches_generated_receipt_transport(connection, vector):
    client, state = connection
    message = json_format.ParseDict(vector["input"], pb.CreateSandboxRequest())
    message.ParseFromString(message.SerializeToString() + bytes.fromhex(vector["unknown_wire_hex"]))
    message.request_id = REQUEST
    original = message.SerializeToString()
    built = create_ownership_key_from_request(original, VECTORS["fingerprint_schema_digest"])
    assert built.fingerprint.hex() == vector["sha256"]
    state.response.fingerprint = built.fingerprint
    state.response.fingerprint_schema_digest = built.schema_digest
    result = client.get("workspace-a", built, expected_sandbox_id=SANDBOX)
    assert state.reads[0].payload_fingerprint == built.fingerprint
    assert result.fingerprint.hex() == vector["sha256"]
    assert message.SerializeToString() == original
    assert not state.fences and len(state.reads) == 1


@pytest.mark.parametrize("code", [
    grpc.StatusCode.PERMISSION_DENIED,
    grpc.StatusCode.UNAUTHENTICATED,
    grpc.StatusCode.CANCELLED,
    grpc.StatusCode.DEADLINE_EXCEEDED,
])
def test_transport_denial_and_cancellation_never_fall_back_or_retry(connection, code):
    client, state = connection
    state.code = code
    with pytest.raises(grpc.RpcError) as raised:
        client.get("workspace-a", key())
    assert raised.value.code() == code
    assert state.health == 1 and len(state.reads) == 1 and not state.fences


def test_fence_missing_receipt_refuses_without_another_rpc(connection):
    client, state = connection
    state.response = None
    with pytest.raises(ValueError, match="invalid Create ownership receipt"):
        client.fence("workspace-a", key())
    assert state.health == 1 and len(state.fences) == 1 and not state.reads
