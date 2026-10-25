<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Protobuf API conventions

This directory defines OpenShell's gRPC contracts. These conventions are the
source of truth for public protobuf API design. Apply them to new APIs and when
changing existing APIs; generated SDK naming follows from these definitions.

## Entity references

- Use `name` for the primary resource targeted by an RPC.
- Use the resource's role for a related resource reference, such as `sandbox`,
  `provider`, `service`, or `rule`.
- Do not append `_name` to a canonical entity reference. Its value is already
  the canonical name. Descriptive values, local map keys, implementation
  labels, and configured registration names that are not entity references may
  retain the suffix. Examples include `display_name`, `file_name`,
  `driver_name`, `runtime_class_name`, `rule_name`, and `middleware_name`.
- Public callers reference entities by canonical name. Keep immutable IDs at
  authentication, persistence, compute-driver, and other internal boundaries.

For example:

```proto
message GetSandboxRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 2;
  string name = 1;
}

message ExposeServiceRequest {
  openshell.datamodel.v1.WorkspaceSelector workspace_scope = 5;
  string sandbox = 1;
  string name = 2;
}
```

`GetSandboxRequest.name` identifies the RPC's primary resource.
`ExposeServiceRequest.sandbox` identifies a related sandbox while `name`
identifies the service being exposed.

## Workspace scope

- Public workspace-scoped requests declare `workspace_scope` before every
  other field. Existing wire field numbers do not need to follow declaration
  order.
- Type `workspace_scope` as
  `openshell.datamodel.v1.WorkspaceSelector`.
- Requests operating in one workspace require a non-empty canonical
  `WorkspaceSelector.workspace`. The `default` workspace is an explicit name,
  not an omitted-value fallback.
- Accept `WorkspaceSelector.all_workspaces` only on collection-list RPCs that
  explicitly document and authorize cross-workspace access. The supported
  public collections are sandboxes, sandbox templates, providers, and
  services.
- Requests whose primary resource is a workspace use `name`, not
  `workspace_scope`.
- Document every request that permits an omitted selector. Current exceptions
  are platform provider-profile scope and authenticated sandbox bootstrap.

## Field and message design

- Prefer a dedicated request and response message for each RPC, including
  requests that are currently empty.
- Use `google.protobuf.Timestamp` for absolute time and
  `google.protobuf.Duration` for elapsed time.
- Use optional presence when omitted and explicitly empty values have different
  meanings. Do not infer presence from a protobuf scalar's default value.
- Keep public request fields in semantic reading order. Field numbers preserve
  wire identity and may therefore differ from declaration order.
- Document authorization-sensitive selector variants and omission semantics on
  the containing request.

## Schema evolution

- Treat field numbers and fully qualified message names as durable wire
  identities.
- When removing or renaming a field, reserve its old number and source name. Do
  not reuse either for a different meaning.
- Review changes against both the public descriptor closure and durable stored
  protobuf closure. The `public_and_durable_schema_inventories_are_complete`
  test in `openshell-server` owns both inventories.
- Regenerate Rust, Python, Go, and TypeScript bindings after contract changes.
  Run `mise run pre-commit`, the affected SDK checks, and relevant server tests
  before submitting the change.

## Supervisor host protocol

[`supervisor_host.proto`](supervisor_host.proto) is the private stream between
a gateway and the supervisor process it shares among its sandboxes: the
supervisor attaches, the gateway sends complete assignment snapshots, and the
supervisor reports what it hosts. It is a version-locked deployment protocol
served on the gateway listener but authorized only for the gateway-minted
supervisor token (`auth_mode: "supervisor"`). It is not imported by
`openshell.proto`, so SDK generation and
gRPC reflection exclude it; the server's schema inventory test classifies it
explicitly. `SandboxInstanceAssignment.launch_material` carries the existing
JSON sandbox instance registration of `openshell-supervisor-control` and is
marked secret.

## Isolation backend protocol

[`isolation_backend.proto`](isolation_backend.proto) defines backend discovery,
boundary binding, and optional suspend/resume RPCs.
[`sandbox_protocol.proto`](sandbox_protocol.proto) defines typed workload
control, process I/O, and network mediation over the bound boundary. Both are
supervisor-to-backend contracts, not gateway RPCs. Backend authors can generate bindings independently
from these definitions. The negotiated Sandbox Protocol version covers the gRPC
services, typed messages, streaming, and lifecycle semantics.

## Create ownership foundations

`openshell-core::create_fingerprint` implements the separate Create encoding with
a measured descriptor closure and typed/RFC vectors in `create_fingerprint.v1.json`,
without changing legacy replay hashes.
The additive ownership schema and internal ledger reserve admission plus its
mutation claim in one transaction, serialize explicit fences, retain immutable
keys/bindings, and expose SELECT-only lookup through the existing durable pools.
The internal binding transaction writes the actual Sandbox at initial version 1,
its immutable binding and the admitted mutation target together, retaining the
original owner after a fence and rolling back all writes on a conflict.
File-backed, independent-connection SQLite tests overlap admission/fence in both
orders and quota admission at the final slot; PostgreSQL execution is still
unqualified, not inferred from SQLite results or Rust compilation.
The authenticated legacy Create dispatcher checks the original caller/workspace/
UUID before replay and atomically repeats that guard with its mutation admission;
closed keys refuse execution and pending audited owners cannot be downgraded.
New legacy admissions retain immutable UUID coverage markers after replay expiry,
so pruning cannot turn known legacy creation into audited absence or a new owner.
Legacy payload hashing/replay remains unchanged for unowned keys; older unindexed
history remains unqualified rather than inferred absent.
Binding resolves the immutable Workspace ID to its actual name within the
transaction; PostgreSQL labels use the existing JSONB storage representation.
The additive receipt/fence wire uses bearer scope plus fresh named-workspace and
original-caller authorization, reads revisions/bindings in one database snapshot,
and refuses missing/unqualified coverage rather than inventing absence.
A newly initialized database records an immutable namespace epoch during migration;
upgraded or interrupted namespaces without that provenance remain unqualified.
Qualified missing-key reads return NOT_FOUND_AS_OF_READ with complete=false,
never absence; an explicit authorized fence can instead retain an ABANDONED
tombstone without driver work.
Audited Create field 10 reserves a detached owner before execution, binds the
actual Sandbox/initial version/mutation target atomically, and commits a driver
effect marker before dispatch.
Only an ended owner without a binding or effect can seal NO_RESOURCE; a lost
completion or uncertain driver outcome retains pending ownership and bindings.
Success and definitive pre-effect failure update receipt and replay-cache
completion metadata atomically; cache expiry cannot erase the permanent UUID.
Both admitted-owner completion after fencing and caller cancellation preserve
the original owner, while interceptor flag downgrade cannot bypass a known fence.
Rust workspace SDK methods check Health per operation and send each receipt/fence
RPC once without automatic mutation retry; canonical Go, Python and TypeScript
bindings are regenerated, not evidence of curated cross-SDK conformance.
The public inventory and canonical Create descriptor manifest remain measured;
durable/overlap inventories and legacy false-request hashes remain unchanged.
Trusted observations, terminal driver journals, curated SDK conformance and
remaining source oracles are incomplete, so neither ownership capability is
advertised; namespace provenance is not installed-runtime or broker-drain proof.
