# Create ownership

`client.CreateOwnership()` provides two additive methods without changing the legacy `Sandboxes()` interface:

- `Get(ctx, workspace, key, expectedSandboxID)` reads the original Create receipt once
- `Fence(ctx, workspace, key)` explicitly closes admission without cancelling an admitted owner

`CreateOwnershipKey` contains the canonical request UUID, the 32-byte original fingerprint and its 64-character schema digest.
Use the approved canonical original-request projection, not the protobuf encoding or an effective/interceptor-rewritten request.
This client accepts an existing fingerprint; a Go canonical fingerprint builder is not implemented yet.
Workspace selection is named and explicit, and an optional expected ID is immutable, never a replacement name.

Both methods recheck `sandbox-create-ownership-v1` through Health for each operation and refuse its absence.
The current source does not advertise that capability while the full ownership/observation contract remains incomplete.
Health is not an atomic negotiation: a downgrade between Health and the operation must still be rejected by the gateway.
The methods never retry the ownership RPC, including under a configured gRPC retry policy; no Create/Start/name-based fallback exists.
A lost fence reply remains uncertain and requires a separate authorized `Get`, not an automatic fence resend.

The result preserves receipt revisions, admission/fence state, optional times, binding versions and incomplete/expired/unsupported states.
Malformed, foreign or contradictory replies are errors, not ownership or absence.
`NOT_FOUND_AS_OF_READ` remains incomplete because a delayed Create may still arrive.
`Complete` describes only recorded creation evidence, never process, socket, poller, runtime or broker drain.
`BROKER_BARRIER_UNQUALIFIED` remains a separate downstream hold.

The source tests use an owned in-memory gRPC transport and the real generated client, with exact call counts and deep-copy assertions.
They are not a real gateway, SQL, driver, installed-image or runtime/restore qualification.
