# Create ownership

`client.CreateOwnership()` provides two additive methods without changing the legacy `Sandboxes()` interface:

- `Get(ctx, workspace, key, expectedSandboxID)` reads the original Create receipt once
- `Fence(ctx, workspace, key)` explicitly closes admission without cancelling an admitted owner

`CreateOwnershipKey` contains the canonical request UUID, the 32-byte original fingerprint and its 64-character schema digest.
Use the approved canonical original-request projection, not the protobuf encoding or an effective/interceptor-rewritten request.
`CreateOwnershipKeyFromRequest(originalWire, expectedSchemaDigest)` builds the key from the exact original binary request using descriptor-projected ProtoJSON and RFC 8785 canonical JSON, not a hash of the binary bytes.
It clears only `request_id` on a decoded copy, preserves the audited flag, rejects malformed/oversized requests and schema mismatches, and never sends Create.
The expected digest comes from the same qualified release's `proto/create_fingerprint.v1.json`, not a hash returned by an arbitrary endpoint.
Workspace selection is named and explicit, and an optional expected ID is immutable, never a replacement name.

Both methods recheck `sandbox-create-ownership-v1` through Health for each operation and refuse its absence.
The current source does not advertise that capability while the full ownership/observation contract remains incomplete.
Health is not an atomic negotiation: a downgrade between Health and the operation must still be rejected by the gateway.
The methods never retry the ownership RPC, including under a configured gRPC retry policy; no Create/Start/name-based fallback exists.
A lost fence reply remains uncertain and requires a separate authorized `Get`, not an automatic fence resend.

The result preserves receipt revisions, admission/fence state, optional times, binding versions and incomplete/expired/unsupported states.
Malformed, foreign or contradictory replies are errors, not ownership or absence.
Successful and expired receipts must retain a terminal owner effect and completion timestamp; `Complete=false` does not bypass this check.
`NOT_FOUND_AS_OF_READ` remains incomplete because a delayed Create may still arrive.
`Complete` describes only recorded creation evidence, never process, socket, poller, runtime or broker drain.
`BROKER_BARRIER_UNQUALIFIED` remains a separate downstream hold.

The source tests use an owned in-memory gRPC transport and the real generated client, with exact call counts and deep-copy assertions.
They are not a real gateway, SQL, driver, installed-image or runtime/restore qualification.

The Go canonical projector embeds the exact compiled descriptor closure exported by the Rust core; it does not substitute Go's runtime `descriptor.proto` metadata or normalize a mismatching digest.
The core test checks the asset byte for byte against the compiled projection, and Go tests exercise the shared canonical and finite-number vectors plus a generated-client receipt read.
Regenerate the asset from the repository root after a schema change, then run the core and Go tests:

```shell
cargo run --locked -p openshell-core \
  --example create_fingerprint_descriptor \
  > /tmp/create_descriptor.bin &&
cp /tmp/create_descriptor.bin \
  sdk/go/openshell/v1/create_descriptor.bin
```

Python/TypeScript curated ownership clients and full cross-SDK/installed-runtime qualification remain incomplete.
