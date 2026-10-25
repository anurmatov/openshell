-- Additive ownership metadata, deliberately independent of live object deletion.
CREATE TABLE sandbox_create_ownership_callers (
    caller_hash TEXT PRIMARY KEY,
    fence_window_ms BIGINT NOT NULL DEFAULT 0,
    fence_count BIGINT NOT NULL DEFAULT 0 CHECK (fence_count >= 0)
);
CREATE TABLE sandbox_create_ownership (
    caller_hash TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    request_uuid TEXT NOT NULL,
    claim_id TEXT NOT NULL UNIQUE,
    original_fingerprint TEXT NOT NULL,
    effective_fingerprint TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    coverage_epoch TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','SUCCEEDED','AMBIGUOUS','NO_RESOURCE','EXPIRED','ABANDONED','FENCED_PENDING')),
    receipt_revision BIGINT NOT NULL CHECK (receipt_revision > 0),
    fence_revision BIGINT NOT NULL CHECK (fence_revision >= 0),
    admission_closed BOOLEAN NOT NULL,
    created_at_ms BIGINT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (caller_hash, workspace_id, request_uuid)
);
CREATE INDEX sandbox_create_ownership_unresolved
    ON sandbox_create_ownership (caller_hash, state);
-- Bindings have no foreign key to objects: deleting a Sandbox cannot delete ownership.
CREATE TABLE sandbox_create_ownership_bindings (
    claim_id TEXT NOT NULL REFERENCES sandbox_create_ownership(claim_id),
    sandbox_id TEXT NOT NULL,
    initial_resource_version BIGINT NOT NULL CHECK (initial_resource_version > 0),
    binding_revision BIGINT NOT NULL CHECK (binding_revision > 0),
    PRIMARY KEY (claim_id, sandbox_id),
    UNIQUE (sandbox_id)
);
CREATE TRIGGER create_ownership_no_delete BEFORE DELETE ON sandbox_create_ownership
BEGIN SELECT RAISE(ABORT, 'ownership retention'); END;
CREATE TRIGGER create_binding_no_delete BEFORE DELETE ON sandbox_create_ownership_bindings
BEGIN SELECT RAISE(ABORT, 'binding retention'); END;
CREATE TRIGGER create_binding_no_update BEFORE UPDATE ON sandbox_create_ownership_bindings
BEGIN SELECT RAISE(ABORT, 'immutable binding'); END;
CREATE TRIGGER create_ownership_immutable BEFORE UPDATE ON sandbox_create_ownership
WHEN OLD.caller_hash IS NOT NEW.caller_hash OR OLD.workspace_id IS NOT NEW.workspace_id
 OR OLD.request_uuid IS NOT NEW.request_uuid OR OLD.claim_id IS NOT NEW.claim_id
 OR OLD.original_fingerprint IS NOT NEW.original_fingerprint
 OR OLD.effective_fingerprint IS NOT NEW.effective_fingerprint
 OR OLD.schema_digest IS NOT NEW.schema_digest OR OLD.coverage_epoch IS NOT NEW.coverage_epoch
 OR OLD.created_at_ms IS NOT NEW.created_at_ms
BEGIN SELECT RAISE(ABORT, 'immutable ownership'); END;

-- Legacy replay rows may expire, but their UUIDs cannot become audited absence.
CREATE TABLE sandbox_create_legacy_keys (
    caller_hash TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    request_uuid TEXT NOT NULL,
    mutation_key TEXT NOT NULL,
    PRIMARY KEY (caller_hash,workspace_id,request_uuid)
);
CREATE TRIGGER create_legacy_key_no_delete BEFORE DELETE ON sandbox_create_legacy_keys
BEGIN SELECT RAISE(ABORT, 'legacy coverage retention'); END;
CREATE TRIGGER create_legacy_key_no_update BEFORE UPDATE ON sandbox_create_legacy_keys
BEGIN SELECT RAISE(ABORT, 'immutable legacy coverage'); END;

-- A namespace is qualified only when this application observes a new database.
CREATE TABLE sandbox_create_coverage (singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch TEXT NOT NULL, fresh BOOLEAN NOT NULL, created_at_ms BIGINT NOT NULL);
CREATE TRIGGER create_coverage_no_update BEFORE UPDATE ON sandbox_create_coverage BEGIN SELECT RAISE(ABORT, 'immutable coverage'); END;
CREATE TRIGGER create_coverage_no_delete BEFORE DELETE ON sandbox_create_coverage BEGIN SELECT RAISE(ABORT, 'coverage retention'); END;
