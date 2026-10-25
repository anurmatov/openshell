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
CREATE FUNCTION refuse_create_ownership_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ownership retention'; END $$;
CREATE TRIGGER create_ownership_no_delete BEFORE DELETE ON sandbox_create_ownership
FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
CREATE TRIGGER create_binding_no_delete BEFORE DELETE ON sandbox_create_ownership_bindings
FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
CREATE TRIGGER create_binding_no_update BEFORE UPDATE ON sandbox_create_ownership_bindings
FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
CREATE FUNCTION check_create_ownership_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (OLD.caller_hash,OLD.workspace_id,OLD.request_uuid,OLD.claim_id,
     OLD.original_fingerprint,OLD.effective_fingerprint,OLD.schema_digest,OLD.coverage_epoch,OLD.created_at_ms)
 IS DISTINCT FROM
    (NEW.caller_hash,NEW.workspace_id,NEW.request_uuid,NEW.claim_id,
     NEW.original_fingerprint,NEW.effective_fingerprint,NEW.schema_digest,NEW.coverage_epoch,NEW.created_at_ms)
 THEN RAISE EXCEPTION 'immutable ownership'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER create_ownership_immutable BEFORE UPDATE ON sandbox_create_ownership
FOR EACH ROW EXECUTE FUNCTION check_create_ownership_immutable();

-- Legacy replay rows may expire, but their UUIDs cannot become audited absence.
CREATE TABLE sandbox_create_legacy_keys (
    caller_hash TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    request_uuid TEXT NOT NULL,
    mutation_key TEXT NOT NULL,
    PRIMARY KEY (caller_hash,workspace_id,request_uuid)
);
CREATE TRIGGER create_legacy_key_no_delete BEFORE DELETE ON sandbox_create_legacy_keys
FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
CREATE TRIGGER create_legacy_key_no_update BEFORE UPDATE ON sandbox_create_legacy_keys
FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();

-- A namespace is qualified only when this application observes a new database.
CREATE TABLE sandbox_create_coverage (singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch TEXT NOT NULL, fresh BOOLEAN NOT NULL, created_at_ms BIGINT NOT NULL);
CREATE TRIGGER create_coverage_no_update BEFORE UPDATE ON sandbox_create_coverage FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
CREATE TRIGGER create_coverage_no_delete BEFORE DELETE ON sandbox_create_coverage FOR EACH ROW EXECUTE FUNCTION refuse_create_ownership_delete();
