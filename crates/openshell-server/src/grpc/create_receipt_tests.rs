// SPDX-License-Identifier: Apache-2.0
use super::*;

async fn ledger() -> (CreateReceiptLedger, SqlitePool) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    for sql in [
        include_str!("../../migrations/sqlite/001_create_objects.sql"),
        include_str!("../../migrations/sqlite/004_add_object_metadata.sql"),
        include_str!("../../migrations/sqlite/005_add_resource_version.sql"),
        include_str!("../../migrations/sqlite/006_add_workspace_column.sql"),
        include_str!("../../migrations/sqlite/009_create_ownership_receipts.sql"),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    (CreateReceiptLedger::Sqlite(pool.clone()), pool)
}
fn receipt(index: u128) -> Receipt {
    Receipt {
        key: ReceiptKey {
            caller_hash: "a".repeat(64),
            workspace_id: uuid::Uuid::from_u128(99998).to_string(),
            request_uuid: uuid::Uuid::from_u128(index + 1).to_string(),
        },
        claim_id: uuid::Uuid::from_u128(index + 10001).to_string(),
        original_fingerprint: "b".repeat(64),
        effective_fingerprint: "c".repeat(64),
        schema_digest: "d".repeat(64),
        coverage_epoch: uuid::Uuid::from_u128(99999).to_string(),
        state: ReceiptState::Pending,
        revision: 1,
        fence_revision: 0,
        admission_closed: false,
        created_at_ms: 100000,
    }
}
async fn count(pool: &SqlitePool, table: &str) -> i64 {
    sqlx::query_scalar(match table {
        "objects" => "SELECT count(*) FROM objects WHERE object_type != 'workspace'",
        "sandbox_create_ownership" => "SELECT count(*) FROM sandbox_create_ownership",
        "sandbox_create_ownership_callers" => {
            "SELECT count(*) FROM sandbox_create_ownership_callers"
        }
        "sandbox_create_ownership_bindings" => {
            "SELECT count(*) FROM sandbox_create_ownership_bindings"
        }
        _ => panic!("unknown fixture table"),
    })
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn create_receipt_admission_and_mutation_claim_are_atomic() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
    assert_eq!(count(&pool, "objects").await, 1);
    assert_eq!(
        ledger
            .read(&row.key, &row.original_fingerprint, &row.schema_digest)
            .await
            .unwrap(),
        Some(row.clone())
    );
    assert!(matches!(
        ledger.reserve(&row, &"1".repeat(64)).await,
        Err(LedgerError::Pending)
    ));
    assert_eq!(count(&pool, "objects").await, 1);
    // A conflicting mutation name rolls the new ownership row back as well.
    assert!(ledger.reserve(&receipt(2), &"1".repeat(64)).await.is_err());
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 1);
}

#[tokio::test]
async fn create_request_fence_wins_and_delayed_admission_has_zero_claims() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    let fenced = ledger.fence(row.clone(), &"1".repeat(64)).await.unwrap();
    assert_eq!(fenced.state, ReceiptState::Abandoned);
    assert!(matches!(
        ledger.reserve(&row, &"1".repeat(64)).await,
        Err(LedgerError::Fenced)
    ));
    assert_eq!(count(&pool, "objects").await, 0);
    assert_eq!(
        ledger.fence(row.clone(), &"1".repeat(64)).await.unwrap(),
        fenced
    );
    assert_eq!(
        ledger
            .read(&row.key, &row.original_fingerprint, &row.schema_digest)
            .await
            .unwrap(),
        Some(fenced)
    );
}

#[tokio::test]
async fn create_request_fence_retains_admitted_owner_and_revision() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
    let fenced = ledger.fence(row.clone(), &"1".repeat(64)).await.unwrap();
    assert_eq!(fenced.state, ReceiptState::FencedPending);
    assert_eq!(fenced.claim_id, row.claim_id);
    assert_eq!(fenced.revision, 2);
    assert_eq!(ledger.fence(row, &"1".repeat(64)).await.unwrap(), fenced);
    assert_eq!(count(&pool, "objects").await, 1);
}

#[tokio::test]
async fn create_receipt_missing_and_mismatched_reads_write_nothing() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    assert!(
        ledger
            .read(&row.key, &row.original_fingerprint, &row.schema_digest)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(count(&pool, "sandbox_create_ownership_callers").await, 0);
    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
    let mut bad = row.clone();
    bad.original_fingerprint = "e".repeat(64);
    assert!(matches!(
        ledger.fence(bad, &"1".repeat(64)).await,
        Err(LedgerError::Mismatch)
    ));
    assert_eq!(
        ledger
            .read(&row.key, &row.original_fingerprint, &row.schema_digest)
            .await
            .unwrap(),
        Some(row)
    );
    assert_eq!(count(&pool, "objects").await, 1);
}

#[tokio::test]
async fn create_request_fence_rate_limit_preserves_rows_and_resets_by_call_time() {
    let (ledger, pool) = ledger().await;
    for index in 0..100 {
        ledger.fence(receipt(index), &"1".repeat(64)).await.unwrap();
    }
    assert!(matches!(
        ledger.fence(receipt(101), &"1".repeat(64)).await,
        Err(LedgerError::FenceRate)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 100);
    let mut later = receipt(101);
    later.created_at_ms += 60000;
    ledger.fence(later, &"1".repeat(64)).await.unwrap();
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 101);
}

#[tokio::test]
async fn create_receipt_quota_never_evicts_pending_owners() {
    let (ledger, pool) = ledger().await;
    for index in 0..1000 {
        ledger
            .reserve(&receipt(index), &format!("{index:064x}"))
            .await
            .unwrap();
    }
    assert!(matches!(
        ledger
            .reserve(&receipt(1001), &format!("{:064x}", 1001))
            .await,
        Err(LedgerError::Capacity)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 1000);
    assert_eq!(count(&pool, "objects").await, 1000);
}

#[tokio::test]
async fn create_receipt_raw_delete_and_binding_update_are_refused() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
    assert!(
        sqlx::query("DELETE FROM sandbox_create_ownership")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE sandbox_create_ownership SET original_fingerprint='changed'")
            .execute(&pool)
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO sandbox_create_ownership_bindings VALUES($1,'sandbox-a',1,1)")
        .bind(&row.claim_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE sandbox_create_ownership_bindings SET sandbox_id='replacement'")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM sandbox_create_ownership_bindings")
            .execute(&pool)
            .await
            .is_err()
    );
    // Live object deletion cannot cascade to either retained ownership table.
    sqlx::query("DELETE FROM objects")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 1);
}

#[tokio::test]
async fn create_request_fence_never_reports_absence_for_a_legacy_claim() {
    let (ledger, pool) = ledger().await;
    let row = receipt(1);
    sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms) VALUES('legacy','mutation_admission_v1',$1,$2,$3,1,1)")
        .bind("1".repeat(64)).bind(format!("_mutation/{}",row.key.caller_hash))
        .bind(b"{}".as_slice()).execute(&pool).await.unwrap();
    assert!(matches!(
        ledger.fence(row, &"1".repeat(64)).await,
        Err(LedgerError::UnsupportedCoverage)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 0);
    assert_eq!(count(&pool, "objects").await, 1);
}

async fn binding_ledger() -> (CreateReceiptLedger, SqlitePool) {
    use prost::Message;
    let (ledger, pool) = ledger().await;
    let workspace = openshell_core::proto::Workspace {
        metadata: Some(openshell_core::proto::ObjectMeta {
            id: receipt(1).key.workspace_id,
            name: "workspace-a".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'workspace','workspace-a','',$2,1,1,'{}',1)")
        .bind(receipt(1).key.workspace_id).bind(workspace.encode_to_vec()).execute(&pool).await.unwrap();
    (ledger, pool)
}

fn sandbox(index: u128, name: &str) -> openshell_core::proto::Sandbox {
    openshell_core::proto::Sandbox {
        metadata: Some(openshell_core::proto::ObjectMeta {
            id: uuid::Uuid::from_u128(index + 20001).to_string(),
            name: name.into(),
            workspace: "workspace-a".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn create_receipt_binding_commits_sandbox_and_owner_after_fence() {
    use prost::Message;
    let (ledger, pool) = binding_ledger().await;
    let owner = receipt(1);
    ledger.reserve(&owner, &"1".repeat(64)).await.unwrap();
    ledger.fence(owner.clone(), &"1".repeat(64)).await.unwrap();
    let resource = sandbox(1, "owned");
    let bound = ledger.bind_resource(&owner, &resource).await.unwrap();
    assert_eq!(bound.metadata.as_ref().unwrap().resource_version, 1);
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM objects WHERE object_type='sandbox'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        openshell_core::proto::Sandbox::decode(bytes.as_slice()).unwrap(),
        bound
    );
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 1);
    let current = ledger
        .read(
            &owner.key,
            &owner.original_fingerprint,
            &owner.schema_digest,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.state, ReceiptState::FencedPending);
    assert!(current.admission_closed);
    assert_eq!(current.revision, 3);
    assert!(
        ledger
            .bind_resource(&owner, &sandbox(2, "second"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "objects").await, 2);
    // Live resource deletion cannot erase the immutable binding.
    sqlx::query("DELETE FROM objects WHERE object_type='sandbox'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 1);
}

#[tokio::test]
async fn create_receipt_binding_refuses_foreign_owner_and_rolls_back_conflict() {
    let (ledger, pool) = binding_ledger().await;
    let owner = receipt(1);
    ledger.reserve(&owner, &"1".repeat(64)).await.unwrap();
    let mut foreign = owner.clone();
    foreign.claim_id = receipt(2).claim_id;
    assert!(
        ledger
            .bind_resource(&foreign, &sandbox(1, "shared"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 0);
    ledger
        .bind_resource(&owner, &sandbox(1, "shared"))
        .await
        .unwrap();
    let second = receipt(2);
    ledger.reserve(&second, &"2".repeat(64)).await.unwrap();
    assert!(
        ledger
            .bind_resource(&second, &sandbox(2, "shared"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 1);
    assert_eq!(
        ledger
            .read(
                &second.key,
                &second.original_fingerprint,
                &second.schema_digest
            )
            .await
            .unwrap(),
        Some(second.clone())
    );
    ledger
        .bind_resource(&second, &sandbox(2, "different"))
        .await
        .unwrap();
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 2);
}

// Independent pools to a real owned SQLite file: no shared single-connection
// mutex can mask missing database transaction serialization.
struct ConcurrentLedger {
    path: std::path::PathBuf,
    first: SqlitePool,
    second: SqlitePool,
}
impl ConcurrentLedger {
    async fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("create-ownership-{}.sqlite", uuid::Uuid::new_v4()));
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_secs(3));
        let first = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .unwrap();
        for sql in [
            include_str!("../../migrations/sqlite/001_create_objects.sql"),
            include_str!("../../migrations/sqlite/004_add_object_metadata.sql"),
            include_str!("../../migrations/sqlite/005_add_resource_version.sql"),
            include_str!("../../migrations/sqlite/006_add_workspace_column.sql"),
            include_str!("../../migrations/sqlite/009_create_ownership_receipts.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&first).await.unwrap();
        }
        let second = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        Self {
            path,
            first,
            second,
        }
    }
    async fn close(self) {
        self.first.close().await;
        self.second.close().await;
        std::fs::remove_file(self.path).unwrap();
    }
}

#[tokio::test]
async fn create_receipt_overlapping_connections_admission_then_fence_retains_owner() {
    let db = ConcurrentLedger::new().await;
    let owner = receipt(1);
    let key = "1".repeat(64);
    // Execute the actual production admission transaction body, but hold its
    // commit while a different connection is attempting the production fence.
    let mut tx = db.first.begin_with("BEGIN IMMEDIATE").await.unwrap();
    reserve_sqlite_transaction(&mut tx, &owner, &key)
        .await
        .unwrap();
    let other = CreateReceiptLedger::Sqlite(db.second.clone());
    let pending = other.fence(owner.clone(), &key);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(4), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.claim_id, owner.claim_id);
    assert_eq!(result.state, ReceiptState::FencedPending);
    assert_eq!(result.revision, 2);
    assert_eq!(count(&db.first, "objects").await, 1);
    assert_eq!(count(&db.first, "sandbox_create_ownership").await, 1);
    db.close().await;
}

#[tokio::test]
async fn create_receipt_overlapping_connections_fence_then_admission_has_no_claim() {
    let db = ConcurrentLedger::new().await;
    let owner = receipt(1);
    let key = "1".repeat(64);
    let mut tx = db.first.begin_with("BEGIN IMMEDIATE").await.unwrap();
    // The public internal fence wrapper normalizes a fresh request this way.
    let mut candidate = owner.clone();
    candidate.state = ReceiptState::Abandoned;
    candidate.admission_closed = true;
    candidate.fence_revision = 1;
    fence_sqlite_transaction(&mut tx, candidate, &key)
        .await
        .unwrap();
    let other = CreateReceiptLedger::Sqlite(db.second.clone());
    let pending = other.reserve(&owner, &key);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), pending)
            .await
            .unwrap(),
        Err(LedgerError::Fenced)
    ));
    assert_eq!(count(&db.first, "objects").await, 0);
    assert_eq!(count(&db.first, "sandbox_create_ownership").await, 1);
    db.close().await;
}

#[tokio::test]
async fn create_receipt_overlapping_connections_quota_accepts_only_last_slot() {
    let db = ConcurrentLedger::new().await;
    let ledger = CreateReceiptLedger::Sqlite(db.first.clone());
    for index in 1..1000 {
        ledger
            .reserve(&receipt(index), &format!("{index:064x}"))
            .await
            .unwrap();
    }
    let owner = receipt(1000);
    let mut tx = db.first.begin_with("BEGIN IMMEDIATE").await.unwrap();
    reserve_sqlite_transaction(&mut tx, &owner, &format!("{:064x}", 1000))
        .await
        .unwrap();
    let other = CreateReceiptLedger::Sqlite(db.second.clone());
    let next = receipt(1001);
    let next_key = format!("{:064x}", 1001);
    let pending = other.reserve(&next, &next_key);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), pending)
            .await
            .unwrap(),
        Err(LedgerError::Capacity)
    ));
    assert_eq!(count(&db.first, "sandbox_create_ownership").await, 1000);
    assert_eq!(count(&db.first, "objects").await, 1000);
    assert_eq!(
        other
            .read(&next.key, &next.original_fingerprint, &next.schema_digest)
            .await
            .unwrap(),
        None
    );
    drop(ledger);
    db.close().await;
}

#[tokio::test]
async fn create_receipt_binding_failure_after_insert_rolls_back_every_write() {
    let (ledger, pool) = binding_ledger().await;
    let owner = receipt(1);
    ledger.reserve(&owner, &"1".repeat(64)).await.unwrap();
    // Fail after Sandbox and binding insertion, at mutation-claim enrichment.
    sqlx::raw_sql("CREATE TRIGGER fail_claim_update BEFORE UPDATE ON objects WHEN OLD.object_type='mutation_admission_v1' BEGIN SELECT RAISE(ABORT, 'owned injected failure'); END")
        .execute(&pool).await.unwrap();
    assert!(
        ledger
            .bind_resource(&owner, &sandbox(1, "owned"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "objects").await, 1);
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 0);
    assert_eq!(
        ledger
            .read(
                &owner.key,
                &owner.original_fingerprint,
                &owner.schema_digest
            )
            .await
            .unwrap(),
        Some(owner)
    );
}

#[tokio::test]
async fn create_receipt_binding_requires_an_admitted_owner_and_matching_workspace() {
    let (ledger, pool) = binding_ledger().await;
    let owner = receipt(1);
    assert!(
        ledger
            .bind_resource(&owner, &sandbox(1, "owned"))
            .await
            .is_err()
    );
    ledger.fence(owner.clone(), &"1".repeat(64)).await.unwrap();
    assert!(
        ledger
            .bind_resource(&owner, &sandbox(1, "owned"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "objects").await, 0);
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 0);
    let second = receipt(2);
    ledger.reserve(&second, &"2".repeat(64)).await.unwrap();
    let mut wrong_workspace = sandbox(2, "foreign");
    wrong_workspace.metadata.as_mut().unwrap().workspace = "workspace-b".into();
    assert!(
        ledger
            .bind_resource(&second, &wrong_workspace)
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "objects").await, 1);
}

#[tokio::test]
async fn create_receipt_binding_cannot_reassign_a_deleted_sandbox_id() {
    let (ledger, pool) = binding_ledger().await;
    let first = receipt(1);
    ledger.reserve(&first, &"1".repeat(64)).await.unwrap();
    ledger
        .bind_resource(&first, &sandbox(1, "original"))
        .await
        .unwrap();
    sqlx::query("DELETE FROM objects WHERE object_type='sandbox'")
        .execute(&pool)
        .await
        .unwrap();
    let next = receipt(2);
    ledger.reserve(&next, &"2".repeat(64)).await.unwrap();
    assert!(
        ledger
            .bind_resource(&next, &sandbox(1, "replacement"))
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "objects").await, 2); // only the two admission claims
    assert_eq!(count(&pool, "sandbox_create_ownership_bindings").await, 1);
    let claim: String =
        sqlx::query_scalar("SELECT claim_id FROM sandbox_create_ownership_bindings")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim, first.claim_id);
    assert_eq!(
        ledger
            .read(&next.key, &next.original_fingerprint, &next.schema_digest)
            .await
            .unwrap(),
        Some(next)
    );
}

fn legacy_payload(key: &ReceiptKey) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format_version":1,"payload_hash":"e".repeat(64),
        "workspace_id":key.workspace_id,"target_id":null,
        "success":null,"completed_at_ms":null
    }))
    .unwrap()
}

#[tokio::test]
async fn create_request_fence_blocks_legacy_downgrade_before_claim() {
    let (ledger, pool) = ledger().await;
    let owner = receipt(1);
    ledger.fence(owner.clone(), &"1".repeat(64)).await.unwrap();
    assert!(matches!(
        ledger
            .reserve_legacy(
                &owner.key,
                &owner.claim_id,
                &"1".repeat(64),
                &legacy_payload(&owner.key),
                100000
            )
            .await,
        Err(LedgerError::Fenced)
    ));
    assert_eq!(count(&pool, "objects").await, 0);
}

#[tokio::test]
async fn create_receipt_legacy_admission_keeps_original_bytes_and_refuses_fence_absence() {
    let (ledger, pool) = ledger().await;
    let owner = receipt(1);
    let bytes = legacy_payload(&owner.key);
    assert_eq!(
        ledger
            .reserve_legacy(&owner.key, &owner.claim_id, &"1".repeat(64), &bytes, 100000)
            .await
            .unwrap(),
        LegacyReservation::Created
    );
    let actual: Vec<u8> = sqlx::query_scalar("SELECT payload FROM objects")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        ledger
            .reserve_legacy(
                &owner.key,
                &receipt(2).claim_id,
                &"1".repeat(64),
                &bytes,
                100000
            )
            .await
            .unwrap(),
        LegacyReservation::Contended
    );
    assert!(matches!(
        ledger.fence(owner.clone(), &"1".repeat(64)).await,
        Err(LedgerError::UnsupportedCoverage)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 0);
    assert_eq!(count(&pool, "objects").await, 1);
}

#[tokio::test]
async fn create_receipt_overlapping_legacy_downgrade_waits_for_fence_commit() {
    let db = ConcurrentLedger::new().await;
    let owner = receipt(1);
    let mut tx = db.first.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let mut candidate = owner.clone();
    candidate.state = ReceiptState::Abandoned;
    candidate.admission_closed = true;
    candidate.fence_revision = 1;
    fence_sqlite_transaction(&mut tx, candidate, &"1".repeat(64))
        .await
        .unwrap();
    let other = CreateReceiptLedger::Sqlite(db.second.clone());
    let key = "1".repeat(64);
    let bytes = legacy_payload(&owner.key);
    let pending = other.reserve_legacy(&owner.key, &owner.claim_id, &key, &bytes, 100000);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), pending)
            .await
            .unwrap(),
        Err(LedgerError::Fenced)
    ));
    assert_eq!(count(&db.first, "objects").await, 0);
    db.close().await;
}

#[tokio::test]
async fn create_receipt_overlapping_legacy_admission_prevents_fence_absence() {
    let db = ConcurrentLedger::new().await;
    let owner = receipt(1);
    let key = "1".repeat(64);
    let mut tx = db.first.begin_with("BEGIN IMMEDIATE").await.unwrap();
    assert_eq!(
        reserve_legacy_sqlite_transaction(
            &mut tx,
            &owner.key,
            &owner.claim_id,
            &key,
            &legacy_payload(&owner.key),
            100000
        )
        .await
        .unwrap(),
        LegacyReservation::Created
    );
    let other = CreateReceiptLedger::Sqlite(db.second.clone());
    let pending = other.fence(owner.clone(), &key);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(4), pending)
            .await
            .unwrap(),
        Err(LedgerError::UnsupportedCoverage)
    ));
    assert_eq!(count(&db.first, "objects").await, 1);
    assert_eq!(count(&db.first, "sandbox_create_ownership").await, 0);
    db.close().await;
}

#[tokio::test]
async fn create_receipt_legacy_guard_never_bypasses_pending_owner_or_storage_failure() {
    let (ledger, pool) = ledger().await;
    let owner = receipt(1);
    ledger.reserve(&owner, &"1".repeat(64)).await.unwrap();
    assert!(matches!(
        ledger.guard_legacy(&owner.key).await,
        Err(LedgerError::Pending)
    ));
    assert!(matches!(
        ledger
            .reserve_legacy(
                &owner.key,
                &receipt(2).claim_id,
                &"2".repeat(64),
                &legacy_payload(&owner.key),
                100000
            )
            .await,
        Err(LedgerError::Pending)
    ));
    sqlx::raw_sql("DROP TABLE sandbox_create_ownership")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        ledger.guard_legacy(&owner.key).await,
        Err(LedgerError::Unavailable)
    ));
    assert!(matches!(
        ledger
            .reserve_legacy(
                &owner.key,
                &receipt(2).claim_id,
                &"2".repeat(64),
                &legacy_payload(&owner.key),
                100000
            )
            .await,
        Err(LedgerError::Unavailable)
    ));
    assert_eq!(count(&pool, "objects").await, 1);
}

#[tokio::test]
async fn create_receipt_legacy_guard_preserves_existing_mutation_quota() {
    let (ledger, pool) = ledger().await;
    for index in 0..1000 {
        ledger
            .reserve(&receipt(index), &format!("{index:064x}"))
            .await
            .unwrap();
    }
    let next = receipt(1001);
    assert_eq!(
        ledger
            .reserve_legacy(
                &next.key,
                &next.claim_id,
                &format!("{:064x}", 1001),
                &legacy_payload(&next.key),
                100000
            )
            .await
            .unwrap(),
        LegacyReservation::Full
    );
    assert_eq!(count(&pool, "objects").await, 1000);
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 1000);
}

#[tokio::test]
async fn create_receipt_legacy_expiry_cannot_become_audited_absence_or_new_owner() {
    let (ledger, pool) = ledger().await;
    let owner = receipt(1);
    ledger
        .reserve_legacy(
            &owner.key,
            &owner.claim_id,
            &"1".repeat(64),
            &legacy_payload(&owner.key),
            100000,
        )
        .await
        .unwrap();
    assert!(
        sqlx::query("DELETE FROM sandbox_create_legacy_keys")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE sandbox_create_legacy_keys SET mutation_key=$1")
            .bind("f".repeat(64))
            .execute(&pool)
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM objects WHERE object_type='mutation_admission_v1'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        ledger.fence(owner.clone(), &"1".repeat(64)).await,
        Err(LedgerError::UnsupportedCoverage)
    ));
    assert!(matches!(
        ledger.reserve(&owner, &"1".repeat(64)).await,
        Err(LedgerError::UnsupportedCoverage)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 0);
    assert!(matches!(
        ledger
            .read(
                &owner.key,
                &owner.original_fingerprint,
                &owner.schema_digest
            )
            .await,
        Err(LedgerError::UnsupportedCoverage)
    ));
    // Legacy UUID reuse still follows the existing legacy admission/replay contract.
    assert_eq!(
        ledger
            .reserve_legacy(
                &owner.key,
                &receipt(2).claim_id,
                &"1".repeat(64),
                &legacy_payload(&owner.key),
                200000
            )
            .await
            .unwrap(),
        LegacyReservation::Created
    );
}
