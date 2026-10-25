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
            workspace_id: "workspace-a".into(),
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
        "objects" => "SELECT count(*) FROM objects",
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
    let fenced = ledger.fence(row.clone()).await.unwrap();
    assert_eq!(fenced.state, ReceiptState::Abandoned);
    assert!(matches!(
        ledger.reserve(&row, &"1".repeat(64)).await,
        Err(LedgerError::Fenced)
    ));
    assert_eq!(count(&pool, "objects").await, 0);
    assert_eq!(ledger.fence(row.clone()).await.unwrap(), fenced);
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
    let fenced = ledger.fence(row.clone()).await.unwrap();
    assert_eq!(fenced.state, ReceiptState::FencedPending);
    assert_eq!(fenced.claim_id, row.claim_id);
    assert_eq!(fenced.revision, 2);
    assert_eq!(ledger.fence(row).await.unwrap(), fenced);
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
        ledger.fence(bad).await,
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
        ledger.fence(receipt(index)).await.unwrap();
    }
    assert!(matches!(
        ledger.fence(receipt(101)).await,
        Err(LedgerError::FenceRate)
    ));
    assert_eq!(count(&pool, "sandbox_create_ownership").await, 100);
    let mut later = receipt(101);
    later.created_at_ms += 60000;
    ledger.fence(later).await.unwrap();
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
