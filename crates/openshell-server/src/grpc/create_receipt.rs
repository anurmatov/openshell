// SPDX-License-Identifier: Apache-2.0

//! Durable admission/fence metadata foundation. No public handler or capability is enabled.
//! Missing records are only a point-in-time read, never proof of absence or retry permission.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, SqlitePool};

#[derive(Debug, thiserror::Error)]
pub(crate) enum LedgerError {
    #[error("create ownership input invalid")]
    Invalid,
    #[error("create ownership storage unavailable")]
    Unavailable,
    #[error("create ownership record invalid")]
    Corrupt,
    #[error("REQUEST_ID_PAYLOAD_MISMATCH")]
    Mismatch,
    #[error("REQUEST_ID_FENCED")]
    Fenced,
    #[error("REQUEST_OUTCOME_UNCERTAIN")]
    Pending,
    #[error("CREATE_OWNERSHIP_CAP_FULL")]
    Capacity,
    #[error("UNSUPPORTED_COVERAGE")]
    UnsupportedCoverage,
    #[error("CREATE_FENCE_RATE_LIMIT")]
    FenceRate,
}

type Result<T> = std::result::Result<T, LedgerError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ReceiptKey {
    pub caller_hash: String,
    pub workspace_id: String,
    pub request_uuid: String,
}

impl ReceiptKey {
    fn validate(&self) -> Result<()> {
        if !digest(&self.caller_hash) || self.workspace_id.is_empty() || !uuid(&self.request_uuid) {
            return Err(LedgerError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum ReceiptState {
    Pending,
    FencedPending,
    Abandoned,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub key: ReceiptKey,
    pub claim_id: String,
    pub original_fingerprint: String,
    pub effective_fingerprint: String,
    pub schema_digest: String,
    pub coverage_epoch: String,
    pub state: ReceiptState,
    pub revision: i64,
    pub fence_revision: i64,
    pub admission_closed: bool,
    pub created_at_ms: i64,
}

impl Receipt {
    fn validate(&self) -> Result<()> {
        self.key.validate()?;
        if !uuid(&self.claim_id)
            || !uuid(&self.coverage_epoch)
            || !digest(&self.original_fingerprint)
            || !digest(&self.effective_fingerprint)
            || !digest(&self.schema_digest)
            || self.revision < 1
            || self.fence_revision < 0
            || self.created_at_ms < 0
        {
            return Err(LedgerError::Invalid);
        }
        Ok(())
    }
    fn sql_state(&self) -> &'static str {
        match self.state {
            ReceiptState::Pending => "PENDING",
            ReceiptState::FencedPending => "FENCED_PENDING",
            ReceiptState::Abandoned => "ABANDONED",
        }
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}
fn decode(payload: &str, key: &ReceiptKey, fingerprint: &str, schema: &str) -> Result<Receipt> {
    let receipt: Receipt = serde_json::from_str(payload).map_err(|_| LedgerError::Corrupt)?;
    receipt.validate().map_err(|_| LedgerError::Corrupt)?;
    if &receipt.key != key {
        return Err(LedgerError::Corrupt);
    }
    if receipt.original_fingerprint != fingerprint || receipt.schema_digest != schema {
        return Err(LedgerError::Mismatch);
    }
    Ok(receipt)
}

/// Pools are supplied by the existing durable Store, never from a caller URL.
#[derive(Clone)]
pub(crate) enum CreateReceiptLedger {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl CreateReceiptLedger {
    /// SELECT only, including missing/mismatched/expired keys. No pruning or mutation dependency.
    pub(crate) async fn read(
        &self,
        key: &ReceiptKey,
        fingerprint: &str,
        schema: &str,
    ) -> Result<Option<Receipt>> {
        key.validate()?;
        if !digest(fingerprint) || !digest(schema) {
            return Err(LedgerError::Invalid);
        }
        let sql = "SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3";
        let payload: Option<String> = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(sql)
                    .bind(&key.caller_hash)
                    .bind(&key.workspace_id)
                    .bind(&key.request_uuid)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(sql)
                    .bind(&key.caller_hash)
                    .bind(&key.workspace_id)
                    .bind(&key.request_uuid)
                    .fetch_optional(pool)
                    .await
            }
        }
        .map_err(|_| LedgerError::Unavailable)?;
        payload
            .map(|payload| decode(&payload, key, fingerprint, schema))
            .transpose()
    }

    /// Reserve an audited owner AND its mutation claim atomically, before dispatch.
    /// An existing key is not replayed or re-executed, even with the identical payload.
    pub(crate) async fn reserve(&self, receipt: &Receipt, mutation_key: &str) -> Result<Receipt> {
        receipt.validate()?;
        if !digest(mutation_key)
            || receipt.state != ReceiptState::Pending
            || receipt.revision != 1
            || receipt.fence_revision != 0
            || receipt.admission_closed
        {
            return Err(LedgerError::Invalid);
        }
        match self {
            Self::Sqlite(pool) => reserve_sqlite(pool, receipt, mutation_key).await,
            Self::Postgres(pool) => reserve_postgres(pool, receipt, mutation_key).await,
        }
    }

    /// Explicit metadata-only abandonment; never invoked by read or an automatic timeout.
    pub(crate) async fn fence(&self, mut receipt: Receipt, mutation_key: &str) -> Result<Receipt> {
        if !digest(mutation_key) {
            return Err(LedgerError::Invalid);
        }
        receipt.validate()?;
        receipt.state = ReceiptState::Abandoned;
        receipt.admission_closed = true;
        receipt.revision = 1;
        receipt.fence_revision = 1;
        match self {
            Self::Sqlite(pool) => fence_sqlite(pool, receipt, mutation_key).await,
            Self::Postgres(pool) => fence_postgres(pool, receipt, mutation_key).await,
        }
    }
}

async fn reserve_sqlite(
    pool: &SqlitePool,
    receipt: &Receipt,
    mutation_key: &str,
) -> Result<Receipt> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if let Some(payload) = payload {
        let previous = decode(
            &payload,
            &receipt.key,
            &receipt.original_fingerprint,
            &receipt.schema_digest,
        )?;
        if previous.admission_closed {
            return Err(LedgerError::Fenced);
        }
        // An admitted owner remains the sole owner; no new execution grant is returned.
        return Err(LedgerError::Pending);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sandbox_create_ownership WHERE caller_hash=$1 AND state IN ('PENDING','AMBIGUOUS','FENCED_PENDING')")
        .bind(&receipt.key.caller_hash).fetch_one(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if count >= 1000 {
        return Err(LedgerError::Capacity);
    }
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    // Version 2 makes old mutation replay code refuse this retained admission, not replay it.
    let claim = serde_json::json!({"format_version":2,"payload_hash":receipt.original_fingerprint,"workspace_id":receipt.key.workspace_id,"target_id":null,"success":null,"completed_at_ms":null});
    sqlx::query("INSERT INTO objects (id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'mutation_admission_v1',$2,$3,$4,$5,$5,'{}',1)")
        .bind(&receipt.claim_id).bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
        .bind(serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)?).bind(receipt.created_at_ms)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(receipt.clone())
}

async fn fence_sqlite(
    pool: &SqlitePool,
    mut receipt: Receipt,
    mutation_key: &str,
) -> Result<Receipt> {
    let now_ms = receipt.created_at_ms;
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if let Some(payload) = payload {
        let mut previous = decode(
            &payload,
            &receipt.key,
            &receipt.original_fingerprint,
            &receipt.schema_digest,
        )?;
        if previous.admission_closed {
            return Ok(previous);
        }
        previous.admission_closed = true;
        previous.state = ReceiptState::FencedPending;
        previous.revision += 1;
        previous.fence_revision = 1;
        receipt = previous;
    }
    if receipt.state == ReceiptState::Abandoned {
        let legacy: Option<String> = sqlx::query_scalar("SELECT id FROM objects WHERE object_type='mutation_admission_v1' AND name=$1 AND workspace=$2")
            .bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
            .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
        if legacy.is_some() {
            return Err(LedgerError::UnsupportedCoverage);
        }
    }
    let (window, count): (i64,i64) = sqlx::query_as("SELECT fence_window_ms,fence_count FROM sandbox_create_ownership_callers WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).fetch_one(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let same_window = now_ms < window || now_ms.saturating_sub(window) < 60000;
    if same_window && count >= 100 {
        return Err(LedgerError::FenceRate);
    }
    sqlx::query("UPDATE sandbox_create_ownership_callers SET fence_window_ms=$2,fence_count=$3 WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).bind(if same_window { window } else { now_ms })
        .bind(if same_window { count+1 } else {1}).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(caller_hash,workspace_id,request_uuid) DO UPDATE SET state=excluded.state,receipt_revision=excluded.receipt_revision,fence_revision=excluded.fence_revision,admission_closed=excluded.admission_closed,payload=excluded.payload")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(receipt)
}

async fn reserve_postgres(pool: &PgPool, receipt: &Receipt, mutation_key: &str) -> Result<Receipt> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let _: String = sqlx::query_scalar(
        "SELECT caller_hash FROM sandbox_create_ownership_callers WHERE caller_hash=$1 FOR UPDATE",
    )
    .bind(&receipt.key.caller_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if let Some(payload) = payload {
        let previous = decode(
            &payload,
            &receipt.key,
            &receipt.original_fingerprint,
            &receipt.schema_digest,
        )?;
        if previous.admission_closed {
            return Err(LedgerError::Fenced);
        }
        // An admitted owner remains the sole owner; no new execution grant is returned.
        return Err(LedgerError::Pending);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sandbox_create_ownership WHERE caller_hash=$1 AND state IN ('PENDING','AMBIGUOUS','FENCED_PENDING')")
        .bind(&receipt.key.caller_hash).fetch_one(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if count >= 1000 {
        return Err(LedgerError::Capacity);
    }
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    // Version 2 makes old mutation replay code refuse this retained admission, not replay it.
    let claim = serde_json::json!({"format_version":2,"payload_hash":receipt.original_fingerprint,"workspace_id":receipt.key.workspace_id,"target_id":null,"success":null,"completed_at_ms":null});
    sqlx::query("INSERT INTO objects (id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'mutation_admission_v1',$2,$3,$4,$5,$5,'{}',1)")
        .bind(&receipt.claim_id).bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
        .bind(serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)?).bind(receipt.created_at_ms)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(receipt.clone())
}

async fn fence_postgres(
    pool: &PgPool,
    mut receipt: Receipt,
    mutation_key: &str,
) -> Result<Receipt> {
    let now_ms = receipt.created_at_ms;
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let _: String = sqlx::query_scalar(
        "SELECT caller_hash FROM sandbox_create_ownership_callers WHERE caller_hash=$1 FOR UPDATE",
    )
    .bind(&receipt.key.caller_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if let Some(payload) = payload {
        let mut previous = decode(
            &payload,
            &receipt.key,
            &receipt.original_fingerprint,
            &receipt.schema_digest,
        )?;
        if previous.admission_closed {
            return Ok(previous);
        }
        previous.admission_closed = true;
        previous.state = ReceiptState::FencedPending;
        previous.revision += 1;
        previous.fence_revision = 1;
        receipt = previous;
    }
    if receipt.state == ReceiptState::Abandoned {
        let legacy: Option<String> = sqlx::query_scalar("SELECT id FROM objects WHERE object_type='mutation_admission_v1' AND name=$1 AND workspace=$2")
            .bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
            .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
        if legacy.is_some() {
            return Err(LedgerError::UnsupportedCoverage);
        }
    }
    let (window, count): (i64,i64) = sqlx::query_as("SELECT fence_window_ms,fence_count FROM sandbox_create_ownership_callers WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).fetch_one(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let same_window = now_ms < window || now_ms.saturating_sub(window) < 60000;
    if same_window && count >= 100 {
        return Err(LedgerError::FenceRate);
    }
    sqlx::query("UPDATE sandbox_create_ownership_callers SET fence_window_ms=$2,fence_count=$3 WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).bind(if same_window { window } else { now_ms })
        .bind(if same_window { count+1 } else {1}).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(caller_hash,workspace_id,request_uuid) DO UPDATE SET state=excluded.state,receipt_revision=excluded.receipt_revision,fence_revision=excluded.fence_revision,admission_closed=excluded.admission_closed,payload=excluded.payload")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "create_receipt_tests.rs"]
mod tests;
