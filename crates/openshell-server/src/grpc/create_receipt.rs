// SPDX-License-Identifier: Apache-2.0

//! Durable request ownership and effect transitions. Capabilities remain unadvertised.
//! Missing records are only a point-in-time read, never proof of absence or retry permission.

use openshell_core::proto::Sandbox;
use prost::Message;
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
    Succeeded,
    NoResource,
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
    #[serde(default)]
    pub effect_started: bool,
    #[serde(default)]
    pub completed_at_ms: Option<i64>,
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
            || self
                .completed_at_ms
                .is_some_and(|time| time < self.created_at_ms)
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
            ReceiptState::Succeeded => "SUCCEEDED",
            ReceiptState::NoResource => "NO_RESOURCE",
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

#[derive(Debug)]
pub(crate) struct ReceiptSnapshot {
    pub receipt: Receipt,
    pub bindings: Vec<(String, i64, i64)>,
}

/// Legacy replay retains its format and quota; this guard grants only one new owner.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LegacyReservation {
    Created,
    Contended,
    Full,
}

/// Pools are supplied by the existing durable Store, never from a caller URL.
#[derive(Clone)]
pub(crate) enum CreateReceiptLedger {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl CreateReceiptLedger {
    /// Once-only startup provenance. An upgrade, restore without provenance or
    /// an uncertain concurrent initializer is never promoted by empty objects.
    pub(crate) async fn initialize_coverage(&self, fresh: bool) -> Result<()> {
        let epoch = uuid::Uuid::new_v4().to_string();
        let now = crate::persistence::current_time_ms();
        let sql = "INSERT INTO sandbox_create_coverage(singleton,epoch,fresh,created_at_ms) VALUES(1,$1,$2,$3) ON CONFLICT(singleton) DO NOTHING";
        match self {
            Self::Sqlite(pool) => sqlx::query(sql)
                .bind(&epoch)
                .bind(fresh)
                .bind(now)
                .execute(pool)
                .await
                .map(|_| ()),
            Self::Postgres(pool) => sqlx::query(sql)
                .bind(&epoch)
                .bind(fresh)
                .bind(now)
                .execute(pool)
                .await
                .map(|_| ()),
        }
        .map_err(|_| LedgerError::Unavailable)?;
        Ok(())
    }

    /// A replay-cache row can expire only after its permanent owner is terminal.
    pub(crate) async fn terminal_claim_completed_at(&self, claim_id: &str) -> Result<Option<i64>> {
        let sql = "SELECT payload FROM sandbox_create_ownership WHERE claim_id=$1";
        let payload: Option<String> = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(sql)
                    .bind(claim_id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(sql)
                    .bind(claim_id)
                    .fetch_optional(pool)
                    .await
            }
        }
        .map_err(|_| LedgerError::Unavailable)?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let row: Receipt = serde_json::from_str(&payload).map_err(|_| LedgerError::Corrupt)?;
        row.validate().map_err(|_| LedgerError::Corrupt)?;
        if row.claim_id != claim_id {
            return Err(LedgerError::Corrupt);
        }
        if !matches!(
            row.state,
            ReceiptState::Succeeded | ReceiptState::NoResource
        ) {
            return Ok(None);
        }
        let snapshot = self
            .read_snapshot(&row.key, &row.original_fingerprint, &row.schema_digest)
            .await?
            .ok_or(LedgerError::Corrupt)?;
        let current = snapshot.receipt;
        if current.claim_id != claim_id
            || !matches!(
                current.state,
                ReceiptState::Succeeded | ReceiptState::NoResource
            )
            || current.completed_at_ms.is_none()
            || (current.state == ReceiptState::Succeeded
                && (!current.effect_started || snapshot.bindings.len() != 1))
            || (current.state == ReceiptState::NoResource
                && (current.effect_started
                    || !current.admission_closed
                    || !snapshot.bindings.is_empty()))
        {
            return Err(LedgerError::Corrupt);
        }
        Ok(current.completed_at_ms)
    }

    /// SELECT only. No timestamp, object count or missing row creates coverage.
    pub(crate) async fn coverage(&self) -> Result<String> {
        let sql = "SELECT epoch,fresh FROM sandbox_create_coverage WHERE singleton=1";
        let row: Option<(String, bool)> = match self {
            Self::Sqlite(pool) => sqlx::query_as(sql).fetch_optional(pool).await,
            Self::Postgres(pool) => sqlx::query_as(sql).fetch_optional(pool).await,
        }
        .map_err(|_| LedgerError::Unavailable)?;
        match row {
            Some((epoch, true)) if uuid(&epoch) => Ok(epoch),
            _ => Err(LedgerError::UnsupportedCoverage),
        }
    }

    /// CAS preserves concurrent fences. A failed proof never reaches the driver.
    pub(crate) async fn driver_started(&self, owner: &Receipt) -> Result<()> {
        self.transition(owner, None).await
    }

    /// Only the admitted owner calls this after the real handler returned.
    /// Errors with any binding/effect remain unresolved, not false absence.
    pub(crate) async fn owner_finished(&self, owner: &Receipt, success: bool) -> Result<()> {
        self.transition(owner, Some(success)).await
    }

    async fn transition(&self, owner: &Receipt, finished: Option<bool>) -> Result<()> {
        for _ in 0..8 {
            let snapshot = self
                .read_snapshot(
                    &owner.key,
                    &owner.original_fingerprint,
                    &owner.schema_digest,
                )
                .await?
                .ok_or(LedgerError::Corrupt)?;
            let mut row = binding_owner(
                &serde_json::to_string(&snapshot.receipt).map_err(|_| LedgerError::Corrupt)?,
                owner,
            )?;
            let previous = row.revision;
            match finished {
                None => {
                    if row.effect_started || snapshot.bindings.len() != 1 {
                        return Err(LedgerError::Corrupt);
                    }
                    row.effect_started = true;
                }
                Some(true) => {
                    if !row.effect_started || snapshot.bindings.len() != 1 {
                        return Err(LedgerError::Corrupt);
                    }
                    row.state = ReceiptState::Succeeded;
                    row.completed_at_ms = Some(crate::persistence::current_time_ms());
                }
                Some(false) if !row.effect_started && snapshot.bindings.is_empty() => {
                    row.state = ReceiptState::NoResource;
                    row.admission_closed = true;
                    row.completed_at_ms = Some(crate::persistence::current_time_ms());
                }
                Some(false) => return Ok(()),
            }
            row.revision = previous.checked_add(1).ok_or(LedgerError::Corrupt)?;
            let payload = serde_json::to_string(&row).map_err(|_| LedgerError::Corrupt)?;
            let sql = "UPDATE sandbox_create_ownership SET state=$1,receipt_revision=$2,admission_closed=$3,payload=$4 WHERE claim_id=$5 AND receipt_revision=$6";
            let updated = if finished.is_some() {
                match self {
                    Self::Sqlite(pool) => {
                        finish_sqlite(pool, &row, previous, &snapshot.bindings).await?
                    }
                    Self::Postgres(pool) => {
                        finish_postgres(pool, &row, previous, &snapshot.bindings).await?
                    }
                }
            } else {
                match self {
                    Self::Sqlite(pool) => sqlx::query(sql)
                        .bind(row.sql_state())
                        .bind(row.revision)
                        .bind(row.admission_closed)
                        .bind(&payload)
                        .bind(&row.claim_id)
                        .bind(previous)
                        .execute(pool)
                        .await
                        .map(|r| r.rows_affected()),
                    Self::Postgres(pool) => sqlx::query(sql)
                        .bind(row.sql_state())
                        .bind(row.revision)
                        .bind(row.admission_closed)
                        .bind(&payload)
                        .bind(&row.claim_id)
                        .bind(previous)
                        .execute(pool)
                        .await
                        .map(|r| r.rows_affected()),
                }
                .map_err(|_| LedgerError::Unavailable)?
            };
            if updated == 1 {
                return Ok(());
            }
        }
        Err(LedgerError::Unavailable)
    }

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
        if payload.is_none() {
            let sql = "SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3";
            let legacy: Option<String> = match self {
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
            if legacy.is_some() {
                return Err(LedgerError::UnsupportedCoverage);
            }
        }
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

    /// Receipt revision and bindings are read from one repeatable, SELECT-only snapshot.
    pub(crate) async fn read_snapshot(
        &self,
        key: &ReceiptKey,
        fingerprint: &str,
        schema: &str,
    ) -> Result<Option<ReceiptSnapshot>> {
        key.validate()?;
        if !digest(fingerprint) || !digest(schema) {
            return Err(LedgerError::Invalid);
        }
        match self {
            Self::Sqlite(pool) => snapshot_sqlite(pool, key, fingerprint, schema).await,
            Self::Postgres(pool) => snapshot_postgres(pool, key, fingerprint, schema).await,
        }
    }

    /// Every UUID-bearing legacy Create consults this before replay or dispatch.
    /// The later atomic reservation repeats the check under the database lock.
    pub(crate) async fn guard_legacy(&self, key: &ReceiptKey) -> Result<()> {
        key.validate()?;
        let sql = "SELECT admission_closed FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3";
        let closed: Option<bool> = match self {
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
        legacy_allowed(closed)
    }

    /// Legacy admission and ownership/fence check share one database transaction.
    /// The existing payload bytes, claim namespace and 1000-row quota are unchanged.
    pub(crate) async fn reserve_legacy(
        &self,
        key: &ReceiptKey,
        claim_id: &str,
        mutation_key: &str,
        payload: &[u8],
        now_ms: i64,
    ) -> Result<LegacyReservation> {
        key.validate()?;
        if !uuid(claim_id) || !digest(mutation_key) || now_ms < 0 {
            return Err(LedgerError::Invalid);
        }
        let admission: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| LedgerError::Invalid)?;
        if admission["format_version"] != 1 || admission["workspace_id"] != key.workspace_id {
            return Err(LedgerError::Invalid);
        }
        match self {
            Self::Sqlite(pool) => {
                reserve_legacy_sqlite(pool, key, claim_id, mutation_key, payload, now_ms).await
            }
            Self::Postgres(pool) => {
                reserve_legacy_postgres(pool, key, claim_id, mutation_key, payload, now_ms).await
            }
        }
    }

    /// Commit the chosen Sandbox and its immutable ownership in the same transaction.
    /// Only the originally admitted owner may bind, including after an explicit fence.
    /// This is not an execution/replay grant and performs no driver work.
    pub(crate) async fn bind_resource(
        &self,
        owner: &Receipt,
        sandbox: &Sandbox,
    ) -> Result<Sandbox> {
        owner.validate()?;
        let metadata = sandbox.metadata.as_ref().ok_or(LedgerError::Invalid)?;
        if !uuid(&metadata.id)
            || metadata.name.is_empty()
            || metadata.workspace.is_empty()
            || metadata.resource_version != 0
        {
            return Err(LedgerError::Invalid);
        }
        let mut resource = sandbox.clone();
        resource
            .metadata
            .as_mut()
            .ok_or(LedgerError::Invalid)?
            .resource_version = 1;
        match self {
            Self::Sqlite(pool) => bind_sqlite(pool, owner, &resource).await?,
            Self::Postgres(pool) => bind_postgres(pool, owner, &resource).await?,
        }
        Ok(resource)
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
    let result = reserve_sqlite_transaction(&mut tx, receipt, mutation_key).await?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(result)
}

async fn reserve_sqlite_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    receipt: &Receipt,
    mutation_key: &str,
) -> Result<Receipt> {
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
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
    let retained_legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if retained_legacy.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
    }
    let legacy_claim: Option<String> = sqlx::query_scalar("SELECT id FROM objects WHERE object_type='mutation_admission_v1' AND name=$1 AND workspace=$2")
        .bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if legacy_claim.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sandbox_create_ownership WHERE caller_hash=$1 AND state IN ('PENDING','AMBIGUOUS','FENCED_PENDING')")
        .bind(&receipt.key.caller_hash).fetch_one(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if count >= 1000 {
        return Err(LedgerError::Capacity);
    }
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    // Version 2 makes old mutation replay code refuse this retained admission, not replay it.
    let claim = serde_json::json!({"format_version":2,"payload_hash":receipt.original_fingerprint,"workspace_id":receipt.key.workspace_id,"target_id":null,"success":null,"completed_at_ms":null});
    sqlx::query("INSERT INTO objects (id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'mutation_admission_v1',$2,$3,$4,$5,$5,'{}',1)")
        .bind(&receipt.claim_id).bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
        .bind(serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)?).bind(receipt.created_at_ms)
        .execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    Ok(receipt.clone())
}

async fn fence_sqlite(pool: &SqlitePool, receipt: Receipt, mutation_key: &str) -> Result<Receipt> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let result = fence_sqlite_transaction(&mut tx, receipt, mutation_key).await?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(result)
}

async fn fence_sqlite_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    mut receipt: Receipt,
    mutation_key: &str,
) -> Result<Receipt> {
    let now_ms = receipt.created_at_ms;
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&receipt.key.caller_hash).execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
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
        if previous.state == ReceiptState::Pending {
            previous.state = ReceiptState::FencedPending;
        }
        previous.revision += 1;
        previous.fence_revision = 1;
        receipt = previous;
    }
    let retained_legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if retained_legacy.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
    }
    if receipt.state == ReceiptState::Abandoned {
        let legacy: Option<String> = sqlx::query_scalar("SELECT id FROM objects WHERE object_type='mutation_admission_v1' AND name=$1 AND workspace=$2")
            .bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
            .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
        if legacy.is_some() {
            return Err(LedgerError::UnsupportedCoverage);
        }
    }
    let (window, count): (i64,i64) = sqlx::query_as("SELECT fence_window_ms,fence_count FROM sandbox_create_ownership_callers WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).fetch_one(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    let same_window = now_ms < window || now_ms.saturating_sub(window) < 60000;
    if same_window && count >= 100 {
        return Err(LedgerError::FenceRate);
    }
    sqlx::query("UPDATE sandbox_create_ownership_callers SET fence_window_ms=$2,fence_count=$3 WHERE caller_hash=$1")
        .bind(&receipt.key.caller_hash).bind(if same_window { window } else { now_ms })
        .bind(if same_window { count+1 } else {1}).execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership (caller_hash,workspace_id,request_uuid,claim_id,original_fingerprint,effective_fingerprint,schema_digest,coverage_epoch,state,receipt_revision,fence_revision,admission_closed,created_at_ms,payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(caller_hash,workspace_id,request_uuid) DO UPDATE SET state=excluded.state,receipt_revision=excluded.receipt_revision,fence_revision=excluded.fence_revision,admission_closed=excluded.admission_closed,payload=excluded.payload")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .bind(&receipt.claim_id).bind(&receipt.original_fingerprint).bind(&receipt.effective_fingerprint)
        .bind(&receipt.schema_digest).bind(&receipt.coverage_epoch).bind(receipt.sql_state())
        .bind(receipt.revision).bind(receipt.fence_revision).bind(receipt.admission_closed)
        .bind(receipt.created_at_ms).bind(serde_json::to_string(&receipt).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
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
    let retained_legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if retained_legacy.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
    }
    let legacy_claim: Option<String> = sqlx::query_scalar("SELECT id FROM objects WHERE object_type='mutation_admission_v1' AND name=$1 AND workspace=$2")
        .bind(mutation_key).bind(format!("_mutation/{}", receipt.key.caller_hash))
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if legacy_claim.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
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
        if previous.state == ReceiptState::Pending {
            previous.state = ReceiptState::FencedPending;
        }
        previous.revision += 1;
        previous.fence_revision = 1;
        receipt = previous;
    }
    let retained_legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&receipt.key.caller_hash).bind(&receipt.key.workspace_id).bind(&receipt.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if retained_legacy.is_some() {
        return Err(LedgerError::UnsupportedCoverage);
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

async fn bind_sqlite(pool: &SqlitePool, owner: &Receipt, sandbox: &Sandbox) -> Result<()> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let payload: String = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&owner.key.caller_hash).bind(&owner.key.workspace_id).bind(&owner.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?.ok_or(LedgerError::Mismatch)?;
    let mut current = binding_owner(&payload, owner)?;
    // Receipt keys carry the immutable Workspace ID; Sandbox metadata carries
    // its name. Resolve that authoritative mapping inside the binding transaction.
    let workspace_name: String = sqlx::query_scalar(
        "SELECT name FROM objects WHERE object_type='workspace' AND id=$1 AND workspace=''",
    )
    .bind(&owner.key.workspace_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?
    .ok_or(LedgerError::Mismatch)?;
    if sandbox
        .metadata
        .as_ref()
        .is_none_or(|metadata| metadata.workspace != workspace_name)
    {
        return Err(LedgerError::Mismatch);
    }
    let existing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sandbox_create_ownership_bindings WHERE claim_id=$1",
    )
    .bind(&owner.claim_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    if existing != 0 {
        return Err(LedgerError::Pending);
    }
    let claim_bytes: Vec<u8> = sqlx::query_scalar("SELECT payload FROM objects WHERE id=$1 AND object_type='mutation_admission_v1' AND workspace=$2")
        .bind(&owner.claim_id).bind(format!("_mutation/{}", owner.key.caller_hash))
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?.ok_or(LedgerError::Corrupt)?;
    let mut claim = binding_claim(&claim_bytes, owner)?;
    let metadata = sandbox.metadata.as_ref().ok_or(LedgerError::Invalid)?;
    let labels = serde_json::to_string(&metadata.labels).map_err(|_| LedgerError::Invalid)?;
    sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'sandbox',$2,$3,$4,$5,$5,$6,1)")
        .bind(&metadata.id).bind(&metadata.name).bind(&metadata.workspace).bind(sandbox.encode_to_vec())
        .bind(owner.created_at_ms).bind(labels).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_bindings(claim_id,sandbox_id,initial_resource_version,binding_revision) VALUES ($1,$2,1,1)")
        .bind(&owner.claim_id).bind(&metadata.id).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    claim["target_id"] = serde_json::Value::String(metadata.id.clone());
    sqlx::query("UPDATE objects SET payload=$2,resource_version=resource_version+1 WHERE id=$1 AND object_type='mutation_admission_v1'")
        .bind(&owner.claim_id).bind(serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    current.revision = current
        .revision
        .checked_add(1)
        .ok_or(LedgerError::Corrupt)?;
    sqlx::query(
        "UPDATE sandbox_create_ownership SET receipt_revision=$2,payload=$3 WHERE claim_id=$1",
    )
    .bind(&owner.claim_id)
    .bind(current.revision)
    .bind(serde_json::to_string(&current).map_err(|_| LedgerError::Corrupt)?)
    .execute(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(())
}

async fn bind_postgres(pool: &PgPool, owner: &Receipt, sandbox: &Sandbox) -> Result<()> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    let _: String = sqlx::query_scalar(
        "SELECT caller_hash FROM sandbox_create_ownership_callers WHERE caller_hash=$1 FOR UPDATE",
    )
    .bind(&owner.key.caller_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    let payload: String = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&owner.key.caller_hash).bind(&owner.key.workspace_id).bind(&owner.key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?.ok_or(LedgerError::Mismatch)?;
    let mut current = binding_owner(&payload, owner)?;
    // Receipt keys carry the immutable Workspace ID; Sandbox metadata carries
    // its name. Resolve that authoritative mapping inside the binding transaction.
    let workspace_name: String = sqlx::query_scalar("SELECT name FROM objects WHERE object_type='workspace' AND id=$1 AND workspace='' FOR SHARE")
        .bind(&owner.key.workspace_id).fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?.ok_or(LedgerError::Mismatch)?;
    if sandbox
        .metadata
        .as_ref()
        .is_none_or(|metadata| metadata.workspace != workspace_name)
    {
        return Err(LedgerError::Mismatch);
    }
    let existing: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sandbox_create_ownership_bindings WHERE claim_id=$1",
    )
    .bind(&owner.claim_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    if existing != 0 {
        return Err(LedgerError::Pending);
    }
    let claim_bytes: Vec<u8> = sqlx::query_scalar("SELECT payload FROM objects WHERE id=$1 AND object_type='mutation_admission_v1' AND workspace=$2")
        .bind(&owner.claim_id).bind(format!("_mutation/{}", owner.key.caller_hash))
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?.ok_or(LedgerError::Corrupt)?;
    let mut claim = binding_claim(&claim_bytes, owner)?;
    let metadata = sandbox.metadata.as_ref().ok_or(LedgerError::Invalid)?;
    let labels = serde_json::to_value(&metadata.labels).map_err(|_| LedgerError::Invalid)?;
    sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'sandbox',$2,$3,$4,$5,$5,$6,1)")
        .bind(&metadata.id).bind(&metadata.name).bind(&metadata.workspace).bind(sandbox.encode_to_vec())
        .bind(owner.created_at_ms).bind(labels).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("INSERT INTO sandbox_create_ownership_bindings(claim_id,sandbox_id,initial_resource_version,binding_revision) VALUES ($1,$2,1,1)")
        .bind(&owner.claim_id).bind(&metadata.id).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    claim["target_id"] = serde_json::Value::String(metadata.id.clone());
    sqlx::query("UPDATE objects SET payload=$2,resource_version=resource_version+1 WHERE id=$1 AND object_type='mutation_admission_v1'")
        .bind(&owner.claim_id).bind(serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)?)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    current.revision = current
        .revision
        .checked_add(1)
        .ok_or(LedgerError::Corrupt)?;
    sqlx::query(
        "UPDATE sandbox_create_ownership SET receipt_revision=$2,payload=$3 WHERE claim_id=$1",
    )
    .bind(&owner.claim_id)
    .bind(current.revision)
    .bind(serde_json::to_string(&current).map_err(|_| LedgerError::Corrupt)?)
    .execute(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(())
}

fn binding_owner(payload: &str, owner: &Receipt) -> Result<Receipt> {
    let current = decode(
        payload,
        &owner.key,
        &owner.original_fingerprint,
        &owner.schema_digest,
    )?;
    if current.claim_id != owner.claim_id
        || current.effective_fingerprint != owner.effective_fingerprint
        || current.coverage_epoch != owner.coverage_epoch
        || !matches!(
            current.state,
            ReceiptState::Pending | ReceiptState::FencedPending
        )
    {
        return Err(LedgerError::Mismatch);
    }
    Ok(current)
}

fn binding_claim(bytes: &[u8], owner: &Receipt) -> Result<serde_json::Value> {
    let claim: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| LedgerError::Corrupt)?;
    if claim["format_version"] != 2
        || claim["payload_hash"] != owner.original_fingerprint
        || claim["workspace_id"] != owner.key.workspace_id
        || claim.get("target_id") != Some(&serde_json::Value::Null)
        || claim.get("success") != Some(&serde_json::Value::Null)
        || claim.get("completed_at_ms") != Some(&serde_json::Value::Null)
    {
        return Err(LedgerError::Corrupt);
    }
    Ok(claim)
}

fn legacy_allowed(closed: Option<bool>) -> Result<()> {
    match closed {
        Some(true) => Err(LedgerError::Fenced),
        Some(false) => Err(LedgerError::Pending),
        None => Ok(()),
    }
}

async fn reserve_legacy_sqlite(
    pool: &SqlitePool,
    key: &ReceiptKey,
    claim_id: &str,
    mutation_key: &str,
    payload: &[u8],
    now_ms: i64,
) -> Result<LegacyReservation> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let result =
        reserve_legacy_sqlite_transaction(&mut tx, key, claim_id, mutation_key, payload, now_ms)
            .await?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(result)
}

async fn reserve_legacy_sqlite_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    key: &ReceiptKey,
    claim_id: &str,
    mutation_key: &str,
    payload: &[u8],
    now_ms: i64,
) -> Result<LegacyReservation> {
    let bucket = format!("_mutation/{}", key.caller_hash);
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&key.caller_hash).execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    let closed: Option<bool> = sqlx::query_scalar("SELECT admission_closed FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    legacy_allowed(closed)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM objects WHERE object_type='mutation_admission_v1' AND workspace=$1",
    )
    .bind(&bucket)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    if count >= 1000 {
        return Ok(LegacyReservation::Full);
    }
    let previous_key: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid)
        .fetch_optional(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if previous_key
        .as_deref()
        .is_some_and(|previous| previous != mutation_key)
    {
        return Err(LedgerError::UnsupportedCoverage);
    }
    let written = sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'mutation_admission_v1',$2,$3,$4,$5,$5,'{}',1) ON CONFLICT (object_type,workspace,name) WHERE name IS NOT NULL DO NOTHING")
        .bind(claim_id).bind(mutation_key).bind(&bucket).bind(payload).bind(now_ms)
        .execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    if written.rows_affected() == 0 {
        return Ok(LegacyReservation::Contended);
    }
    sqlx::query("INSERT INTO sandbox_create_legacy_keys(caller_hash,workspace_id,request_uuid,mutation_key) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).bind(mutation_key)
        .execute(&mut **tx).await.map_err(|_| LedgerError::Unavailable)?;
    Ok(LegacyReservation::Created)
}

async fn reserve_legacy_postgres(
    pool: &PgPool,
    key: &ReceiptKey,
    claim_id: &str,
    mutation_key: &str,
    payload: &[u8],
    now_ms: i64,
) -> Result<LegacyReservation> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    let bucket = format!("_mutation/{}", key.caller_hash);
    sqlx::query("INSERT INTO sandbox_create_ownership_callers(caller_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&key.caller_hash).execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query(
        "SELECT caller_hash FROM sandbox_create_ownership_callers WHERE caller_hash=$1 FOR UPDATE",
    )
    .bind(&key.caller_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    // Same quota lock as the existing generic mutation admission path.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind("mutation_admission_v1")
        .bind(&bucket)
        .execute(&mut *tx)
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let closed: Option<bool> = sqlx::query_scalar("SELECT admission_closed FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    legacy_allowed(closed)?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM objects WHERE object_type='mutation_admission_v1' AND workspace=$1",
    )
    .bind(&bucket)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    if count >= 1000 {
        return Ok(LegacyReservation::Full);
    }
    let previous_key: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid)
        .fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if previous_key
        .as_deref()
        .is_some_and(|previous| previous != mutation_key)
    {
        return Err(LedgerError::UnsupportedCoverage);
    }
    let written = sqlx::query("INSERT INTO objects(id,object_type,name,workspace,payload,created_at_ms,updated_at_ms,labels,resource_version) VALUES ($1,'mutation_admission_v1',$2,$3,$4,$5,$5,'{}',1) ON CONFLICT (object_type,workspace,name) WHERE name IS NOT NULL DO NOTHING")
        .bind(claim_id).bind(mutation_key).bind(&bucket).bind(payload).bind(now_ms)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if written.rows_affected() == 0 {
        return Ok(LegacyReservation::Contended);
    }
    sqlx::query("INSERT INTO sandbox_create_legacy_keys(caller_hash,workspace_id,request_uuid,mutation_key) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).bind(mutation_key)
        .execute(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(LegacyReservation::Created)
}

async fn snapshot_sqlite(
    pool: &SqlitePool,
    key: &ReceiptKey,
    fingerprint: &str,
    schema: &str,
) -> Result<Option<ReceiptSnapshot>> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let Some(payload) = payload else {
        let legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
            .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
        if legacy.is_some() {
            return Err(LedgerError::UnsupportedCoverage);
        }
        return Ok(None);
    };
    let receipt = decode(&payload, key, fingerprint, schema)?;
    // One extra row detects the wire cap; all bindings remain retained in storage.
    let bindings: Vec<(String,i64,i64)> = sqlx::query_as("SELECT sandbox_id,initial_resource_version,binding_revision FROM sandbox_create_ownership_bindings WHERE claim_id=$1 ORDER BY sandbox_id LIMIT 17")
        .bind(&receipt.claim_id).fetch_all(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if bindings
        .iter()
        .any(|(id, version, revision)| !uuid(id) || *version < 1 || *revision < 1)
    {
        return Err(LedgerError::Corrupt);
    }
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(Some(ReceiptSnapshot { receipt, bindings }))
}

async fn snapshot_postgres(
    pool: &PgPool,
    key: &ReceiptKey,
    fingerprint: &str,
    schema: &str,
) -> Result<Option<ReceiptSnapshot>> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
        .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    let Some(payload) = payload else {
        let legacy: Option<String> = sqlx::query_scalar("SELECT mutation_key FROM sandbox_create_legacy_keys WHERE caller_hash=$1 AND workspace_id=$2 AND request_uuid=$3")
            .bind(&key.caller_hash).bind(&key.workspace_id).bind(&key.request_uuid).fetch_optional(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
        if legacy.is_some() {
            return Err(LedgerError::UnsupportedCoverage);
        }
        return Ok(None);
    };
    let receipt = decode(&payload, key, fingerprint, schema)?;
    // One extra row detects the wire cap; all bindings remain retained in storage.
    let bindings: Vec<(String,i64,i64)> = sqlx::query_as("SELECT sandbox_id,initial_resource_version,binding_revision FROM sandbox_create_ownership_bindings WHERE claim_id=$1 ORDER BY sandbox_id LIMIT 17")
        .bind(&receipt.claim_id).fetch_all(&mut *tx).await.map_err(|_| LedgerError::Unavailable)?;
    if bindings
        .iter()
        .any(|(id, version, revision)| !uuid(id) || *version < 1 || *revision < 1)
    {
        return Err(LedgerError::Corrupt);
    }
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(Some(ReceiptSnapshot { receipt, bindings }))
}

fn completed_claim(
    bytes: &[u8],
    row: &Receipt,
    bindings: &[(String, i64, i64)],
) -> Result<Vec<u8>> {
    let mut claim: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| LedgerError::Corrupt)?;
    let target = bindings
        .first()
        .map(|(id, _, _)| serde_json::Value::String(id.clone()))
        .unwrap_or(serde_json::Value::Null);
    if claim["format_version"] != 2
        || claim["payload_hash"] != row.original_fingerprint
        || claim["workspace_id"] != row.key.workspace_id
        || claim["target_id"] != target
        || !claim["completed_at_ms"].is_null()
        || !claim["success"].is_null()
    {
        return Err(LedgerError::Corrupt);
    }
    claim["completed_at_ms"] = serde_json::json!(row.completed_at_ms.ok_or(LedgerError::Corrupt)?);
    // Not a replayable success. Version 2 remains fenced by the permanent ledger.
    serde_json::to_vec(&claim).map_err(|_| LedgerError::Corrupt)
}

async fn finish_sqlite(
    pool: &SqlitePool,
    row: &Receipt,
    previous: i64,
    bindings: &[(String, i64, i64)],
) -> Result<u64> {
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| LedgerError::Unavailable)?;
    let (bytes,version):(Vec<u8>,i64)=sqlx::query_as("SELECT payload,resource_version FROM objects WHERE object_type='mutation_admission_v1' AND id=$1 AND workspace=$2")
        .bind(&row.claim_id).bind(format!("_mutation/{}",row.key.caller_hash)).fetch_optional(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.ok_or(LedgerError::Corrupt)?;
    let claim = completed_claim(&bytes, row, bindings)?;
    let updated=sqlx::query("UPDATE sandbox_create_ownership SET state=$1,receipt_revision=$2,admission_closed=$3,payload=$4 WHERE claim_id=$5 AND receipt_revision=$6")
        .bind(row.sql_state()).bind(row.revision).bind(row.admission_closed).bind(serde_json::to_string(row).map_err(|_|LedgerError::Corrupt)?).bind(&row.claim_id).bind(previous).execute(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.rows_affected();
    if updated == 0 {
        return Ok(0);
    }
    let claim_updated=sqlx::query("UPDATE objects SET payload=$1,resource_version=resource_version+1 WHERE id=$2 AND object_type='mutation_admission_v1' AND resource_version=$3")
        .bind(claim).bind(&row.claim_id).bind(version).execute(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.rows_affected();
    if claim_updated != 1 {
        return Err(LedgerError::Corrupt);
    }
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(1)
}

async fn finish_postgres(
    pool: &PgPool,
    row: &Receipt,
    previous: i64,
    bindings: &[(String, i64, i64)],
) -> Result<u64> {
    let mut tx = pool.begin().await.map_err(|_| LedgerError::Unavailable)?;
    let _: String = sqlx::query_scalar(
        "SELECT caller_hash FROM sandbox_create_ownership_callers WHERE caller_hash=$1 FOR UPDATE",
    )
    .bind(&row.key.caller_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| LedgerError::Unavailable)?;
    let (bytes,version):(Vec<u8>,i64)=sqlx::query_as("SELECT payload,resource_version FROM objects WHERE object_type='mutation_admission_v1' AND id=$1 AND workspace=$2 FOR UPDATE")
        .bind(&row.claim_id).bind(format!("_mutation/{}",row.key.caller_hash)).fetch_optional(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.ok_or(LedgerError::Corrupt)?;
    let claim = completed_claim(&bytes, row, bindings)?;
    let updated=sqlx::query("UPDATE sandbox_create_ownership SET state=$1,receipt_revision=$2,admission_closed=$3,payload=$4 WHERE claim_id=$5 AND receipt_revision=$6")
        .bind(row.sql_state()).bind(row.revision).bind(row.admission_closed).bind(serde_json::to_string(row).map_err(|_|LedgerError::Corrupt)?).bind(&row.claim_id).bind(previous).execute(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.rows_affected();
    if updated == 0 {
        return Ok(0);
    }
    let claim_updated=sqlx::query("UPDATE objects SET payload=$1,resource_version=resource_version+1 WHERE id=$2 AND object_type='mutation_admission_v1' AND resource_version=$3")
        .bind(claim).bind(&row.claim_id).bind(version).execute(&mut *tx).await.map_err(|_|LedgerError::Unavailable)?.rows_affected();
    if claim_updated != 1 {
        return Err(LedgerError::Corrupt);
    }
    tx.commit().await.map_err(|_| LedgerError::Unavailable)?;
    Ok(1)
}
