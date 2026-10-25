// SPDX-License-Identifier: Apache-2.0
//! Authenticated receipt reads and explicit fences, never lifecycle dispatch.

use super::create_receipt::{LedgerError, ReceiptKey, ReceiptSnapshot, ReceiptState};
use crate::{
    ServerState,
    auth::workspace_authz::{MinWorkspaceRole, authorize_workspace},
};
use openshell_core::{ObjectId, proto::*, rpc_error};
use std::sync::Arc;
use tonic::{Request, Response, Status};

async fn owner<T>(
    state: &ServerState,
    request: &Request<T>,
    scope: Option<&WorkspaceSelector>,
) -> Result<(ReceiptKey, String), Status> {
    let principal = super::extract_principal(request)?;
    let caller = super::mutation_replay::authenticated_caller_hash(state, &principal)?;
    let selected = crate::auth::workspace_authz::selected_workspace_name(scope)?;
    let grant = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        selected,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace: Workspace = state
        .store
        .get_message_by_name("", &grant.workspace)
        .await
        .map_err(|_| Status::unavailable("workspace authorization unavailable"))?
        .ok_or_else(|| Status::permission_denied("workspace unavailable"))?;
    Ok((
        ReceiptKey {
            caller_hash: caller,
            workspace_id: workspace.object_id().into(),
            request_uuid: String::new(),
        },
        grant.workspace,
    ))
}

fn validate(
    key: &mut ReceiptKey,
    request_id: &str,
    fingerprint: &[u8],
    schema: &str,
) -> Result<(), Status> {
    let normalized = super::mutation_replay::validate_request_id(request_id)?;
    if normalized != request_id || fingerprint.len() != 32 {
        return Err(Status::invalid_argument(
            "canonical request UUID and 32-byte fingerprint required",
        ));
    }
    let compiled = openshell_core::create_fingerprint::schema_digest()
        .map_err(|_| Status::unavailable("fingerprint schema unavailable"))?;
    if schema != hex::encode(compiled) {
        return Err(rpc_error::failed_precondition(
            "FINGERPRINT_SCHEMA_MISMATCH",
            "create descriptor closure differs",
        ));
    }
    key.request_uuid = normalized;
    Ok(())
}

fn error(error: LedgerError) -> Status {
    match error {
        LedgerError::Mismatch => rpc_error::failed_precondition(
            "REQUEST_ID_PAYLOAD_MISMATCH",
            "original create fingerprint differs",
        ),
        LedgerError::UnsupportedCoverage => unsupported(),
        LedgerError::FenceRate => Status::resource_exhausted("CREATE_FENCE_RATE_LIMIT"),
        LedgerError::Fenced => {
            rpc_error::failed_precondition("REQUEST_ID_FENCED", "create admission closed")
        }
        _ => Status::unavailable("create ownership evidence unavailable"),
    }
}
fn unsupported() -> Status {
    rpc_error::failed_precondition(
        "UNSUPPORTED_COVERAGE",
        "create ownership coverage is not qualified",
    )
}

fn response(
    snapshot: ReceiptSnapshot,
    expected: Option<&str>,
) -> Result<GetSandboxCreateReceiptResponse, Status> {
    if let Some(id) = expected {
        if uuid::Uuid::parse_str(id).is_err()
            || !snapshot.bindings.iter().any(|(bound, _, _)| bound == id)
        {
            return Err(Status::aborted(
                "expected immutable sandbox identity does not match",
            ));
        }
    }
    let row = snapshot.receipt;
    // A terminal enum alone cannot prove that creation admission ended without
    // effects. Reject contradictory durable evidence without repairing a read.
    if row.state == ReceiptState::Abandoned
        && (!row.admission_closed || row.fence_revision <= 0 || !snapshot.bindings.is_empty())
    {
        return Err(Status::unavailable(
            "inconsistent abandoned ownership evidence",
        ));
    }
    let exceeded = snapshot.bindings.len() > 16;
    let state = if exceeded {
        CreateReceiptState::Ambiguous
    } else {
        match row.state {
            ReceiptState::Pending if !snapshot.bindings.is_empty() => CreateReceiptState::Ambiguous,
            ReceiptState::Pending => CreateReceiptState::Pending,
            ReceiptState::FencedPending => CreateReceiptState::FencedPending,
            ReceiptState::Abandoned => CreateReceiptState::Abandoned,
        }
    };
    let bindings = snapshot
        .bindings
        .into_iter()
        .take(16)
        .map(|(id, version, revision)| CreateOwnershipBinding {
            claim_incarnation_id: row.claim_id.clone(),
            sandbox_id: id,
            initial_resource_version: version as u64,
            binding_revision: revision as u64,
            effect_state: CreateEffectState::ResourceCommitted.into(),
            // No current resource/readiness/driver-completion claim is inferred.
            ..Default::default()
        })
        .collect();
    Ok(GetSandboxCreateReceiptResponse {
        receipt_state: state.into(),
        request_id: row.key.request_uuid,
        fingerprint: hex::decode(row.original_fingerprint)
            .map_err(|_| Status::unavailable("invalid ownership fingerprint"))?,
        receipt_revision: row.revision as u64,
        created_at: Some(
            openshell_core::time::timestamp_from_millis(row.created_at_ms)
                .map_err(|_| Status::unavailable("invalid ownership timestamp"))?,
        ),
        coverage_epoch: row.coverage_epoch,
        bindings,
        complete: !exceeded && state == CreateReceiptState::Abandoned,
        fingerprint_schema_digest: row.schema_digest,
        fence_revision: row.fence_revision as u64,
        admission_closed: row.admission_closed,
        reason_code: if exceeded {
            "BINDING_LIMIT".into()
        } else {
            String::new()
        },
        ..Default::default()
    })
}

pub(super) async fn get(
    state: &Arc<ServerState>,
    request: Request<GetSandboxCreateReceiptRequest>,
) -> Result<Response<GetSandboxCreateReceiptResponse>, Status> {
    let body = request.get_ref();
    let (mut key, _) = owner(state, &request, body.workspace_scope.as_ref()).await?;
    validate(
        &mut key,
        &body.request_id,
        &body.payload_fingerprint,
        &body.fingerprint_schema_digest,
    )?;
    if body.expected_sandbox_id.as_ref().is_some_and(|value| {
        uuid::Uuid::parse_str(value).map_or(true, |id| id.is_nil() || id.to_string() != *value)
    }) {
        return Err(Status::invalid_argument(
            "expected_sandbox_id must be a canonical nonzero UUID",
        ));
    }
    let snapshot = state
        .store
        .create_receipt_ledger()
        .read_snapshot(
            &key,
            &hex::encode(&body.payload_fingerprint),
            &body.fingerprint_schema_digest,
        )
        .await
        .map_err(error)?;
    // Coverage-floor initialization is not yet implemented: missing history is
    // explicitly unqualified, never promoted to NOT_FOUND or absence.
    let snapshot = snapshot.ok_or_else(unsupported)?;
    Ok(Response::new(response(
        snapshot,
        body.expected_sandbox_id.as_deref(),
    )?))
}

pub(super) async fn fence(
    state: &Arc<ServerState>,
    request: Request<FenceSandboxCreateRequest>,
) -> Result<Response<FenceSandboxCreateResponse>, Status> {
    let body = request.get_ref();
    let (mut key, workspace_name) = owner(state, &request, body.workspace_scope.as_ref()).await?;
    validate(
        &mut key,
        &body.request_id,
        &body.payload_fingerprint,
        &body.fingerprint_schema_digest,
    )?;
    let ledger = state.store.create_receipt_ledger();
    let fingerprint = hex::encode(&body.payload_fingerprint);
    let snapshot = ledger
        .read_snapshot(&key, &fingerprint, &body.fingerprint_schema_digest)
        .await
        .map_err(error)?
        .ok_or_else(unsupported)?;
    let mut candidate = snapshot.receipt;
    candidate.created_at_ms = crate::persistence::current_time_ms();
    // Only existing covered ownership is fenceable until namespace coverage is
    // initialized. No missing/unqualified legacy UUID is claimed absent.
    ledger
        .fence(
            candidate,
            &super::mutation_replay::create_mutation_key(
                &key.caller_hash,
                &workspace_name,
                &key.request_uuid,
            )?,
        )
        .await
        .map_err(error)?;
    let latest = ledger
        .read_snapshot(&key, &fingerprint, &body.fingerprint_schema_digest)
        .await
        .map_err(error)?
        .ok_or_else(unsupported)?;
    Ok(Response::new(FenceSandboxCreateResponse {
        receipt: Some(response(latest, None)?),
    }))
}

pub(super) async fn reject_unqualified_create(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    owner(state, &request, request.get_ref().workspace_scope.as_ref()).await?;
    super::mutation_replay::validate_request_id(&request.get_ref().request_id)?;
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::create_receipt::Receipt;
    use crate::grpc::{
        OpenShellService,
        test_support::{authed_request, test_server_state},
    };
    use openshell_core::proto::open_shell_server::OpenShell;
    use openshell_core::rpc_error::StatusExt;

    pub(super) async fn fixture() -> (Arc<ServerState>, GetSandboxCreateReceiptRequest, Receipt) {
        let state = test_server_state().await;
        let request = authed_request(());
        let workspace_scope = Some(WorkspaceSelector {
            selection: Some(workspace_selector::Selection::Workspace("default".into())),
        });
        let (mut key, _) = owner(&state, &request, workspace_scope.as_ref())
            .await
            .unwrap();
        key.request_uuid = uuid::Uuid::new_v4().to_string();
        let schema = hex::encode(openshell_core::create_fingerprint::schema_digest().unwrap());
        let lookup = GetSandboxCreateReceiptRequest {
            workspace_scope,
            request_id: key.request_uuid.clone(),
            payload_fingerprint: vec![3; 32],
            fingerprint_schema_digest: schema.clone(),
            ..Default::default()
        };
        let row = Receipt {
            key,
            claim_id: uuid::Uuid::new_v4().to_string(),
            original_fingerprint: hex::encode(&lookup.payload_fingerprint),
            effective_fingerprint: "4".repeat(64),
            schema_digest: schema,
            coverage_epoch: uuid::Uuid::new_v4().to_string(),
            state: ReceiptState::Pending,
            revision: 1,
            fence_revision: 0,
            admission_closed: false,
            created_at_ms: crate::persistence::current_time_ms(),
        };
        (state, lookup, row)
    }
    fn fence_request(lookup: &GetSandboxCreateReceiptRequest) -> FenceSandboxCreateRequest {
        FenceSandboxCreateRequest {
            workspace_scope: lookup.workspace_scope.clone(),
            request_id: lookup.request_id.clone(),
            payload_fingerprint: lookup.payload_fingerprint.clone(),
            fingerprint_schema_digest: lookup.fingerprint_schema_digest.clone(),
        }
    }
    #[tokio::test]
    async fn missing_history_refuses_fence_without_creating_an_absence_claim() {
        let (state, lookup, row) = fixture().await;
        let service = OpenShellService::new(state.clone());
        let status = service
            .fence_sandbox_create(authed_request(fence_request(&lookup)))
            .await
            .unwrap_err();
        assert_eq!(
            status.get_error_details().error_info().unwrap().reason,
            "UNSUPPORTED_COVERAGE"
        );
        assert!(
            state
                .store
                .create_receipt_ledger()
                .read(&row.key, &row.original_fingerprint, &row.schema_digest)
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn select_only_read_does_not_fence_an_admitted_owner() {
        let (state, lookup, row) = fixture().await;
        let ledger = state.store.create_receipt_ledger();
        ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
        let read = OpenShellService::new(state)
            .get_sandbox_create_receipt(authed_request(lookup))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(read.receipt_state, CreateReceiptState::Pending as i32);
        assert!(!read.complete);
        assert!(!read.admission_closed);
        assert_eq!(read.fence_revision, 0);
        assert_eq!(
            ledger
                .read(&row.key, &row.original_fingerprint, &row.schema_digest)
                .await
                .unwrap(),
            Some(row)
        );
    }
    #[tokio::test]
    async fn explicit_fence_and_readback_keep_the_same_revision() {
        let (state, lookup, row) = fixture().await;
        state
            .store
            .create_receipt_ledger()
            .reserve(&row, &"1".repeat(64))
            .await
            .unwrap();
        let service = OpenShellService::new(state);
        let fenced = service
            .fence_sandbox_create(authed_request(fence_request(&lookup)))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        assert_eq!(
            fenced.receipt_state,
            CreateReceiptState::FencedPending as i32
        );
        assert!(!fenced.complete);
        let read = service
            .get_sandbox_create_receipt(authed_request(lookup.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(fenced, read);
        let repeated = service
            .fence_sandbox_create(authed_request(fence_request(&lookup)))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        assert_eq!(repeated, read);
    }
    #[tokio::test]
    async fn mismatched_original_fingerprint_cannot_fence_the_owner() {
        let (state, mut lookup, row) = fixture().await;
        let ledger = state.store.create_receipt_ledger();
        ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
        lookup.payload_fingerprint = vec![8; 32];
        let status = OpenShellService::new(state)
            .fence_sandbox_create(authed_request(fence_request(&lookup)))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status.get_error_details().error_info().unwrap().reason,
            "REQUEST_ID_PAYLOAD_MISMATCH"
        );
        assert_eq!(
            ledger
                .read(&row.key, &row.original_fingerprint, &row.schema_digest)
                .await
                .unwrap(),
            Some(row)
        );
    }
    #[tokio::test]
    async fn supervisor_or_anonymous_body_cannot_supply_caller_authority() {
        let (state, lookup, _) = fixture().await;
        let mut request = authed_request(lookup);
        request
            .extensions_mut()
            .insert(crate::auth::principal::Principal::Anonymous);
        let status = OpenShellService::new(state)
            .get_sandbox_create_receipt(request)
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }
    #[tokio::test]
    async fn binding_read_is_not_runtime_readiness_or_expected_id_replacement() {
        let (state, mut lookup, row) = fixture().await;
        let ledger = state.store.create_receipt_ledger();
        ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: "owned-binding".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        ledger.bind_resource(&row, &sandbox).await.unwrap();
        let service = OpenShellService::new(state);
        let read = service
            .get_sandbox_create_receipt(authed_request(lookup.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(read.receipt_state, CreateReceiptState::Ambiguous as i32);
        assert!(!read.complete);
        assert_eq!(read.bindings.len(), 1);
        assert_eq!(
            read.bindings[0].effect_state,
            CreateEffectState::ResourceCommitted as i32
        );
        lookup.expected_sandbox_id = Some(uuid::Uuid::new_v4().to_string());
        assert_eq!(
            service
                .get_sandbox_create_receipt(authed_request(lookup))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
    }
    #[tokio::test]
    async fn schema_mismatch_and_unqualified_audited_create_stay_closed() {
        let (state, mut lookup, _) = fixture().await;
        lookup.fingerprint_schema_digest = "0".repeat(64);
        let service = OpenShellService::new(state);
        let status = service
            .get_sandbox_create_receipt(authed_request(lookup.clone()))
            .await
            .unwrap_err();
        assert_eq!(
            status.get_error_details().error_info().unwrap().reason,
            "FINGERPRINT_SCHEMA_MISMATCH"
        );
        let status = service
            .create_sandbox(authed_request(CreateSandboxRequest {
                workspace_scope: lookup.workspace_scope,
                require_ownership_receipt: true,
                request_id: lookup.request_id,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(
            status.get_error_details().error_info().unwrap().reason,
            "UNSUPPORTED_COVERAGE"
        );
        assert!(
            !service
                .health(Request::new(HealthRequest {}))
                .await
                .unwrap()
                .get_ref()
                .capabilities
                .iter()
                .any(|value| value == "sandbox-create-ownership-v1")
        );
    }
    #[tokio::test]
    async fn interceptor_cannot_downgrade_a_required_receipt_into_legacy_create() {
        use prost::Message;
        let (state, lookup, _) = fixture().await;
        let original = CreateSandboxRequest {
            workspace_scope: lookup.workspace_scope,
            require_ownership_receipt: true,
            request_id: lookup.request_id,
            ..Default::default()
        };
        let mut effective = original.clone();
        effective.require_ownership_receipt = false;
        let mut request = authed_request(effective);
        request
            .extensions_mut()
            .insert(super::super::mutation_replay::OriginalMutation(
                original.encode_to_vec(),
            ));
        let status = OpenShellService::new(state)
            .create_sandbox(request)
            .await
            .unwrap_err();
        assert_eq!(
            status.get_error_details().error_info().unwrap().reason,
            "UNSUPPORTED_COVERAGE"
        );
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    use crate::grpc::create_receipt::CreateReceiptLedger;
    use crate::grpc::test_support::authed_request;

    #[tokio::test]
    async fn abandoned_requires_closed_positive_fence_and_no_bindings_without_lookup_writes() {
        for closed in [false, true] {
            for fence_revision in [0, 1] {
                for bound in [false, true] {
                    let (state, lookup, mut row) = tests::fixture().await;
                    let ledger = state.store.create_receipt_ledger();
                    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
                    if bound {
                        let sandbox = Sandbox {
                            metadata: Some(ObjectMeta {
                                id: uuid::Uuid::new_v4().to_string(),
                                name: "terminal-binding".into(),
                                workspace: "default".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        };
                        ledger.bind_resource(&row, &sandbox).await.unwrap();
                    }
                    row.state = ReceiptState::Abandoned;
                    row.admission_closed = closed;
                    row.fence_revision = fence_revision;
                    let CreateReceiptLedger::Sqlite(pool) = &ledger else {
                        panic!("SQLite fixture");
                    };
                    let payload = serde_json::to_string(&row).unwrap();
                    sqlx::query("UPDATE sandbox_create_ownership SET state='ABANDONED',admission_closed=$1,fence_revision=$2,payload=$3 WHERE claim_id=$4")
                        .bind(closed).bind(fence_revision).bind(&payload).bind(&row.claim_id)
                        .execute(pool).await.unwrap();
                    let before = ledger
                        .read_snapshot(&row.key, &row.original_fingerprint, &row.schema_digest)
                        .await
                        .unwrap()
                        .unwrap();
                    let changes: i64 = sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                    let result = get(&state, authed_request(lookup)).await;
                    if closed && fence_revision > 0 && !bound {
                        let read = result.unwrap().into_inner();
                        assert_eq!(read.receipt_state, CreateReceiptState::Abandoned as i32);
                        assert!(read.complete && read.admission_closed);
                        assert_eq!(read.fence_revision, 1);
                        assert!(read.bindings.is_empty());
                    } else {
                        let status = result.unwrap_err();
                        assert_eq!(
                            status.code(),
                            tonic::Code::Unavailable,
                            "closed={closed},fence={fence_revision},bound={bound}"
                        );
                        assert_eq!(
                            status.message(),
                            "inconsistent abandoned ownership evidence"
                        );
                    }
                    let after = ledger
                        .read_snapshot(&row.key, &row.original_fingerprint, &row.schema_digest)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(before.receipt, after.receipt);
                    assert_eq!(before.bindings, after.bindings);
                    let after_changes: i64 = sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                    assert_eq!(
                        changes, after_changes,
                        "lookup must not repair corrupt evidence"
                    );
                }
            }
        }
    }
}
