// SPDX-License-Identifier: Apache-2.0
//! Authenticated receipt reads and explicit fences, never lifecycle dispatch.

use super::create_receipt::{LedgerError, Receipt, ReceiptKey, ReceiptSnapshot, ReceiptState};
use crate::{
    ServerState,
    auth::workspace_authz::{MinWorkspaceRole, authorize_workspace},
};
use openshell_core::rpc_error::StatusExt as _;
use openshell_core::{ObjectId, proto::*, rpc_error};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub(super) async fn owner<T>(
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

pub(super) fn error(error: LedgerError) -> Status {
    match error {
        LedgerError::Mismatch => rpc_error::failed_precondition(
            "REQUEST_ID_PAYLOAD_MISMATCH",
            "original create fingerprint differs",
        ),
        LedgerError::UnsupportedCoverage => unsupported(),
        LedgerError::Pending => rpc_error::failed_precondition(
            "REQUEST_OUTCOME_UNCERTAIN",
            "request already admitted; never replay Create",
        ),
        LedgerError::Capacity => limit_error("CREATE_OWNERSHIP_CAP_FULL"),
        LedgerError::FenceRate => limit_error("CREATE_FENCE_RATE_LIMIT"),
        LedgerError::Fenced => {
            rpc_error::failed_precondition("REQUEST_ID_FENCED", "create admission closed")
        }
        _ => Status::unavailable("create ownership evidence unavailable"),
    }
}
fn limit_error(reason: &str) -> Status {
    Status::with_error_details(
        tonic::Code::ResourceExhausted,
        reason,
        rpc_error::ErrorDetails::with_error_info(
            reason,
            rpc_error::ERROR_DOMAIN,
            std::collections::HashMap::new(),
        ),
    )
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
            ReceiptState::NoResource => CreateReceiptState::NoResource,
            ReceiptState::Succeeded
                if row.completed_at_ms.is_some_and(|time| {
                    crate::persistence::current_time_ms().saturating_sub(time) >= 86_400_000
                }) =>
            {
                CreateReceiptState::Expired
            }
            ReceiptState::Succeeded => CreateReceiptState::Succeeded,
        }
    };
    if (row.state == ReceiptState::NoResource
        && (!row.admission_closed
            || row.effect_started
            || row.completed_at_ms.is_none()
            || !snapshot.bindings.is_empty()))
        || (row.state == ReceiptState::Succeeded
            && (!row.effect_started
                || row.completed_at_ms.is_none()
                || snapshot.bindings.len() != 1))
    {
        return Err(Status::unavailable(
            "inconsistent terminal ownership evidence",
        ));
    }
    let terminal = row.completed_at_ms.is_some();
    let effect_started = row.effect_started;
    let bindings = snapshot
        .bindings
        .into_iter()
        .take(16)
        .map(|(id, version, revision)| CreateOwnershipBinding {
            claim_incarnation_id: row.claim_id.clone(),
            sandbox_id: id,
            initial_resource_version: version as u64,
            binding_revision: revision as u64,
            effect_state: (if terminal {
                CreateEffectState::OwnerTerminal
            } else if effect_started {
                CreateEffectState::DriverStarted
            } else {
                CreateEffectState::ResourceCommitted
            })
            .into(),
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
        expires_at: if row.state == ReceiptState::Succeeded {
            row.completed_at_ms
                .map(|time| {
                    openshell_core::time::timestamp_from_millis(time.saturating_add(86_400_000))
                })
                .transpose()
                .map_err(|_| Status::unavailable("invalid receipt expiry"))?
        } else {
            None
        },
        completed_at: row
            .completed_at_ms
            .map(openshell_core::time::timestamp_from_millis)
            .transpose()
            .map_err(|_| Status::unavailable("invalid completion timestamp"))?,
        complete: !exceeded
            && matches!(
                state,
                CreateReceiptState::Abandoned
                    | CreateReceiptState::Succeeded
                    | CreateReceiptState::NoResource
            ),
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
    let Some(snapshot) = snapshot else {
        let epoch = state
            .store
            .create_receipt_ledger()
            .coverage()
            .await
            .map_err(error)?;
        return Ok(Response::new(GetSandboxCreateReceiptResponse {
            receipt_state: CreateReceiptState::NotFoundAsOfRead.into(),
            request_id: body.request_id.clone(),
            fingerprint: body.payload_fingerprint.clone(),
            coverage_epoch: epoch,
            fingerprint_schema_digest: body.fingerprint_schema_digest.clone(),
            complete: false,
            ..Default::default()
        }));
    };
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
        .map_err(error)?;
    let mut candidate = if let Some(snapshot) = snapshot {
        snapshot.receipt
    } else {
        Receipt {
            key: key.clone(),
            claim_id: uuid::Uuid::new_v4().to_string(),
            original_fingerprint: fingerprint.clone(),
            effective_fingerprint: fingerprint.clone(),
            schema_digest: body.fingerprint_schema_digest.clone(),
            coverage_epoch: ledger.coverage().await.map_err(error)?,
            state: ReceiptState::Pending,
            revision: 1,
            fence_revision: 0,
            admission_closed: false,
            created_at_ms: crate::persistence::current_time_ms(),
            effect_started: false,
            completed_at_ms: None,
        }
    };
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

#[cfg(test)]
#[derive(Default)]
struct AuditedAdmissionBarrier {
    admitted: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
    finished: tokio::sync::Notify,
}

/// The real public Create path, with admission owned through caller cancellation.
pub(super) async fn create(
    state: &Arc<ServerState>,
    mut request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    use prost::Message;
    static EXECUTORS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(64)));
    let original = request
        .extensions()
        .get::<super::mutation_replay::OriginalMutation>()
        .map(|value| CreateSandboxRequest::decode(value.0.as_slice()))
        .transpose()
        .map_err(|_| Status::invalid_argument("invalid original Create"))?
        .unwrap_or_else(|| request.get_ref().clone());
    if original.request_id != request.get_ref().request_id
        || request.get_ref().encoded_len() > 4 * 1024 * 1024
    {
        return Err(Status::invalid_argument(
            "invalid audited Create request identity or size",
        ));
    }
    let (mut key, workspace) = owner(state, &request, original.workspace_scope.as_ref()).await?;
    let (effective_key, _) =
        owner(state, &request, request.get_ref().workspace_scope.as_ref()).await?;
    if key.workspace_id != effective_key.workspace_id
        || key.caller_hash != effective_key.caller_hash
    {
        return Err(Status::permission_denied(
            "Create scope cannot be rewritten",
        ));
    }
    let schema = openshell_core::create_fingerprint::schema_digest().map_err(|_| unsupported())?;
    let fingerprint = openshell_core::create_fingerprint::fingerprint(&original, &schema)
        .map_err(|_| Status::invalid_argument("invalid original Create projection"))?;
    validate(
        &mut key,
        &original.request_id,
        &fingerprint,
        &hex::encode(schema),
    )?;
    let ledger = state.store.create_receipt_ledger();
    if let Some(previous) = ledger
        .read(&key, &hex::encode(fingerprint), &hex::encode(schema))
        .await
        .map_err(error)?
    {
        if previous.admission_closed {
            return Err(error(LedgerError::Fenced));
        }
    }
    if !original.require_ownership_receipt || !request.get_ref().require_ownership_receipt {
        return Err(unsupported());
    }
    let row = Receipt {
        key: key.clone(),
        claim_id: uuid::Uuid::new_v4().to_string(),
        original_fingerprint: hex::encode(fingerprint),
        effective_fingerprint: hex::encode(
            openshell_core::create_fingerprint::fingerprint(request.get_ref(), &schema)
                .map_err(|_| Status::invalid_argument("invalid effective Create projection"))?,
        ),
        schema_digest: hex::encode(schema),
        coverage_epoch: ledger.coverage().await.map_err(error)?,
        state: ReceiptState::Pending,
        revision: 1,
        fence_revision: 0,
        admission_closed: false,
        created_at_ms: crate::persistence::current_time_ms(),
        effect_started: false,
        completed_at_ms: None,
    };
    let mutation_key = super::mutation_replay::create_mutation_key(
        &key.caller_hash,
        &workspace,
        &key.request_uuid,
    )?;
    let permit = EXECUTORS
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("create ownership workers busy"))?;
    #[cfg(test)]
    let barrier = request
        .extensions()
        .get::<Arc<AuditedAdmissionBarrier>>()
        .cloned();
    let state = state.clone();
    tokio::spawn(crate::auth::audit::in_current_request(async move {
        let _permit = permit;
        let row = ledger.reserve(&row, &mutation_key).await.map_err(error)?;
        #[cfg(test)]
        if let Some(barrier) = barrier.as_ref() {
            barrier.admitted.notify_one();
            barrier.proceed.notified().await;
        }
        request.extensions_mut().insert(row.clone());
        let result = super::sandbox::handle_create_sandbox(&state, request).await;
        ledger
            .owner_finished(&row, result.is_ok())
            .await
            .map_err(error)?;
        #[cfg(test)]
        if let Some(barrier) = barrier.as_ref() {
            barrier.finished.notify_one();
        }
        result
    }))
    .await
    .map_err(|_| {
        rpc_error::failed_precondition(
            "REQUEST_OUTCOME_UNCERTAIN",
            "admitted Create owner did not confirm completion",
        )
    })?
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
            effect_started: false,
            completed_at_ms: None,
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
    async fn fresh_namespace_missing_key_fence_creates_only_a_tombstone() {
        let (state, lookup, row) = fixture().await;
        let service = OpenShellService::new(state.clone());
        let receipt = service
            .fence_sandbox_create(authed_request(fence_request(&lookup)))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        assert_eq!(receipt.receipt_state, CreateReceiptState::Abandoned as i32);
        assert!(receipt.complete && receipt.admission_closed);
        assert!(receipt.bindings.is_empty());
        assert!(
            state
                .store
                .create_receipt_ledger()
                .read(&row.key, &row.original_fingerprint, &row.schema_digest)
                .await
                .unwrap()
                .is_some_and(|row| row.state == ReceiptState::Abandoned)
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
    async fn schema_mismatch_and_invalid_create_refuse_with_capabilities_withheld() {
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
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
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

#[cfg(test)]
mod audited_execution_tests {
    use super::*;
    use crate::grpc::{
        OpenShellService,
        test_support::{authed_request, test_server_state},
    };
    use openshell_core::rpc_error::StatusExt;
    use openshell_core::{ObjectId, proto::open_shell_server::OpenShell};

    fn request(name: &str) -> CreateSandboxRequest {
        CreateSandboxRequest {
            workspace_scope: Some(WorkspaceSelector {
                selection: Some(workspace_selector::Selection::Workspace("default".into())),
            }),
            request_id: uuid::Uuid::new_v4().to_string(),
            require_ownership_receipt: true,
            name: name.into(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        }
    }

    fn lookup(request: &CreateSandboxRequest) -> GetSandboxCreateReceiptRequest {
        let schema = openshell_core::create_fingerprint::schema_digest().unwrap();
        GetSandboxCreateReceiptRequest {
            workspace_scope: request.workspace_scope.clone(),
            request_id: request.request_id.clone(),
            payload_fingerprint: openshell_core::create_fingerprint::fingerprint(request, &schema)
                .unwrap()
                .to_vec(),
            fingerprint_schema_digest: hex::encode(schema),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn audited_create_returns_bound_terminal_receipt_and_never_replays() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let service = OpenShellService::new(state.clone());
        let request = request("audited-owner");
        let read = lookup(&request);
        let created = service
            .create_sandbox(authed_request(request.clone()))
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap();
        let receipt = service
            .get_sandbox_create_receipt(authed_request(read.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(receipt.receipt_state, CreateReceiptState::Succeeded as i32);
        assert!(receipt.complete);
        assert_eq!(receipt.bindings.len(), 1);
        assert_eq!(receipt.bindings[0].sandbox_id, created.object_id());
        assert_eq!(receipt.bindings[0].initial_resource_version, 1);
        assert_eq!(
            receipt.bindings[0].effect_state,
            CreateEffectState::OwnerTerminal as i32
        );
        let error = service
            .create_sandbox(authed_request(request))
            .await
            .unwrap_err();
        assert_eq!(
            error.get_error_details().error_info().unwrap().reason,
            "REQUEST_OUTCOME_UNCERTAIN"
        );
        let after = service
            .get_sandbox_create_receipt(authed_request(read))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(receipt, after);
        assert_eq!(driver.sandbox_create_count(), 1);
    }

    #[tokio::test]
    async fn audited_validation_failure_seals_no_resource_without_binding() {
        let state = test_server_state().await;
        let service = OpenShellService::new(state);
        let mut request = request("invalid-owner");
        request.spec = None;
        let read = lookup(&request);
        assert_eq!(
            service
                .create_sandbox(authed_request(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let receipt = service
            .get_sandbox_create_receipt(authed_request(read))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(receipt.receipt_state, CreateReceiptState::NoResource as i32);
        assert!(receipt.complete && receipt.admission_closed && receipt.bindings.is_empty());
    }

    #[tokio::test]
    async fn fresh_namespace_fence_closes_a_delayed_audited_create() {
        let state = test_server_state().await;
        let service = OpenShellService::new(state);
        let request = request("delayed-audited");
        let read = lookup(&request);
        let fenced = service
            .fence_sandbox_create(authed_request(FenceSandboxCreateRequest {
                workspace_scope: read.workspace_scope.clone(),
                request_id: read.request_id.clone(),
                payload_fingerprint: read.payload_fingerprint.clone(),
                fingerprint_schema_digest: read.fingerprint_schema_digest.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        assert!(fenced.complete && fenced.admission_closed);
        assert_eq!(fenced.receipt_state, CreateReceiptState::Abandoned as i32);
        assert_eq!(
            service
                .create_sandbox(authed_request(request))
                .await
                .unwrap_err()
                .get_error_details()
                .error_info()
                .unwrap()
                .reason,
            "REQUEST_ID_FENCED"
        );
        assert_eq!(
            service
                .get_sandbox_create_receipt(authed_request(read))
                .await
                .unwrap()
                .into_inner(),
            fenced
        );
    }
    #[tokio::test]
    async fn audited_binding_failure_rolls_back_and_calls_no_driver() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let super::super::create_receipt::CreateReceiptLedger::Sqlite(pool) =
            state.store.create_receipt_ledger()
        else {
            panic!("SQLite fixture")
        };
        sqlx::raw_sql("CREATE TRIGGER refuse_binding BEFORE INSERT ON sandbox_create_ownership_bindings BEGIN SELECT RAISE(ABORT,'owned test failure'); END;").execute(&pool).await.unwrap();
        let service = OpenShellService::new(state.clone());
        let request = request("rollback-binding");
        let read = lookup(&request);
        assert_eq!(
            service
                .create_sandbox(authed_request(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(driver.sandbox_create_count(), 0);
        let resources: i64 =
            sqlx::query_scalar("SELECT count(*) FROM objects WHERE object_type='sandbox'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(resources, 0);
        let receipt = service
            .get_sandbox_create_receipt(authed_request(read))
            .await
            .unwrap()
            .into_inner();
        assert!(receipt.complete && receipt.bindings.is_empty());
        assert_eq!(receipt.receipt_state, CreateReceiptState::NoResource as i32);
    }

    #[tokio::test]
    async fn audited_lost_completion_retains_binding_without_create_retry() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let super::super::create_receipt::CreateReceiptLedger::Sqlite(pool) =
            state.store.create_receipt_ledger()
        else {
            panic!("SQLite fixture")
        };
        sqlx::raw_sql("CREATE TRIGGER refuse_success BEFORE UPDATE ON sandbox_create_ownership WHEN NEW.state='SUCCEEDED' BEGIN SELECT RAISE(ABORT,'owned lost acknowledgement'); END;").execute(&pool).await.unwrap();
        let service = OpenShellService::new(state);
        let request = request("lost-completion");
        let read = lookup(&request);
        assert_eq!(
            service
                .create_sandbox(authed_request(request.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        let before = service
            .get_sandbox_create_receipt(authed_request(read.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(before.receipt_state, CreateReceiptState::Ambiguous as i32);
        assert!(!before.complete);
        assert_eq!(before.bindings.len(), 1);
        assert_eq!(
            before.bindings[0].effect_state,
            CreateEffectState::DriverStarted as i32
        );
        assert_eq!(
            service
                .create_sandbox(authed_request(request))
                .await
                .unwrap_err()
                .get_error_details()
                .error_info()
                .unwrap()
                .reason,
            "REQUEST_OUTCOME_UNCERTAIN"
        );
        assert_eq!(
            service
                .get_sandbox_create_receipt(authed_request(read))
                .await
                .unwrap()
                .into_inner(),
            before
        );
        assert_eq!(driver.sandbox_create_count(), 1);
    }

    #[tokio::test]
    async fn audited_known_fence_refuses_interceptor_flag_downgrade_without_effects() {
        use prost::Message;
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let service = OpenShellService::new(state);
        let original = request("fenced-downgrade");
        let read = lookup(&original);
        service
            .fence_sandbox_create(authed_request(FenceSandboxCreateRequest {
                workspace_scope: read.workspace_scope,
                request_id: read.request_id,
                payload_fingerprint: read.payload_fingerprint,
                fingerprint_schema_digest: read.fingerprint_schema_digest,
            }))
            .await
            .unwrap();
        let mut effective = original.clone();
        effective.require_ownership_receipt = false;
        let mut request = authed_request(effective);
        request
            .extensions_mut()
            .insert(crate::grpc::mutation_replay::OriginalMutation(
                original.encode_to_vec(),
            ));
        assert_eq!(
            service
                .create_sandbox(request)
                .await
                .unwrap_err()
                .get_error_details()
                .error_info()
                .unwrap()
                .reason,
            "REQUEST_ID_FENCED"
        );
        assert_eq!(driver.sandbox_create_count(), 0);
    }
    #[tokio::test]
    async fn audited_admission_wins_then_fence_preserves_owner_through_completion() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let service = Arc::new(OpenShellService::new(state));
        let request = request("admission-winner");
        let read = lookup(&request);
        let barrier = Arc::new(AuditedAdmissionBarrier::default());
        let mut create = authed_request(request);
        create.extensions_mut().insert(barrier.clone());
        let runner = service.clone();
        let owner = tokio::spawn(async move { runner.create_sandbox(create).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.admitted.notified(),
        )
        .await
        .unwrap();
        assert_eq!(driver.sandbox_create_count(), 0);
        let fenced = service
            .fence_sandbox_create(authed_request(FenceSandboxCreateRequest {
                workspace_scope: read.workspace_scope.clone(),
                request_id: read.request_id.clone(),
                payload_fingerprint: read.payload_fingerprint.clone(),
                fingerprint_schema_digest: read.fingerprint_schema_digest.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .receipt
            .unwrap();
        assert_eq!(
            fenced.receipt_state,
            CreateReceiptState::FencedPending as i32
        );
        assert!(!fenced.complete && fenced.admission_closed && fenced.bindings.is_empty());
        barrier.proceed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), owner)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let done = service
            .get_sandbox_create_receipt(authed_request(read))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(done.receipt_state, CreateReceiptState::Succeeded as i32);
        assert!(done.complete && done.admission_closed);
        assert_eq!(done.fence_revision, fenced.fence_revision);
        assert_eq!(done.bindings.len(), 1);
        assert_eq!(driver.sandbox_create_count(), 1);
    }

    #[tokio::test]
    async fn audited_caller_cancellation_does_not_drop_admitted_owner() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let service = Arc::new(OpenShellService::new(state));
        let request = request("cancelled-caller");
        let read = lookup(&request);
        let barrier = Arc::new(AuditedAdmissionBarrier::default());
        let mut create = authed_request(request);
        create.extensions_mut().insert(barrier.clone());
        let runner = service.clone();
        let caller = tokio::spawn(async move { runner.create_sandbox(create).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.admitted.notified(),
        )
        .await
        .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        barrier.proceed.notify_one();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.finished.notified(),
        )
        .await
        .unwrap();
        let done = service
            .get_sandbox_create_receipt(authed_request(read))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(done.receipt_state, CreateReceiptState::Succeeded as i32);
        assert!(done.complete);
        assert_eq!(driver.sandbox_create_count(), 1);
    }
    #[tokio::test]
    async fn audited_expired_replay_cache_never_reopens_terminal_uuid() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let service = OpenShellService::new(state.clone());
        let mut request = request("terminal-cache");
        request.spec = None;
        let read = lookup(&request);
        assert_eq!(
            service
                .create_sandbox(authed_request(request.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let ledger = state.store.create_receipt_ledger();
        let super::super::create_receipt::CreateReceiptLedger::Sqlite(pool) = &ledger else {
            panic!("SQLite fixture")
        };
        let payload: String = sqlx::query_scalar("SELECT payload FROM sandbox_create_ownership")
            .fetch_one(pool)
            .await
            .unwrap();
        let row: Receipt = serde_json::from_str(&payload).unwrap();
        let before = service
            .get_sandbox_create_receipt(authed_request(read.clone()))
            .await
            .unwrap()
            .into_inner();
        let bucket = format!("_mutation/{}", row.key.caller_hash);
        assert!(
            crate::grpc::mutation_replay::prune_expired_at(
                &state.store,
                &bucket,
                row.completed_at_ms.unwrap() + 86_400_001
            )
            .await
            .unwrap()
        );
        let claims: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM objects WHERE object_type='mutation_admission_v1'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(claims, 0);
        assert_eq!(
            service
                .get_sandbox_create_receipt(authed_request(read))
                .await
                .unwrap()
                .into_inner(),
            before
        );
        for required in [true, false] {
            request.require_ownership_receipt = required;
            assert_eq!(
                service
                    .create_sandbox(authed_request(request.clone()))
                    .await
                    .unwrap_err()
                    .get_error_details()
                    .error_info()
                    .unwrap()
                    .reason,
                "REQUEST_ID_FENCED"
            );
        }
        assert_eq!(driver.sandbox_create_count(), 0);
    }
    #[tokio::test]
    async fn audited_missing_key_lookup_is_incomplete_and_performs_zero_writes() {
        let driver = Arc::new(crate::compute::NoopTestDriver::default());
        let state = crate::grpc::test_support::test_server_state_with_compute_driver(
            "test",
            driver.clone(),
        )
        .await;
        let super::super::create_receipt::CreateReceiptLedger::Sqlite(pool) =
            state.store.create_receipt_ledger()
        else {
            panic!("SQLite fixture")
        };
        let before: i64 = sqlx::query_scalar("SELECT total_changes()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let service = OpenShellService::new(state);
        let read = service
            .get_sandbox_create_receipt(authed_request(lookup(&request("unseen-request"))))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            read.receipt_state,
            CreateReceiptState::NotFoundAsOfRead as i32
        );
        assert!(!read.complete && !read.admission_closed && read.bindings.is_empty());
        assert_eq!(read.receipt_revision, 0);
        assert_eq!(read.fence_revision, 0);
        let after: i64 = sqlx::query_scalar("SELECT total_changes()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(driver.sandbox_create_count(), 0);
    }
}
