// SPDX-License-Identifier: Apache-2.0
use super::*;
fn report() -> SupervisorOwnershipReport {
    SupervisorOwnershipReport {
        sequence: 1,
        main_instance_id: "main".into(),
        network_instance_id: "network".into(),
        applied_policy_hash: vec![1; 32],
        inventory_digest: vec![2; 32],
        observed_at: Some(prost_types::Timestamp {
            seconds: 1,
            nanos: 0,
        }),
        ..Default::default()
    }
}
#[test]
fn runtime_ownership_rejects_unsolicited_and_stale_sessions() {
    let mut reports = SessionReports::default();
    assert!(reports.record("old", report()).is_err());
    reports.begin("current", "main", 1, false);
    assert!(reports.record("current", report()).is_err());
    reports.begin("current", "main", 1, true);
    assert!(reports.record("old", report()).is_err());
    assert!(reports.record("current", report()).is_ok());
    reports.begin("replacement", "main", 2, true);
    assert!(reports.record("current", report()).is_err());
    assert!(reports.read("replacement").is_err());
}
#[test]
fn runtime_ownership_sequence_replay_and_invalid_report_invalidate() {
    let mut reports = SessionReports::default();
    reports.begin("session", "main", 1, true);
    reports.record("session", report()).unwrap();
    assert!(reports.record("session", report()).is_err());
    assert!(reports.read("session").is_err());
}
#[test]
fn runtime_ownership_complete_claim_retains_transport_record_only() {
    let mut reports = SessionReports::default();
    reports.begin("session", "main", 1, true);
    let mut body = report();
    body.complete = true;
    let absent = OwnershipDomainEvidence {
        state: OwnershipState::ProvenAbsent as i32,
        complete: true,
        source_id: "source".into(),
        source_revision: 1,
        observed_at: body.observed_at,
        ..Default::default()
    };
    body.processes = Some(absent.clone());
    body.sockets = Some(absent.clone());
    body.pollers = Some(absent);
    reports.record("session", body).unwrap();
    assert_eq!(reports.read("session").unwrap().report.sequence, 1);
    // This internal transport record has no placement/terminal qualification field.
    // The public RPC's independent driver/trust gate is tested below.
    assert_eq!(
        reports.read("session").unwrap().report.main_instance_id,
        "main"
    );
}
#[test]
fn runtime_ownership_wrong_instance_or_hash_cannot_replace_current() {
    for mutate in [0, 1, 2] {
        let mut reports = SessionReports::default();
        reports.begin("session", "main", 1, true);
        reports.record("session", report()).unwrap();
        let mut bad = report();
        bad.sequence = 2;
        match mutate {
            0 => bad.main_instance_id = "foreign".into(),
            1 => bad.applied_policy_hash.clear(),
            _ => bad.inventory_digest.clear(),
        }
        assert!(reports.record("session", bad).is_err());
        assert!(reports.read("session").is_err());
    }
}
#[test]
fn runtime_ownership_invalid_domains_and_unbounded_items_refuse() {
    let mut body = report();
    body.processes = Some(OwnershipDomainEvidence {
        state: OwnershipState::ProvenAbsent as i32,
        complete: true,
        count: 1,
        ..Default::default()
    });
    assert!(validate_report(&body, "main").is_err());
    body = report();
    body.process_items = vec![ProcessIdentity::default(); 4097];
    assert!(validate_report(&body, "main").is_err());
}
#[test]
fn runtime_ownership_five_second_expiry_is_not_heartbeat_refresh() {
    let mut reports = SessionReports::default();
    reports.begin("session", "main", 1, true);
    reports.record("session", report()).unwrap();
    reports.report.as_mut().unwrap().received = Instant::now() - Duration::from_secs(5);
    assert!(reports.read("session").is_err());
}

async fn snapshot_fixture() -> (
    Arc<ServerState>,
    GetSandboxOwnershipSnapshotRequest,
    super::super::create_receipt::Receipt,
) {
    use crate::grpc::{create_receipt::*, test_support::authed_request};
    let state = crate::grpc::test_support::test_server_state().await;
    let scope = Some(WorkspaceSelector {
        selection: Some(workspace_selector::Selection::Workspace("default".into())),
    });
    let (mut key, _) =
        super::super::create_request_fence::owner(&state, &authed_request(()), scope.as_ref())
            .await
            .unwrap();
    key.request_uuid = uuid::Uuid::new_v4().to_string();
    let row = Receipt {
        key,
        claim_id: uuid::Uuid::new_v4().to_string(),
        original_fingerprint: hex::encode([3; 32]),
        effective_fingerprint: hex::encode([4; 32]),
        schema_digest: hex::encode(openshell_core::create_fingerprint::schema_digest().unwrap()),
        coverage_epoch: uuid::Uuid::new_v4().to_string(),
        state: ReceiptState::Pending,
        revision: 1,
        fence_revision: 0,
        admission_closed: false,
        created_at_ms: crate::persistence::current_time_ms(),
        effect_started: false,
        completed_at_ms: None,
    };
    let ledger = state.store.create_receipt_ledger();
    ledger.reserve(&row, &"1".repeat(64)).await.unwrap();
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "owned-snapshot".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    ledger.bind_resource(&row, &sandbox).await.unwrap();
    let body = GetSandboxOwnershipSnapshotRequest {
        workspace_scope: scope,
        name: "owned-snapshot".into(),
        expected_sandbox_id: sandbox.object_id().into(),
        expected_resource_version: 1,
        page_size: 100,
        create_request_id: row.key.request_uuid.clone(),
        original_fingerprint: vec![3; 32],
        expected_receipt_revision: 2,
        ..Default::default()
    };
    (state, body, row)
}
#[tokio::test]
async fn runtime_ownership_public_snapshot_requires_original_owner_without_writes() {
    use crate::grpc::{OpenShellService, test_support::authed_request};
    use openshell_core::proto::open_shell_server::OpenShell;
    let (state, body, row) = snapshot_fixture().await;
    let ledger = state.store.create_receipt_ledger();
    let before = ledger
        .read_snapshot(&row.key, &row.original_fingerprint, &row.schema_digest)
        .await
        .unwrap()
        .unwrap();
    let mut request = authed_request(body.clone());
    request
        .extensions_mut()
        .insert(crate::auth::principal::Principal::Anonymous);
    let service = OpenShellService::new(state);
    assert_eq!(
        service
            .get_sandbox_ownership_snapshot(request)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut wrong = body;
    wrong.original_fingerprint = vec![9; 32];
    assert_eq!(
        service
            .get_sandbox_ownership_snapshot(authed_request(wrong))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let after = ledger
        .read_snapshot(&row.key, &row.original_fingerprint, &row.schema_digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.receipt, after.receipt);
    assert_eq!(before.bindings, after.bindings);
}
#[tokio::test]
async fn runtime_ownership_public_terminal_and_cursor_do_not_invent_evidence() {
    use crate::grpc::{OpenShellService, test_support::authed_request};
    use openshell_core::proto::open_shell_server::OpenShell;
    use openshell_core::rpc_error::StatusExt;
    let (state, mut body, _) = snapshot_fixture().await;
    body.terminal_only = true;
    body.name.clear();
    body.expected_resource_version = 0;
    let service = OpenShellService::new(state);
    let error = service
        .get_sandbox_ownership_snapshot(authed_request(body.clone()))
        .await
        .unwrap_err();
    assert_eq!(
        error.get_error_details().error_info().unwrap().reason,
        "TRUST_BOUNDARY_UNQUALIFIED"
    );
    body.page_token = "unissued".into();
    assert_eq!(
        service
            .get_sandbox_ownership_snapshot(authed_request(body))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
}
#[tokio::test]
async fn runtime_ownership_public_replacement_and_revision_never_select_newest() {
    use crate::grpc::{OpenShellService, test_support::authed_request};
    use openshell_core::proto::open_shell_server::OpenShell;
    let (state, body, _) = snapshot_fixture().await;
    let service = OpenShellService::new(state);
    for kind in 0..3 {
        let mut bad = body.clone();
        match kind {
            0 => bad.expected_receipt_revision += 1,
            1 => bad.expected_sandbox_id = uuid::Uuid::new_v4().to_string(),
            _ => bad.expected_resource_version += 1,
        }
        assert_eq!(
            service
                .get_sandbox_ownership_snapshot(authed_request(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
    }
    assert_eq!(
        service
            .get_sandbox_ownership_snapshot(authed_request(body))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
}

#[test]
fn runtime_ownership_duplicates_refuse_instead_of_deduplicating_complete_evidence() {
    let identity = ProcessIdentity {
        kernel_boot_id: "11111111-1111-4111-8111-111111111111".into(),
        pid: 10,
        starttime_ticks: 20,
        pid_namespace_inode: 30,
        net_namespace_inode: 40,
        executable_digest: vec![1; 32],
        platform_component_id: "component".into(),
    };
    let mut body = report();
    body.process_items = vec![identity.clone()];
    body.socket_items = vec![SocketObservation {
        inode: 50,
        protocol: "tcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port: 10000,
        remote_ip: "127.0.0.1".into(),
        remote_port: 10001,
        owners: vec![identity.clone()],
        connection_incarnation: "connection".into(),
    }];
    body.poll_items = vec![PollObservation {
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        process: Some(identity),
        destination_id: "destination".into(),
        token_version_fingerprint: vec![3; 32],
        started_at: body.observed_at,
        active: true,
        operation_revision: 1,
    }];
    validate_report(&body, "main").unwrap();
    for duplicate in 0..3 {
        let mut bad = body.clone();
        match duplicate {
            0 => bad.process_items.push(bad.process_items[0].clone()),
            1 => bad.socket_items.push(bad.socket_items[0].clone()),
            _ => bad.poll_items.push(bad.poll_items[0].clone()),
        }
        assert!(validate_report(&bad, "main").is_err());
    }
}
