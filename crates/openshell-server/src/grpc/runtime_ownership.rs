// SPDX-License-Identifier: Apache-2.0
//! Current-stream report intake, not qualification of supervisor placement.
//! No report body can mint driver trust, policy installation or terminal evidence.
use crate::ServerState;
use openshell_core::{ObjectId, proto::*, rpc_error};
use prost::Message;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

#[derive(Default)]
pub(crate) struct SessionReports {
    session: String,
    main: String,
    epoch: u64,
    negotiated: bool,
    sequence: u64,
    report: Option<ReceivedReport>,
}
pub(crate) struct ReceivedReport {
    pub(crate) report: SupervisorOwnershipReport,
    received: Instant,
}
impl SessionReports {
    pub(crate) fn begin(&mut self, session: &str, main: &str, epoch: u64, negotiated: bool) {
        *self = Self {
            session: session.into(),
            main: main.into(),
            epoch,
            negotiated,
            ..Default::default()
        };
    }
    pub(crate) fn record(
        &mut self,
        session: &str,
        report: SupervisorOwnershipReport,
    ) -> Result<(), Status> {
        // A late old stream must not invalidate the replacement's evidence.
        if self.session != session {
            return Err(Status::aborted("OWNERSHIP_SESSION_CHANGED"));
        }
        // Malformed or repeated current-stream input invalidates existing evidence.
        self.report = None;
        if !self.negotiated || self.epoch == 0 || report.sequence <= self.sequence {
            return Err(Status::failed_precondition("OWNERSHIP_REPORT_REFUSED"));
        }
        validate_report(&report, &self.main)?;
        self.sequence = report.sequence;
        self.report = Some(ReceivedReport {
            report,
            received: Instant::now(),
        });
        Ok(())
    }
    pub(crate) fn read(&self, session: &str) -> Result<&ReceivedReport, Status> {
        if self.session != session {
            return Err(Status::aborted("OWNERSHIP_SESSION_CHANGED"));
        }
        let report = self
            .report
            .as_ref()
            .ok_or_else(|| Status::unavailable("OWNERSHIP_REPORT_UNAVAILABLE"))?;
        if report.received.elapsed() >= Duration::from_secs(5) {
            return Err(Status::failed_precondition("SNAPSHOT_EXPIRED"));
        }
        if report.report.sequence != self.sequence {
            return Err(Status::unavailable("OWNERSHIP_REPORT_UNAVAILABLE"));
        }
        Ok(report)
    }
}
fn invalid() -> Status {
    Status::invalid_argument("OWNERSHIP_REPORT_INVALID")
}
fn timestamp(t: &Option<prost_types::Timestamp>) -> bool {
    t.as_ref().is_some_and(|t| {
        (-62135596800..=253402300799).contains(&t.seconds) && (0..1_000_000_000).contains(&t.nanos)
    })
}
fn process(p: &ProcessIdentity) -> bool {
    uuid::Uuid::parse_str(&p.kernel_boot_id).is_ok()
        && p.pid > 0
        && p.starttime_ticks > 0
        && p.pid_namespace_inode > 0
        && p.net_namespace_inode > 0
        && p.executable_digest.len() == 32
        && !p.platform_component_id.is_empty()
        && p.platform_component_id.len() <= 128
}
fn domain(d: &Option<OwnershipDomainEvidence>, items: usize) -> Result<(), Status> {
    if let Some(d) = d {
        let state = OwnershipState::try_from(d.state).map_err(|_| invalid())?;
        if state == OwnershipState::Unspecified
            || d.reason_code.len() > 128
            || d.source_id.len() > 128
        {
            return Err(invalid());
        }
        if d.complete
            && (!timestamp(&d.observed_at)
                || d.source_id.is_empty()
                || d.source_revision == 0
                || d.count != items as u64
                || match state {
                    OwnershipState::Present => items == 0,
                    OwnershipState::ProvenAbsent => items != 0,
                    _ => true,
                })
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn validate_report(r: &SupervisorOwnershipReport, main: &str) -> Result<(), Status> {
    if r.sequence == 0
        || main.is_empty()
        || r.main_instance_id != main
        || r.main_instance_id.len() > 128
        || r.network_instance_id.is_empty()
        || r.network_instance_id.len() > 128
        || r.applied_policy_hash.len() != 32
        || r.inventory_digest.len() != 32
        || !timestamp(&r.observed_at)
        || r.process_items.len() > 4096
        || r.socket_items.len() > 20000
        || r.poll_items.len() > 20000
        || r.encoded_len() > 4 * 1024 * 1024
    {
        return Err(invalid());
    }
    domain(&r.processes, r.process_items.len())?;
    domain(&r.sockets, r.socket_items.len())?;
    domain(&r.pollers, r.poll_items.len())?;
    if r.complete
        && (r.processes.as_ref().is_none_or(|d| !d.complete)
            || r.sockets.as_ref().is_none_or(|d| !d.complete)
            || r.pollers.as_ref().is_none_or(|d| !d.complete))
    {
        return Err(invalid());
    }
    if r.process_items.iter().any(|p| !process(p)) {
        return Err(invalid());
    }
    let identities: HashSet<_> = r.process_items.iter().map(Message::encode_to_vec).collect();
    if identities.len() != r.process_items.len() {
        return Err(invalid());
    }
    let mut socket_keys = HashSet::new();
    for s in &r.socket_items {
        if !socket_keys.insert((s.inode, s.protocol.as_str()))
            || s.inode == 0
            || !matches!(s.protocol.as_str(), "tcp" | "tcp6")
            || s.local_ip.parse::<std::net::IpAddr>().is_err()
            || s.remote_ip.parse::<std::net::IpAddr>().is_err()
            || s.local_port > 65535
            || s.remote_port > 65535
            || s.owners.is_empty()
            || s.owners.len() > 4096
            || s.connection_incarnation.is_empty()
            || s.connection_incarnation.len() > 128
            || s.owners
                .iter()
                .any(|p| !process(p) || !identities.contains(&p.encode_to_vec()))
        {
            return Err(invalid());
        }
    }
    let mut operation_ids = HashSet::new();
    for p in &r.poll_items {
        if !operation_ids.insert(p.operation_id.as_str())
            || uuid::Uuid::parse_str(&p.operation_id).is_err()
            || p.operation_revision == 0
            || p.token_version_fingerprint.len() != 32
            || !timestamp(&p.started_at)
            || p.destination_id.is_empty()
            || p.destination_id.len() > 128
            || p.process
                .as_ref()
                .is_none_or(|i| !process(i) || !identities.contains(&i.encode_to_vec()))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Authenticates and binds the original receipt before considering live evidence.
/// Current driver/placement qualification is absent, so no report or Docker404
/// can produce a successful public snapshot yet. No mutations or cursor minting.
pub(super) async fn get(
    state: &Arc<ServerState>,
    request: Request<GetSandboxOwnershipSnapshotRequest>,
) -> Result<Response<GetSandboxOwnershipSnapshotResponse>, Status> {
    let b = request.get_ref();
    let (mut key, workspace) =
        super::create_request_fence::owner(state, &request, b.workspace_scope.as_ref()).await?;
    let canonical = super::mutation_replay::validate_request_id(&b.create_request_id)?;
    if canonical != b.create_request_id
        || b.original_fingerprint.len() != 32
        || uuid::Uuid::parse_str(&b.expected_sandbox_id).map_or(true, |id| {
            id.is_nil() || id.to_string() != b.expected_sandbox_id
        })
        || b.expected_receipt_revision == 0
        || !(1..=100).contains(&b.page_size)
    {
        return Err(invalid());
    }
    key.request_uuid = canonical;
    let schema = openshell_core::create_fingerprint::schema_digest()
        .map_err(|_| Status::unavailable("fingerprint schema unavailable"))?;
    let row = state
        .store
        .create_receipt_ledger()
        .read_snapshot(
            &key,
            &hex::encode(&b.original_fingerprint),
            &hex::encode(schema),
        )
        .await
        .map_err(super::create_request_fence::error)?
        .ok_or_else(|| Status::permission_denied("ownership receipt unavailable"))?;
    if row.receipt.revision <= 0 || row.bindings.len() > 16 {
        return Err(Status::unavailable("OWNERSHIP_RECEIPT_INVALID"));
    }
    if row.receipt.revision as u64 != b.expected_receipt_revision
        || !row
            .bindings
            .iter()
            .any(|(id, _, _)| id == &b.expected_sandbox_id)
    {
        return Err(Status::aborted("OWNERSHIP_BINDING_CHANGED"));
    }
    if !b.page_token.is_empty() {
        // No public snapshot has been qualified or issued, so no cursor is valid.
        return Err(Status::invalid_argument("OWNERSHIP_CURSOR_INVALID"));
    }
    if b.terminal_only {
        return Err(rpc_error::failed_precondition(
            "TRUST_BOUNDARY_UNQUALIFIED",
            "terminal manifest and driver proof unavailable",
        ));
    }
    if b.name.is_empty() || b.expected_resource_version == 0 {
        return Err(invalid());
    }
    let sandbox: Sandbox = state
        .store
        .get_message_by_name(&workspace, &b.name)
        .await
        .map_err(|_| Status::unavailable("sandbox read unavailable"))?
        .ok_or_else(|| Status::aborted("OWNERSHIP_RESOURCE_CHANGED"))?;
    if sandbox.object_id() != b.expected_sandbox_id
        || sandbox.metadata.as_ref().map_or(0, |m| m.resource_version)
            != b.expected_resource_version
    {
        return Err(Status::aborted("OWNERSHIP_RESOURCE_CHANGED"));
    }
    let session = state
        .supervisor_sessions
        .current_session_id(&b.expected_sandbox_id)
        .ok_or_else(|| Status::unavailable("OWNERSHIP_SESSION_UNAVAILABLE"))?;
    state
        .supervisor_sessions
        .require_ownership_report(&b.expected_sandbox_id, &session)?;
    // A live authenticated stream alone cannot attest protected placement,
    // current installed policy, a complete driver manifest or terminal state.
    Err(rpc_error::failed_precondition(
        "TRUST_BOUNDARY_UNQUALIFIED",
        "driver-qualified protected placement unavailable",
    ))
}

#[cfg(test)]
#[path = "runtime_ownership_tests.rs"]
mod tests;
