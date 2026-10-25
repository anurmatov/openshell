// SPDX-License-Identifier: Apache-2.0
//! Namespace observations are facts, never a trust-boundary or broker-absence proof.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::procfs::{ProcTcpAddressFamily, parse_proc_socket_addr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub kernel_boot_id: String,
    pub pid: u32,
    pub starttime_ticks: u64,
    pub pid_namespace_inode: u64,
    pub net_namespace_inode: u64,
    pub executable_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketObservation {
    pub inode: u64,
    pub protocol: String,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub owners: Vec<ProcessIdentity>,
}

/// Two stable procfs scans, not a qualified supervisor report or immutable RPC page.
/// No absence/complete/connection-incarnation claim is exposed by this local fact type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceInventory {
    pub processes: Vec<ProcessIdentity>,
    pub sockets: Vec<SocketObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObservationError {
    #[error("OWNERSHIP_SOURCE_UNAVAILABLE")]
    Unavailable,
    #[error("OWNERSHIP_SOURCE_CHANGED")]
    Changed,
    #[error("OWNERSHIP_SOURCE_UNOWNED")]
    Unowned,
    #[error("OWNERSHIP_SNAPSHOT_LIMIT")]
    Limit,
}

/// Attached to the actual network runtime's published entrypoint PID, not workload JSON.
/// Driver-qualified placement/session/policy and outbound report transport are still
/// required before any caller can treat these facts as authoritative evidence.
pub struct OwnershipCollector {
    entrypoint: Arc<AtomicU32>,
}

impl OwnershipCollector {
    pub(crate) fn new(entrypoint: Arc<AtomicU32>) -> Self {
        Self { entrypoint }
    }

    pub fn inventory(&self) -> Result<NamespaceInventory, ObservationError> {
        let pid = self.entrypoint.load(Ordering::Acquire);
        let facts = collect_at(Path::new("/proc"), pid, || {})?;
        if self.entrypoint.load(Ordering::Acquire) != pid {
            return Err(ObservationError::Changed);
        }
        Ok(facts)
    }
}

fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, ObservationError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| ObservationError::Unavailable)?
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ObservationError::Unavailable)?;
    if bytes.len() as u64 > cap {
        return Err(ObservationError::Limit);
    }
    Ok(bytes)
}

fn namespaces(root: &Path, pid: u32) -> Result<(u64, u64), ObservationError> {
    let p = root.join(pid.to_string()).join("ns");
    let pidns = fs::metadata(p.join("pid"))
        .map_err(|_| ObservationError::Unavailable)?
        .ino();
    let netns = fs::metadata(p.join("net"))
        .map_err(|_| ObservationError::Unavailable)?
        .ino();
    if pidns == 0 || netns == 0 {
        return Err(ObservationError::Unavailable);
    }
    Ok((pidns, netns))
}

fn identity(root: &Path, pid: u32, boot: &str) -> Result<ProcessIdentity, ObservationError> {
    let p = root.join(pid.to_string());
    let raw = read_bounded(&p.join("stat"), 32768)?;
    let stat = std::str::from_utf8(&raw).map_err(|_| ObservationError::Unavailable)?;
    let (id, _) = stat.split_once(" (").ok_or(ObservationError::Unavailable)?;
    if id.parse::<u32>().ok() != Some(pid) {
        return Err(ObservationError::Unavailable);
    }
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or(ObservationError::Unavailable)?;
    let birth = fields
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .ok_or(ObservationError::Unavailable)?;
    let (pid_namespace_inode, net_namespace_inode) = namespaces(root, pid)?;
    // Open the procfs magic link, never the pathname returned by readlink/argv.
    let executable_digest = Sha256::digest(read_bounded(&p.join("exe"), 64 * 1024 * 1024)?).into();
    Ok(ProcessIdentity {
        kernel_boot_id: boot.into(),
        pid,
        starttime_ticks: birth,
        pid_namespace_inode,
        net_namespace_inode,
        executable_digest,
    })
}

fn scan(root: &Path, pid: u32, deadline: Instant) -> Result<NamespaceInventory, ObservationError> {
    let boot = read_bounded(&root.join("sys/kernel/random/boot_id"), 128)?;
    let boot = std::str::from_utf8(&boot)
        .map_err(|_| ObservationError::Unavailable)?
        .trim();
    let parsed = uuid::Uuid::parse_str(boot).map_err(|_| ObservationError::Unavailable)?;
    if parsed.is_nil() || parsed.to_string() != boot {
        return Err(ObservationError::Unavailable);
    }
    let expected = identity(root, pid, boot)?;
    let mut pids = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| ObservationError::Unavailable)? {
        let entry = entry.map_err(|_| ObservationError::Unavailable)?;
        if let Ok(id) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(id);
            if pids.len() > 32768 {
                return Err(ObservationError::Limit);
            }
        }
    }
    pids.sort_unstable();
    let mut processes = Vec::new();
    let mut owners: BTreeMap<u64, Vec<ProcessIdentity>> = BTreeMap::new();
    for current in pids {
        if Instant::now() >= deadline {
            return Err(ObservationError::Limit);
        }
        let ns = namespaces(root, current)?;
        if ns != (expected.pid_namespace_inode, expected.net_namespace_inode) {
            continue;
        }
        let before = identity(root, current, boot)?;
        if processes.len() == 4096 {
            return Err(ObservationError::Limit);
        }
        let fd = root.join(current.to_string()).join("fd");
        for (index, entry) in fs::read_dir(fd)
            .map_err(|_| ObservationError::Unavailable)?
            .enumerate()
        {
            if index >= 20000 || Instant::now() >= deadline {
                return Err(ObservationError::Limit);
            }
            let entry = entry.map_err(|_| ObservationError::Unavailable)?;
            let link = fs::read_link(entry.path()).map_err(|_| ObservationError::Unavailable)?;
            let text = link.to_str().ok_or(ObservationError::Unavailable)?;
            if let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|v| v.strip_suffix(']'))
            {
                let inode = inode
                    .parse::<u64>()
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or(ObservationError::Unavailable)?;
                let list = owners.entry(inode).or_default();
                if !list.contains(&before) {
                    list.push(before.clone());
                }
            }
        }
        if identity(root, current, boot)? != before {
            return Err(ObservationError::Changed);
        }
        processes.push(before);
    }
    if !processes.contains(&expected) {
        return Err(ObservationError::Changed);
    }
    let mut sockets = Vec::new();
    for (table, family) in [
        ("tcp", ProcTcpAddressFamily::Ipv4),
        ("tcp6", ProcTcpAddressFamily::Ipv6),
        ("udp", ProcTcpAddressFamily::Ipv4),
        ("udp6", ProcTcpAddressFamily::Ipv6),
    ] {
        let bytes = read_bounded(
            &root.join(pid.to_string()).join("net").join(table),
            4 * 1024 * 1024,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ObservationError::Unavailable)?;
        if text.lines().next().is_none() {
            return Err(ObservationError::Unavailable);
        }
        for line in text.lines().skip(1) {
            if Instant::now() >= deadline {
                return Err(ObservationError::Limit);
            }
            if sockets.len() == 20000 {
                return Err(ObservationError::Limit);
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return Err(ObservationError::Unavailable);
            }
            let inode = fields[9]
                .parse::<u64>()
                .map_err(|_| ObservationError::Unavailable)?;
            if inode == 0 {
                continue;
            } // Kernel rows without an owning socket are not absence evidence.
            let local =
                parse_proc_socket_addr(fields[1], family).ok_or(ObservationError::Unavailable)?;
            let remote =
                parse_proc_socket_addr(fields[2], family).ok_or(ObservationError::Unavailable)?;
            let owning = owners
                .get(&inode)
                .cloned()
                .ok_or(ObservationError::Unowned)?;
            sockets.push(SocketObservation {
                inode,
                protocol: table.into(),
                local,
                remote,
                owners: owning,
            });
        }
    }
    sockets.sort_by(|a, b| {
        (&a.protocol, a.inode, a.local, a.remote).cmp(&(&b.protocol, b.inode, b.local, b.remote))
    });
    if identity(root, pid, boot)? != expected {
        return Err(ObservationError::Changed);
    }
    if Instant::now() >= deadline {
        return Err(ObservationError::Limit);
    }
    Ok(NamespaceInventory { processes, sockets })
}

fn collect_at(
    root: &Path,
    pid: u32,
    between: impl FnOnce(),
) -> Result<NamespaceInventory, ObservationError> {
    if pid == 0 {
        return Err(ObservationError::Unavailable);
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    let first = scan(root, pid, deadline)?;
    between();
    let second = scan(root, pid, deadline)?;
    if first != second {
        return Err(ObservationError::Changed);
    }
    Ok(second)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    struct Fixture(tempfile::TempDir);
    impl Fixture {
        fn new() -> Self {
            let this = Self(tempfile::tempdir().unwrap());
            fs::create_dir_all(this.0.path().join("sys/kernel/random")).unwrap();
            fs::write(
                this.0.path().join("sys/kernel/random/boot_id"),
                "11111111-1111-4111-8111-111111111111\n",
            )
            .unwrap();
            for name in ["pidns", "netns", "executable"] {
                fs::write(this.0.path().join(name), name).unwrap();
            }
            this.process(17, 100);
            this
        }
        fn process(&self, pid: u32, birth: u64) {
            let p = self.0.path().join(pid.to_string());
            fs::create_dir_all(p.join("ns")).unwrap();
            fs::create_dir_all(p.join("fd")).unwrap();
            fs::create_dir_all(p.join("net")).unwrap();
            for (link, target) in [
                ("ns/pid", "pidns"),
                ("ns/net", "netns"),
                ("exe", "executable"),
            ] {
                symlink(self.0.path().join(target), p.join(link)).unwrap();
            }
            self.stat(pid, birth);
            for table in ["tcp", "tcp6", "udp", "udp6"] {
                fs::write(p.join("net").join(table), "header\n").unwrap();
            }
        }
        fn stat(&self, pid: u32, birth: u64) {
            let mut fields = vec!["0".to_owned(); 20];
            fields[0] = "S".into();
            fields[19] = birth.to_string();
            fs::write(
                self.0.path().join(pid.to_string()).join("stat"),
                format!("{pid} (name with ) bracket) {}\n", fields.join(" ")),
            )
            .unwrap();
        }
        fn collect(&self) -> Result<NamespaceInventory, ObservationError> {
            collect_at(self.0.path(), 17, || {})
        }
    }

    #[test]
    fn ownership_collects_all_namespace_members_not_only_descendants() {
        let f = Fixture::new();
        f.process(23, 200);
        let facts = f.collect().unwrap();
        assert_eq!(
            facts.processes.iter().map(|p| p.pid).collect::<Vec<_>>(),
            [17, 23]
        );
        assert_eq!(facts.processes[1].starttime_ticks, 200);
        assert_eq!(facts.processes[0].executable_digest.len(), 32);
        assert!(facts.sockets.is_empty());
    }

    #[test]
    fn ownership_socket_tuple_uses_actual_procfs_parser_and_all_owners() {
        let f = Fixture::new();
        f.process(23, 200);
        fs::write(
            f.0.path().join("17/net/tcp"),
            "header\n0: 0100007F:C350 0200007F:01BB 01 0 0 0 1000 0 456\n",
        )
        .unwrap();
        for pid in [17, 23] {
            symlink("socket:[456]", f.0.path().join(format!("{pid}/fd/3"))).unwrap();
        }
        let facts = f.collect().unwrap();
        assert_eq!(facts.sockets.len(), 1);
        let socket = &facts.sockets[0];
        assert_eq!(socket.local.to_string(), "127.0.0.1:50000");
        assert_eq!(socket.remote.to_string(), "127.0.0.2:443");
        assert_eq!(socket.owners.len(), 2);
    }

    #[test]
    fn ownership_pid_reuse_between_scans_refuses() {
        let f = Fixture::new();
        assert_eq!(
            collect_at(f.0.path(), 17, || f.stat(17, 101)),
            Err(ObservationError::Changed)
        );
    }

    #[test]
    fn ownership_new_member_between_scans_refuses() {
        let f = Fixture::new();
        assert_eq!(
            collect_at(f.0.path(), 17, || f.process(23, 200)),
            Err(ObservationError::Changed)
        );
    }

    #[test]
    fn ownership_changed_executable_between_scans_refuses() {
        let f = Fixture::new();
        assert_eq!(
            collect_at(f.0.path(), 17, || fs::write(
                f.0.path().join("executable"),
                "changed"
            )
            .unwrap()),
            Err(ObservationError::Changed)
        );
    }

    #[test]
    fn ownership_unknown_namespace_member_never_becomes_zero() {
        let f = Fixture::new();
        f.process(23, 200);
        fs::remove_file(f.0.path().join("23/ns/net")).unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Unavailable));
    }

    #[test]
    fn ownership_missing_fd_directory_refuses() {
        let f = Fixture::new();
        fs::remove_dir(f.0.path().join("17/fd")).unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Unavailable));
    }

    #[test]
    fn ownership_missing_tcp6_is_not_an_empty_ipv6_inventory() {
        let f = Fixture::new();
        fs::remove_file(f.0.path().join("17/net/tcp6")).unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Unavailable));
    }

    #[test]
    fn ownership_unowned_socket_refuses() {
        let f = Fixture::new();
        fs::write(
            f.0.path().join("17/net/tcp"),
            "header\n0: 0100007F:C350 0200007F:01BB 01 0 0 0 1000 0 456\n",
        )
        .unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Unowned));
    }

    #[test]
    fn ownership_unpublished_pid_is_unavailable_before_proc_access() {
        assert_eq!(
            collect_at(
                std::path::Path::new("/unavailable-synthetic-root"),
                0,
                || {}
            ),
            Err(ObservationError::Unavailable)
        );
    }

    #[test]
    fn ownership_invalid_boot_id_and_stat_are_refused_without_raw_values() {
        let f = Fixture::new();
        fs::write(
            f.0.path().join("sys/kernel/random/boot_id"),
            "synthetic-secret-sentinel",
        )
        .unwrap();
        let error = f.collect().unwrap_err();
        assert_eq!(error, ObservationError::Unavailable);
        assert!(!error.to_string().contains("synthetic-secret"));
        fs::write(
            f.0.path().join("sys/kernel/random/boot_id"),
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        fs::write(f.0.path().join("17/stat"), "17 (malformed) S").unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Unavailable));
    }
    #[test]
    fn ownership_runtime_handle_refuses_unpublished_entrypoint() {
        let handle = OwnershipCollector::new(Arc::new(AtomicU32::new(0)));
        assert_eq!(handle.inventory(), Err(ObservationError::Unavailable));
    }

    #[test]
    fn ownership_executable_limit_is_not_an_empty_digest() {
        let f = Fixture::new();
        File::options()
            .write(true)
            .open(f.0.path().join("executable"))
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        assert_eq!(f.collect(), Err(ObservationError::Limit));
    }
    #[test]
    fn ownership_udp_ipv6_uses_same_production_tuple_parser() {
        let f = Fixture::new();
        fs::write(f.0.path().join("17/net/udp6"),
            "header\n0: 00000000000000000000000001000000:C350 00000000000000000000000001000000:01BB 01 0 0 0 1000 0 789\n").unwrap();
        symlink("socket:[789]", f.0.path().join("17/fd/3")).unwrap();
        let facts = f.collect().unwrap();
        assert_eq!(facts.sockets[0].protocol, "udp6");
        assert_eq!(facts.sockets[0].remote.to_string(), "[::1]:443");
    }

    #[test]
    fn ownership_socket_owner_disappearing_between_scans_refuses() {
        let f = Fixture::new();
        fs::write(
            f.0.path().join("17/net/tcp"),
            "header\n0: 0100007F:C350 0200007F:01BB 01 0 0 0 1000 0 456\n",
        )
        .unwrap();
        symlink("socket:[456]", f.0.path().join("17/fd/3")).unwrap();
        assert_eq!(
            collect_at(f.0.path(), 17, || fs::remove_file(
                f.0.path().join("17/fd/3")
            )
            .unwrap()),
            Err(ObservationError::Unowned)
        );
    }

    #[test]
    fn ownership_root_namespace_change_between_scans_refuses() {
        let f = Fixture::new();
        let _old_inode = File::open(f.0.path().join("netns")).unwrap();
        assert_eq!(
            collect_at(f.0.path(), 17, || {
                fs::remove_file(f.0.path().join("netns")).unwrap();
                fs::write(f.0.path().join("netns"), "new namespace").unwrap();
            }),
            Err(ObservationError::Changed)
        );
    }
}
