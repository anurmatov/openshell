// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private native process plumbing behind the Sandbox Protocol server.

use async_trait::async_trait;
use openshell_isolation_interface::contract::{
    BackendError, BoundaryDuplexStream, BoundaryExitStatus, BoundaryInput, BoundaryOutput,
    BoundarySignal, ExecSpec, LoopbackTarget,
};
use std::sync::Arc;

#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Attach to the admitted process's retained standard I/O. The boundary
    /// remains the process owner and may permit only one control attachment.
    async fn attach(&self) -> Result<ProcessAttachment, BackendError> {
        Err(BackendError::Unsupported(
            "process attachment is not supported".to_string(),
        ))
    }
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and its backend-owned process group.
    async fn terminate(&self) -> Result<(), BackendError>;
}

pub struct ProcessAttachment {
    /// Stdin writer.
    pub stdin: BoundaryInput,
    /// Stdout reader, or the PTY-merged output stream.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY processes.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when the admitted process owns a terminal.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

#[async_trait]
pub trait BoundaryTerminal: Send + Sync {
    /// Resize the terminal.
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError>;
}

pub struct ExecSession {
    /// The spawned process.
    pub process: Arc<dyn BoundaryProcess>,
    /// Stdin writer, if not a PTY-merged stream.
    pub stdin: Option<BoundaryInput>,
    /// Stdout reader.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY exec.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when a terminal was requested.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

#[async_trait]
pub trait BoundaryExec: Send + Sync {
    /// Spawn `spec` inside the boundary, returning an owned session.
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError>;
}

#[async_trait]
pub trait BoundaryLoopbackConnector: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryDuplexStream, BackendError>;
}

// The protected native leaf owns this source; callers cannot choose a PID or
// path. These bounded facts do not prove placement, terminal or broker absence.
#[cfg(target_os = "linux")]
pub(crate) mod ownership_inventory {
    use openshell_sandbox_backend::boundary_protocol::{
        OwnershipProcessWire as ProcessIdentity, OwnershipSocketWire as SocketObservation,
    };
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::time::{Duration, Instant};
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct NamespaceInventory {
        pub processes: Vec<ProcessIdentity>,
        pub sockets: Vec<SocketObservation>,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ObservationError {
        Unavailable,
        Changed,
        Unowned,
        Limit,
    }
    impl std::fmt::Display for ObservationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "OWNERSHIP_SOURCE_{self:?}")
        }
    }
    #[derive(Clone, Copy)]
    enum ProcTcpAddressFamily {
        Ipv4,
        Ipv6,
    }

    /// Capture an immutable launch incarnation. Failure never becomes an empty inventory.
    pub(crate) fn bind(pid: u32) -> Result<ProcessIdentity, ObservationError> {
        bind_at(Path::new("/proc"), pid)
    }
    fn bind_at(root: &Path, pid: u32) -> Result<ProcessIdentity, ObservationError> {
        if pid == 0 {
            return Err(ObservationError::Unavailable);
        }
        let boot = read_bounded(&root.join("sys/kernel/random/boot_id"), 128)?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|_| ObservationError::Unavailable)?
            .trim();
        let parsed = uuid::Uuid::parse_str(boot).map_err(|_| ObservationError::Unavailable)?;
        if parsed.is_nil() || parsed.to_string() != boot {
            return Err(ObservationError::Unavailable);
        }
        identity(root, pid, boot, Instant::now() + Duration::from_secs(1))
    }
    pub(crate) fn observe(
        anchor: &ProcessIdentity,
    ) -> Result<NamespaceInventory, ObservationError> {
        observe_at(Path::new("/proc"), anchor, || false)
    }
    fn observe_at(
        root: &Path,
        anchor: &ProcessIdentity,
        cancelled: impl Fn() -> bool,
    ) -> Result<NamespaceInventory, ObservationError> {
        if cancelled() || bind_at(root, anchor.pid)? != *anchor {
            return Err(ObservationError::Changed);
        }
        let facts = collect_at(root, anchor.pid, || {})?;
        if cancelled() || bind_at(root, anchor.pid)? != *anchor {
            return Err(ObservationError::Changed);
        }
        Ok(facts)
    }
    pub(crate) fn parse_proc_socket_addr(
        value: &str,
        address_family: ProcTcpAddressFamily,
    ) -> Option<SocketAddr> {
        let (address, port) = value.rsplit_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;

        let ip = match address_family {
            ProcTcpAddressFamily::Ipv4 => {
                if address.len() != 8 {
                    return None;
                }
                let address = u32::from_str_radix(address, 16).ok()?;
                IpAddr::V4(Ipv4Addr::from(address.to_le_bytes()))
            }
            ProcTcpAddressFamily::Ipv6 => {
                if address.len() != 32 {
                    return None;
                }
                let mut bytes = [0u8; 16];
                for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
                    let chunk = std::str::from_utf8(chunk).ok()?;
                    let word = u32::from_str_radix(chunk, 16).ok()?;
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
        };

        Some(SocketAddr::new(ip, port))
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

    fn identity(
        root: &Path,
        pid: u32,
        boot: &str,
        deadline: Instant,
    ) -> Result<ProcessIdentity, ObservationError> {
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
        let executable_digest = executable_digest(&p.join("exe"), deadline)?;
        Ok(ProcessIdentity {
            kernel_boot_id: boot.into(),
            pid,
            starttime_ticks: birth,
            pid_namespace_inode,
            net_namespace_inode,
            executable_digest,
        })
    }

    fn executable_digest(path: &Path, deadline: Instant) -> Result<[u8; 32], ObservationError> {
        let mut file = File::open(path).map_err(|_| ObservationError::Unavailable)?;
        let mut hash =
            openshell_crypto::sha256_digest().map_err(|_| ObservationError::Unavailable)?;
        let mut buffer = [0u8; 65536];
        let mut total = 0usize;
        loop {
            if Instant::now() >= deadline {
                return Err(ObservationError::Limit);
            }
            let n = file
                .read(&mut buffer)
                .map_err(|_| ObservationError::Unavailable)?;
            if n == 0 {
                break;
            }
            total = total.checked_add(n).ok_or(ObservationError::Limit)?;
            if total > 64 * 1024 * 1024 {
                return Err(ObservationError::Limit);
            }
            hash.update(&buffer[..n])
                .map_err(|_| ObservationError::Unavailable)?;
        }
        hash.finish().map_err(|_| ObservationError::Unavailable)
    }

    fn scan(
        root: &Path,
        pid: u32,
        deadline: Instant,
    ) -> Result<NamespaceInventory, ObservationError> {
        let boot = read_bounded(&root.join("sys/kernel/random/boot_id"), 128)?;
        let boot = std::str::from_utf8(&boot)
            .map_err(|_| ObservationError::Unavailable)?
            .trim();
        let parsed = uuid::Uuid::parse_str(boot).map_err(|_| ObservationError::Unavailable)?;
        if parsed.is_nil() || parsed.to_string() != boot {
            return Err(ObservationError::Unavailable);
        }
        let expected = identity(root, pid, boot, deadline)?;
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
            let before = identity(root, current, boot, deadline)?;
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
                let link =
                    fs::read_link(entry.path()).map_err(|_| ObservationError::Unavailable)?;
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
            if identity(root, current, boot, deadline)? != before {
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
                let local = parse_proc_socket_addr(fields[1], family)
                    .ok_or(ObservationError::Unavailable)?;
                let remote = parse_proc_socket_addr(fields[2], family)
                    .ok_or(ObservationError::Unavailable)?;
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
            (&a.protocol, a.inode, a.local, a.remote).cmp(&(
                &b.protocol,
                b.inode,
                b.local,
                b.remote,
            ))
        });
        if identity(root, pid, boot, deadline)? != expected {
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
        fn ownership_inventory_collects_all_namespace_members_not_only_descendants() {
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
        fn ownership_inventory_socket_tuple_uses_actual_procfs_parser_and_all_owners() {
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
        fn ownership_inventory_pid_reuse_between_scans_refuses() {
            let f = Fixture::new();
            assert_eq!(
                collect_at(f.0.path(), 17, || f.stat(17, 101)),
                Err(ObservationError::Changed)
            );
        }

        #[test]
        fn ownership_inventory_new_member_between_scans_refuses() {
            let f = Fixture::new();
            assert_eq!(
                collect_at(f.0.path(), 17, || f.process(23, 200)),
                Err(ObservationError::Changed)
            );
        }

        #[test]
        fn ownership_inventory_changed_executable_between_scans_refuses() {
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
        fn ownership_inventory_unknown_namespace_member_never_becomes_zero() {
            let f = Fixture::new();
            f.process(23, 200);
            fs::remove_file(f.0.path().join("23/ns/net")).unwrap();
            assert_eq!(f.collect(), Err(ObservationError::Unavailable));
        }

        #[test]
        fn ownership_inventory_missing_fd_directory_refuses() {
            let f = Fixture::new();
            fs::remove_dir(f.0.path().join("17/fd")).unwrap();
            assert_eq!(f.collect(), Err(ObservationError::Unavailable));
        }

        #[test]
        fn ownership_inventory_missing_tcp6_is_not_an_empty_ipv6_inventory() {
            let f = Fixture::new();
            fs::remove_file(f.0.path().join("17/net/tcp6")).unwrap();
            assert_eq!(f.collect(), Err(ObservationError::Unavailable));
        }

        #[test]
        fn ownership_inventory_unowned_socket_refuses() {
            let f = Fixture::new();
            fs::write(
                f.0.path().join("17/net/tcp"),
                "header\n0: 0100007F:C350 0200007F:01BB 01 0 0 0 1000 0 456\n",
            )
            .unwrap();
            assert_eq!(f.collect(), Err(ObservationError::Unowned));
        }

        #[test]
        fn ownership_inventory_unpublished_pid_is_unavailable_before_proc_access() {
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
        fn ownership_inventory_invalid_boot_id_and_stat_are_refused_without_raw_values() {
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
        fn ownership_inventory_immutable_anchor_refuses_self_consistent_replacement() {
            let f = Fixture::new();
            let anchor = bind_at(f.0.path(), 17).unwrap();
            f.stat(17, 101);
            assert_eq!(
                observe_at(f.0.path(), &anchor, || false),
                Err(ObservationError::Changed)
            );
        }
        #[test]
        fn ownership_inventory_cancelled_read_never_returns_facts() {
            let f = Fixture::new();
            let anchor = bind_at(f.0.path(), 17).unwrap();
            assert_eq!(
                observe_at(f.0.path(), &anchor, || true),
                Err(ObservationError::Changed)
            );
        }

        #[test]
        fn ownership_inventory_deadline_and_read_overflow_refuse() {
            let f = Fixture::new();
            assert_eq!(
                scan(f.0.path(), 17, Instant::now()),
                Err(ObservationError::Limit)
            );
            assert_eq!(
                read_bounded(&f.0.path().join("executable"), 1),
                Err(ObservationError::Limit)
            );
        }

        #[test]
        fn ownership_inventory_namespace_replacement_refuses() {
            let f = Fixture::new();
            let anchor = bind_at(f.0.path(), 17).unwrap();
            fs::remove_file(f.0.path().join("17/ns/pid")).unwrap();
            fs::write(f.0.path().join("17/ns/pid"), "replacement").unwrap();
            assert_eq!(
                observe_at(f.0.path(), &anchor, || false),
                Err(ObservationError::Changed)
            );
        }
    }
}
