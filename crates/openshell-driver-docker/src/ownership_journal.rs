// SPDX-License-Identifier: Apache-2.0
//! Retained attempts are not a closed manifest, terminal proof or broker barrier.
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalError {
    Invalid,
    Unavailable,
    Corrupt,
    Limit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EventKind {
    CreateAttempt,
    ComponentCreated,
    StartAttempt,
    StopAttempt,
    StopReturned,
    DeleteAttempt,
    DeleteReturned,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    pub kind: EventKind,
    pub component_id: Option<String>,
}
impl Event {
    pub(crate) fn new(kind: EventKind) -> Self {
        Self {
            kind,
            component_id: None,
        }
    }
    fn validate(&self) -> Result<(), JournalError> {
        match (&self.kind, &self.component_id) {
            (EventKind::ComponentCreated, Some(id))
                if id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Ok(())
            }
            (EventKind::ComponentCreated, _) | (_, Some(_)) => Err(JournalError::Invalid),
            _ => Ok(()),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Coverage {
    OpenUnqualified,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    format_version: u32,
    namespace: String,
    sandbox_id: String,
    pub revision: u64,
    pub coverage: Coverage,
    pub events: Vec<Event>,
}
impl Record {
    fn validate(&self, namespace: &str, id: &str) -> Result<(), JournalError> {
        if self.format_version != 1
            || self.namespace != namespace
            || self.sandbox_id != id
            || self.events.is_empty()
            || self.events.len() > 64
            || self.revision != self.events.len() as u64
        {
            return Err(JournalError::Corrupt);
        }
        for event in &self.events {
            event.validate().map_err(|_| JournalError::Corrupt)?;
        }
        Ok(())
    }
}
fn scope(directory: &Path, namespace: &str, id: &str) -> Result<(), JournalError> {
    if namespace.is_empty()
        || namespace.len() > 63
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || namespace == "."
        || namespace == ".."
        || id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        || directory.file_name().and_then(|s| s.to_str()) != Some(id)
        || directory
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            != Some(namespace)
        || directory
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            != Some("docker-ownership-evidence")
    {
        return Err(JournalError::Invalid);
    }
    Ok(())
}
/// Legacy attempt capture only. Closed component/task/generation/engine fencing is incomplete.
pub(crate) fn append_at(
    directory: &Path,
    namespace: &str,
    id: &str,
    event: Event,
) -> Result<Record, JournalError> {
    scope(directory, namespace, id)?;
    event.validate()?;
    #[cfg(target_os = "linux")]
    {
        platform::append(directory, namespace, id, event)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(JournalError::Unavailable)
    }
}
/// Lookup never creates directories/locks or repairs corrupt state.
#[allow(dead_code)] // The authenticated compute observation RPC is not qualified yet.
pub(crate) fn read_at(directory: &Path, namespace: &str, id: &str) -> Result<Record, JournalError> {
    scope(directory, namespace, id)?;
    #[cfg(target_os = "linux")]
    {
        platform::read(directory, namespace, id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(JournalError::Unavailable)
    }
}
#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    fn owned_fd(raw: i32) -> Result<File, JournalError> {
        if raw < 0 {
            return Err(JournalError::Unavailable);
        }
        // SAFETY: successful open/openat returns one newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(raw) })
    }
    fn open_file(dir: &File, name: &str, flags: i32) -> Result<File, JournalError> {
        let name = CString::new(name).map_err(|_| JournalError::Invalid)?;
        // SAFETY: live directory and NUL-terminated name; mode supplied for O_CREAT.
        let file = owned_fd(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0o600,
            )
        })?;
        let m = file.metadata().map_err(|_| JournalError::Unavailable)?;
        // SAFETY: geteuid takes no pointers and does not mutate state.
        let uid = unsafe { libc::geteuid() };
        if !m.is_file()
            || m.uid() != uid
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
            || m.len() > 65536
        {
            return Err(JournalError::Unavailable);
        }
        Ok(file)
    }
    fn directory(path: &Path, create: bool) -> Result<File, JournalError> {
        if !path.is_absolute() {
            return Err(JournalError::Invalid);
        }
        let components: Vec<_> = path.components().collect();
        if components.len() < 4 {
            return Err(JournalError::Invalid);
        }
        // SAFETY: static root opened read-only without following links.
        let mut dir = owned_fd(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        })?;
        for (index, component) in components.iter().enumerate().skip(1) {
            let Component::Normal(name) = component else {
                return Err(JournalError::Invalid);
            };
            let name = CString::new(name.as_bytes()).map_err(|_| JournalError::Invalid)?;
            if create {
                // SAFETY: directory descriptor and C string remain live.
                let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
                if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(JournalError::Unavailable);
                }
                if rc == 0 {
                    dir.sync_all().map_err(|_| JournalError::Unavailable)?;
                }
            }
            // SAFETY: each component is relative to the pinned parent, never a symlink.
            dir = owned_fd(unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            })?;
            if index >= components.len() - 3 {
                let m = dir.metadata().map_err(|_| JournalError::Unavailable)?;
                // SAFETY: geteuid takes no pointers and does not mutate state.
                if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
                    return Err(JournalError::Unavailable);
                }
            }
        }
        Ok(dir)
    }
    fn load(dir: &File, ns: &str, id: &str) -> Result<Record, JournalError> {
        let file = open_file(dir, "journal.json", libc::O_RDONLY)?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| JournalError::Unavailable)?;
        if bytes.len() > 65536 {
            return Err(JournalError::Limit);
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
        record.validate(ns, id)?;
        Ok(record)
    }
    pub(super) fn read(path: &Path, ns: &str, id: &str) -> Result<Record, JournalError> {
        let dir = directory(path, false)?;
        let mut pending = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live directory descriptor and writable stat; no link is followed.
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c"journal.next".as_ptr(),
                pending.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(JournalError::Unavailable);
        }
        load(&dir, ns, id)
    }
    pub(super) fn append(
        path: &Path,
        ns: &str,
        id: &str,
        event: Event,
    ) -> Result<Record, JournalError> {
        let dir = directory(path, true)?;
        let lock = open_file(&dir, "journal.lock", libc::O_RDWR | libc::O_CREAT)?;
        lock.try_lock().map_err(|_| JournalError::Unavailable)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: live dir, writable stat; populated only on success.
        let exists = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c"journal.json".as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        let mut record = if exists == 0 {
            load(&dir, ns, id)?
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Record {
                format_version: 1,
                namespace: ns.into(),
                sandbox_id: id.into(),
                revision: 0,
                coverage: Coverage::OpenUnqualified,
                events: Vec::new(),
            }
        } else {
            return Err(JournalError::Unavailable);
        };
        if record.events.len() == 64 {
            return Err(JournalError::Limit);
        }
        record.events.push(event);
        record.revision = record.revision.checked_add(1).ok_or(JournalError::Limit)?;
        record.validate(ns, id)?;
        let bytes = serde_json::to_vec(&record).map_err(|_| JournalError::Corrupt)?;
        if bytes.len() > 65536 {
            return Err(JournalError::Limit);
        }
        // One unresolved staged write blocks further capture instead of leaking temp files.
        // Never overwrite/remove an uncertain or preexisting staging object.
        let next = "journal.next";
        let mut file = open_file(&dir, next, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        // Retain failed private attempts; never unlink an unknown replacement.
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| JournalError::Unavailable)?;
        let name = CString::new(next).map_err(|_| JournalError::Invalid)?;
        // SAFETY: both names are relative to the same pinned private directory.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                name.as_ptr(),
                dir.as_raw_fd(),
                c"journal.json".as_ptr(),
            )
        } != 0
        {
            return Err(JournalError::Unavailable);
        }
        dir.sync_all().map_err(|_| JournalError::Unavailable)?;
        Ok(record)
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    struct Fixture(tempfile::TempDir);
    impl Fixture {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }
        fn directory(&self) -> std::path::PathBuf {
            self.0
                .path()
                .join("docker-ownership-evidence")
                .join("synthetic")
                .join(ID)
        }
        fn append(&self, event: Event) -> Result<Record, JournalError> {
            append_at(&self.directory(), "synthetic", ID, event)
        }
        fn read(&self) -> Result<Record, JournalError> {
            read_at(&self.directory(), "synthetic", ID)
        }
    }
    #[test]
    fn ownership_journal_missing_read_does_not_create_state() {
        let f = Fixture::new();
        assert!(matches!(f.read(), Err(JournalError::Unavailable)));
        assert!(!f.directory().exists());
    }
    #[test]
    fn ownership_journal_retains_exact_components_but_stays_unqualified() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let id = "a".repeat(64);
        let r = f
            .append(Event {
                kind: EventKind::ComponentCreated,
                component_id: Some(id.clone()),
            })
            .unwrap();
        assert_eq!(r.revision, 2);
        assert_eq!(r.events[1].component_id.as_deref(), Some(id.as_str()));
        assert_eq!(r.coverage, Coverage::OpenUnqualified);
        assert_eq!(f.read().unwrap(), r);
    }
    #[test]
    fn ownership_journal_stop_delete_returns_never_prove_absence() {
        let f = Fixture::new();
        for kind in [
            EventKind::CreateAttempt,
            EventKind::StopAttempt,
            EventKind::StopReturned,
            EventKind::DeleteAttempt,
            EventKind::DeleteReturned,
            EventKind::StartAttempt,
        ] {
            let r = f.append(Event::new(kind)).unwrap();
            assert_eq!(r.coverage, Coverage::OpenUnqualified);
        }
        assert_eq!(f.read().unwrap().revision, 6);
    }
    #[test]
    fn ownership_journal_corruption_is_not_repaired() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let path = f.directory().join("journal.json");
        fs::write(&path, b"not-json").unwrap();
        assert!(matches!(f.read(), Err(JournalError::Corrupt)));
        assert!(f.append(Event::new(EventKind::StopAttempt)).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not-json");
    }
    #[test]
    fn ownership_journal_unknown_fields_and_revision_conflicts_refuse() {
        for field in ["foreign", "revision", "sandbox_id", "coverage"] {
            let f = Fixture::new();
            f.append(Event::new(EventKind::CreateAttempt)).unwrap();
            let path = f.directory().join("journal.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value[field] = match field {
                "revision" => serde_json::json!(99),
                "sandbox_id" => serde_json::json!("foreign"),
                "coverage" => serde_json::json!("qualified"),
                _ => serde_json::json!(true),
            };
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(f.read().is_err());
        }
    }
    #[test]
    fn ownership_journal_permissions_are_private() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        assert_eq!(
            fs::metadata(f.directory()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["journal.json", "journal.lock"] {
            assert_eq!(
                fs::metadata(f.directory().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn ownership_journal_permissive_or_symlinked_custody_refuses() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        fs::set_permissions(f.directory(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(f.read().is_err());
        fs::set_permissions(f.directory(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(f.directory().join("journal.json")).unwrap();
        symlink(
            f.0.path().join("foreign"),
            f.directory().join("journal.json"),
        )
        .unwrap();
        assert!(f.append(Event::new(EventKind::StopAttempt)).is_err());
        assert!(!f.0.path().join("foreign").exists());
    }
    #[test]
    fn ownership_journal_parent_symlink_is_not_followed() {
        let f = Fixture::new();
        let foreign = f.0.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        symlink(&foreign, f.0.path().join("docker-ownership-evidence")).unwrap();
        assert!(f.append(Event::new(EventKind::CreateAttempt)).is_err());
        assert_eq!(fs::read_dir(foreign).unwrap().count(), 0);
    }
    #[test]
    fn ownership_journal_capacity_never_truncates_retained_events() {
        let f = Fixture::new();
        for _ in 0..64 {
            f.append(Event::new(EventKind::StartAttempt)).unwrap();
        }
        let before = fs::read(f.directory().join("journal.json")).unwrap();
        assert!(matches!(
            f.append(Event::new(EventKind::StopAttempt)),
            Err(JournalError::Limit)
        ));
        assert_eq!(
            fs::read(f.directory().join("journal.json")).unwrap(),
            before
        );
    }
    #[test]
    fn ownership_journal_invalid_component_and_scope_are_refused() {
        let f = Fixture::new();
        assert!(
            f.append(Event {
                kind: EventKind::ComponentCreated,
                component_id: Some("name-not-id".into())
            })
            .is_err()
        );
        assert!(
            append_at(
                &f.directory(),
                "../foreign",
                ID,
                Event::new(EventKind::CreateAttempt)
            )
            .is_err()
        );
        assert!(!f.directory().exists());
    }
    #[test]
    fn ownership_journal_boundary_removal_preserves_separate_evidence() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let boundary = f.0.path().join("docker").join("synthetic").join(ID);
        fs::create_dir_all(&boundary).unwrap();
        fs::write(boundary.join("sandbox.jwt"), "synthetic").unwrap();
        fs::remove_dir_all(boundary).unwrap();
        assert_eq!(f.read().unwrap().revision, 1);
    }
    #[test]
    fn ownership_journal_concurrent_successes_have_one_revision_each() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let directory = f.directory();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = directory.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    append_at(&path, "synthetic", ID, Event::new(EventKind::StartAttempt)).is_ok()
                })
            })
            .collect();
        barrier.wait();
        let successes = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(f.read().unwrap().revision, 1 + successes as u64);
    }
    #[test]
    fn ownership_journal_hardlinks_refuse_without_changing_foreign_bytes() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let original = f.directory().join("journal.json");
        let foreign = f.0.path().join("foreign");
        fs::hard_link(&original, &foreign).unwrap();
        let before = fs::read(&foreign).unwrap();
        assert!(f.append(Event::new(EventKind::StopAttempt)).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), before);
    }

    #[test]
    fn ownership_journal_foreign_lock_is_untouched() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let lock = f.directory().join("journal.lock");
        fs::remove_file(&lock).unwrap();
        let foreign = f.0.path().join("foreign-lock");
        fs::write(&foreign, "synthetic-foreign").unwrap();
        symlink(&foreign, &lock).unwrap();
        let before = fs::read(f.directory().join("journal.json")).unwrap();
        assert!(f.append(Event::new(EventKind::StopAttempt)).is_err());
        assert_eq!(
            fs::read(f.directory().join("journal.json")).unwrap(),
            before
        );
        assert_eq!(fs::read(&foreign).unwrap(), b"synthetic-foreign");
    }
    #[test]
    fn ownership_journal_pending_write_refuses_without_overwrite_or_growth() {
        let f = Fixture::new();
        f.append(Event::new(EventKind::CreateAttempt)).unwrap();
        let pending = f.directory().join("journal.next");
        fs::write(&pending, "synthetic-uncertain-write").unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(f.directory().join("journal.json")).unwrap();
        assert!(f.append(Event::new(EventKind::StopAttempt)).is_err());
        assert_eq!(
            fs::read(f.directory().join("journal.json")).unwrap(),
            before
        );
        assert_eq!(fs::read(&pending).unwrap(), b"synthetic-uncertain-write");
        assert_eq!(fs::read_dir(f.directory()).unwrap().count(), 3);
        assert!(matches!(f.read(), Err(JournalError::Unavailable)));
    }
}
