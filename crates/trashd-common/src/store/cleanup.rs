//! Reclaim data already retired by a purge or abandoned before publication.
//! Ordinary trash selection and retention policy stay in the parent module.

use super::*;

/// Prefix of trees detached for deletion inside a root's `.trashd/`.
pub(super) const DETACHED_PREFIX: &str = "purging-";
pub(super) const COPY_STAGE_PREFIX: &str = ".trashd-copy-";
pub(super) const STAGES_PER_SWEEP: usize = 32;

/// Work on data whose removal was already authorized. Pending jobs remain
/// private and can be retried without selecting additional ordinary entries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// Detached jobs and abandoned stages removed during this pass.
    pub removed: usize,
    /// Detached jobs whose physical deletion failed during this pass. Live
    /// stages and stages outside the bounded sample are not deletion jobs.
    pub pending: usize,
}

impl CleanupReport {
    fn note_removal(&mut self, result: io::Result<()>) {
        match result {
            Ok(()) => self.removed += 1,
            Err(_) => self.pending += 1,
        }
    }
}

impl TrashStore {
    /// Count detached deletion jobs without mutating data or selecting
    /// ordinary entries. Unpublished stages may still belong to live writers.
    pub fn pending_cleanup(&self) -> Result<usize, TrashError> {
        self.all_trash_dirs()
            .iter()
            .try_fold(0usize, |total, (root, _)| {
                self.pending_cleanup_in_root(root)
                    .map(|pending| total.saturating_add(pending))
            })
    }

    /// Read-only diagnostics follow ordinary listing's policy: a broken
    /// secondary root warns, while a broken home root remains an error.
    pub(super) fn pending_cleanup_in_root(&self, root: &Path) -> Result<usize, TrashError> {
        match pending_detached(root) {
            Ok(pending) => Ok(pending),
            Err(error) if root == self.home => Err(error.into()),
            Err(error) => {
                Self::warn_unreadable_root(root, error.into());
                Ok(0)
            }
        }
    }

    /// Retry detached purges and reclaim a bounded batch of abandoned copy
    /// and encoding stages. Active writers retain their locks and data. This
    /// never applies retention policy to ordinary entries or expands a user's
    /// confirmed empty selection.
    pub fn cleanup_unfinished(&self) -> Result<CleanupReport, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        self.cleanup_unfinished_in_roots(&roots)
    }

    pub(super) fn cleanup_unfinished_in_roots(
        &self,
        roots: &[PathBuf],
    ) -> Result<CleanupReport, TrashError> {
        let mut report = CleanupReport::default();
        let mut failure = None;
        for root in roots {
            let cleaned = (|| {
                self.ensure_trusted_parent_recent(root, unsafe { libc::geteuid() })?;
                let (candidates, mut cleaned) = sweep_detached_report(root)?;
                let stages = self.sweep_abandoned_stages(root, &candidates);
                cleaned.removed += stages.removed;
                cleaned.pending += stages.pending;
                Ok::<_, io::Error>(cleaned)
            })();
            match cleaned {
                Ok(cleaned) => {
                    report.removed += cleaned.removed;
                    report.pending += cleaned.pending;
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(report)
    }

    /// Unpublished stages still have their original data. Claim abandoned
    /// work under the root lock, then remove outside it. Cross-device copies
    /// hold the root lock; announced data stages hold their own file locks.
    /// Sample at most 32 candidates in the existing unlocked sweep, keeping
    /// writer-lock work bounded and reaching stages behind live work over
    /// later maintenance passes (#383, #388, #389).
    pub(super) fn claim_abandoned_stages(
        &self,
        root: &Path,
        candidates: &[CString],
    ) -> Option<(fs::File, Vec<CString>)> {
        if candidates.is_empty() {
            return None;
        }
        let uid = unsafe { libc::geteuid() };
        self.ensure_trusted_parent_recent(root, uid).ok()?;
        let guard = RootMutationGuard::try_acquire_as(root, uid).ok()??;
        let state_dir = CString::new(root.join(".trashd").as_os_str().as_bytes()).ok()?;
        let state = open_directory_at(libc::AT_FDCWD, &state_dir, true, false).ok()?;
        let mut claimed = Vec::new();
        for name in candidates.iter().take(STAGES_PER_SWEEP) {
            if is_copy_stage(name) {
                if let Ok(claim) = claim_copy_stage_at(state.as_raw_fd(), name) {
                    claimed.push(claim);
                }
            } else if is_data_stage(name)
                && let Ok(Some(stage)) = try_lock_data_stage_at(state.as_raw_fd(), name)
                && let Ok(claim) = claim_data_stage_at(state.as_raw_fd(), name, &stage)
            {
                claimed.push(claim);
            }
        }
        drop(guard);
        Some((state, claimed))
    }

    pub(super) fn sweep_abandoned_stages(
        &self,
        root: &Path,
        candidates: &[CString],
    ) -> CleanupReport {
        let mut report = CleanupReport::default();
        if let Some((state, claimed)) = self.claim_abandoned_stages(root, candidates) {
            for name in claimed {
                // Failed removals retain the purging- claim and are retried
                // by the existing sweep; mount roots are never traversed.
                report.note_removal(remove_tree_at(state.as_raw_fd(), &name, 0));
            }
        }
        report
    }
}

pub(super) fn is_data_stage(name: &CStr) -> bool {
    name.to_bytes()
        .strip_prefix(DATA_STAGE_PREFIX.as_bytes())
        .is_some_and(|token| {
            token.len() == DATA_STAGE_RANDOM_LEN && token.iter().all(u8::is_ascii_alphanumeric)
        })
}

/// Opening read-only also handles preserved 0400 modes. Root may have
/// restored another owner's metadata onto the stage; the private parent
/// and announced-name protocol authorize cleanup, not the inode's owner.
pub(super) fn try_lock_data_stage_at(state: RawFd, name: &CStr) -> io::Result<Option<fs::File>> {
    let before = stat_at(state, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(None);
    }
    let descriptor = unsafe {
        libc::openat(
            state,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    if stat_identity(&stat_fd(descriptor)?) != stat_identity(&before) {
        return Ok(None);
    }
    // A shared lock conflicts with the producer's exclusive lock and also
    // works on read-only descriptors on NFS. Root guards serialize claims.
    if unsafe { libc::flock(descriptor, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(io::Error::last_os_error())
        };
    }
    Ok(Some(file))
}

pub(super) fn claim_data_stage_at(
    state: RawFd,
    name: &CStr,
    locked: &fs::File,
) -> io::Result<CString> {
    let opened = stat_fd(locked.as_raw_fd())?;
    let current = stat_at(state, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if opened.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat_identity(&opened) != stat_identity(&current)
    {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    claim_copy_stage_at(state, name)
}

pub(super) fn is_copy_stage(name: &CStr) -> bool {
    let Some(suffix) = name.to_bytes().strip_prefix(COPY_STAGE_PREFIX.as_bytes()) else {
        return false;
    };
    let mut parts = suffix.split(|&byte| byte == b'-');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
    }) && parts.next().is_none()
}

/// Exclusive mkdir claims a private container even on filesystems without
/// RENAME_NOREPLACE. Its data name is initially absent, so the rename cannot
/// replace another stage or unrelated state. A crash leaves a purging-
/// container that the normal detached sweep can finish.
pub(super) fn claim_copy_stage_at(state: RawFd, name: &CStr) -> io::Result<CString> {
    for attempt in 0u32..64 {
        let claim = CString::new(format!(
            "{DETACHED_PREFIX}copy-{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos())
        ))?;
        if unsafe { libc::mkdirat(state, claim.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error);
        }
        let claimed = (|| {
            let directory = open_directory_at(state, &claim, true, false)?;
            if unsafe {
                libc::renameat(
                    state,
                    name.as_ptr(),
                    directory.as_raw_fd(),
                    c"data".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if let Err(error) = claimed {
            let _ = raw_unlinkat(state, &claim, libc::AT_REMOVEDIR);
            return Err(error);
        }
        return Ok(claim);
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

/// Move a directory entry's data into its root's private state directory
/// (same filesystem), returning that directory and the new name.
pub(super) fn detach_for_removal(entry: &TrashEntry) -> io::Result<(fs::File, CString)> {
    let state_dir = CString::new(entry.trash_root.join(".trashd").as_os_str().as_bytes())?;
    let state = open_directory_at(libc::AT_FDCWD, &state_dir, true, false)?;
    let files_dir = CString::new(entry.trash_root.join("files").as_os_str().as_bytes())?;
    let files = open_directory_at(libc::AT_FDCWD, &files_dir, true, true)?;
    let data_name = CString::new(
        entry
            .trashed_path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .as_bytes(),
    )?;
    for attempt in 0u32..64 {
        let name = CString::new(format!(
            "{DETACHED_PREFIX}{}-{}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos())
        ))?;
        match rename_noreplace_at(files.as_raw_fd(), &data_name, state.as_raw_fd(), &name) {
            Ok(()) => return Ok((state, name)),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(error) if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
                // No RENAME_NOREPLACE here: delete in place, under the lock.
                remove_tree_at(files.as_raw_fd(), &data_name, 0)?;
                return Ok((state, CString::default()));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

fn open_cleanup_state(root: &Path) -> io::Result<Option<fs::File>> {
    let path = CString::new(root.join(".trashd").as_os_str().as_bytes())?;
    match open_directory_at(libc::AT_FDCWD, &path, true, false) {
        Ok(state) => Ok(Some(state)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read-only accounting: unknown or live stages are not deletion jobs.
pub(super) fn pending_detached(root: &Path) -> io::Result<usize> {
    let Some(state) = open_cleanup_state(root)? else {
        return Ok(0);
    };
    let mut pending = 0usize;
    for_each_entry(state.as_raw_fd(), |name, _| {
        if name.to_bytes().starts_with(DETACHED_PREFIX.as_bytes()) {
            pending += 1;
        }
        std::ops::ControlFlow::Continue(())
    })?;
    Ok(pending)
}

/// Delete trees an earlier purge detached but could not finish. Reuse the
/// full unlocked enumeration to sample bounded unpublished stages. A large
/// stage pool is reclaimed across later passes, rather than in one pass.
fn sweep_detached_report(root: &Path) -> io::Result<(Vec<CString>, CleanupReport)> {
    use std::hash::BuildHasher;
    let selection = std::collections::hash_map::RandomState::new();
    sweep_detached_report_prioritized(root, |name| selection.hash_one(name.to_bytes()))
}

#[cfg(test)]
pub(super) fn sweep_detached(root: &Path) -> Vec<CString> {
    sweep_detached_report(root).map_or_else(|_| Vec::new(), |(candidates, _)| candidates)
}

#[cfg(test)]
pub(super) fn sweep_detached_prioritized(
    root: &Path,
    priority: impl Fn(&CStr) -> u64,
) -> Vec<CString> {
    sweep_detached_report_prioritized(root, priority)
        .map_or_else(|_| Vec::new(), |(candidates, _)| candidates)
}

fn sweep_detached_report_prioritized(
    root: &Path,
    priority: impl Fn(&CStr) -> u64,
) -> io::Result<(Vec<CString>, CleanupReport)> {
    let Some(state) = open_cleanup_state(root)? else {
        return Ok((Vec::new(), CleanupReport::default()));
    };
    let mut report = CleanupReport::default();
    // Sample the full scan, keeping only 32 names. Always keeping the first
    // 32 could hide abandoned stages behind long-lived locked ones forever.
    let mut candidates: std::collections::BinaryHeap<(u64, CString)> =
        std::collections::BinaryHeap::new();
    for_each_entry(state.as_raw_fd(), |name, _| {
        if name.to_bytes().starts_with(DETACHED_PREFIX.as_bytes()) {
            report.note_removal(remove_tree_at(state.as_raw_fd(), name, 0));
        } else if is_copy_stage(name) || is_data_stage(name) {
            let rank = priority(name);
            if candidates.len() < STAGES_PER_SWEEP {
                candidates.push((rank, name.to_owned()));
            } else if candidates
                .peek()
                .is_some_and(|(last, saved)| (rank, name) < (*last, saved.as_c_str()))
            {
                candidates.pop();
                candidates.push((rank, name.to_owned()));
            }
        }
        std::ops::ControlFlow::Continue(())
    })?;
    Ok((
        candidates.into_iter().map(|(_, name)| name).collect(),
        report,
    ))
}
