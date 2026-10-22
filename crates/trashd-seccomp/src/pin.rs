//! Pin the supervised process's filesystem context into the supervisor.
//!
//! The historic approach resolved `/proc/<pid>/cwd` and `/proc/<pid>/fd/N` as
//! STRINGS and then re-walked those names from the supervisor's own context —
//! two independent path resolutions with a wide race window, wrong when the
//! target lives in another mount namespace or chroot, and divergent symlink
//! resolution (audit #6).
//!
//! Instead we hold kernel references:
//!
//! * absolute paths  → O_PATH fd on `/proc/<pid>/root`
//! * `AT_FDCWD`      → O_PATH fd on `/proc/<pid>/cwd`
//! * explicit dirfd  → `pidfd_getfd(2)` duplicate of the target's fd
//!
//! and then resolve every path prefix with a SINGLE `openat2(2)` call relative
//! to that fd, and move the file with `renameat(parent_fd, name, …)`. The
//! kernel does the walking while holding the pinned inode; a sibling process
//! renaming directories in between can no longer divert the operation.
//!
//! If fd pinning or confined resolution is unavailable, the supervisor lets
//! the target's kernel execute the original syscall. It must never re-resolve
//! a target pathname through the supervisor's mount namespace.
//!
//! Residuals (accepted, documented):
//! * Absolute-path walks use RESOLVE_IN_ROOT, so `..` and absolute symlinks
//!   clamp at the target's pinned root — matching what the target's own
//!   kernel would do. CWD/dirfd-relative walks use RESOLVE_BENEATH. A walk
//!   that would leave the pinned base (through `..` or an absolute symlink)
//!   is not trashed; the original target syscall executes instead.
//! * The leaf component may be swapped by a sibling between fstatat and
//!   renameat — identical to what plain unlink(2) acts on; trash_at re-stats
//!   post-move so recorded metadata always matches the trashed inode.
//! * rmdir emptiness can go stale before the move; a repopulated tree lands
//!   in the trash whole (recoverable), matching the legacy acceptance.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use trashd_common::TrashStore;
use trashd_common::store::TrashError;

/// Owned fd guard: closes on drop. The historic code leaked the duplicated
/// dirfd and the resolved parent fd on EVERY intercepted delete, exhausting
/// the supervisor's fd table during bulk deletes (review finding, #6 fix).
struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl std::os::unix::io::AsRawFd for FdGuard {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// An O_PATH/O_DIRECTORY reference to the supervised process's filesystem
/// context. Owns its fds; `Drop` closes them.
pub struct TargetFs {
    pid: u32,
    procfd: RawFd,
    root_fd: Option<RawFd>,
    cwd_fd: Option<RawFd>,
    /// `shares_our_view`, once computed for this operation.
    view: std::cell::Cell<Option<bool>>,
}

impl Drop for TargetFs {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.procfd);
            if let Some(fd) = self.root_fd.take() {
                libc::close(fd);
            }
            if let Some(fd) = self.cwd_fd.take() {
                libc::close(fd);
            }
        }
    }
}

impl TargetFs {
    /// Pin the exact triggering task, including non-leader threads.
    pub fn open(pid: u32) -> io::Result<Self> {
        Self::open_selected(pid, true)
    }

    /// Pin only bases this operation will use. Every operation needs the
    /// root for shares_our_view's policy/record guard; only cwd-relative paths
    /// need cwd. The startup probe continues to validate both backends.
    pub(crate) fn open_for_operation(
        pid: u32,
        absolute: bool,
        dirfd: Option<i32>,
    ) -> io::Result<Self> {
        Self::open_selected(
            pid,
            !absolute && matches!(dirfd, None | Some(libc::AT_FDCWD)),
        )
    }

    fn open_selected(pid: u32, need_cwd: bool) -> io::Result<Self> {
        let procfd = open_proc_dir(&format!("/proc/{pid}")).ok_or_else(io::Error::last_os_error)?;
        let root_fd = open_task_directory(procfd, c"root");
        let cwd_fd = need_cwd
            .then(|| open_task_directory(procfd, c"cwd"))
            .flatten();
        Ok(Self {
            pid,
            procfd,
            root_fd,
            cwd_fd,
            view: std::cell::Cell::new(None),
        })
    }

    /// O_PATH fd on the target's filesystem root (for absolute paths).
    pub fn root(&self) -> Option<RawFd> {
        self.root_fd
    }

    /// True when a relative walk resolves for the target exactly as for this
    /// process: the same root (mount and inode) in the same mount namespace,
    /// so `..` and absolute symlinks reach the same inodes either way (#195).
    /// Anything else (a chroot, even one into a bind mount of `/`, or another
    /// namespace) keeps RESOLVE_BENEATH and #62's protection.
    ///
    /// Asked twice per operation, it is computed once; our own side never
    /// changes and is computed once per supervisor (#320).
    pub fn shares_our_view(&self) -> bool {
        if let Some(shared) = self.view.get() {
            return shared;
        }
        let shared = self.compute_shares_our_view();
        self.view.set(Some(shared));
        shared
    }

    fn compute_shares_our_view(&self) -> bool {
        let Some(root) = self.root_fd else {
            return false;
        };
        let Some((our_root, our_ns)) = our_view() else {
            return false;
        };
        mount_identity(root, c"", libc::AT_EMPTY_PATH) == Some(our_root)
            && namespace_identity(self.procfd, c"ns/mnt") == Some(our_ns)
    }

    /// O_PATH fd on the target's cwd (for `AT_FDCWD`-relative paths).
    pub fn cwd(&self) -> Option<RawFd> {
        self.cwd_fd
    }

    /// Duplicate the target's `dirfd` into this process via pidfd_getfd(2)
    /// (Linux 5.6+), with an exact task proc-descriptor fallback. The duplicate shares the open file description, so it
    /// references the same directory inode even if the target (or a sibling)
    /// closes or renames things afterwards.
    pub fn dup_dirfd(&self, dirfd: i32) -> io::Result<RawFd> {
        if crate::broker::is_connected() {
            return crate::broker::duplicate_fd(self.pid, dirfd);
        }
        let name = CString::new(format!("fd/{dirfd}"))?;
        open_task_directory(self.procfd, &name).ok_or_else(io::Error::last_os_error)
    }
}

/// (mount id, device, inode) of a directory, or None when the kernel cannot
/// report a mount id (statx STATX_MNT_ID, Linux 5.8+).
/// Mount id, device major/minor and inode of a directory.
type MountIdentity = (u64, u32, u32, u64);
/// Device and inode of a namespace file.
type NamespaceIdentity = (u64, u64);

/// This supervisor's root mount identity and mount namespace: a process's
/// root and namespace only change through calls the supervisor never makes.
fn our_view() -> Option<(MountIdentity, NamespaceIdentity)> {
    static VIEW: std::sync::OnceLock<Option<(MountIdentity, NamespaceIdentity)>> =
        std::sync::OnceLock::new();
    *VIEW.get_or_init(|| {
        Some((
            mount_identity(libc::AT_FDCWD, c"/", 0)?,
            namespace_identity(libc::AT_FDCWD, c"/proc/self/ns/mnt")?,
        ))
    })
}

fn namespace_identity(dir: RawFd, name: &CStr) -> Option<NamespaceIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstatat(dir, name.as_ptr(), &mut stat, 0) } == 0)
        .then_some((stat.st_dev, stat.st_ino))
}

fn mount_identity(dir: RawFd, name: &CStr, flags: libc::c_int) -> Option<MountIdentity> {
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_INO | libc::STATX_MNT_ID;
    if unsafe {
        libc::statx(
            dir,
            name.as_ptr(),
            flags | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            mask,
            &mut stx,
        )
    } != 0
        || stx.stx_mask & libc::STATX_MNT_ID == 0
    {
        return None;
    }
    Some((
        stx.stx_mnt_id,
        stx.stx_dev_major,
        stx.stx_dev_minor,
        stx.stx_ino,
    ))
}

fn open_task_directory(procfd: RawFd, name: &CStr) -> Option<RawFd> {
    let fd = unsafe {
        libc::openat(
            procfd,
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 { None } else { Some(fd) }
}

/// All mandatory filesystem backends must work before preload defers.
pub fn startup_probe(pid: u32, inherited_dirfd: i32) -> io::Result<()> {
    let fs = TargetFs::open(pid)?;
    let root = fs.root().ok_or_else(io::Error::last_os_error)?;
    let cwd = fs.cwd().ok_or_else(io::Error::last_os_error)?;
    let _root = FdGuard(resolve_parent(root, OsStr::new("."), true)?);
    let _cwd = FdGuard(resolve_parent(cwd, OsStr::new("."), false)?);
    let _dir = FdGuard(fs.dup_dirfd(inherited_dirfd)?);
    // Invalid descriptors/empty names cannot mutate anything; ENOENT/EBADF
    // proves renameat2 reaches the kernel rather than an inherited denial.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            -1,
            c"".as_ptr(),
            -1,
            c"".as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    let error = io::Error::last_os_error();
    if result != -1 || !matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EBADF)) {
        return Err(error);
    }
    Ok(())
}

fn open_proc_dir(path: &str) -> Option<RawFd> {
    let c = CString::new(path).ok()?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 { None } else { Some(fd) }
}

/// Resolve every component of `prefix` EXCEPT the final one, in a single
/// `openat2(2)` call relative to `base_fd` (Linux 5.6+). Ordinary symlinks in
/// intermediate components are followed. Absolute paths use RESOLVE_IN_ROOT,
/// which clamps `..` and absolute symlink restarts at the TARGET'S pinned root.
/// Relative paths use RESOLVE_BENEATH, which refuses any walk that escapes the
/// pinned cwd/dirfd; the caller then lets the target kernel execute the syscall
/// in its own namespace. Magic links are rejected in both modes. Returns an
/// owned O_DIRECTORY fd for the parent.
pub fn resolve_parent(base_fd: RawFd, prefix: &OsStr, absolute: bool) -> io::Result<RawFd> {
    resolve_parent_with(
        base_fd,
        prefix,
        if absolute {
            libc::RESOLVE_IN_ROOT
        } else {
            libc::RESOLVE_BENEATH
        },
    )
}

/// Candidate absolute path of a pinned directory as this process sees it.
/// The kernel's " (deleted)" suffix is ambiguous with a literal filename;
/// physical_path verifies that case instead of treating it as authoritative.
fn pinned_directory_path(directory: RawFd) -> Option<std::path::PathBuf> {
    let path = std::fs::read_link(format!("/proc/self/fd/{directory}")).ok()?;
    path.is_absolute().then_some(path)
}

fn stat_at(directory: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn same_inode(first: &libc::stat, second: &libc::stat) -> bool {
    first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_mode == second.st_mode
        && first.st_uid == second.st_uid
        && first.st_gid == second.st_gid
}

fn same_entry(first: &libc::stat, second: &libc::stat) -> bool {
    same_inode(first, second)
        && first.st_size == second.st_size
        && first.st_mtime == second.st_mtime
        && first.st_mtime_nsec == second.st_mtime_nsec
        && first.st_ctime == second.st_ctime
        && first.st_ctime_nsec == second.st_ctime_nsec
}

fn same_directory(first: RawFd, second: RawFd) -> bool {
    let mut a: libc::stat = unsafe { std::mem::zeroed() };
    let mut b: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(first, &mut a) == 0 && libc::fstat(second, &mut b) == 0 })
        && a.st_mode & libc::S_IFMT == libc::S_IFDIR
        && same_inode(&a, &b)
}

/// A foreign mount namespace can hide a policy file without changing its
/// parent inode. Verify every policy lookup and ancestor, not just the first
/// directory. Namespace clones may have different mount IDs for the same
/// underlying directories; device/inode identity is what makes the recorded
/// physical path restore into the directory we actually removed from.
fn same_policy_ancestors(source: RawFd, mapped: RawFd, path: &std::path::Path) -> bool {
    let duplicate = |fd| {
        let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        (fd >= 0).then(|| FdGuard(fd))
    };
    let (Some(mut source), Some(mut mapped)) = (duplicate(source), duplicate(mapped)) else {
        return false;
    };
    let mut ancestors = path.ancestors().peekable();
    while ancestors.next().is_some() {
        if !same_directory(source.0, mapped.0) {
            return false;
        }
        match (
            stat_at(source.0, c".trashd.toml"),
            stat_at(mapped.0, c".trashd.toml"),
        ) {
            (Ok(a), Ok(b)) if same_entry(&a, &b) => {}
            (Err(a), Err(b))
                if a.raw_os_error() == Some(libc::ENOENT)
                    && b.raw_os_error() == Some(libc::ENOENT) => {}
            _ => return false,
        }
        if ancestors.peek().is_some() {
            let (Some(a), Some(b)) = (
                open_task_directory(source.0, c"..").map(FdGuard),
                open_task_directory(mapped.0, c"..").map(FdGuard),
            ) else {
                return false;
            };
            source = a;
            mapped = b;
        }
    }
    true
}

/// Path policy and Path= use the supervisor's physical view. A chroot's
/// absolute spelling cannot be used there (#387). A /proc fd link from a
/// foreign namespace is only a candidate: reopen it and prove both parent
/// and leaf still identify the pinned objects. Also prove policy visibility
/// when mount namespaces differ. Unreachable/overmounted paths are declined,
/// never retried through an unverified display spelling.
fn physical_path(fs: &TargetFs, parent: RawFd, name: &OsStr) -> Option<std::path::PathBuf> {
    let candidate = pinned_directory_path(parent)?;
    if fs.shares_our_view() && !candidate.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Some(candidate.join(name));
    }
    let candidate = CString::new(candidate.as_os_str().as_bytes()).ok()?;
    let mapped = unsafe {
        libc::open(
            candidate.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if mapped < 0 {
        return None;
    }
    let mapped = FdGuard(mapped);
    let name_c = CString::new(name.as_bytes()).ok()?;
    if !same_directory(parent, mapped.0)
        || !same_entry(
            &stat_at(parent, &name_c).ok()?,
            &stat_at(mapped.0, &name_c).ok()?,
        )
    {
        return None;
    }
    let path = pinned_directory_path(mapped.0)?;
    let ours = namespace_identity(libc::AT_FDCWD, c"/proc/self/ns/mnt")?;
    if namespace_identity(fs.procfd, c"ns/mnt")? != ours
        && !same_policy_ancestors(parent, mapped.0, &path)
    {
        return None;
    }
    Some(path.join(name))
}

/// `resolve_parent` with an explicit containment mode: RESOLVE_IN_ROOT,
/// RESOLVE_BENEATH, or 0 for a target that shares this process's view.
fn resolve_parent_with(base_fd: RawFd, prefix: &OsStr, containment: u64) -> io::Result<RawFd> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const _: () = assert!(std::mem::size_of::<OpenHow>() == 24); // OPEN_HOW_SIZE_VER0

    let c = CString::new(prefix.as_bytes())?;
    // RESOLVE_NO_XDEV is deliberately NOT set: crossing mounts is legal.
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        // IN_ROOT matches how the target's own root clamps absolute walks.
        // BENEATH prevents a relative walk from escaping the pinned cwd/dirfd
        // into the supervisor's namespace. Mount crossings remain legal.
        resolve: libc::RESOLVE_NO_MAGICLINKS | containment,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            base_fd as i64,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

/// True when the directory `name` inside `parent_fd` contains no entries
/// besides `.` and `..`. Errors are surfaced: the caller must be able to
/// POSITIVELY confirm emptiness before trashing an rmdir target.
pub fn dir_is_empty(parent_fd: RawFd, name: &OsStr) -> io::Result<bool> {
    let c = CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent_fd,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dh = unsafe { libc::fdopendir(fd) };
    if dh.is_null() {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    let mut empty = true;
    unsafe {
        // readdir(3) returns NULL both at end-of-dir AND on error; only errno
        // distinguishes them. Treating an error as "empty" would let rmdir
        // trash a directory we never verified (#6 review).
        *libc::__errno_location() = 0;
        loop {
            let e = libc::readdir(dh);
            if e.is_null() {
                if io::Error::last_os_error().raw_os_error() != Some(0)
                    && io::Error::last_os_error().raw_os_error().is_some()
                {
                    libc::closedir(dh);
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            let n = CStr::from_ptr((*e).d_name.as_ptr()).to_bytes();
            if n != b"." && n != b".." {
                empty = false;
                break;
            }
        }
        libc::closedir(dh);
    }
    Ok(empty)
}

/// fstatat(AT_SYMLINK_NOFOLLOW) convenience: (st_mode, st_dev, st_size).
pub fn stat_nofollow(parent_fd: RawFd, name: &OsStr) -> io::Result<(u32, u64, i64)> {
    let c = CString::new(name.as_bytes())?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent_fd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.st_mode, st.st_dev as u64, st.st_size))
}

/// Outcome of the pinned interception attempt.
#[derive(Debug)]
pub enum Decision {
    /// We moved the file into the trash; the supervisor answers success.
    Trashed,
    /// Let the kernel execute the real syscall (bypass lists, refusals, and
    /// cases where the kernel produces the exact errno better than we can).
    Continue,
    /// The entry could not be trashed here (unresolvable in our view, a
    /// cross-device target, a store failure): a deferring preload trashes
    /// it in-process; anything else the kernel runs (#355).
    Decline,
    /// Fail the syscall with this errno WITHOUT executing it.
    Errno(i32),
}

/// Race-free handling of one trapped delete (#6): pin the target's filesystem
/// context, walk the prefix with one openat2 against that base, apply rmdir/
/// unlink semantics via fstatat/readdir on pinned fds, then move the entry
/// with renameat through [`trashd_common::TrashStore::trash_at`].
///
/// Resolution and storage errors surface as `Continue`: the target's kernel
/// executes the original syscall in the correct mount namespace. The
/// supervisor never performs a path-based fallback mutation.
#[allow(clippy::too_many_arguments)]
pub fn try_pinned(
    pid: u32,
    syscall_nr: i32,
    args: &[u64; 6],
    raw: &OsStr,
    _display: &std::path::Path,
    remove_dir: bool,
    notify_fd: i32,
    notify_id: u64,
    store: &TrashStore,
) -> io::Result<Decision> {
    #[cfg(target_arch = "x86_64")]
    const NR_UNLINKAT: i32 = 263;
    #[cfg(target_arch = "aarch64")]
    const NR_UNLINKAT: i32 = 35;

    if syscall_nr == NR_UNLINKAT && (args[2] as i32 & !libc::AT_REMOVEDIR) != 0 {
        return Ok(Decision::Continue);
    }
    // Only unlinkat carries a dirfd argument; unlink/rmdir are CWD-relative.
    let dirfd: Option<i32> = if syscall_nr == NR_UNLINKAT {
        Some(args[0] as i32)
    } else {
        None
    };

    // A trailing slash requires the final component to be a DIRECTORY:
    // unlink("regularfile/") must fail ENOTDIR like the real syscall, not
    // trash the file (review finding).
    let had_trailing_slash = raw.as_bytes().last() == Some(&b'/');

    // Split off the FINAL component; strip trailing slashes. An all-slash
    // path names the root itself — nothing meaningful to delete.
    let bytes = raw.as_bytes();
    let mut end = bytes.len();
    while end > 1 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    let stripped = &bytes[..end];
    if stripped.is_empty() || stripped == b"/" {
        return Ok(Decision::Continue);
    }
    let (mut prefix, final_comp): (&[u8], &[u8]) = match stripped.iter().rposition(|&b| b == b'/') {
        Some(i) => (&stripped[..=i], &stripped[i + 1..]),
        None => (b"", stripped),
    };
    let name = OsStr::from_bytes(final_comp);
    if name.is_empty() || name == "." || name == ".." {
        // The kernel produces the right errno for these pathological forms.
        return Ok(Decision::Continue);
    }

    let tfs = TargetFs::open_for_operation(pid, bytes.first() == Some(&b'/'), dirfd)?;

    // Task-reuse guard: a still-valid id proves these newly pinned task
    // descriptors belong to the blocked target. Unit tests have no listener.
    if notify_fd >= 0 && !crate::supervisor::notif_id_valid(notify_fd, notify_id) {
        return Ok(Decision::Continue);
    }

    // Pin the BASE and hold every duplicated fd in guards so no exit path
    // leaks (the first cut of this fix leaked 1-2 fds per delete).
    //
    // CRITICAL for absolute paths (#6 review): openat2 IGNORES dirfd when the
    // pathname is absolute — the pinned target-root fd would be silently
    // bypassed and "/a/b" resolved against the SUPERVISOR'S root. The prefix
    // below is therefore rewritten RELATIVE to that root.
    let mut dup_base: Option<FdGuard> = None;
    let base: RawFd = if bytes.first() == Some(&b'/') {
        while prefix.first() == Some(&b'/') {
            prefix = &prefix[1..]; // "///a/" -> "a/"
        }
        tfs.root()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no root fd"))?
    } else {
        match dirfd {
            None | Some(libc::AT_FDCWD) => tfs
                .cwd()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "no cwd fd"))?,
            Some(fd) => {
                let g = FdGuard(tfs.dup_dirfd(fd)?);
                let raw_fd = g.0;
                dup_base = Some(g);
                raw_fd
            }
        }
    };

    // The ancestor broker obtains its own pidfd when duplicating an explicit
    // dirfd. Revalidate after that round trip so PID reuse cannot select a
    // descriptor belonging to a different process (#6). Without one, the
    // check after pinning already covers every descriptor in use (#320).
    if dup_base.is_some()
        && notify_fd >= 0
        && !crate::supervisor::notif_id_valid(notify_fd, notify_id)
    {
        return Ok(Decision::Continue);
    }

    // Base sanity: whatever we were given must actually be a directory.
    let mut bst: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(base, &mut bst) } != 0 || bst.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Ok(Decision::Errno(libc::ENOTDIR));
    }

    // Resolve every non-final component in ONE kernel-side walk from the
    // pinned base. Borrowed when the base IS the parent; owned otherwise.
    let _owned_parent: Option<FdGuard>;
    let parent: RawFd = if prefix.is_empty() || prefix == b"/" {
        base
    } else {
        let containment = if bytes.first() == Some(&b'/') {
            libc::RESOLVE_IN_ROOT
        } else if tfs.shares_our_view() {
            0
        } else {
            libc::RESOLVE_BENEATH
        };
        match resolve_parent_with(base, OsStr::from_bytes(prefix), containment) {
            Ok(fd) => {
                let g = FdGuard(fd);
                let raw_fd = g.0;
                _owned_parent = Some(g);
                raw_fd
            }
            // Component vanished, resolution escaped the pinned base, or the
            // kernel lacks openat2: leave the original syscall to the target's
            // namespace rather than re-resolving this path here.
            Err(_) => return Ok(Decision::Decline),
        }
    };

    // Type checks against the PINNED parent (symlinks NOT followed for the
    // final component — matches unlink/rmdir semantics).
    let (mode, _dev, _size) = match stat_nofollow(parent, name) {
        Ok(v) => v,
        Err(_) => return Ok(Decision::Continue),
    };
    let fmt = mode & libc::S_IFMT;
    if remove_dir {
        if fmt != libc::S_IFDIR {
            return Ok(Decision::Errno(libc::ENOTDIR));
        }
        // rmdir requires POSITIVELY-confirmed emptiness. A sibling repopulating
        // the dir between this check and the move lands the whole tree in the
        // trash (recoverable), which is still safer than permanent deletion.
        match dir_is_empty(parent, name) {
            Ok(true) => {}
            Ok(false) => return Ok(Decision::Errno(libc::ENOTEMPTY)),
            Err(_) => return Ok(Decision::Decline),
        }
    } else if fmt == libc::S_IFDIR {
        return Ok(Decision::Errno(libc::EISDIR));
    } else if had_trailing_slash {
        // Kernel semantics restored: trailing slash demands a directory.
        return Ok(Decision::Errno(libc::ENOTDIR));
    }

    // Policy and the recorded Path= follow where the pinned parent really is,
    // not how the target spelled it (`/proc/self/cwd/x`, `/dev/fd/N/x`, `..`):
    // re-resolving a spelling here reads the SUPERVISOR's view (#226). Our
    // /proc path needs an identity proof when the target has another view.
    let Some(physical) = physical_path(&tfs, parent, name) else {
        return Ok(Decision::Decline);
    };

    // The move itself: renameat(pinned_parent, name -> trash/files/<id>)
    // inside TrashStore::trash_at, which applies config eligibility to that
    // path for parity with the other layers. A physical path is canonical
    // already and needs no second resolution (#320).
    let still_valid = || notify_fd < 0 || crate::supervisor::notif_id_valid(notify_fd, notify_id);
    let trashed = store.trash_at_canonical(parent, name, &physical, Some("seccomp"), still_valid);
    match trashed {
        Ok(_id) => Ok(Decision::Trashed),
        // Policy: the preload would decide the same, so declining only
        // cost a second round trip (#357).
        Err(TrashError::Excluded(_) | TrashError::Refused(_) | TrashError::TooLarge { .. }) => {
            Ok(Decision::Continue)
        }
        // EXDEV (namespaced/cross-device target), hash/store hiccups, and
        // unsafe stores all defer to the target's own layer. Re-resolving
        // `display` in the supervisor could mutate an unrelated host path.
        Err(_) => Ok(Decision::Decline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    struct ForeignTarget(std::process::Child);

    impl Drop for ForeignTarget {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Change only a helper process's root/mount namespace. No fork inside
    /// the harness, no host mount or permission changes, and Drop reaps it.
    fn foreign_target(directory: &Path, mode: &str) -> Option<ForeignTarget> {
        use std::io::BufRead;
        use std::process::{Command, Stdio};
        let script = r#"
import ctypes, errno, os, sys, time
libc = ctypes.CDLL(None, use_errno=True)
directory, mode = sys.argv[1:]
def checked(result):
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.EPERM, errno.EACCES, errno.ENOSYS):
            print('SKIP: filesystem namespace privileges unavailable', flush=True)
            sys.exit(77)
        raise OSError(error, os.strerror(error))
if mode == 'chroot':
    checked(libc.chroot(os.fsencode(directory)))
    os.chdir('/')
else:
    checked(libc.unshare(0x00020000))
    checked(libc.mount(None, b'/', None, 0x4000 | 0x40000, None))
    if mode == 'parent':
        checked(libc.mount(b'tmpfs', os.fsencode(directory), b'tmpfs', 0, None))
        with open(os.path.join(directory, 'victim.txt'), 'wb') as file:
            file.write(b'target namespace')
    elif mode in ('leaf', 'policy', 'ancestor-policy'):
        source, target = ('replacement', 'victim.txt') if mode == 'leaf' else ('replacement.toml', '.trashd.toml')
        target_directory = os.path.dirname(directory) if mode == 'ancestor-policy' else directory
        checked(libc.mount(os.fsencode(os.path.join(directory, source)), os.fsencode(os.path.join(target_directory, target)), None, 4096, None))
    os.chdir(directory)
print('ready', flush=True)
time.sleep(60)
"#;
        let child = Command::new("/usr/bin/python3")
            .args(["-u", "-c", script])
            .arg(directory)
            .arg(mode)
            .env("TRASH_BYPASS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn isolated filesystem helper");
        let mut child = ForeignTarget(child);
        let mut line = String::new();
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        if line.starts_with("SKIP:") {
            eprintln!("{}", line.trim());
            return None;
        }
        assert_eq!(line.trim(), "ready", "filesystem helper failed to start");
        Some(child)
    }

    #[test]
    fn physical_mapping_distinguishes_literal_deleted_suffix() {
        let fixture = tempfile::tempdir().unwrap();
        let literal = fixture.path().join("literal (deleted)");
        std::fs::create_dir(&literal).unwrap();
        std::fs::write(literal.join("victim.txt"), b"still reachable").unwrap();
        let filesystem = TargetFs::open(std::process::id()).unwrap();
        let parent = FdGuard(open_proc_dir(literal.to_str().unwrap()).unwrap());
        assert_eq!(
            physical_path(&filesystem, parent.0, OsStr::new("victim.txt")),
            Some(literal.join("victim.txt"))
        );

        let removed = fixture.path().join("removed");
        std::fs::create_dir(&removed).unwrap();
        let parent = FdGuard(open_proc_dir(removed.to_str().unwrap()).unwrap());
        std::fs::remove_dir(&removed).unwrap();
        // Even when the deleted marker happens to name a real directory,
        // its inode cannot stand in for the removed pinned parent.
        let shadow = fixture.path().join("removed (deleted)");
        std::fs::create_dir(&shadow).unwrap();
        std::fs::write(shadow.join("victim.txt"), b"unrelated").unwrap();
        assert_eq!(
            physical_path(&filesystem, parent.0, OsStr::new("victim.txt")),
            None
        );
    }

    #[test]
    fn chrooted_absolute_paths_use_physical_policy_and_restore_location() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: changing the helper's root requires root");
            return;
        }
        let (unused_store, jail, fixture) = setup("chroot-physical");
        drop(unused_store);
        let Some(target) = foreign_target(&jail, "chroot") else {
            return;
        };
        assert!(!TargetFs::open(target.0.id()).unwrap().shares_our_view());
        let victim = jail.join("victim.txt");
        std::fs::write(&victim, b"restore inside the jail").unwrap();
        let config = trashd_common::Config {
            never_trash: Vec::new(),
            only_trash: vec![victim.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let store = TrashStore::open_isolated(&fixture.path().join("allowed"), config).unwrap();
        let attempt = |store: &TrashStore, raw: &OsStr| {
            try_pinned(
                target.0.id(),
                libc::SYS_unlinkat as i32,
                &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
                raw,
                Path::new("/victim.txt"),
                false,
                -1,
                0,
                store,
            )
            .unwrap()
        };
        assert!(matches!(
            attempt(&store, OsStr::new("/victim.txt")),
            Decision::Trashed
        ));
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].info.original_path, victim);
        assert_eq!(store.restore(&entries[0].id, None).unwrap(), victim);
        assert_eq!(std::fs::read(&victim).unwrap(), b"restore inside the jail");

        let config = trashd_common::Config {
            never_trash: vec![victim.to_string_lossy().into_owned()],
            only_trash: Vec::new(),
            ..Default::default()
        };
        let store = TrashStore::open_isolated(&fixture.path().join("excluded"), config).unwrap();
        assert!(matches!(
            attempt(&store, OsStr::new("/victim.txt")),
            Decision::Continue
        ));
        assert!(victim.exists());
        assert!(store.list(None).unwrap().is_empty());

        // Path= also preserves raw names through the verified mapping.
        let raw = OsStr::from_bytes(b"raw-\xff");
        let victim = jail.join(raw);
        std::fs::write(&victim, b"raw name").unwrap();
        let config = trashd_common::Config {
            never_trash: Vec::new(),
            ..Default::default()
        };
        let store = TrashStore::open_isolated(&fixture.path().join("raw"), config).unwrap();
        assert!(matches!(
            attempt(&store, OsStr::from_bytes(b"/raw-\xff")),
            Decision::Trashed
        ));
        let entries = store.list(None).unwrap();
        assert_eq!(entries[0].info.original_path, victim);
    }

    #[test]
    fn foreign_namespace_mapping_proves_leaf_and_policy_visibility() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: changing the helper's mount namespace requires root");
            return;
        }
        for mode in ["clone", "parent", "leaf", "policy", "ancestor-policy"] {
            let (store, work, _fixture) = setup("namespace-physical");
            let victim = work.join("victim.txt");
            std::fs::write(&victim, b"host namespace").unwrap();
            std::fs::write(work.join("replacement"), b"target namespace").unwrap();
            std::fs::write(work.join(".trashd.toml"), b"never_trash = []\n").unwrap();
            std::fs::write(
                work.parent().unwrap().join(".trashd.toml"),
                b"never_trash = []\n",
            )
            .unwrap();
            std::fs::write(work.join("replacement.toml"), b"only_trash = ['*.keep']\n").unwrap();
            let Some(target) = foreign_target(&work, mode) else {
                return;
            };
            let filesystem = TargetFs::open(target.0.id()).unwrap();
            assert!(!filesystem.shares_our_view());
            let mapped = physical_path(
                &filesystem,
                filesystem.cwd().unwrap(),
                OsStr::new("victim.txt"),
            );
            assert_eq!(mapped, (mode == "clone").then(|| victim.clone()), "{mode}");
            let decision = try_pinned(
                target.0.id(),
                libc::SYS_unlinkat as i32,
                &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
                OsStr::new("victim.txt"),
                &victim,
                false,
                -1,
                0,
                &store,
            )
            .unwrap();
            if mode == "clone" {
                assert!(
                    matches!(decision, Decision::Trashed),
                    "{mode}: {decision:?}"
                );
                let entries = store.list(None).unwrap();
                assert_eq!(entries[0].info.original_path, victim);
                assert_eq!(store.restore(&entries[0].id, None).unwrap(), victim);
            } else {
                assert!(
                    matches!(decision, Decision::Decline),
                    "{mode}: {decision:?}"
                );
                assert_eq!(std::fs::read(&victim).unwrap(), b"host namespace");
                assert!(store.list(None).unwrap().is_empty());
                let target_view = format!("/proc/{}/cwd/victim.txt", target.0.id());
                assert_eq!(
                    std::fs::read(target_view).unwrap(),
                    if mode.ends_with("policy") {
                        b"host namespace".as_slice()
                    } else {
                        b"target namespace".as_slice()
                    }
                );
            }
        }
    }

    #[test]
    fn operation_context_pins_only_required_bases() {
        use std::os::unix::fs::MetadataExt;
        let pid = std::process::id();
        let cases = [
            (true, None, false),
            (true, Some(37), false),
            (false, None, true),
            (false, Some(libc::AT_FDCWD), true),
            (false, Some(37), false),
        ];
        for (absolute, dirfd, cwd) in cases {
            let context = TargetFs::open_for_operation(pid, absolute, dirfd).unwrap();
            assert!(context.root().is_some());
            assert_eq!(context.cwd().is_some(), cwd);
            for (fd, path) in [
                (context.root(), Path::new("/")),
                (context.cwd(), Path::new(".")),
            ] {
                if let Some(fd) = fd {
                    let mut actual: libc::stat = unsafe { std::mem::zeroed() };
                    assert_eq!(unsafe { libc::fstat(fd, &mut actual) }, 0);
                    let expected = std::fs::metadata(path).unwrap();
                    assert_eq!(
                        (actual.st_dev, actual.st_ino),
                        (expected.dev(), expected.ino())
                    );
                }
            }
        }
        // Readiness continues to pin both mandatory directory backends.
        let startup = TargetFs::open(pid).unwrap();
        assert!(startup.root().is_some());
        assert!(startup.cwd().is_some());
    }

    /// No ambient configuration, environment mutation or mount discovery.
    fn setup(dir_name: &str) -> (TrashStore, PathBuf, tempfile::TempDir) {
        let fixture = tempfile::Builder::new().prefix(dir_name).tempdir().unwrap();
        let data = fixture.path();
        std::fs::create_dir_all(data.join("work")).unwrap();
        let config = trashd_common::Config {
            never_trash: Vec::new(),
            only_trash: Vec::new(),
            ..Default::default()
        };
        let store = TrashStore::open_isolated(&data.join("trash"), config).unwrap();
        (store, data.join("work"), fixture)
    }

    /// Spawn a child whose CWD is `dir`, wait until /proc/<pid>/cwd agrees.
    /// The Child is returned; every caller kills + waits it.
    #[allow(clippy::zombie_processes)] // ownership transfers to the caller
    fn spawn_with_cwd(dir: &Path) -> std::process::Child {
        use std::process::{Command, Stdio};
        let script = format!("cd '{}' && exec sleep 30", dir.display());
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let link = std::fs::read_link(format!("/proc/{}/cwd", child.id())).ok();
            if link.as_deref().map(|p| p.as_os_str()) == Some(dir.as_os_str()) {
                return child;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("helper never entered dir");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    const NR_UNLINKAT_X86_64: i32 = 263;
    const NR_UNLINKAT_AARCH64: i32 = 35;

    #[test]
    fn unsupported_flags_defer_before_filesystem_access() {
        let (store, _path, _fixture) = setup("invalid-unlinkat");
        let nr = libc::SYS_unlinkat as i32;
        let args = [libc::AT_FDCWD as u64, 0, 1024, 0, 0, 0];
        assert!(matches!(
            try_pinned(
                0,
                nr,
                &args,
                OsStr::new("victim"),
                std::path::Path::new("victim"),
                false,
                -1,
                0,
                &store
            )
            .unwrap(),
            Decision::Continue
        ));
        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn filesystem_pinning_accepts_worker_tid() {
        std::thread::spawn(|| {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
            let fs = TargetFs::open(tid).unwrap();
            assert!(fs.root().is_some());
            assert!(fs.cwd().is_some());
            let directory = std::fs::File::open(".").unwrap();
            use std::os::fd::AsRawFd;
            let pinned = FdGuard(fs.dup_dirfd(directory.as_raw_fd()).unwrap());
            let broker_pinned =
                crate::broker::duplicate_locally(tid, directory.as_raw_fd()).unwrap();
            let broker_file = std::fs::File::from(broker_pinned);
            use std::os::unix::fs::MetadataExt;
            assert!(broker_file.metadata().unwrap().is_dir());
            assert_eq!(
                broker_file.metadata().unwrap().ino(),
                directory.metadata().unwrap().ino()
            );
            let stat = unsafe { libc::fcntl(pinned.0, libc::F_GETFL) };
            assert!(stat >= 0);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn root_resolution_clamps_dotdot_and_follows_symlinks() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("root");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir(root.join("outside")).unwrap();
        std::fs::create_dir(fixture.path().join("outside")).unwrap();
        symlink("outside", root.join("relative")).unwrap();
        symlink("/outside", root.join("absolute")).unwrap();
        let base = FdGuard(open_proc_dir(root.to_str().unwrap()).unwrap());
        let expected = std::fs::metadata(root.join("outside")).unwrap().ino();
        for path in ["a/../../outside", "relative", "absolute"] {
            let result = FdGuard(resolve_parent(base.0, OsStr::new(path), true).unwrap());
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(result.0, &mut stat) }, 0);
            assert_eq!(stat.st_ino, expected, "{path}");
        }
    }

    #[test]
    fn relative_resolution_refuses_to_escape_pinned_base() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let fixture = tempfile::tempdir().unwrap();
        let base_dir = fixture.path().join("base");
        let inside = base_dir.join("inside");
        let outside = fixture.path().join("outside");
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink("inside", base_dir.join("inside-link")).unwrap();
        symlink("../outside", base_dir.join("relative-escape")).unwrap();
        symlink(&outside, base_dir.join("absolute-escape")).unwrap();

        let base = FdGuard(open_proc_dir(base_dir.to_str().unwrap()).unwrap());

        // An ordinary symlink that remains beneath the pinned base is valid.
        let resolved = FdGuard(resolve_parent(base.0, OsStr::new("inside-link"), false).unwrap());
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(resolved.0, &mut stat) }, 0);
        assert_eq!(stat.st_ino, std::fs::metadata(&inside).unwrap().ino());

        // Both lexical and symlink escapes must be handed back to the target
        // kernel; resolving either in the supervisor can select a host inode.
        for escape in ["../outside", "relative-escape", "absolute-escape"] {
            let err = resolve_parent(base.0, OsStr::new(escape), false).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EXDEV), "{escape}: {err}");
        }
    }

    /// Relative paths that leave the cwd through `..` or a symlink.
    fn escape_fixture(name: &str) -> (TrashStore, PathBuf, PathBuf, PathBuf, tempfile::TempDir) {
        use std::os::unix::fs::symlink;
        let (store, work, guard) = setup(name);
        let outside = work.parent().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let dotdot_victim = outside.join("dotdot.txt");
        let symlink_victim = outside.join("symlink.txt");
        std::fs::write(&dotdot_victim, b"dotdot").unwrap();
        std::fs::write(&symlink_victim, b"symlink").unwrap();
        symlink(&outside, work.join("escape")).unwrap();
        (store, work, dotdot_victim, symlink_victim, guard)
    }

    fn unlinkat_nr() -> i32 {
        if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        }
    }

    // Regression (#195): a target that shares the supervisor's root mount
    // and mount namespace resolves `..` and symlinks exactly as the
    // supervisor does. Handing those deletes back made them permanent, since
    // the preload had already deferred to seccomp.
    #[test]
    fn pinned_relative_escape_is_trashed_for_a_target_sharing_our_view() {
        let (store, work, dotdot_victim, symlink_victim, _g) = escape_fixture("relative-escape");
        let mut child = spawn_with_cwd(&work);
        let args: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];
        for (raw, display) in [
            ("../outside/dotdot.txt", &dotdot_victim),
            ("escape/symlink.txt", &symlink_victim),
        ] {
            let decision = try_pinned(
                child.id(),
                unlinkat_nr(),
                &args,
                OsStr::new(raw),
                display,
                false,
                -1,
                0,
                &store,
            )
            .expect("pinned attempt");
            assert!(matches!(decision, Decision::Trashed), "{raw}: {decision:?}");
            assert!(!display.exists(), "{raw}: not moved");
        }
        assert_eq!(store.list(None).unwrap().len(), 2);
        child.kill().unwrap();
        let _ = child.wait();
    }

    // #62 still holds: in another mount namespace (or under another root)
    // the same text can name a different inode, so escapes are handed back
    // to the target's kernel and the host path is never touched.
    #[test]
    fn pinned_relative_escape_defers_for_a_foreign_mount_namespace() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP: a private mount namespace requires root");
            return;
        }
        let (store, work, dotdot_victim, symlink_victim, _g) = escape_fixture("foreign-escape");
        let mut child = std::process::Command::new("/usr/bin/unshare")
            .args(["-m", "--propagation", "private", "/bin/sh", "-c"])
            .arg(format!("cd '{}' && exec sleep 30", work.display()))
            .spawn()
            .expect("spawn namespaced helper");
        // unshare execs sh, which execs sleep in the same pid (comm, not exe:
        // multi-call coreutils run every tool from one binary).
        let target = (0..250)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(20));
                let comm = std::fs::read_to_string(format!("/proc/{}/comm", child.id())).ok()?;
                let cwd = std::fs::read_link(format!("/proc/{}/cwd", child.id())).ok()?;
                (comm.trim() == "sleep" && cwd == work).then_some(child.id())
            })
            .expect("namespaced helper never started");
        let args: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];
        for (raw, display) in [
            ("../outside/dotdot.txt", &dotdot_victim),
            ("escape/symlink.txt", &symlink_victim),
        ] {
            let decision = try_pinned(
                target,
                unlinkat_nr(),
                &args,
                OsStr::new(raw),
                display,
                false,
                -1,
                0,
                &store,
            )
            .expect("pinned attempt");
            // Left to the target's own layer (#355).
            assert!(matches!(decision, Decision::Decline), "{raw}: {decision:?}");
            assert!(display.exists(), "supervisor must not mutate {display:?}");
        }
        assert!(store.list(None).unwrap().is_empty());
        child.kill().unwrap();
        let _ = child.wait();
    }

    // Regression (#195): when the trash lives on another filesystem (or the
    // filesystem lacks RENAME_NOREPLACE), the supervisor copies from the
    // pinned parent instead of continuing into a permanent delete.
    #[test]
    fn pinned_cross_device_delete_is_trashed_not_continued() {
        use std::os::unix::fs::MetadataExt;
        let (store, _work, _g) = setup("cross-device");
        let shm = PathBuf::from(format!("/dev/shm/trashd-pin-xdev-{}", std::process::id()));
        std::fs::create_dir_all(&shm).unwrap();
        if std::fs::metadata(&shm).unwrap().dev()
            == std::fs::metadata(store.home_dir()).unwrap().dev()
        {
            eprintln!("SKIP: /dev/shm shares the store's filesystem");
            return;
        }
        let victim = shm.join("victim.txt");
        std::fs::write(&victim, b"cross-device").unwrap();
        let mut child = spawn_with_cwd(&shm);
        let decision = try_pinned(
            child.id(),
            unlinkat_nr(),
            &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
            OsStr::new("victim.txt"),
            &victim,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");
        child.kill().unwrap();
        let _ = child.wait();
        let survived = victim.exists();
        let _ = std::fs::remove_dir_all(&shm);
        assert!(matches!(decision, Decision::Trashed), "{decision:?}");
        assert!(!survived);
        let entries = store.list(None).unwrap();
        assert_eq!(
            std::fs::read(&entries[0].trashed_path).unwrap(),
            b"cross-device"
        );
    }

    #[test]
    fn pinned_store_failure_defers_without_mutating_display_path() {
        let (store, work, _g) = setup("store-failure");
        let victim = work.join("victim.txt");
        std::fs::write(&victim, b"keep me").unwrap();

        // Make the isolated store unusable after it has opened. The pinned
        // attempt must return Continue while leaving the source inode alone;
        // the supervisor must never retry through the display pathname.
        let files = store.home_dir().join("files");
        std::fs::remove_dir(&files).unwrap();
        std::fs::write(&files, b"not a directory").unwrap();

        let mut child = spawn_with_cwd(&work);
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };
        let decision = try_pinned(
            child.id(),
            nr,
            &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
            OsStr::new("victim.txt"),
            &victim,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");

        // A store failure leaves it to the target's own layer (#355).
        assert!(matches!(decision, Decision::Decline));
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn pinned_flow_trashes_via_cwd_fd() {
        let (store, work, _g) = setup("cwd");
        let victim = work.join("victim.txt");
        std::fs::write(&victim, b"race-free").unwrap();

        let mut child = spawn_with_cwd(&work);
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };
        let args: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];

        let decision = try_pinned(
            child.id(),
            nr,
            &args,
            OsStr::new("victim.txt"),
            &victim,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");

        match decision {
            Decision::Trashed => {}
            other => panic!("expected Trashed, got {other:?}"),
        }
        assert!(!victim.exists(), "moved out of the child's cwd");
        let entries = store.list(None).unwrap();
        assert!(
            entries.iter().any(|e| e.info.original_path == victim),
            "entry recorded with display path"
        );
        child.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn pinned_policy_and_record_follow_the_pinned_parent() {
        // The display string is only a spelling: `/proc/self/cwd/x` matches a
        // `/proc/*` exclusion although the file lives in an ordinary
        // directory. Policy and Path= come from the pinned parent (#226).
        let fixture = tempfile::Builder::new()
            .prefix("spelling")
            .tempdir()
            .unwrap();
        let work = fixture.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let config = trashd_common::Config {
            never_trash: vec!["/proc/*".into()],
            only_trash: Vec::new(),
            ..Default::default()
        };
        let store = TrashStore::open_isolated(&fixture.path().join("trash"), config).unwrap();
        let victim = work.join("victim.txt");
        std::fs::write(&victim, b"spelled elsewhere").unwrap();

        let mut child = spawn_with_cwd(&work);
        let nr = libc::SYS_unlinkat as i32;
        let args: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];
        let decision = try_pinned(
            child.id(),
            nr,
            &args,
            OsStr::new("victim.txt"),
            Path::new("/proc/self/cwd/victim.txt"),
            false,
            -1,
            0,
            &store,
        );
        child.kill().unwrap();
        let _ = child.wait();

        assert!(matches!(decision.unwrap(), Decision::Trashed));
        let entries = store.list(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].info.original_path, victim);
    }

    #[test]
    fn pinned_flow_trashes_via_duplicated_dirfd_and_prefix_walk() {
        let (store, work, _g) = setup("dirfd");
        let sub = work.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let victim = sub.join("deep.txt");
        std::fs::write(&victim, b"nested").unwrap();
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };

        // (a) explicit dirfd: child holds an O_RDONLY fd on `sub` as fd 3.
        use std::process::{Command, Stdio};
        let script = format!("exec 3<'{}' && exec sleep 30", sub.display());
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn fd-holding child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let ok = std::fs::read_link(format!("/proc/{}/fd/3", child.id()))
                .map(|l| l == sub)
                .unwrap_or(false);
            if ok || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let tfs = TargetFs::open(child.id()).expect("pin target");
        let dirfd = tfs.dup_dirfd(3).expect("pidfd_getfd target fd 3");
        let args_dirfd: [u64; 6] = [3, 0, 0, 0, 0, 0]; // unlinkat(3, "deep.txt", 0)
        let d = try_pinned(
            child.id(),
            nr,
            &args_dirfd,
            OsStr::new("deep.txt"),
            &victim,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");
        assert!(matches!(d, Decision::Trashed), "got {d:?}");
        assert!(!victim.exists(), "moved via duplicated dirfd");
        child.kill().unwrap();
        let _ = child.wait();
        unsafe { libc::close(dirfd) }; // RawFd is Copy — close explicitly
        drop(tfs);

        // (b) multi-component prefix: AT_FDCWD at `work`, victim at l1/l2/f.txt
        let nested_dir = work.join("l1").join("l2");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(nested_dir.join("f.txt"), b"x").unwrap();
        let mut c2 = spawn_with_cwd(&work);
        let args_cwd: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];
        let d = try_pinned(
            c2.id(),
            nr,
            &args_cwd,
            OsStr::new("l1/l2/f.txt"),
            &nested_dir.join("f.txt"),
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned prefix attempt");
        assert!(matches!(d, Decision::Trashed), "got {d:?}");
        assert!(
            !nested_dir.join("f.txt").exists(),
            "moved via openat2 prefix walk"
        );
        c2.kill().unwrap();
        let _ = c2.wait();
    }

    #[test]
    fn pinned_rmdir_semantics_enotempty_and_eisdir() {
        let (store, work, _g) = setup("rmdir");
        let nonempty = work.join("full");
        std::fs::create_dir_all(&nonempty).unwrap();
        std::fs::write(nonempty.join("keep"), b"x").unwrap();

        let mut child = spawn_with_cwd(&work);
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };

        // unlinkat(..., AT_REMOVEDIR) on NON-empty dir → ENOTEMPTY
        let args_rm: [u64; 6] = [libc::AT_FDCWD as u64, 0, libc::AT_REMOVEDIR as u64, 0, 0, 0];
        let d = try_pinned(
            child.id(),
            nr,
            &args_rm,
            OsStr::new("full"),
            &nonempty,
            true,
            -1,
            0,
            &store,
        )
        .unwrap();
        assert!(
            matches!(d, Decision::Errno(e) if e == libc::ENOTEMPTY),
            "got {d:?}"
        );
        assert!(nonempty.exists());

        // plain unlinkat on a DIRECTORY → EISDIR
        let d = try_pinned(
            child.id(),
            nr,
            &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
            OsStr::new("full"),
            &nonempty,
            false,
            -1,
            0,
            &store,
        )
        .unwrap();
        assert!(
            matches!(d, Decision::Errno(e) if e == libc::EISDIR),
            "got {d:?}"
        );

        // rmdir on an EMPTY dir → Trashed
        let empty = work.join("hollow");
        std::fs::create_dir(&empty).unwrap();
        let d = try_pinned(
            child.id(),
            nr,
            &args_rm,
            OsStr::new("hollow"),
            &empty,
            true,
            -1,
            0,
            &store,
        )
        .unwrap();
        assert!(matches!(d, Decision::Trashed), "got {d:?}");
        assert!(!empty.exists());
        child.kill().unwrap();
        let _ = child.wait();
    }

    // Regression (review, HIGH): ABSOLUTE pathnames must resolve against the
    // PINNED TARGET ROOT. openat2 ignores dirfd for absolute pathnames, so the
    // prefix is rewritten relative to the root fd — the first cut of the fix
    // leaked the absolute prefix through and walked the SUPERVISOR'S root.
    #[test]
    fn pinned_absolute_path_resolves_against_target_root() {
        let (store, work, _g) = setup("absroot");
        let victim = work.join("abs_victim.txt");
        std::fs::write(&victim, b"absolute").unwrap();
        // A child whose cwd is deliberately ELSEWHERE — only the pinned root
        // can resolve an absolute pathname correctly.
        let mut child = spawn_with_cwd(work.parent().unwrap());

        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };
        let d = try_pinned(
            child.id(),
            nr,
            &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
            OsStr::new(&format!("/{}", victim.strip_prefix("/").unwrap().display())),
            &victim,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");
        assert!(matches!(d, Decision::Trashed), "got {d:?}");
        assert!(
            !victim.exists(),
            "absolute-path victim moved via pinned root"
        );
        child.kill().unwrap();
        let _ = child.wait();
    }

    // Regression (review, LOW): unlink("regularfile/") must be ENOTDIR like
    // the real syscall — trailing slashes are semantic, not decoration.
    #[test]
    fn pinned_trailing_slash_on_regular_file_is_enotdir() {
        let (store, work, _g) = setup("trailslash");
        let f = work.join("plain.txt");
        std::fs::write(&f, b"x").unwrap();
        let mut child = spawn_with_cwd(&work);
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };
        let d = try_pinned(
            child.id(),
            nr,
            &[libc::AT_FDCWD as u64, 0, 0, 0, 0, 0],
            OsStr::new("plain.txt/"),
            &f,
            false,
            -1,
            0,
            &store,
        )
        .expect("pinned attempt");
        assert!(
            matches!(d, Decision::Errno(e) if e == libc::ENOTDIR),
            "got {d:?}"
        );
        assert!(f.exists(), "file untouched");
        child.kill().unwrap();
        let _ = child.wait();
    }

    /// RACE TEST (#6): a sibling process renames the target's parent
    /// directory continuously while deletes are intercepted. The pinned-fd
    /// flow must track the INODE (child cwd + our duplicated fds), never a
    /// stale name, and every trashed file must be exactly the requested one.
    #[test]
    fn pinned_flow_survives_parent_rename_races() {
        let (store, work, _g) = setup("racer");
        let a = work.join("ra");
        let b = work.join("rb");
        std::fs::create_dir_all(&a).unwrap();
        let mut child = spawn_with_cwd(&a);
        let nr = if cfg!(target_arch = "x86_64") {
            NR_UNLINKAT_X86_64
        } else {
            NR_UNLINKAT_AARCH64
        };
        let args_cwd: [u64; 6] = [libc::AT_FDCWD as u64, 0, 0, 0, 0, 0];

        const ROUNDS: usize = 60;
        let mut trashed = 0usize;
        for i in 0..ROUNDS {
            let name = format!("race{i}.txt");
            let content = format!("payload-{i}");
            // Write into whichever name currently holds the child's dir.
            let cur_is_a = std::fs::symlink_metadata(&a).is_ok();
            let live_dir = if cur_is_a { &a } else { &b };
            let path = live_dir.join(&name);
            std::fs::write(&path, &content).unwrap();

            // Flip the directory names RIGHT BEFORE the interception — the
            // historic string-based flow would resolve the child's cwd name
            // fresh and can land anywhere; the pinned flow follows the inode.
            if cur_is_a {
                let _ = std::fs::rename(&a, &b);
            } else {
                let _ = std::fs::rename(&b, &a);
            }

            let d = try_pinned(
                child.id(),
                nr,
                &args_cwd,
                OsStr::new(&name),
                &path,
                false,
                -1,
                0,
                &store,
            )
            .expect("pinned attempt");
            match d {
                Decision::Trashed => trashed += 1,
                Decision::Continue | Decision::Decline => {}
                Decision::Errno(e) => panic!("round {i}: unexpected errno {e}"),
            }

            // Flip back so the next round finds a stable name.
            if std::fs::symlink_metadata(&b).is_ok() && !std::fs::symlink_metadata(&a).is_ok() {
                let _ = std::fs::rename(&b, &a);
            }
        }

        assert!(
            trashed >= ROUNDS * 9 / 10,
            "racer should trash nearly all rounds ({trashed}/{ROUNDS})"
        );

        // Every trashed entry must carry EXACTLY its own payload.
        let mut verified = 0usize;
        for e in store.list(None).unwrap() {
            if !e.id.starts_with("race") || e.orphaned {
                continue;
            }
            let data = std::fs::read_to_string(&e.trashed_path).unwrap();
            assert_eq!(
                data,
                format!("payload-{}", {
                    let idx = e.id.trim_start_matches("race").split('.').next().unwrap();
                    idx.parse::<usize>().unwrap()
                }),
                "entry {} carries the wrong payload",
                e.id
            );
            verified += 1;
        }
        assert_eq!(verified, trashed, "every trashed round must verify");
        child.kill().unwrap();
        let _ = child.wait();
    }
}
