//! Session-wide permission boundary shared by the watchdog and supervisors.
//!
//! There is no portable way to prove that a task has no inherited Landlock
//! domain: its restricting ancestor may already have exited. Once any target
//! attempts restriction setup, leave all subsequent deletes to the target's
//! own security context. This costs one bit for the lifetime of the session,
//! rather than an incomplete, bounded history of task identities.

use std::io;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static STATE: OnceLock<RestrictionState> = OnceLock::new();

struct RestrictionState(NonNull<AtomicBool>);

// The mapping contains only an atomic, and is unmapped only when its owner
// drops after all references end. Each fork owns its own mapping reference.
unsafe impl Send for RestrictionState {}
unsafe impl Sync for RestrictionState {}

impl RestrictionState {
    fn new() -> io::Result<Self> {
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<AtomicBool>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let pointer = NonNull::new(mapping.cast::<AtomicBool>()).unwrap();
        unsafe { pointer.as_ptr().write(AtomicBool::new(false)) };
        Ok(Self(pointer))
    }

    fn note(&self) {
        unsafe { self.0.as_ref() }.store(true, Ordering::Release);
    }

    fn restricts(&self) -> bool {
        unsafe { self.0.as_ref() }.load(Ordering::Acquire)
    }
}

impl Drop for RestrictionState {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.as_ptr().cast(), std::mem::size_of::<AtomicBool>()) };
    }
}

/// Allocate after forking the target, before forking either worker. Targets
/// never inherit the mapping, and a replacement supervisor sees every write
/// made by its predecessors or the watchdog without a broker round trip.
pub fn initialize() -> io::Result<()> {
    STATE
        .set(RestrictionState::new()?)
        .map_err(|_| io::Error::other("Landlock tracking already initialized"))
}

/// The shared store completes before the notification may be continued.
/// If tracking was not initialized, refuse setup rather than allow an
/// untracked security-context transition.
pub fn note_restriction() -> io::Result<()> {
    let state = STATE
        .get()
        .ok_or_else(|| io::Error::other("Landlock tracking unavailable"))?;
    state.note();
    Ok(())
}

/// Unknown tracking state must never authorize supervisor-side mutation.
pub fn restricts() -> bool {
    STATE.get().is_none_or(RestrictionState::restricts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_restriction_survives_worker_exit_without_a_record_limit() {
        // Re-run this test alone so no concurrent tests hold process locks.
        // Forked workers below perform only atomics, ioctls and _exit.
        const CHILD: &str = "TRASHD_TEST_LANDLOCK_SHARED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "landlock::tests::shared_restriction_survives_worker_exit_without_a_record_limit",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        assert!(restricts(), "unknown tracking state declines mutations");
        assert!(
            note_restriction().is_err(),
            "unknown tracking cannot acknowledge setup"
        );
        initialize().unwrap();
        assert!(!restricts(), "ordinary sessions retain interception");
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // More setup events than the former 512-record limit, in an
            // exiting worker. No task identity or live ancestry is needed.
            let mut notif: crate::supervisor::SeccompNotif = unsafe { std::mem::zeroed() };
            notif.data.nr = 446; // landlock_restrict_self on both supported ABIs
            for tid in 1..=1024 {
                notif.pid = tid;
                // This is the handler used by watchdog drain, emergency
                // passthrough, supervisor fallback, and panic recovery. An
                // invalid listener cannot prevent the preceding state write.
                crate::supervisor::decline(-1, &notif);
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert!(restricts(), "restriction outlives the recording worker");
        let replacement = unsafe { libc::fork() };
        assert!(replacement >= 0);
        if replacement == 0 {
            unsafe { libc::_exit(i32::from(!restricts())) };
        }
        assert_eq!(
            unsafe { libc::waitpid(replacement, &mut status, 0) },
            replacement
        );
        assert_eq!(status, 0, "replacement inherits the shared restriction");
    }
}
