//! Collision candidates shared by the store and standalone preload.
//!
//! The basename and first timestamped ID stay readable. Further collisions
//! must not restart a linear search through the trash on every deletion, nor
//! exhaust a fixed namespace and turn an intercepted unlink permanent (#399).
//!
//! Every name fits the trash filesystem's own NAME_MAX: eCryptfs takes 143
//! bytes, and an id sized for 255 got no sidecar there. The preload then
//! deleted for real what the shim refused to (cross-layer-6).

use std::sync::atomic::{AtomicU64, Ordering};

/// NAME_MAX where a filesystem cannot tell its own.
const DEFAULT_NAME_MAX: usize = 255;
/// What a base name leaves for a collision suffix and `.trashinfo`: the
/// 223 bytes of a 255-byte NAME_MAX.
const SUFFIX_ROOM: usize = 32;

pub(crate) struct CollisionNames<'a> {
    basename: &'a str,
    timestamp: &'a str,
    first: bool,
    pid: u32,
    name_max: usize,
}

impl<'a> CollisionNames<'a> {
    pub(crate) fn new(basename: &'a str, timestamp: &'a str, name_max: usize) -> Self {
        Self {
            basename,
            timestamp,
            first: true,
            pid: 0,
            name_max,
        }
    }

    pub(crate) fn next(&mut self) -> String {
        let suffix = if self.first {
            self.first = false;
            format!(".{}", self.timestamp)
        } else {
            if self.pid == 0 {
                self.pid = std::process::id();
            }
            format!(".{}.{:x}.{:x}", self.timestamp, self.pid, next_sequence())
        };
        // `.trashinfo` takes ten bytes. Shorten only the collision candidate,
        // preserving valid UTF-8 even when a long name needs the larger suffix.
        let limit = self
            .name_max
            .saturating_sub(10 + suffix.len())
            .min(self.name_max.saturating_sub(SUFFIX_ROOM));
        let basename = &self.basename[..self.basename.floor_char_boundary(limit)];
        format!("{basename}{suffix}")
    }
}

/// `name` cut, on a character boundary, to the id a filesystem with this
/// NAME_MAX takes, with room left for `.trashinfo` and a collision suffix.
pub(crate) fn base_within(name: &str, name_max: usize) -> &str {
    &name[..name.floor_char_boundary(name_max.saturating_sub(SUFFIX_ROOM))]
}

/// NAME_MAX of the filesystem holding `dir`, at most 255.
pub(crate) fn name_max(dir: &std::path::Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    let Ok(dir) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return DEFAULT_NAME_MAX;
    };
    match unsafe { libc::pathconf(dir.as_ptr(), libc::_PC_NAME_MAX) } {
        max if max > 0 => (max as usize).min(DEFAULT_NAME_MAX),
        _ => DEFAULT_NAME_MAX,
    }
}

/// The next budget to claim an id within after a name `name_max` allowed
/// was refused as too long (ENAMETOOLONG: a filesystem whose NAME_MAX it
/// reports wrong). None once a budget that small is refused too.
pub(crate) fn smaller_name_max(name_max: usize) -> Option<usize> {
    (name_max > 2 * SUFFIX_ROOM).then(|| name_max - 16)
}

fn next_sequence() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    if NEXT.load(Ordering::Relaxed) == 0 {
        // A seed per process avoids walking old IDs when a PID is reused.
        // This uses a clock syscall the preload already needs, not getrandom
        // which older application seccomp allowlists may kill. Forked children
        // keep the seed but have a different PID. Atomic reservation remains
        // authoritative for clock/PID reuse and every residual collision.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|stamp| stamp.as_nanos() as u64)
            .unwrap_or(1)
            .max(1);
        let _ = NEXT.compare_exchange(0, seed, Ordering::Relaxed, Ordering::Relaxed);
    }
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collision_candidates_preserve_first_timestamp_then_advance() {
        let mut first = CollisionNames::new("same", "20260102030405", 255);
        let mut second = CollisionNames::new("same", "20260102030405", 255);
        assert_eq!(first.next(), "same.20260102030405");
        assert_eq!(second.next(), "same.20260102030405");
        let a = first.next();
        let b = second.next();
        let c = first.next();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // cross-layer-6: ids fit the trash filesystem's own NAME_MAX (143 bytes
    // on eCryptfs), not an assumed 255.
    #[test]
    fn candidates_fit_the_filesystems_name_limit() {
        let name = "名".repeat(47);
        for name_max in [143, 255] {
            let base = base_within(&name, name_max);
            assert!(base.len() + ".trashinfo".len() <= name_max, "{name_max}");
            let mut names = CollisionNames::new(base, "20260102030405", name_max);
            for _ in 0..3 {
                let name = names.next();
                assert!(
                    name.len() + ".trashinfo".len() <= name_max,
                    "{name_max}: {name}"
                );
                assert!(name.starts_with('名'));
            }
        }
    }

    #[test]
    fn collision_candidates_fit_long_unicode_filenames() {
        let basename = "é".repeat(120);
        let mut names = CollisionNames::new(&basename, "20260102030405", 255);
        for _ in 0..3 {
            let name = names.next();
            assert!(name.len() + ".trashinfo".len() <= 255);
            assert!(name.starts_with('é'));
        }
    }
}
