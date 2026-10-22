//! Collision candidates shared by the store and standalone preload.
//!
//! The basename and first timestamped ID stay readable. Further collisions
//! must not restart a linear search through the trash on every deletion, nor
//! exhaust a fixed namespace and turn an intercepted unlink permanent (#399).

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct CollisionNames<'a> {
    basename: &'a str,
    timestamp: &'a str,
    first: bool,
    pid: u32,
}

impl<'a> CollisionNames<'a> {
    pub(crate) fn new(basename: &'a str, timestamp: &'a str) -> Self {
        Self {
            basename,
            timestamp,
            first: true,
            pid: 0,
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
        let limit = 255usize.saturating_sub(10 + suffix.len()).min(223);
        let basename = &self.basename[..self.basename.floor_char_boundary(limit)];
        format!("{basename}{suffix}")
    }
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
        let mut first = CollisionNames::new("same", "20260102030405");
        let mut second = CollisionNames::new("same", "20260102030405");
        assert_eq!(first.next(), "same.20260102030405");
        assert_eq!(second.next(), "same.20260102030405");
        let a = first.next();
        let b = second.next();
        let c = first.next();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn collision_candidates_fit_long_unicode_filenames() {
        let basename = "é".repeat(120);
        let mut names = CollisionNames::new(&basename, "20260102030405");
        for _ in 0..3 {
            let name = names.next();
            assert!(name.len() + ".trashinfo".len() <= 255);
            assert!(name.starts_with('é'));
        }
    }
}
