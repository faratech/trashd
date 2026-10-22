//! Nonblocking filter provenance protocol; shared without store dependencies.
#![allow(dead_code)]
pub const COOKIE_ENV: &str = "TRASHD_SECCOMP_COOKIE";
pub const PROOF_ERRNO: i32 = 4093;

/// Fourth syscall argument of an unlinkat the preload hands to the
/// supervisor (unlinkat ignores it). A marked deletion the supervisor will
/// not perform with its own credentials is answered ENOSYS instead of being
/// left to the kernel, so the preload trashes it in-process with the
/// target's own (#349). Sixty-four bits: an unmarked call's stale register
/// does not match by accident.
pub const DEFER_MARK: u64 = 0x7472_6173_6864_6d6b;

/// Explicit native source retirement after publishing a verified copy.
/// The filter also binds argument six to the syscall's instruction pointer:
/// tags left in unused registers cannot exempt an ordinary unlink (#393).
pub const RETIRE_MARK: u64 = 0x7472_6173_6864_726d;
pub const RETIRE_GUARD: u64 = 0x736f_7572_6365_6f6b;

/// Retire a copied source without recursively entering our supervisor while
/// its publication lock is held. Native kernel permission checks still run.
///
/// # Safety
/// `pathname` must point to a valid NUL-terminated pathname for this call.
pub unsafe fn retire_unlink(pathname: *const libc::c_char) -> std::io::Result<()> {
    #[cfg(target_arch = "aarch64")]
    let result: isize = {
        let result;
        unsafe {
            std::arch::asm!(
                "adr x5, 2f",
                "svc #0",
                "2:",
                in("x8") libc::SYS_unlinkat,
                inlateout("x0") libc::AT_FDCWD as isize => result,
                in("x1") pathname,
                in("x2") 0usize,
                in("x3") RETIRE_MARK,
                in("x4") RETIRE_GUARD,
                lateout("x5") _,
                options(nostack),
            );
        }
        result
    };
    #[cfg(target_arch = "x86_64")]
    let result: isize = {
        let result;
        unsafe {
            std::arch::asm!(
                "lea r9, [rip + 2f]",
                "syscall",
                "2:",
                // Preserve libc unlink's syscall surface for existing
                // sandbox profiles that permit unlink but deny unlinkat.
                inlateout("rax") libc::SYS_unlink as isize => result,
                in("rdi") pathname,
                in("rsi") 0usize,
                in("rdx") 0usize,
                in("r10") RETIRE_MARK,
                in("r8") RETIRE_GUARD,
                lateout("r9") _,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    };
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    return if unsafe {
        libc::syscall(
            libc::SYS_unlinkat,
            libc::AT_FDCWD as libc::c_long,
            pathname,
            0 as libc::c_long,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    };
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(-result as i32))
    }
}

pub fn parse(value: &str) -> Option<[u32; 4]> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut words = [0; 4];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u32::from_str_radix(&value[i * 8..i * 8 + 8], 16).ok()?;
    }
    Some(words)
}

pub fn encode(cookie: [u32; 4]) -> String {
    cookie.iter().map(|w| format!("{w:08x}")).collect()
}

pub fn random() -> std::io::Result<[u32; 4]> {
    let mut bytes = [0u8; 16];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(std::io::Error::other("empty random cookie"));
        }
        offset += n as usize;
    }
    Ok(std::array::from_fn(|i| {
        u32::from_ne_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("four bytes"))
    }))
}

pub fn verified(cookie: [u32; 4]) -> bool {
    unsafe {
        let saved = *libc::__errno_location();
        let control = libc::syscall(
            libc::SYS_getpid,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        );
        let proof = libc::syscall(
            libc::SYS_getpid,
            cookie[0] as libc::c_ulong,
            cookie[1] as libc::c_ulong,
            cookie[2] as libc::c_ulong,
            cookie[3] as libc::c_ulong,
        );
        let verified = control > 0 && proof == -1 && *libc::__errno_location() == PROOF_ERRNO;
        *libc::__errno_location() = saved;
        verified
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cookie_roundtrip_and_invalid_values() {
        let cookie = [0, 1, u32::MAX, 0x12345678];
        assert_eq!(super::parse(&super::encode(cookie)), Some(cookie));
        for s in [
            "",
            "1",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "éééééééééééééééé",
        ] {
            assert_eq!(super::parse(s), None);
        }
        assert!(!super::verified(cookie));
    }
}
