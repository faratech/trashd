//! Nonblocking filter provenance protocol; shared without SQLite dependencies.
#![allow(dead_code)]
pub const COOKIE_ENV: &str = "TRASHD_SECCOMP_COOKIE";
pub const PROOF_ERRNO: i32 = 4093;

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
