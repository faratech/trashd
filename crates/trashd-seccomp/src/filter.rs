//! BPF filter construction for seccomp.
//!
//! Builds a BPF program that traps unlink(2), unlinkat(2), and rmdir(2)
//! with SECCOMP_RET_USER_NOTIF, allowing all other syscalls.

use std::io;

// BPF instruction opcodes
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// seccomp_data offsets
const OFFSET_NR: u32 = 0;   // offsetof(seccomp_data, nr)
const OFFSET_ARCH: u32 = 4; // offsetof(seccomp_data, arch)

// Architecture
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

// x86_64 syscall numbers
#[cfg(target_arch = "x86_64")]
const SYS_UNLINK: u32 = 87;
#[cfg(target_arch = "x86_64")]
const SYS_RMDIR: u32 = 84;
#[cfg(target_arch = "x86_64")]
const SYS_UNLINKAT: u32 = 263;

// aarch64 syscall numbers (no unlink/rmdir — only unlinkat)
#[cfg(target_arch = "aarch64")]
const SYS_UNLINKAT: u32 = 35;

// seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;

// seccomp constants
pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// A BPF instruction (struct sock_filter).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// A BPF program (struct sock_fprog).
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Build the BPF filter program that traps delete-related syscalls.
#[cfg(target_arch = "x86_64")]
pub fn build_filter() -> Vec<SockFilter> {
    vec![
        // [0] Load architecture
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        // [1] Check x86_64 — if not, skip to ALLOW
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        // [2] Wrong arch → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [3] Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        // [4] Check unlink
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINK, 3, 0),
        // [5] Check unlinkat
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 2, 0),
        // [6] Check rmdir
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_RMDIR, 1, 0),
        // [7] No match → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [8] Match → USER_NOTIF (trap to supervisor)
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    ]
}

/// Build the BPF filter for aarch64 (only unlinkat exists).
#[cfg(target_arch = "aarch64")]
pub fn build_filter() -> Vec<SockFilter> {
    vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 0, 1),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    ]
}

/// Install the seccomp filter and return the notification fd.
///
/// Must be called after `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
pub fn install_filter() -> io::Result<i32> {
    let filter = build_filter();
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as libc::c_long,
            SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            &prog as *const SockFprog as libc::c_long,
        )
    };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}
