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
const OFFSET_NR: u32 = 0; // offsetof(seccomp_data, nr)
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

// io_uring (same generic numbers on both arches). io_uring can execute
// IORING_OP_UNLINKAT/UNLINK/RMDIR from kernel workers WITHOUT a syscall
// entry, so allowing io_uring_setup/enter/register would let a supervised
// process permanently delete files with no notification at all (#90) — the
// same reason Chromium/Android disable io_uring under seccomp filters.
const SYS_IO_URING_SETUP: u32 = 425;
const SYS_IO_URING_ENTER: u32 = 426;
const SYS_IO_URING_REGISTER: u32 = 427;

// seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;
// ERRNO|ENOSYS: fail the syscall without executing it. Used for io_uring and
// for non-native architectures — both fail LOUDLY instead of being allowed
// past the filter (a wrong-arch process used to get silent real deletes).
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ERRNO_ENOSYS: u32 = SECCOMP_RET_ERRNO | 38; // ENOSYS

// seccomp constants
pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// A BPF instruction (struct sock_filter).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
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
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Build the BPF filter program that traps delete-related syscalls.
#[cfg(target_arch = "x86_64")]
pub fn build_filter() -> Vec<SockFilter> {
    //  [0] LD arch                [6] JEQ io_uring_setup     -> ERRNO
    //  [1] JEQ native -> [2], else ERRNO[11]
    //  [2] LD nr                  [7] JEQ io_uring_enter     -> ERRNO
    //  [3] JEQ unlink  -> NOTIF   [8] JEQ io_uring_register  -> ERRNO
    //  [4] JEQ unlinkat-> NOTIF   [9]  RET ALLOW
    //  [5] JEQ rmdir   -> NOTIF   [10] RET USER_NOTIF
    //                             [11] RET ERRNO|ENOSYS
    vec![
        // [0] Load architecture
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        // [1] Native arch → continue; anything else → ERRNO|ENOSYS (a 32-bit
        // process under the 64-bit supervisor used to get silent ALLOWs)
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 9),
        // [2] Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        // [3..5] unlink/unlinkat/rmdir → USER_NOTIF [10]
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINK, 6, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 5, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_RMDIR, 4, 0),
        // [6..8] io_uring → ERRNO|ENOSYS [11]
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_SETUP, 4, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_ENTER, 3, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_REGISTER, 2, 0),
        // [9] No match → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [10] delete syscalls trap to the supervisor
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        // [11] io_uring and wrong-arch syscalls fail loudly
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS),
    ]
}

/// Build the BPF filter for aarch64 (only unlinkat exists).
#[cfg(target_arch = "aarch64")]
pub fn build_filter() -> Vec<SockFilter> {
    //  [0] LD arch    [3] JEQ unlinkat -> NOTIF[8]
    //  [1] JEQ native -> [2], else ERRNO[9]
    //  [2] LD nr      [4..6] JEQ io_uring_* -> ERRNO[9]
    //                 [7] RET ALLOW  [8] RET USER_NOTIF  [9] RET ERRNO|ENOSYS
    vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 7),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 4, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_SETUP, 4, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_ENTER, 3, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_REGISTER, 2, 0),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal cBPF interpreter: runs the program against (arch, nr) the same
    /// way the kernel would, so the hand-computed jt/jf offsets stay pinned.
    fn run_filter(prog: &[SockFilter], arch: u32, nr: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = &prog[pc];
            if ins.code == BPF_LD | BPF_W | BPF_ABS {
                acc = match ins.k {
                    OFFSET_NR => nr,
                    OFFSET_ARCH => arch,
                    _ => panic!("unexpected absolute load offset {}", ins.k),
                };
                pc += 1;
            } else if ins.code == BPF_JMP | BPF_JEQ | BPF_K {
                pc += 1 + if acc == ins.k {
                    ins.jt as usize
                } else {
                    ins.jf as usize
                };
            } else if ins.code == BPF_RET | BPF_K {
                return ins.k;
            } else {
                panic!("unexpected instruction {ins:?}");
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: u32 = AUDIT_ARCH_X86_64;

    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: u32 = AUDIT_ARCH_AARCH64;

    // Regression (#90, #91): the delete syscalls trap, io_uring is refused
    // with ENOSYS, wrong-arch tokens are refused with ENOSYS, and everything
    // else is allowed.
    #[test]
    fn filter_decisions_match_policy() {
        let prog = build_filter();

        let unlinkat_nr: u32 = if cfg!(target_arch = "x86_64") { 263 } else { 35 };

        assert_eq!(
            run_filter(&prog, NATIVE_ARCH, unlinkat_nr),
            SECCOMP_RET_USER_NOTIF
        );
        if cfg!(target_arch = "x86_64") {
            assert_eq!(run_filter(&prog, NATIVE_ARCH, 87), SECCOMP_RET_USER_NOTIF); // unlink
            assert_eq!(run_filter(&prog, NATIVE_ARCH, 84), SECCOMP_RET_USER_NOTIF); // rmdir
        }
        for io_uring_nr in [425u32, 426, 427] {
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, io_uring_nr),
                SECCOMP_RET_ERRNO_ENOSYS,
                "io_uring syscall {io_uring_nr} must be refused"
            );
        }
        // Wrong arch is never ALLOW: e.g. an i386 token (AUDIT_ARCH_I386)
        // under the 64-bit supervisor gets ENOSYS instead of silent passage.
        assert_eq!(run_filter(&prog, 0x4000_0003, 87), SECCOMP_RET_ERRNO_ENOSYS);
        // Ordinary syscalls keep working.
        assert_eq!(run_filter(&prog, NATIVE_ARCH, 1), SECCOMP_RET_ALLOW); // write
        assert_eq!(run_filter(&prog, NATIVE_ARCH, 257), SECCOMP_RET_ALLOW); // openat
    }
}
