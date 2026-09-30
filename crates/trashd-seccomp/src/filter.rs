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
// Only the x86_64 program emits a JGE (the x32 guard); the interpreter in
// tests still needs the constant on every arch.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const BPF_JGE: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// x32 processes report arch == AUDIT_ARCH_X86_64 but OR 0x40000000 into every
// syscall number, so the arch check alone cannot catch them (#123). Numbers
// with that bit set are rejected outright — same loud-fail policy as a
// non-native architecture.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

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
fn build_base_filter() -> Vec<SockFilter> {
    //  [0] LD arch
    //  [1] JEQ native -> [2], else ERRNO[12]
    //  [2] LD nr
    //  [3] JGE x32-bit           -> ERRNO[12]
    //  [4] JEQ unlink        -> NOTIF[11]
    //  [5] JEQ unlinkat      -> NOTIF[11]
    //  [6] JEQ rmdir         -> NOTIF[11]
    //  [7] JEQ io_uring_setup    -> ERRNO[12]
    //  [8] JEQ io_uring_enter    -> ERRNO[12]
    //  [9] JEQ io_uring_register -> ERRNO[12]
    // [10] RET ALLOW   [11] RET USER_NOTIF   [12] RET ERRNO|ENOSYS
    vec![
        // [0] Load architecture
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        // [1] Native arch → continue; anything else → ERRNO|ENOSYS (a 32-bit
        // process under the 64-bit supervisor used to get silent ALLOWs)
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 10),
        // [2] Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        // [3] x32 syscalls carry this bit and reuse the native arch token, so
        // the arch check cannot catch them; without this they would silently
        // ALLOW every delete (#123). Reject them like a foreign architecture.
        bpf_jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 8, 0),
        // [4..6] unlink/unlinkat/rmdir → USER_NOTIF [11]
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINK, 6, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 5, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_RMDIR, 4, 0),
        // [7..9] io_uring → ERRNO|ENOSYS [12]
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_SETUP, 4, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_ENTER, 3, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_IO_URING_REGISTER, 2, 0),
        // [10] No match → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [11] delete syscalls trap to the supervisor
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        // [12] io_uring, wrong-arch, and x32 syscalls fail loudly
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS),
    ]
}

/// Build the BPF filter for aarch64 (only unlinkat exists).
#[cfg(target_arch = "aarch64")]
fn build_base_filter() -> Vec<SockFilter> {
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

/// Identify this filter with a cookie in otherwise unused getpid arguments.
pub fn build_filter(cookie: [u32; 4]) -> Vec<SockFilter> {
    let mut proof = vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, native_arch(), 0, 11),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_getpid as u32, 0, 9),
    ];
    for (i, word) in cookie.into_iter().enumerate() {
        proof.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16 + i as u32 * 8));
        proof.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            word,
            0,
            (7 - i * 2) as u8,
        ));
    }
    proof.push(bpf_stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | crate::seccomp_identity::PROOF_ERRNO as u32,
    ));
    proof.extend(build_base_filter());
    proof
}

fn native_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
}

/// Install the seccomp filter and return the notification fd.
///
/// Requires NoNewPrivs or CAP_SYS_ADMIN in the current user namespace.
pub fn install_filter(cookie: [u32; 4]) -> io::Result<i32> {
    let filter = build_filter(cookie);
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
        run_filter_args(prog, arch, nr, [0; 4])
    }

    fn run_filter_args(prog: &[SockFilter], arch: u32, nr: u32, args: [u32; 4]) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = &prog[pc];
            if ins.code == BPF_LD | BPF_W | BPF_ABS {
                acc = match ins.k {
                    OFFSET_NR => nr,
                    OFFSET_ARCH => arch,
                    offset if (16..48).contains(&offset) && (offset - 16) % 8 == 0 => {
                        args[((offset - 16) / 8) as usize]
                    }
                    _ => panic!("unexpected absolute load offset {}", ins.k),
                };
                pc += 1;
            } else if ins.code == BPF_JMP | BPF_JEQ | BPF_K {
                pc += 1 + if acc == ins.k {
                    ins.jt as usize
                } else {
                    ins.jf as usize
                };
            } else if ins.code == BPF_JMP | BPF_JGE | BPF_K {
                pc += 1 + if acc >= ins.k {
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

    #[test]
    fn kernel_cookie_proof_is_nonblocking_and_preserves_errno() {
        if std::env::var_os("TRASHD_TEST_COOKIE_PROOF").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "filter::tests::kernel_cookie_proof_is_nonblocking_and_preserves_errno",
                    "--nocapture",
                ])
                .env("TRASHD_TEST_COOKIE_PROOF", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // Identity-only filter in a disposable process: no notification
        // listener and no deletion interception or filesystem mutation.
        let cookie = [0x12345678, 0xabcdef01, 0x78901234, 0x56789abc];
        let mut instructions = build_filter(cookie);
        instructions.truncate(13);
        instructions.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        let program = SockFprog {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) },
            0
        );
        unsafe {
            *libc::__errno_location() = libc::ENOENT;
        }
        assert!(crate::seccomp_identity::verified(cookie));
        assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOENT);
        assert!(!crate::seccomp_identity::verified([0; 4]));
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_getpid, 0, 0, 0, 0) },
            std::process::id() as libc::c_long
        );
    }

    #[test]
    fn only_native_cookie_probe_proves_filter_identity() {
        let cookie = [1, 2, 3, 4];
        let filter = build_filter(cookie);
        let getpid = libc::SYS_getpid as u32;
        assert_eq!(
            run_filter_args(&filter, NATIVE_ARCH, getpid, cookie),
            SECCOMP_RET_ERRNO | crate::seccomp_identity::PROOF_ERRNO as u32
        );
        assert_eq!(run_filter(&filter, NATIVE_ARCH, getpid), SECCOMP_RET_ALLOW);
        for i in 0..4 {
            let mut wrong = cookie;
            wrong[i] ^= 1;
            assert_eq!(
                run_filter_args(&filter, NATIVE_ARCH, getpid, wrong),
                SECCOMP_RET_ALLOW
            );
        }
        assert_eq!(
            run_filter_args(&filter, 0, getpid, cookie),
            SECCOMP_RET_ERRNO_ENOSYS
        );
    }

    // Regression (#90, #91): the delete syscalls trap, io_uring is refused
    // with ENOSYS, wrong-arch tokens are refused with ENOSYS, and everything
    // else is allowed.
    #[test]
    fn filter_decisions_match_policy() {
        let prog = build_filter([1, 2, 3, 4]);

        let unlinkat_nr: u32 = if cfg!(target_arch = "x86_64") {
            263
        } else {
            35
        };

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
        // Regression (#123): x32 syscalls reuse the native arch token with
        // 0x40000000 ORed into the number — they must fail loudly, not fall
        // through to ALLOW.
        if cfg!(target_arch = "x86_64") {
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, 87 | 0x4000_0000),
                SECCOMP_RET_ERRNO_ENOSYS
            );
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, 263 | 0x4000_0000),
                SECCOMP_RET_ERRNO_ENOSYS
            );
            // Ordinary 64-bit numbers (no x32 bit) are unaffected.
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, 0x3FFF_FFFF),
                SECCOMP_RET_ALLOW
            );
        }
        // Ordinary syscalls keep working.
        assert_eq!(run_filter(&prog, NATIVE_ARCH, 1), SECCOMP_RET_ALLOW); // write
        assert_eq!(run_filter(&prog, NATIVE_ARCH, 257), SECCOMP_RET_ALLOW); // openat
    }
}
