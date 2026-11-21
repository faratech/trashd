//! BPF filter construction for seccomp.
//!
//! Builds a BPF program that traps unlink(2), unlinkat(2), and rmdir(2)
//! with SECCOMP_RET_USER_NOTIF, allowing all other syscalls. The compat
//! ABIs (i386 and x32 on x86_64, AArch32 on aarch64) have their deletion,
//! io_uring and Landlock syscalls refused with ENOSYS, and run otherwise.

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
const BPF_X: u16 = 0x08;
const BPF_MISC: u16 = 0x07;
const BPF_TAX: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// x32 processes report arch == AUDIT_ARCH_X86_64 but OR 0x40000000 into every
// syscall number, so the arch check alone cannot catch them (#123). Their
// deletion numbers are refused like a compat architecture's.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp_data offsets
const OFFSET_NR: u32 = 0; // offsetof(seccomp_data, nr)
const OFFSET_ARCH: u32 = 4; // offsetof(seccomp_data, arch)
const OFFSET_IP: u32 = 8; // offsetof(seccomp_data, instruction_pointer)

// Architecture
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
// The compat ABI a native kernel runs beside its own.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_COMPAT: u32 = 0x4000_0003; // AUDIT_ARCH_I386
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_COMPAT: u32 = 0x4000_0028; // AUDIT_ARCH_ARM

// The compat ABI's unlink, rmdir and unlinkat. Its io_uring and
// landlock_restrict_self numbers are the generic ones below.
#[cfg(target_arch = "x86_64")]
const COMPAT_DELETES: [u32; 3] = [10, 40, 301];
#[cfg(target_arch = "aarch64")]
const COMPAT_DELETES: [u32; 3] = [10, 40, 328];

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

#[cfg(target_arch = "x86_64")]
const SYS_RETIRE: u32 = SYS_UNLINK;
#[cfg(target_arch = "aarch64")]
const SYS_RETIRE: u32 = SYS_UNLINKAT;

// landlock_restrict_self (446 on both architectures): trapping it lets
// the supervisor learn that a thread entered a Landlock domain it does not
// share, instead of lending that thread its own unrestricted credentials
// (#390). Sandbox setup itself is always continued.
const SYS_LANDLOCK_RESTRICT_SELF: u32 = 446;

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

/// What a compat ABI may not do: delete (the supervisor serves only the
/// native ABI, so these fail loudly instead of passing as real deletes),
/// use io_uring (#90), or enter a Landlock domain the supervisor would not
/// learn of (#390). Everything else runs: refusing every compat syscall left
/// 32-bit programs unable even to write or exit (seccomp-orch-4).
const COMPAT_REFUSALS: [u32; 7] = [
    COMPAT_DELETES[0],
    COMPAT_DELETES[1],
    COMPAT_DELETES[2],
    SYS_IO_URING_SETUP,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_REGISTER,
    SYS_LANDLOCK_RESTRICT_SELF,
];

/// Build the BPF filter program that traps delete-related syscalls.
#[cfg(target_arch = "x86_64")]
fn build_base_filter() -> Vec<SockFilter> {
    // x32 numbers carry X32_SYSCALL_BIT on the native arch token, so its
    // refusals are the x86_64 deletion numbers with that bit (#123).
    const X32_REFUSALS: [u32; 7] = [
        SYS_UNLINK | X32_SYSCALL_BIT,
        SYS_RMDIR | X32_SYSCALL_BIT,
        SYS_UNLINKAT | X32_SYSCALL_BIT,
        SYS_IO_URING_SETUP | X32_SYSCALL_BIT,
        SYS_IO_URING_ENTER | X32_SYSCALL_BIT,
        SYS_IO_URING_REGISTER | X32_SYSCALL_BIT,
        SYS_LANDLOCK_RESTRICT_SELF | X32_SYSCALL_BIT,
    ];
    //  [0] LD arch
    //  [1] JEQ x86_64 -> [2], else i386 [12]
    //  [2] LD nr
    //  [3] JGE x32-bit           -> x32 [22]
    //  [4] JEQ unlink        -> NOTIF[30]
    //  [5] JEQ unlinkat      -> NOTIF[30]
    //  [6] JEQ rmdir         -> NOTIF[30]
    //  [7] JEQ landlock_restrict_self -> NOTIF[30]
    //  [8] JEQ io_uring_setup    -> ERRNO[31]
    //  [9] JEQ io_uring_enter    -> ERRNO[31]
    // [10] JEQ io_uring_register -> ERRNO[31]
    // [11] RET ALLOW
    // [12] JEQ i386 -> [13], else ERRNO[31] (an unknown architecture)
    // [13] LD nr
    // [14..20] JEQ i386 refusals -> ERRNO[31]
    // [21] RET ALLOW
    // [22..28] JEQ x32 refusals -> ERRNO[31]
    // [29] RET ALLOW   [30] RET USER_NOTIF   [31] RET ERRNO|ENOSYS
    const COMPAT: usize = 12;
    const X32: usize = 22;
    const NOTIF: usize = 30;
    const ENOSYS: usize = 31;
    let to = |from: usize, target: usize| (target - from - 1) as u8;
    let mut program = vec![
        // [0] Load architecture
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        // [1] Native arch → continue; anything else → the compat checks
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_X86_64,
            0,
            to(1, COMPAT),
        ),
        // [2] Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        // [3] x32 syscalls carry this bit and reuse the native arch token, so
        // the arch check cannot catch them; without this they would silently
        // ALLOW every delete (#123).
        bpf_jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, to(3, X32), 0),
        // [4..7] unlink/unlinkat/rmdir and landlock_restrict_self → NOTIF
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINK, to(4, NOTIF), 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, to(5, NOTIF), 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_RMDIR, to(6, NOTIF), 0),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_LANDLOCK_RESTRICT_SELF,
            to(7, NOTIF),
            0,
        ),
        // [8..10] io_uring → ERRNO|ENOSYS
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_SETUP,
            to(8, ENOSYS),
            0,
        ),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_ENTER,
            to(9, ENOSYS),
            0,
        ),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_REGISTER,
            to(10, ENOSYS),
            0,
        ),
        // [11] No match → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [12] i386 continues; an unknown architecture fails loudly
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_COMPAT,
            0,
            to(COMPAT, ENOSYS),
        ),
        // [13] Load syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
    ];
    for nr in COMPAT_REFUSALS {
        let at = program.len();
        program.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, to(at, ENOSYS), 0));
    }
    // [21] Any other i386 syscall → ALLOW
    program.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    debug_assert_eq!(program.len(), X32);
    for nr in X32_REFUSALS {
        let at = program.len();
        program.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, to(at, ENOSYS), 0));
    }
    program.extend([
        // [29] Any other x32 syscall → ALLOW
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // [30] delete syscalls trap to the supervisor
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        // [31] io_uring, compat deletes and an unknown arch fail loudly
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS),
    ]);
    debug_assert_eq!(program.len(), ENOSYS + 1);
    program
}

/// Build the BPF filter for aarch64 (only unlinkat exists).
#[cfg(target_arch = "aarch64")]
fn build_base_filter() -> Vec<SockFilter> {
    //  [0] LD arch    [3] JEQ unlinkat -> NOTIF[19]
    //  [1] JEQ native -> [2], else AArch32 [9]
    //  [2] LD nr      [4] JEQ landlock_restrict_self -> NOTIF[19]
    //                 [5..7] JEQ io_uring_* -> ERRNO[20]
    //                 [8] RET ALLOW
    //  [9] JEQ AArch32 -> [10], else ERRNO[20] (an unknown architecture)
    // [10] LD nr     [11..17] JEQ AArch32 refusals -> ERRNO[20]
    // [18] RET ALLOW  [19] RET USER_NOTIF  [20] RET ERRNO|ENOSYS
    const COMPAT: usize = 9;
    const NOTIF: usize = 19;
    const ENOSYS: usize = 20;
    let to = |from: usize, target: usize| (target - from - 1) as u8;
    let mut program = vec![
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_AARCH64,
            0,
            to(1, COMPAT),
        ),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, to(3, NOTIF), 0),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_LANDLOCK_RESTRICT_SELF,
            to(4, NOTIF),
            0,
        ),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_SETUP,
            to(5, ENOSYS),
            0,
        ),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_ENTER,
            to(6, ENOSYS),
            0,
        ),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            SYS_IO_URING_REGISTER,
            to(7, ENOSYS),
            0,
        ),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_COMPAT,
            0,
            to(COMPAT, ENOSYS),
        ),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
    ];
    for nr in COMPAT_REFUSALS {
        let at = program.len();
        program.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, to(at, ENOSYS), 0));
    }
    program.extend([
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO_ENOSYS),
    ]);
    debug_assert_eq!(program.len(), ENOSYS + 1);
    program
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
    proof.extend(build_retirement_filter());
    proof.extend(build_base_filter());
    proof
}

/// Explicit source retirement stays in the caller's kernel context while
/// it holds the copy's publication lock. Bind both tags to this syscall's
/// site, so stale argument registers cannot exempt later calls (#393).
fn build_retirement_filter() -> Vec<SockFilter> {
    let mut program = Vec::new();
    for (offset, value) in [
        (OFFSET_ARCH, native_arch()),
        (OFFSET_NR, SYS_RETIRE),
        (32, 0), // unlinkat flags on ARM; explicitly zero unused arg on x86
        (40, crate::seccomp_identity::RETIRE_MARK as u32),
        (44, (crate::seccomp_identity::RETIRE_MARK >> 32) as u32),
        (48, crate::seccomp_identity::RETIRE_GUARD as u32),
        (52, (crate::seccomp_identity::RETIRE_GUARD >> 32) as u32),
    ] {
        program.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offset));
        program.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, value, 0, 0));
    }
    for (ip, argument) in [(OFFSET_IP, 56), (OFFSET_IP + 4, 60)] {
        program.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, ip));
        program.push(bpf_stmt(BPF_MISC | BPF_TAX, 0));
        program.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, argument));
        program.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0));
    }
    program.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    let end = program.len();
    for (index, instruction) in program.iter_mut().enumerate() {
        if instruction.code == BPF_JMP | BPF_JEQ | BPF_K
            || instruction.code == BPF_JMP | BPF_JEQ | BPF_X
        {
            // Any mismatch continues at the original complete filter.
            instruction.jf = (end - index - 1) as u8;
        }
    }
    program
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
        let mut full = [0; 6];
        for (destination, word) in full.iter_mut().zip(args) {
            *destination = u64::from(word);
        }
        run_filter_context(prog, arch, nr, full, 0)
    }

    fn run_filter_context(prog: &[SockFilter], arch: u32, nr: u32, args: [u64; 6], ip: u64) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        let mut index: u32 = 0;
        loop {
            let ins = &prog[pc];
            if ins.code == BPF_LD | BPF_W | BPF_ABS {
                acc = match ins.k {
                    OFFSET_NR => nr,
                    OFFSET_ARCH => arch,
                    OFFSET_IP => ip as u32,
                    offset if offset == OFFSET_IP + 4 => (ip >> 32) as u32,
                    offset if (16..64).contains(&offset) && offset % 4 == 0 => {
                        (args[((offset - 16) / 8) as usize] >> ((offset % 8) * 8)) as u32
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
            } else if ins.code == BPF_MISC | BPF_TAX {
                index = acc;
                pc += 1;
            } else if ins.code == BPF_JMP | BPF_JEQ | BPF_X {
                pc += 1 + if acc == index {
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
    fn retirement_tags_are_bound_to_the_native_syscall_site() {
        let program = build_filter([1, 2, 3, 4]);
        let ip = 0x1234_5678_abcd_ef00;
        let args = [
            libc::AT_FDCWD as u64,
            0,
            0,
            crate::seccomp_identity::RETIRE_MARK,
            crate::seccomp_identity::RETIRE_GUARD,
            ip,
        ];
        let decide = |arch, nr, args, ip| run_filter_context(&program, arch, nr, args, ip);
        assert_eq!(decide(NATIVE_ARCH, SYS_RETIRE, args, ip), SECCOMP_RET_ALLOW);
        for argument in [3, 4, 5] {
            for bit in [0, 31, 32, 63] {
                let mut changed = args;
                changed[argument] ^= 1 << bit;
                assert_eq!(
                    decide(NATIVE_ARCH, SYS_RETIRE, changed, ip),
                    SECCOMP_RET_USER_NOTIF
                );
            }
        }
        for bit in [0, 32] {
            assert_eq!(
                decide(NATIVE_ARCH, SYS_RETIRE, args, ip ^ (1 << bit)),
                SECCOMP_RET_USER_NOTIF
            );
        }
        let mut directory = args;
        directory[2] = libc::AT_REMOVEDIR as u64;
        assert_eq!(
            decide(NATIVE_ARCH, SYS_RETIRE, directory, ip),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(decide(0, SYS_RETIRE, args, ip), SECCOMP_RET_ERRNO_ENOSYS);
        for nr in [425, 426, 427] {
            assert_eq!(decide(NATIVE_ARCH, nr, args, ip), SECCOMP_RET_ERRNO_ENOSYS);
        }
        // Sandbox setup is observed, never blocked: the supervisor records
        // the new Landlock domain, then continues the call (#390).
        assert_eq!(
            decide(NATIVE_ARCH, SYS_LANDLOCK_RESTRICT_SELF, args, ip),
            SECCOMP_RET_USER_NOTIF
        );
        assert_eq!(
            decide(0, SYS_LANDLOCK_RESTRICT_SELF, args, ip),
            SECCOMP_RET_ERRNO_ENOSYS
        );
        #[cfg(target_arch = "x86_64")]
        {
            for nr in [SYS_UNLINKAT, SYS_RMDIR] {
                assert_eq!(decide(NATIVE_ARCH, nr, args, ip), SECCOMP_RET_USER_NOTIF);
            }
            assert_eq!(
                decide(NATIVE_ARCH, SYS_RETIRE | X32_SYSCALL_BIT, args, ip),
                SECCOMP_RET_ERRNO_ENOSYS
            );
        }
    }

    #[test]
    fn kernel_retirement_preserves_native_results_and_traps_other_sites() {
        use std::os::unix::ffi::OsStrExt;
        const CHILD: &str = "TRASHD_TEST_NATIVE_RETIRE_ROOT";
        const TEST: &str =
            "filter::tests::kernel_retirement_preserves_native_results_and_traps_other_sites";
        let Some(root) = std::env::var_os(CHILD) else {
            let root = tempfile::tempdir().unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(CHILD, root.path())
                .env("TRASH_BYPASS", "1")
                .output()
                .unwrap();
            assert!(child.status.success(), "{child:?}");
            return;
        };
        let root = std::path::Path::new(&root);
        let file = root.join("file");
        let link = root.join("link");
        let directory = root.join("directory");
        std::fs::write(&file, b"native retirement").unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();
        std::fs::create_dir(&directory).unwrap();
        let name =
            |path: &std::path::Path| std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // No listener is needed: every ordinary delete is refused instead.
        // Only a correctly bound retirement can reach the native kernel.
        let mut instructions = build_filter([1, 2, 3, 4]);
        for instruction in &mut instructions {
            if instruction.code == BPF_RET | BPF_K && instruction.k == SECCOMP_RET_USER_NOTIF {
                instruction.k = SECCOMP_RET_ERRNO | libc::EACCES as u32;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            // An existing sandbox can permit libc unlink (87), while
            // denying unlinkat (263). Retirement must keep that surface.
            let deny_unlinkat = [
                bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR),
                bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_UNLINKAT, 0, 1),
                bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32),
                bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            ];
            let program = SockFprog {
                len: deny_unlinkat.len() as u16,
                filter: deny_unlinkat.as_ptr(),
            };
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) },
                0
            );
        }
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
        let file_name = name(&file);
        assert_eq!(
            unsafe { libc::unlinkat(libc::AT_FDCWD, file_name.as_ptr(), 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES)
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(unsafe { libc::unlink(file_name.as_ptr()) }, -1);
        #[cfg(target_arch = "x86_64")]
        let (first, second) = (file_name.as_ptr() as libc::c_long, 0 as libc::c_long);
        #[cfg(target_arch = "aarch64")]
        let (first, second) = (
            libc::AT_FDCWD as libc::c_long,
            file_name.as_ptr() as libc::c_long,
        );
        assert_eq!(
            unsafe {
                libc::syscall(
                    SYS_RETIRE as libc::c_long,
                    first,
                    second,
                    0 as libc::c_long,
                    crate::seccomp_identity::RETIRE_MARK,
                    crate::seccomp_identity::RETIRE_GUARD,
                    0usize,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES)
        );
        unsafe { crate::seccomp_identity::retire_unlink(name(&link).as_ptr()) }.unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"native retirement");
        let directory_error =
            unsafe { crate::seccomp_identity::retire_unlink(name(&directory).as_ptr()) }
                .unwrap_err();
        assert_eq!(directory_error.raw_os_error(), Some(libc::EISDIR));
        unsafe { crate::seccomp_identity::retire_unlink(file_name.as_ptr()) }.unwrap();
        assert!(!file.exists());
        let missing =
            unsafe { crate::seccomp_identity::retire_unlink(file_name.as_ptr()) }.unwrap_err();
        assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
    }

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

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_I386: u32 = 0x4000_0003;

    // seccomp-orch-4: every syscall of a 32-bit process failed ENOSYS, so
    // under a wrapped login a 32-bit program could not even write or exit.
    // Only the compat ABIs' deletion, io_uring and Landlock numbers are
    // refused; the deletions still fail loudly instead of being allowed.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn compat_abis_refuse_only_their_deletes() {
        let cookie = [1, 2, 3, 4];
        let prog = build_filter(cookie);
        // i386: read, write, brk, mmap2, exit_group, openat, getpid, execve
        for nr in [3, 4, 45, 192, 252, 295, 20, 11] {
            assert_eq!(
                run_filter(&prog, AUDIT_ARCH_I386, nr),
                SECCOMP_RET_ALLOW,
                "i386 {nr}"
            );
        }
        // i386 unlink, rmdir, unlinkat, io_uring_*, landlock_restrict_self
        for nr in [10, 40, 301, 425, 426, 427, 446] {
            assert_eq!(
                run_filter(&prog, AUDIT_ARCH_I386, nr),
                SECCOMP_RET_ERRNO_ENOSYS,
                "i386 {nr}"
            );
        }
        // x32: the native numbers with the x32 bit set.
        for nr in [0, 1, 2, 12, 59, 60, 231, 257] {
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, nr | X32_SYSCALL_BIT),
                SECCOMP_RET_ALLOW,
                "x32 {nr}"
            );
        }
        for nr in [87, 84, 263, 425, 426, 427, 446] {
            assert_eq!(
                run_filter(&prog, NATIVE_ARCH, nr | X32_SYSCALL_BIT),
                SECCOMP_RET_ERRNO_ENOSYS,
                "x32 {nr}"
            );
        }
        // An unknown architecture is still refused outright.
        assert_eq!(run_filter(&prog, 0, 3), SECCOMP_RET_ERRNO_ENOSYS);
        // A compat getpid never proves the filter's identity.
        assert_eq!(
            run_filter_args(&prog, AUDIT_ARCH_I386, 20, cookie),
            SECCOMP_RET_ALLOW
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn compat_abis_refuse_only_their_deletes() {
        const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
        let cookie = [1, 2, 3, 4];
        let prog = build_filter(cookie);
        // AArch32: read, write, brk, exit_group, openat, getpid, execve
        for nr in [3, 4, 45, 248, 322, 20, 11] {
            assert_eq!(
                run_filter(&prog, AUDIT_ARCH_ARM, nr),
                SECCOMP_RET_ALLOW,
                "arm {nr}"
            );
        }
        for nr in [10, 40, 328, 425, 426, 427, 446] {
            assert_eq!(
                run_filter(&prog, AUDIT_ARCH_ARM, nr),
                SECCOMP_RET_ERRNO_ENOSYS,
                "arm {nr}"
            );
        }
        assert_eq!(run_filter(&prog, 0, 3), SECCOMP_RET_ERRNO_ENOSYS);
        assert_eq!(
            run_filter_args(&prog, AUDIT_ARCH_ARM, 20, cookie),
            SECCOMP_RET_ALLOW
        );
    }

    /// A static i386 program: write(1, "ok\n", 3), then unlink("victim"),
    /// then exit with the negated unlink result (its errno, or 0).
    #[cfg(target_arch = "x86_64")]
    fn i386_probe() -> Vec<u8> {
        const BASE: u32 = 0x0804_8000;
        const CODE: u32 = 52 + 32; // ELF header + one program header
        let mov = |opcode: u8, value: u32| {
            let mut bytes = vec![opcode];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes
        };
        let message = BASE + CODE + 45;
        let victim = message + 3;
        let mut code = Vec::new();
        code.extend(mov(0xB8, 4)); // eax = write
        code.extend(mov(0xBB, 1)); // ebx = stdout
        code.extend(mov(0xB9, message)); // ecx
        code.extend(mov(0xBA, 3)); // edx
        code.extend([0xCD, 0x80]); // int 0x80
        code.extend(mov(0xB8, 10)); // eax = unlink
        code.extend(mov(0xBB, victim)); // ebx
        code.extend([0xCD, 0x80]);
        code.extend([0xF7, 0xD8, 0x89, 0xC3]); // neg eax; mov ebx, eax
        code.extend(mov(0xB8, 1)); // eax = exit
        code.extend([0xCD, 0x80]);
        assert_eq!(code.len(), 45);
        code.extend(b"ok\nvictim\0");
        let total = CODE + code.len() as u32;
        let mut image = b"\x7fELF\x01\x01\x01\0\0\0\0\0\0\0\0\0".to_vec();
        for half in [2u16, 3] {
            image.extend(half.to_le_bytes()); // ET_EXEC, EM_386
        }
        for word in [1u32, BASE + CODE, 52, 0, 0] {
            image.extend(word.to_le_bytes()); // version, entry, phoff, shoff, flags
        }
        for half in [52u16, 32, 1, 0, 0, 0] {
            image.extend(half.to_le_bytes()); // ehsize, phentsize, phnum, sh*
        }
        for word in [1u32, 0, BASE, BASE, total, total, 5, 0x1000] {
            image.extend(word.to_le_bytes()); // PT_LOAD, R+X
        }
        image.extend(code);
        image
    }

    // seccomp-orch-4, against the kernel: a 32-bit program runs under the
    // real filter and its deletion fails ENOSYS, leaving the file in place.
    // No listener is involved; trapped native deletes are refused here.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn kernel_runs_32_bit_programs_and_refuses_their_deletes() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        let fixture = tempfile::tempdir().unwrap();
        let probe = fixture.path().join("probe32");
        std::fs::write(&probe, i386_probe()).unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(fixture.path().join("victim"), b"stays").unwrap();
        let mut instructions = build_filter([1, 2, 3, 4]);
        for instruction in &mut instructions {
            if instruction.code == BPF_RET | BPF_K && instruction.k == SECCOMP_RET_USER_NOTIF {
                instruction.k = SECCOMP_RET_ERRNO | libc::EACCES as u32;
            }
        }
        let mut command = std::process::Command::new(&probe);
        command.current_dir(fixture.path());
        unsafe {
            command.pre_exec(move || {
                let program = SockFprog {
                    len: instructions.len() as u16,
                    filter: instructions.as_ptr(),
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = match command.output() {
            Ok(output) => output,
            Err(error) if error.raw_os_error() == Some(libc::ENOEXEC) => {
                eprintln!("SKIP: this kernel runs no 32-bit programs");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        if output.status.code() == Some(libc::EACCES) {
            // An emulator (binfmt qemu-i386) issued native syscalls instead.
            eprintln!("SKIP: 32-bit programs run under an emulator here");
            return;
        }
        assert_eq!(output.stdout, b"ok\n", "{output:?}");
        assert_eq!(output.status.code(), Some(libc::ENOSYS), "{output:?}");
        assert_eq!(
            std::fs::read(fixture.path().join("victim")).unwrap(),
            b"stays"
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
        // A wrong arch never deletes: an unknown token gets ENOSYS, and so do
        // a compat ABI's deletes (seccomp-orch-4: only those) instead of
        // silent passage.
        assert_eq!(run_filter(&prog, 0, 87), SECCOMP_RET_ERRNO_ENOSYS);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            run_filter(&prog, AUDIT_ARCH_I386, 10),
            SECCOMP_RET_ERRNO_ENOSYS
        );
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
