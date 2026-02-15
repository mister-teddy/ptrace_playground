# TODO: 100% chroot-compatible semantics (ptrace/rootless)

## Status (already done)
- [x] Library API: move ptrace rootless-chroot into `src/rootless.rs`, export `Args` + `rootless_chroot`, keep `src/main.rs` as a thin CLI wrapper. (commit `e257b10`)
- [x] Loader-shim startup model: custom `_start`, unmap Android `linker64`, reset signal handlers, install private `rt_sigreturn` restorer, set guest TLS before jumping into glibc `ld-linux`. (commit `553479b`)
- [x] End-to-end tests: `pacman -V` and a network test (`pacman -Syy` + `pacman -Ss '^bash$'`) in the Arch aarch64 rootfs. (commit `0e128ba`)

Target: indistinguishable from `chroot(rootfs)` for all observable filesystem path behavior from inside the guest process tree, to the extent the kernel would behave under a real chroot by the same uid/gid and mount namespace.

This implies:
- Every syscall that can accept a path (directly or indirectly) must behave like it would inside a real chroot.
- Path resolution must match kernel rules: cwd, dirfd, symlinks (absolute/relative), `..`, follow/no-follow flags, and race behavior as closely as possible.
- No path “escapes” via absolute symlink targets, `/proc/self/fd`, `/proc/self/exe`, `/proc/self/cwd`, `*at(dirfd=...)`, etc.
- Returned paths (e.g. `getcwd`, readlink results from `/proc`) must not leak the host prefix.

Non-goals (still true under real `chroot` too):
- You do not gain privilege; mount syscalls still fail unless they would succeed normally.
- UID/GID remain the same unless you also implement `setuid` behavior (not part of chroot).

---

## 0. Define an oracle for “100%”
1. Build a reference runner using a *real* `chroot` on Linux (rooted environment / container) with the same rootfs.
2. For each test case below, capture:
   - syscall return values
   - errno
   - side effects (created files, link contents)
3. Your ptrace implementation must match oracle outputs for every case.

---

## 1. Full syscall surface inventory (must be exhaustive)
Task: enumerate and implement handling for *all* Linux syscalls that:
- take a pathname (string pointer), OR
- take a `struct` containing a pathname, OR
- accept `fd` that can be a “path fd” (`open_by_handle_at`, `*at` dirfds), OR
- return a pathname that must be guest-relative.

Start with the kernel’s syscall table for the arch (aarch64) and classify:
- Path input syscalls (one or more paths)
- Path output syscalls (`getcwd`, `readlink*`, `/proc` readlink emulation impact)
- “Path-like” syscalls using fd indirection

Deliverable: `SYSCALLS.md` listing each syscall and one of:
- “handled (emulated/translated)”
- “pass-through (safe)”
- “blocked (and must match chroot errno)”
with rationale.

---

## 2. Implement kernel-faithful path resolution in userspace (PRoot-grade)
Implement a resolver that matches the kernel’s VFS rules:

`resolve(state, dirfd, path, flags, op_kind) -> { host_path, guest_path, metadata }`

Requirements (no “best effort”):
- Correct parsing and normalization rules:
  - multiple slashes, trailing slashes, empty path with `AT_EMPTY_PATH`
  - dot and dotdot handling; prevent escaping guest root on `..` (like chroot)
- Correct base selection:
  - absolute path starts from guest `/`
  - relative starts from guest cwd
  - `*at` uses `dirfd` base when `dirfd != AT_FDCWD`
- Correct symlink handling:
  - component-by-component walk
  - absolute symlink target restarts from guest `/`
  - relative symlink target splices into current path
  - enforce max symlink depth (same limit as kernel, typically 40)
  - respect:
    - `O_NOFOLLOW`
    - `AT_SYMLINK_NOFOLLOW`
    - `AT_SYMLINK_FOLLOW`
    - operations that require “don’t follow final component” (create/unlink/rename patterns)
- Correct trailing-slash semantics (must error on non-dir)
- Correct error/errno mapping (ENOENT, ELOOP, ENOTDIR, EACCES, etc.)
- Correct race semantics as close as possible:
  - where kernel would be subject to TOCTOU, your resolver must not invent impossible results
  - prefer fd-based walking when possible (see next section)

Deliverable: `resolver.rs` with unit tests matching the oracle.

---

## 3. Make it race-correct: fd-based walking (openat2/RESOLVE_*)
For 100% compatibility you eventually need fd-based resolution rather than string-rewrite-only.

Tasks:
- If kernel supports `openat2`, use it for resolving and enforcing:
  - `RESOLVE_BENEATH`
  - `RESOLVE_NO_MAGICLINKS`
  - `RESOLVE_NO_SYMLINKS` (when needed)
  - `RESOLVE_NO_XDEV` (if binds emulate mounts)
- When not available, emulate using iterative `openat` + `O_PATH` + `fstat` + `readlinkat`:
  - walk each component with a directory fd
  - never depend on host-global `/` once resolution begins
- Maintain correct semantics for:
  - `..` and symlink interactions
  - final-component follow rules per operation

Deliverable: “fd-walk” resolver mode used for all operations where possible.

---

## 4. Fully emulate `dirfd` behavior (stateful fd tracking)
A real chroot heavily uses `*at` syscalls; to be identical you must handle arbitrary `dirfd`.

Tasks:
- Maintain fd table:
  - track directory fds (including `O_PATH` fds)
  - track cwd changes via `chdir` and `fchdir`
  - track fd duplication: `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD/F_DUPFD_CLOEXEC)`
  - track closure: `close`
- For unknown fds:
  - resolve via `/proc/<pid>/fd/<n>` readlink, but ensure guest semantics (see /proc section)

Deliverable: `fd_table.rs` with oracle-matching tests.

---

## 5. Implement translation/emulation for every path syscall
For each syscall, specify:
- which argument(s) are paths
- which follow/no-follow rules apply
- how many paths
- whether the syscall writes path data back

Key “must be correct” tricky ones:
- `symlinkat(target, newdirfd, linkpath)`:
  - translate linkpath location
  - DO NOT “host-translate” the link contents; link contents must remain guest-space
- `linkat`, `renameat2`:
  - two-path correctness and flags (`AT_SYMLINK_FOLLOW`, `RENAME_NOREPLACE`, etc.)
- `unlinkat` + `AT_REMOVEDIR`
- `mknodat` / device node behavior should match chroot environment (likely EPERM)
- `statx` flags and `AT_*` handling
- `openat2` struct parsing (if supported)
- `execveat` + `AT_EMPTY_PATH`
- `mkdirat` with trailing slash behavior

Deliverable: per-syscall handlers and tests.

---

## 6. Exec correctness (ELF, PT_INTERP, #!, argv0, auxv)
To be chroot-compatible, `execve("/bin/sh")` must behave as it would in chroot, including interpreter lookup.

Tasks:
- For `execve/execveat`:
  - resolve the executable path via resolver
  - handle `#!` scripts:
    - read first line, parse interpreter + optional arg
    - resolve interpreter inside guest root
    - preserve script path semantics
- For dynamic ELF:
  - ensure loader-shim path is used *only* as an implementation detail but guest semantics match:
    - correct `AT_EXECFN`, `argv[0]` expectations
    - correct error behavior if binary missing/interpreter missing
- Ensure env/cwd inheritance matches chroot.

Deliverable: exec tests against oracle.

---

## 7. /proc, /dev, and “magic links” must match chroot
Real chroot still sees host `/proc` if mounted, but the *paths returned* by proc magic links must not escape the chrooted view.

Tasks:
- Decide whether guest `/proc` is:
  1) bound from host `/proc` (most common), but then you must also:
     - intercept `readlink("/proc/self/cwd")`, `/proc/self/root`, `/proc/self/exe`, `/proc/self/fd/*` and rewrite outputs to guest paths
     - intercept `openat` of `/proc/self/fd/*` to prevent escape-by-fd-path
  2) fully virtualized `/proc` (harder)
- `/dev`:
  - ensure device node availability matches your environment (and chroot would see)
  - avoid inconsistent `/dev/random` expectations

Deliverable: proc/dev compatibility tests.

---

## 8. getcwd and other path-returning APIs
- `getcwd` must return guest path, not host prefix.
- `readlink*` results must be guest-correct (esp. /proc links).
- For errors, returned lengths must match kernel behavior.

Deliverable: path-return tests against oracle.

---

## 9. Make binds behave like mount binds (if you support binds)
If you support binds, the behavior must mirror bind mounts inside chroot, including:
- longest-prefix matching
- crossing bind boundaries with `..` and symlinks
- rename/link across bind boundaries (xdev behavior) consistent with a mount topology

This likely requires modeling a mount tree and enforcing `st_dev` cross-device semantics.

Deliverable: mount-model + bind tests.

---

## 10. Signals / seccomp / Android runtime interactions (don’t break correctness)
Chroot compatibility is meaningless if the process can’t start.

Tasks:
- Keep the existing “don’t rewrite syscalls originating from linker64 mappings” gating until loader-shim unmaps it.
- loader-shim:
  - must unmap linker64
  - must install SIGSYS restorer/handler for seccomp traps
  - must set guest-compatible TLS (TPIDR_EL0)
- Ensure tracer does not alter signal delivery semantics compared to chroot (beyond ptrace side effects).

Deliverable: stable execution of dynamic glibc workloads.

---

## 11. Oracle-grade test suite (this is what makes “100%” real)
Build a test harness that can run the same binary:
- once under real `chroot` (oracle)
- once under ptrace rootless chroot
and compares:
- return codes
- stdout/stderr
- filesystem effects
- errno for failing calls

Test categories:
- Path resolution matrix:
  - absolute/relative
  - cwd changes
  - dirfd variations
  - symlink targets absolute/relative
  - `..` interactions
  - trailing slashes
  - MAXSYMLINKS loops
- Two-path syscalls
- Proc magic links
- Real workloads:
  - `pacman -Syy`
  - `pacman -Ss '^bash$'`
  - `pacman -Sy curl` (download + signatures)
  - optional: install a small package and run it

Deliverable: `tests/oracle_*` and “compare mode” runner.

---

## 12. Documentation + invariants
- Document exact guarantees (no escapes, chroot parity).
- Document kernel feature detection (openat2 availability).
- Add debug tooling:
  - log unhandled path syscalls
  - log resolver decisions and symlink expansions
  - optional “strict mode” that aborts on any unhandled path syscall

Deliverable: `DOCS.md`, `SYSCALLS.md`, debug flags.
