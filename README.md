# ptrace_playground

ptrace-based "rootless chroot" for Android/Termux (AArch64) plus a tiny loader-shim that can hand off into a glibc `ld-linux-*.so` without keeping Android's `linker64` runtime mapped.

## Library Usage

1. Add the crate to your project (path example):

```sh
cargo add ptrace_playground --path ../ptrace_playground
```

2. Build the loader-shim binary (you will pass its path to the library, or set an env var):

```sh
cargo build -p ptrace_playground --bin loader_shim --release
```

3. Call `rootless_chroot(Args { .. })`:

```rust
use std::process::Command;

use ptrace_playground::{Args, rootless_chroot};

fn main() {
    let mut cmd = Command::new("/usr/bin/pacman");
    cmd.arg("-V");

    rootless_chroot(Args {
        command: cmd,
        rootfs: "./archfs".to_string(),
        binds: vec![
            // (host_path, guest_path)
            ("/data/data/com.termux/files/home".to_string(), "/hosthome".to_string()),
        ],
        // Option A: pass the shim path explicitly
        shim_exe: Some("./target/release/loader_shim".into()),
        // Option B: omit this and set `PTRACE_PLAYGROUND_SHIM=/abs/path/to/loader_shim`
        log: None,
    });
}
```

Notes:
- The API takes a `std::process::Command`; `rootless_chroot` will set `cwd` to `rootfs` and ptrace-trace the child.
- On Android, dynamically-linked glibc binaries should be executed via `loader_shim`. Statically-linked binaries can run without it.

## Shipping The Loader-Shim With The Library

On stable Cargo, a library dependency cannot reliably force its *binary targets* (like `loader_shim`) to be built and made available to downstream crates. That leaves a few practical options:

1. **"Bring your own shim" (current model, stable)**
   - You ship `loader_shim` as a separate executable alongside your app, and pass its path via `Args { shim_exe: ... }` (or `PTRACE_PLAYGROUND_SHIM`).
   - This is the simplest and most portable option with stable tooling.

2. **Out-of-band install (stable)**
   - Ask users to install the shim once, then discover it at runtime:
     - `cargo install ptrace_playground --bin loader_shim`
     - or package it in your APK/Termux package.

3. **Embed prebuilt shim bytes (stable, you own the matrix)**
   - You can `include_bytes!()` a prebuilt `loader_shim` for *specific* targets you care about (e.g. Android aarch64), then at runtime write it to a temp file and `execve()` it.
   - Tradeoff: you must produce/update binaries for each supported target and handle executable permissions.

4. **Nightly Cargo artifact dependencies (best ergonomics, not stable)**
   - With nightly `-Z bindeps` / artifact dependencies, a library can depend on a binary and get its path during build.
   - This can enable a clean "just depend on the crate" experience, but requires opting into nightly tooling.

5. **Build the shim in `build.rs` (possible, but generally discouraged)**
   - A `build.rs` could invoke `rustc` itself to build `loader_shim` and stash it into `OUT_DIR`.
   - Tradeoff: more fragile (toolchain probing, flags, reproducibility) and easy to break across environments.

If you tell me which packaging target you want (Termux-only? APK? crates.io?), I can wire up one of the stable approaches (usually #1 or #3) and add a helper API like `ensure_loader_shim()`.
