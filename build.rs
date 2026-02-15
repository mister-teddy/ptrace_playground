fn main() {
    // `loader_shim` defines its own `_start` and doesn't want the platform CRT `_start`.
    // This keeps the main binary (`ptrace_playground`) using the normal Rust startup.
    println!("cargo:rustc-link-arg-bin=loader_shim=-nostartfiles");
    println!("cargo:rustc-link-arg-bin=loader_shim=-static");
    // Android's linker64 rejects non-PIE executables (ET_EXEC). Keep loader_shim as PIE (ET_DYN).
    println!("cargo:rustc-link-arg-bin=loader_shim=-Wl,-pie");
    println!("cargo:rustc-link-arg-bin=loader_shim=-Wl,-e,_start");
}
