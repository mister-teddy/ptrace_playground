use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ptrace_playground")
}

fn shim() -> &'static str {
    env!("CARGO_BIN_EXE_loader_shim")
}

fn archfs_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn ensure_archfs_ready(rootfs_dir: &Path) {
    let archive_path = rootfs_dir.join("ArchLinuxARM-aarch64-latest.tar.gz");
    let url = "http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz";

    fs::create_dir_all(rootfs_dir).unwrap();
    if !rootfs_dir.join("usr/bin/pacman").exists() {
        if !archive_path.exists() {
            download_arch_rootfs(url, &archive_path);
        }
        extract_rootfs(&archive_path, rootfs_dir);
    }
}

fn ensure_resolv_conf(rootfs_dir: &Path) {
    let etc = rootfs_dir.join("etc");
    fs::create_dir_all(&etc).unwrap();
    let resolv = etc.join("resolv.conf");
    // Arch rootfs commonly ships `/etc/resolv.conf` as a symlink (e.g. into systemd-resolved).
    // In our test rootfs that target typically doesn't exist, which breaks any networked workload
    // (pacman will fail on DNS). In a real chroot setup, users usually provide a working resolv.conf,
    // so the test enforces that invariant.
    if let Ok(meta) = fs::symlink_metadata(&resolv) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(&resolv);
        }
    }
    if !resolv.exists() {
        // Enough for pacman/libcurl DNS on most networks; avoid depending on host file locations.
        fs::write(&resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n").unwrap();
    }
}

#[test]
fn can_ls_root() {
    let out = Command::new(bin())
        .args(["--run-rootless", ".", "ls", "/src"])
        .env("PTRACE_PLAYGROUND_SHIM", shim())
        .output()
        .expect("run binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("main.rs"), "stdout was:\n{stdout}");
}

#[test]
fn can_run_pacman_version_in_archlinux_arm64_rootfs() {
    // If another test panicked while holding the lock, don't permanently brick the suite.
    let _guard = archfs_lock().lock().unwrap_or_else(|e| e.into_inner());
    let rootfs_dir = Path::new("archfs");
    ensure_archfs_ready(rootfs_dir);

    let out = Command::new(bin())
        .args(["--run-rootless", "archfs", "/usr/bin/pacman", "-V"])
        .env("PTRACE_PLAYGROUND_SHIM", shim())
        .output()
        .expect("run pacman under rootless");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("{}", stdout);
    assert!(
        stdout.contains("Pacman v") || stdout.contains("pacman v"),
        "stdout was:\n{stdout}"
    );
}

#[test]
fn can_pacman_sync_search_over_network() {
    let _guard = archfs_lock().lock().unwrap_or_else(|e| e.into_inner());
    let rootfs_dir = Path::new("archfs");
    ensure_archfs_ready(rootfs_dir);
    ensure_resolv_conf(rootfs_dir);

    let out = Command::new(bin())
        .args(["--run-rootless", "archfs", "/usr/bin/pacman", "-Syy"])
        .env("PTRACE_PLAYGROUND_SHIM", shim())
        .env("PTRACE_PLAYGROUND_FAKE_ROOT", "1")
        .output()
        .expect("run pacman -Syy under rootless");
    assert!(
        out.status.success(),
        "pacman -Syy failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(bin())
        .args(["--run-rootless", "archfs", "/usr/bin/pacman", "-Ss", "^bash$"])
        .env("PTRACE_PLAYGROUND_SHIM", shim())
        .output()
        .expect("run pacman -Ss under rootless");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "pacman -Ss failed.\nstdout:\n{}\nstderr:\n{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("core/bash") || stdout.contains("/bash "),
        "stdout was:\n{stdout}"
    );
}

fn download_arch_rootfs(url: &str, archive_path: &Path) {
    let archive = archive_path.to_string_lossy().to_string();
    let curl_status = Command::new("curl")
        .args(["-L", "--fail", "--retry", "3", "-o", &archive, url])
        .status();
    match curl_status {
        Ok(status) if status.success() => return,
        Ok(status) => panic!("curl failed downloading {url} with status {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => panic!("failed to execute curl: {err}"),
    }

    let wget_status = Command::new("wget")
        .args(["-O", &archive, url])
        .status()
        .unwrap_or_else(|err| panic!("failed to execute wget: {err}"));
    assert!(wget_status.success(), "wget failed downloading {url}");
}

fn extract_rootfs(archive_path: &Path, rootfs_dir: &Path) {
    let status = Command::new("tar")
        .arg("-xpf")
        .arg(archive_path)
        .arg("-C")
        .arg(rootfs_dir)
        .status()
        .unwrap_or_else(|err| panic!("failed to execute tar for extraction: {err}"));
    assert!(status.success(), "tar extraction failed");
}
