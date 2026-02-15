use std::fs;
use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ptrace_playground")
}

fn shim() -> &'static str {
    env!("CARGO_BIN_EXE_loader_shim")
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
    let rootfs_dir = Path::new("archfs");
    let archive_path = rootfs_dir.join("ArchLinuxARM-aarch64-latest.tar.gz");
    let url = "http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz";

    fs::create_dir_all(rootfs_dir).unwrap();
    if !rootfs_dir.join("usr/bin/pacman").exists() {
        if !archive_path.exists() {
            download_arch_rootfs(url, &archive_path);
        }
        extract_rootfs(&archive_path, rootfs_dir);
    }

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
