use std::ffi::OsString;
use std::process::Command;

use ptrace_playground::{Args, rootless_chroot};

fn main() {
    let mut cli = std::env::args_os();
    let _exe = cli.next();

    if let Some(mode) = cli.next() {
        if mode == "--run-rootless" {
            let rootfs = cli.next().expect("missing rootfs");

            // Optional: --shim <path>
            let mut shim: Option<OsString> = None;
            let mut prog: Option<OsString> = None;
            let mut rest: Vec<OsString> = Vec::new();
            while let Some(arg) = cli.next() {
                if prog.is_none() && arg == "--shim" {
                    shim = Some(cli.next().expect("missing --shim value"));
                    continue;
                }
                if prog.is_none() {
                    prog = Some(arg);
                    continue;
                }
                rest.push(arg);
            }

            let prog = prog.expect("missing command");
            let mut command = Command::new(prog);
            command.args(rest);

            rootless_chroot(Args {
                command,
                rootfs: rootfs.to_string_lossy().to_string(),
                binds: vec![],
                shim_exe: shim,
                log: None,
            });
            return;
        }
    }

    // Convenience default if run without args.
    let mut command = Command::new("ls");
    command.arg("/src");

    rootless_chroot(Args {
        command,
        rootfs: ".".to_string(),
        binds: vec![],
        shim_exe: None,
        log: None,
    });
}
