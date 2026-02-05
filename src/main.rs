use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread,
};

use nix::{
    sys::{ptrace, wait},
    unistd::Pid,
};

fn main() {
    let mut command = Command::new("ls");
    command.arg("/");
    command.stdout(Stdio::piped());
    unsafe {
        command.pre_exec(|| Ok(ptrace::traceme()?));
    }
    let child = command.spawn().unwrap();
    let pid = Pid::from_raw(child.id() as i32);
    println!("{:?}", pid);
    thread::spawn(move || {
        loop {
            wait::wait().unwrap();
            println!("Waited!");
            ptrace::cont(pid, None).unwrap();
        }
    });
    let output = child.wait_with_output().unwrap();
    println!("Output: {:?}", output);
}
