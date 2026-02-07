use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::ptrace::AddressType;
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use nix::unistd::read as nix_read;
use std::{cmp, fs, mem};
use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

pub struct Args<'a> {
    pub command: Command,
    pub binds: Vec<(String, String)>,
    pub log: Option<Box<dyn FnMut(String) + 'a>>,
}

fn spawn_traced<'a>(mut args: Args<'a>) {
    // Build binds
    let binds = args.binds;

    // Build the command
    let mut command = args.command;

    // Pipe stdout to Rust
    command.stdout(Stdio::piped());

    // PTRACE_TRACE_ME
    unsafe {
        command.pre_exec(|| Ok(ptrace::traceme()?));
    }

    // Spawn it
    let mut child = command.spawn().unwrap();
    let pid = Pid::from_raw(child.id() as i32);

    // Make stdout non-blocking
    let mut stdout = child.stdout.take().unwrap();
    let flags = OFlag::from_bits_truncate(fcntl(&stdout, FcntlArg::F_GETFL).unwrap());
    fcntl(&stdout, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();

    // Wait for the initial exec stop and enable syscall-stops.
    wait::waitpid(pid, None).unwrap();
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap();
    ptrace::syscall(pid, None).unwrap();

    // Prepare to read stdout non-blockingly
    let mut buf = [0u8; 4096];
    let mut carry = String::new();
    let mut in_syscall = false;
    loop {
        match wait::waitpid(pid, None) {
            Ok(wait::WaitStatus::PtraceSyscall(_)) => {
                drain_stdout(&mut stdout, &mut buf, &mut carry, &mut args.log);

                if !in_syscall {
                    if let Err(e) = rewrite_syscall_path(pid, &binds) {
                        eprintln!("rewrite error: {e}");
                    }
                }
                in_syscall = !in_syscall;
                ptrace::syscall(pid, None).unwrap();
            }
            Ok(wait::WaitStatus::Stopped(_, sig)) => {
                drain_stdout(&mut stdout, &mut buf, &mut carry, &mut args.log);
                ptrace::syscall(pid, Some(sig)).unwrap();
            }
            Ok(wait::WaitStatus::Exited(_, _)) | Ok(wait::WaitStatus::Signaled(_, _, _)) => {
                drain_stdout(&mut stdout, &mut buf, &mut carry, &mut args.log);
                break;
            }
            Ok(_) => {
                ptrace::syscall(pid, None).unwrap();
            }
            Err(e) => {
                println!("{e:?}");
                break;
            }
        }
    }

    // The end
    println!("Finished!");
}

fn drain_stdout<'a>(
    stdout: &mut std::process::ChildStdout,
    buf: &mut [u8],
    carry: &mut String,
    log: &mut Option<Box<dyn FnMut(String) + 'a>>,
) {
    loop {
        match nix_read(&mut *stdout, buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                carry.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(pos) = carry.find('\n') {
                    let line = carry[..pos].trim_end_matches('\r');
                    if let Some(log) = log.as_mut() {
                        log(line.to_string());
                    } else {
                        println!("{line}");
                    }
                    carry.drain(..=pos);
                }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                break; // nothing available right now -> don't block
            }
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }
}

fn rewrite_syscall_path(pid: Pid, binds: &[(String, String)]) -> nix::Result<()> {
    let Some((syscall, args)) = read_syscall_from_proc(pid)? else {
        return Ok(());
    };

    let path_addr = match syscall as i64 {
        nix::libc::SYS_openat => Some(args[1] as usize),
        nix::libc::SYS_execve => Some(args[0] as usize),
        nix::libc::SYS_execveat => Some(args[1] as usize),
        nix::libc::SYS_statx => Some(args[1] as usize),
        _ => None,
    };

    let Some(addr) = path_addr else {
        return Ok(());
    };

    let path_bytes = read_cstring(pid, addr)?;
    let path = String::from_utf8_lossy(&path_bytes);
    let Some(mapped) = apply_binds(&path, binds) else {
        return Ok(());
    };

    if requires_existing_path(syscall, &args) && !mapped_path_exists(pid, &mapped) {
        return Ok(());
    }

    let mut mapped_bytes = mapped.as_bytes().to_vec();
    mapped_bytes.push(0);
    if mapped_bytes.len() > path_bytes.len() + 1 {
        return Ok(());
    }

    let mut padded = vec![0u8; path_bytes.len() + 1];
    padded[..mapped_bytes.len()].copy_from_slice(&mapped_bytes);
    write_bytes(pid, addr, &padded)?;
    Ok(())
}

fn apply_binds(path: &str, binds: &[(String, String)]) -> Option<String> {
    let mut best: Option<(&str, &str)> = None;
    for (from, to) in binds {
        if path_matches_prefix(path, from) {
            if best.is_none() || from.len() > best.unwrap().0.len() {
                best = Some((from.as_str(), to.as_str()));
            }
        }
    }

    let (from, to) = best?;
    let mut rest = &path[from.len()..];
    if to == "." {
        let trimmed = rest.trim_start_matches('/');
        return if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    let mut mapped = to.to_string();
    if mapped.ends_with('/') && rest.starts_with('/') {
        rest = rest.trim_start_matches('/');
    }
    if !rest.is_empty() {
        if !mapped.ends_with('/') && !rest.starts_with('/') {
            mapped.push('/');
        }
        mapped.push_str(rest);
    }
    if mapped == path { None } else { Some(mapped) }
}

fn requires_existing_path(syscall: u64, args: &[u64; 6]) -> bool {
    match syscall as i64 {
        nix::libc::SYS_execve | nix::libc::SYS_execveat | nix::libc::SYS_statx => true,
        nix::libc::SYS_openat => {
            let flags = args[2] as i32;
            (flags & nix::fcntl::OFlag::O_CREAT.bits()) == 0
        }
        _ => false,
    }
}

fn mapped_path_exists(pid: Pid, mapped: &str) -> bool {
    let path = if mapped.starts_with('/') {
        mapped.to_string()
    } else {
        let cwd = fs::read_link(format!("/proc/{}/cwd", pid)).unwrap_or_default();
        cwd.join(mapped).to_string_lossy().to_string()
    };
    fs::metadata(path).is_ok()
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    if prefix.ends_with('/') || path.len() == prefix.len() {
        return true;
    }
    path.as_bytes().get(prefix.len()) == Some(&b'/')
}

fn read_cstring(pid: Pid, addr: usize) -> nix::Result<Vec<u8>> {
    let word_size = mem::size_of::<nix::libc::c_long>();
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        if out.len() > 4096 {
            return Err(nix::Error::from(nix::errno::Errno::ENAMETOOLONG));
        }
        let word = ptrace::read(pid, (addr + offset) as AddressType)? as usize;
        let bytes = word.to_ne_bytes();
        for i in 0..word_size {
            let b = bytes[i];
            if b == 0 {
                return Ok(out);
            }
            out.push(b);
        }
        offset += word_size;
    }
}

fn write_bytes(pid: Pid, addr: usize, data: &[u8]) -> nix::Result<()> {
    let word_size = mem::size_of::<nix::libc::c_long>();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = cmp::min(offset + word_size, data.len());
        let mut word_bytes = vec![0u8; word_size];
        if end - offset < word_size {
            let existing = ptrace::read(pid, (addr + offset) as AddressType)? as usize;
            let existing_bytes = existing.to_ne_bytes();
            word_bytes.copy_from_slice(&existing_bytes[..word_size]);
        }
        word_bytes[..(end - offset)].copy_from_slice(&data[offset..end]);
        let mut full = [0u8; mem::size_of::<usize>()];
        full[..word_size].copy_from_slice(&word_bytes);
        let word = usize::from_ne_bytes(full) as nix::libc::c_long;
        ptrace::write(pid, (addr + offset) as AddressType, word)?;
        offset += word_size;
    }
    Ok(())
}

fn read_syscall_from_proc(pid: Pid) -> nix::Result<Option<(u64, [u64; 6])>> {
    let path = format!("/proc/{}/syscall", pid);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Ok(None),
    };
    let mut parts = content.split_whitespace();
    let sysno = match parts.next().and_then(parse_num) {
        Some(value) => value,
        None => return Ok(None),
    };
    let mut args = [0u64; 6];
    for slot in &mut args {
        if let Some(value) = parts.next().and_then(parse_num) {
            *slot = value;
        }
    }
    Ok(Some((sysno, args)))
}

fn parse_num(value: &str) -> Option<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

fn main() {
    let mut command = Command::new("ls");
    command.arg("/src");

    spawn_traced(Args {
        command,
        binds: vec![("/".to_string(), ".".to_string())],
        log: None,
    });
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use crate::spawn_traced;

    #[test]
    fn can_ls_root() {
        let mut command = Command::new("ls");
        command.arg("/src");

        let mut res = Vec::new();
        spawn_traced(super::Args {
            command,
            binds: vec![("/".to_string(), ".".to_string())],
            log: Some(Box::new(|line| {
                res.push(line);
            })),
        });

        assert_eq!(res, vec!["main.rs"]);
    }
}
