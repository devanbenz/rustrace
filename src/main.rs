use std::{os::unix::process::CommandExt, collections::HashMap};
use nix::sys::wait::waitpid;
use owo_colors::OwoColorize;
use anyhow::Result;

fn main() -> Result<()> {
    let syscall_table = parse_syscalls_table()?;
    let mut command = std::process::Command::new("cat");
    command.arg("/etc/hosts");
    unsafe {
        command.pre_exec(|| {
            use nix::sys::ptrace::traceme;
            traceme().map_err(|e| e.into())
        });
    }

    let child = command.spawn().unwrap();
    let child_pid = nix::unistd::Pid::from_raw(child.id() as _);
    let res = nix::sys::wait::waitpid(child_pid, None).unwrap();
    eprintln!("waitpid result: {:?}", res.yellow());

    let mut is_sys_exit = false;
    loop {
        nix::sys::ptrace::syscall(child_pid, None)?;
        _ = waitpid(child_pid, None)?;
        if is_sys_exit {
            let regs = nix::sys::ptrace::getregs(child_pid)?;
            eprintln!("{}({:x}, {:x}, {:x}, ..) = {:x}",
            syscall_table[&regs.orig_rax].green(),
            regs.rdi.blue(),
            regs.rsi.blue(),
            regs.rdx.blue(),
            regs.rax.yellow(),
            );
        }
        is_sys_exit = !is_sys_exit;
    }
}

fn parse_syscalls_table() -> Result<HashMap<u64, String>> {
    let json: serde_json::Value = serde_json::from_str(include_str!("syscall.json"))?;
    let syscall_table: HashMap<u64, String> = json["aaData"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item[0].as_u64().unwrap(),
                item[1].as_str().unwrap().to_owned(),
            )
        })
    .collect();

    Ok(syscall_table)
}
