//! Password change, session kill, fish/root shell. (Original: step_change_passwords, step_kill_other_sessions,
//! step_install_fish, step_set_root_shell_to_fish.)
use crate::{cmd, ctx::Ctx, pkg, util};
use std::{collections::HashSet, fs};

pub fn passwords(c: &Ctx) -> Result<(), String> {
    let set = |user: &str, pw: Option<String>| match pw {
        Some(p) if !user.is_empty() && !user.contains(':') => {
            if !cmd::run_in("chpasswd", &[], &format!("{user}:{p}\n")).ok { c.warn(format!("password change failed for {user}")); }
        }
        _ => c.warn(format!("no password set for '{user}'")),
    };
    set(&c.user, c.pw_user.lock().unwrap().take());
    set("root", c.pw_root.lock().unwrap().take());
    Ok(())
}

pub struct Proc { pub pid: u32, pub ppid: u32, pub sid: u32, pub tty: u32, pub comm: String, pub uid: u32 }

pub fn procs() -> Vec<Proc> {
    let mut v = vec![];
    for e in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let s = util::read(&format!("/proc/{pid}/stat"));
        let (Some(a), Some(b)) = (s.find('('), s.rfind(')')) else { continue };
        let f: Vec<&str> = s[b + 1..].split_whitespace().collect(); // state ppid pgrp session tty_nr
        if f.len() < 5 { continue; }
        let uid = util::read(&format!("/proc/{pid}/status")).lines().find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|x| x.split_whitespace().next()?.parse().ok()).unwrap_or(0);
        v.push(Proc { pid, ppid: f[1].parse().unwrap_or(0), sid: f[3].parse().unwrap_or(0), tty: f[4].parse().unwrap_or(0),
                      comm: s[a + 1..b].to_string(), uid });
    }
    v
}

/// Everything the script must never kill: itself, descendants, own session, ancestors (weakness 10: no utmp, /proc only).
pub fn protected(c: &Ctx, ps: &[Proc]) -> HashSet<u32> {
    let me = std::process::id();
    let mut keep: HashSet<u32> = [me].into();
    loop {
        let n = keep.len();
        for p in ps { if keep.contains(&p.ppid) { keep.insert(p.pid); } }
        if keep.len() == n { break; }
    }
    if let Some(m) = ps.iter().find(|p| p.pid == me) { for p in ps { if p.sid == m.sid { keep.insert(p.pid); } } }
    keep.extend(c.ancestors.iter().copied());
    keep
}

pub fn kill_sessions(c: &Ctx) -> Result<(), String> {
    let ps = procs();
    let keep = protected(c, &ps);
    let ttys: HashSet<u32> = ps.iter().filter(|p| c.is_ancestor(p.pid) && p.tty != 0).map(|p| p.tty).collect();
    for p in &ps {
        if keep.contains(&p.pid) || p.pid == 1 { continue; }
        let major = (p.tty >> 8) & 0xff;
        let on_tty = p.tty != 0 && (major == 136 || major == 4) && !ttys.contains(&p.tty) && !["agetty", "getty", "login"].contains(&p.comm.as_str());
        // ttyless sessions: ssh -N, sshd session children, detached tmux/screen servers
        let cl = util::read(&format!("/proc/{}/cmdline", p.pid)).replace('\0', " ");
        let sshd_sess = p.comm == "sshd" && cl.starts_with("sshd: ") && !cl.contains("[listener]") && !cl.contains("[accepted]");
        let mux = (p.comm.starts_with("tmux") || p.comm.starts_with("screen") || p.comm == "SCREEN") && p.uid != 0;
        let user_ssh = p.comm == "ssh" && p.uid >= 1000;
        if on_tty || sshd_sess || mux || user_ssh {
            c.log(&format!("kill session proc {} ({}) uid {}", p.pid, p.comm, p.uid));
            unsafe { libc::kill(p.pid as i32, libc::SIGKILL); }
        }
    }
    Ok(())
}

pub fn install_fish(c: &Ctx) -> Result<(), String> {
    if c.no_pkg {
        if cmd::find("fish").is_none() { c.report_only("fish not installed, would run: apt-get update; apt-get install fish"); }
        c.report_only("apt itself should be upgraded (CVE-2026-109518), fixed: 2.4.15ubuntu0.1 (22.04) / 2.8.4ubuntu0.1 (24.04)");
    } else {
        if !pkg::apt(&["update"], 0).ok { c.warn("apt update failed"); }
        if !pkg::apt(&["install", "--only-upgrade", "apt"], 0).ok { c.warn("apt self-upgrade failed (CVE-2026-109518)"); }
        if !pkg::apt(&["install", "fish"], 0).ok { c.warn("fish install failed"); }
    }
    if let Some(f) = cmd::find("fish") {
        if !util::read("/etc/shells").lines().any(|l| l == f) {
            let mut t = util::read("/etc/shells"); t.push_str(&format!("{f}\n"));
            let _ = fs::write("/etc/shells", t);
        }
    }
    Ok(())
}

pub fn root_shell(c: &Ctx) -> Result<(), String> {
    match cmd::find("fish") {
        None => c.warn("fish not installed, root shell left unchanged"),
        Some(f) => if !cmd::run("chsh", &["-s", &f, "root"]).ok { c.warn("could not set root shell to fish") },
    }
    Ok(())
}
