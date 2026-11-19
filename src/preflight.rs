//! Keylogger/rootkit checks that run before any password is typed.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};
use std::{collections::HashSet, fs, path::Path};

fn pids() -> Vec<u32> {
    fs::read_dir("/proc").into_iter().flatten().flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok()).collect()
}
fn exe(pid: u32) -> String { fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default() }
fn comm(pid: u32) -> String { util::read(&format!("/proc/{pid}/comm")).trim().to_string() }

fn preload(c: &Ctx) {
    let t = util::read("/etc/ld.so.preload");
    if !t.trim().is_empty() { c.finding(format!("/etc/ld.so.preload existed (removed): {}", t.replace('\n', " "))); }
    util::chattr("/etc/ld.so.preload", false);
    let _ = fs::remove_file("/etc/ld.so.preload");
    for p in pids() {
        if let Ok(e) = fs::read(format!("/proc/{p}/environ")) {
            if e.split(|b| *b == 0).any(|v| v.starts_with(b"LD_PRELOAD=")) { c.finding(format!("pid {p} ({}) has LD_PRELOAD set", exe(p))); }
        }
    }
}

fn ptrace(c: &Ctx) {
    for p in pids() {
        let st = util::read(&format!("/proc/{p}/status"));
        let Some(tr) = st.lines().find_map(|l| l.strip_prefix("TracerPid:")).and_then(|x| x.trim().parse::<u32>().ok()) else { continue };
        if tr == 0 || c.is_ancestor(tr) { continue; }
        c.finding(format!("pid {p} ({}) is traced by pid {tr} ({}), killing tracer", comm(p), exe(tr)));
        unsafe { libc::kill(tr as i32, libc::SIGKILL); }
    }
}

fn sniffers(c: &Ctx) {
    for p in pids() {
        if c.is_ancestor(p) || !cf::TTY_SNIFFERS.contains(&comm(p).as_str()) { continue; }
        c.finding(format!("tty/key logger process killed: pid {p} ({})", comm(p)));
        unsafe { libc::kill(p as i32, libc::SIGKILL); }
    }
    for f in util::files_in("/etc/pam.d") {
        for l in util::read(&f.to_string_lossy()).lines() {
            if l.contains("pam_tty_audit") { c.finding(format!("pam_tty_audit in use: {}: {l}", f.display())); }
        }
    }
}

fn pam_dirs() -> impl Iterator<Item = &'static str> { cf::PAM_DIRS.iter().copied().filter(|d| Path::new(d).is_dir()) }

fn pam_and_login(c: &Ctx) {
    let have: HashSet<String> = pkg::installed().into_iter().collect();
    let auth: Vec<String> = cf::AUTH_PACKAGES.iter().filter(|p| have.contains(**p)).map(|s| s.to_string()).collect();
    let bad = pkg::tampered(&auth);
    if !bad.is_empty() {
        let names: Vec<String> = bad.iter().map(|b| b.0.clone()).collect();
        if c.no_pkg {
            c.finding(format!("tampered auth packages, NOT reinstalled (--no-apt): {}", names.join(" ")));
        } else {
            c.finding(format!("tampered auth packages, reinstalling: {}", names.join(" ")));
            println!("  NOTICE: apt-get --reinstall on tampered packages (may wait for the dpkg lock)");
            let mut a = vec!["--reinstall", "install"]; a.extend(names.iter().map(|s| s.as_str()));
            c.log(&pkg::apt(&a, 0).text);
            for p in pkg::tampered(&names) { c.finding(format!("STILL TAMPERED after reinstall: {} ({})", p.0, p.1.first().cloned().unwrap_or_default())); }
        }
    }
    // every .so named in pam.d must exist and be packaged
    let mut mods = std::collections::BTreeSet::new();
    for f in util::files_in("/etc/pam.d") {
        for l in util::read(&f.to_string_lossy()).lines() {
            if l.trim_start().starts_with('#') { continue; }
            for w in l.split(|ch: char| !(ch.is_ascii_alphanumeric() || "_./-".contains(ch))) {
                if w.ends_with(".so") { mods.insert(w.to_string()); }
            }
        }
    }
    for m in mods {
        let path = if m.starts_with('/') { Some(m.clone()) } else { pam_dirs().map(|d| format!("{d}/{m}")).find(|p| Path::new(p).exists()) };
        match path {
            Some(p) if Path::new(&p).exists() => if !c.is_owned(&p) { c.finding(format!("unpackaged PAM module in use: {p}")); },
            _ => c.finding(format!("PAM module referenced but not found: {m}")),
        }
    }
    for d in pam_dirs() { for f in util::files_in(d) {
        let s = f.to_string_lossy().into_owned();
        if !c.is_owned(&s) { c.finding(format!("unpackaged file in PAM module dir: {s}")); }
    } }
}

fn kernel_modules(c: &Ctx) {
    let listed: HashSet<String> = util::read("/proc/modules").lines().filter_map(|l| l.split_whitespace().next().map(String::from)).collect();
    for m in &listed {
        let f = cmd::run("modinfo", &["-n", m]).text.trim().to_string();
        if f.starts_with('/') && !c.is_owned(&f) { c.finding(format!("kernel module not owned by a package: {m} ({f})")); }
    }
    // loaded per /sys/module but hidden from /proc/modules (rootkit hiding)
    for e in fs::read_dir("/sys/module").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if Path::new(&format!("/sys/module/{n}/initstate")).exists() && !listed.contains(&n) {
            c.finding(format!("module {n} is live in /sys/module but missing from /proc/modules"));
        }
    }
    let t: u64 = util::read("/proc/sys/kernel/tainted").trim().parse().unwrap_or(0);
    if t & (1 | 1 << 12 | 1 << 13) != 0 { c.warn(format!("PREFLIGHT info: kernel taint flags = {t} (proprietary/out-of-tree/unsigned module loaded)")); }
}

fn ebpf(c: &Ctx) {
    if cmd::find("bpftool").is_none() { return; }
    let n = cmd::run("bpftool", &["prog", "show"]).text.lines().filter(|l| l.chars().next().map_or(false, |x| x.is_ascii_digit())).count();
    if n > 0 { c.warn(format!("PREFLIGHT info: {n} eBPF programs loaded (systemd loads some), review with: bpftool prog show")); }
}

/// PIDs that answer kill(pid,0) but have no /proc entry. Rechecked once to dodge exit races.
fn hidden_pids(c: &Ctx) {
    let max: i32 = util::read("/proc/sys/kernel/pid_max").trim().parse().unwrap_or(32768).min(4_194_304);
    let alive = |p: i32| unsafe { libc::kill(p, 0) == 0 || *libc::__errno_location() == libc::EPERM };
    let cand: Vec<i32> = (2..=max).filter(|p| alive(*p) && !Path::new(&format!("/proc/{p}")).exists()).collect();
    if cand.is_empty() { return; }
    std::thread::sleep(std::time::Duration::from_millis(200));
    for p in cand { if alive(p) && !Path::new(&format!("/proc/{p}")).exists() { c.finding(format!("pid {p} exists (kill 0) but is hidden from /proc")); } }
}

fn harden() {
    let _ = fs::write("/proc/sys/kernel/yama/ptrace_scope", "2");
    let _ = fs::write("/proc/sys/dev/tty/legacy_tiocsti", "0"); // kernel 6.2+
}

/// Runs every check, then lets the user abort before any password is typed.
pub fn run(c: &Ctx) -> bool {
    println!("Pre-flight: keylogger/rootkit checks (before any password is typed)");
    std::thread::scope(|s| {
        s.spawn(|| kernel_modules(c));
        s.spawn(|| ebpf(c));
        s.spawn(|| hidden_pids(c));
        println!("  preload hooks");        preload(c);
        println!("  ptrace taps");          ptrace(c);
        println!("  tty sniffers");         sniffers(c);
        println!("  PAM and login binaries"); pam_and_login(c);
        println!("  ptrace/tty hardening"); harden();
    });
    let f = c.findings.lock().unwrap().clone();
    if f.is_empty() { println!("  clean.\n"); return true; }
    println!("\n--- Pre-flight findings ---");
    for l in &f { println!("{l}"); }
    println!();
    crate::prompt::confirm("Findings above. Enter passwords anyway? [y/N] ")
}

/// Cheap subset for --watch: no prompts, no package work.
pub fn quick(c: &Ctx) { preload(c); ptrace(c); sniffers(c); hidden_pids(c); }
