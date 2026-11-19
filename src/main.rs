mod cmd; mod config; mod ctx; mod pkg; mod preflight; mod prompt; mod runner; mod steps; mod util; mod watch;

use std::{env, ffi::CString, os::unix::{fs::PermissionsExt, process::CommandExt}, process::exit};

fn usage() { println!("Usage: paranoia [--no-apt|--report-only] [--no-passwords] [--strict] [--passwords-fd=N] [--watch[=SECS]]\n  --no-apt        make no package changes, log what would be done\n  --no-passwords  skip the password prompts\n  --passwords-fd=N  read user password then root password (one per line) from fd N, no prompts\n  --strict        verify critical packages against freshly downloaded signed .debs\n  --watch[=SECS]  after the run, re-check every SECS (default 60) and print new findings"); }

/// Invoking user from SUDO_USER, else the kernel loginuid (not env-spoofable).
fn invoking_user() -> String {
    if let Ok(u) = env::var("MH_USER") { return u; }
    if let Ok(u) = env::var("SUDO_USER") { if !u.is_empty() { return u; } }
    let uid = std::fs::read_to_string("/proc/self/loginuid").unwrap_or_default().trim().to_string();
    let pw = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    pw.lines().find_map(|l| { let f: Vec<&str> = l.split(':').collect(); (f.len() > 2 && f[2] == uid).then(|| f[0].to_string()) })
        .unwrap_or_default()
}

fn harden_process() {
    unsafe {
        for s in [libc::SIGHUP, libc::SIGPIPE, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] { libc::signal(s, libc::SIG_IGN); }
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0); // keep typed passwords out of ptrace/core dumps
    }
}

/// Self-chmod (downloaded file has no +x), then re-exec through sudo or pkexec.
fn elevate(args: &[String]) -> ! {
    let exe = std::fs::read_link("/proc/self/exe").unwrap_or_default();
    let _ = std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755));
    for tool in ["/usr/bin/sudo", "/usr/bin/pkexec"] {
        if std::path::Path::new(tool).exists() {
            let mut c = std::process::Command::new(tool);
            c.env_clear().env("TERM", env::var("TERM").unwrap_or_else(|_| "xterm".into())).arg(&exe).args(args);
            eprintln!("{tool}: {}", c.exec());
        }
    }
    eprintln!("Need root and neither sudo nor pkexec worked.");
    exit(1)
}

/// Copy ourselves into a memfd and exec from it: later package reinstalls or disk tampering cannot affect the running copy.
fn reexec_from_memfd(args: &[String], user: &str) {
    let Ok(bin) = std::fs::read("/proc/self/exe") else { return };
    unsafe {
        let name = CString::new("mh").unwrap();
        let fd = libc::memfd_create(name.as_ptr(), 0);
        if fd < 0 { return; }
        let mut off = 0usize;
        while off < bin.len() {
            let n = libc::write(fd, bin[off..].as_ptr() as *const libc::c_void, bin.len() - off);
            if n <= 0 { libc::close(fd); return; }
            off += n as usize;
        }
        let a0 = CString::new("paranoia").unwrap();
        let cargs: Vec<CString> = args.iter().filter_map(|a| CString::new(a.as_str()).ok()).collect();
        let mut argv: Vec<*const libc::c_char> = vec![a0.as_ptr()];
        argv.extend(cargs.iter().map(|c| c.as_ptr()));
        argv.push(std::ptr::null());
        let envs: Vec<CString> = [
            "MH_MEMFD=1".to_string(), format!("MH_USER={user}"),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            "HOME=/root".into(), "LANG=C.UTF-8".into(),
            format!("TERM={}", env::var("TERM").unwrap_or_else(|_| "xterm".into())),
        ].iter().filter_map(|e| CString::new(e.as_str()).ok()).collect();
        let mut envp: Vec<*const libc::c_char> = envs.iter().map(|c| c.as_ptr()).collect();
        envp.push(std::ptr::null());
        libc::syscall(libc::SYS_execveat, fd, b"\0".as_ptr(), argv.as_ptr(), envp.as_ptr(), libc::AT_EMPTY_PATH);
        libc::close(fd); // only reached if exec failed; carry on from disk copy
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (mut no_pkg, mut no_pw, mut strict, mut watch, mut pwfd) = (false, false, false, 0u64, -1i32);
    for a in &args {
        match a.as_str() {
            "--no-apt" | "--report-only" => no_pkg = true,
            "--no-passwords" => no_pw = true,
            "--strict" => strict = true,
            w if w.starts_with("--passwords-fd=") => pwfd = w[15..].parse().unwrap_or(-1),
            "--watch" => watch = 60,
            w if w.starts_with("--watch=") => watch = w[8..].parse().unwrap_or(60).max(10),
            "-h" | "--help" => { usage(); return; }
            o => { eprintln!("Unknown option: {o}"); exit(1); }
        }
    }
    harden_process();
    if unsafe { libc::geteuid() } != 0 { elevate(&args); }
    let user = invoking_user();
    if env::var_os("MH_MEMFD").is_none() { reexec_from_memfd(&args, &user); }

    let ctx = match ctx::Ctx::new(no_pkg, user) {
        Ok(c) => c,
        Err(e) => { eprintln!("cannot create work dir: {e}"); exit(1); }
    };
    if no_pkg { println!("NOTICE: --no-apt: NO package changes will be made. Repairs needing apt are only logged (REPORT-ONLY lines in the final report)."); }
    else { println!("NOTICE: apt-get runs in several steps (reinstalls, snap removal, targeted security upgrade). Steps may pause for the dpkg lock. Do not interrupt."); }
    println!("If this terminal drops the run continues (SIGHUP ignored). Reattach with: tail -f {}/main.log\n", ctx.work.display());
    steps::audit::apt_hooks(&ctx);
    println!("Fixing network (before any apt or DNS use)");
    let _ = steps::network::run(&ctx);
    // stop Ubuntu's own apt jobs (they hold the dpkg lock) and disable apt retries (CVE-2026-109518)
    cmd::run_t("systemctl", &["stop", "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service", "unattended-upgrades.service", "packagekit.service"], 60);
    let _ = std::fs::write("/etc/apt/apt.conf.d/99-no-retries", "Acquire::Retries \"0\";\n");
    ctx.reindex();
    println!("Cleaning shell environment (before pre-flight)");
    if let Err(e) = steps::shell::run(&ctx) { ctx.warn(format!("shell reset failed: {e}")); }
    if !preflight::run(&ctx) { println!("Aborted before password entry."); exit(1); }
    if !no_pw {
        let (u, r) = if pwfd >= 0 { prompt::from_fd(pwfd) } else { (prompt::new_password(&ctx.user), prompt::new_password("root")) };
        if u.is_none() || r.is_none() { eprintln!("No tty for password prompts (use --passwords-fd=N or --no-passwords)."); exit(1); }
        *ctx.pw_user.lock().unwrap() = u;
        *ctx.pw_root.lock().unwrap() = r;
    }
    println!("paranoia: {} step(s), no_pkg={}", steps::all(strict).len(), no_pkg);
    runner::run_all(&ctx, &steps::all(strict));
    runner::report(&ctx);
    if watch > 0 { watch::run(&ctx, watch); }
}
