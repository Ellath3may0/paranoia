//! Dependency-aware parallel step runner with progress line, apt notices and final report.
use crate::ctx::Ctx;
use std::{collections::HashSet, io::Write, sync::{Condvar, Mutex}, time::{Duration, Instant}};

pub struct Step {
    pub name: &'static str,
    pub after: &'static [&'static str],
    pub apt: bool,
    pub run: fn(&Ctx) -> Result<(), String>,
}

static APT_LOCK: Mutex<()> = Mutex::new(());
static RUNNING: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static RESULTS: Mutex<Vec<(&'static str, Option<String>)>> = Mutex::new(Vec::new());

/// (description, estimated seconds on a 2 vCPU / 4 GB VM), from the original step table.
pub fn meta(name: &str) -> (&'static str, u64) {
    match name {
        "passwords" => ("Change user and root passwords", 2),
        "kill_sessions" => ("Kill other sessions", 2),
        "remote_tools" => ("Disable unscored remote access tools", 1),
        "integrity" => ("Binary integrity check", 8),
        "sysctl" => ("Apply sysctl hardening", 1),
        "lpe" => ("Temporary kernel LPE mitigations", 2),
        "fish" => ("apt update and install fish", 45),
        "root_shell" => ("Set root shell to fish", 1),
        "snap" => ("Migrate scored snaps, remove snap", 90),
        "bootloader" => ("Check and fix bootloader", 5),
        "schedulers" => ("Archive jobs, remove cron/at/timers", 15),
        "upgrade" => ("Targeted security upgrade", 60),
        "purge" => ("Purge remote-access packages", 10),
        "strict" => ("Strict package verification", 60),
        "firewall" => ("Build nftables firewall", 4),
        "network_recheck" => ("Re-verify network state", 3),
        "permissions" => ("Fix permissions and ownership", 45),
        "mail_php" => ("Mail and PHP read-only checks", 2),
        "temp_files" => ("Remove temp files", 1),
        "memory_only" => ("Stop memory-only processes", 1),
        "audit" => ("ssh/sudo/accounts/authorized_keys audit", 10),
        "persistence" => ("Persistence sweep", 5),
        "mounts" => ("Mount hardening", 1),
        "daemon_reload" => ("Daemon reload", 3),
        _ => ("step", 5),
    }
}

pub fn run_all(ctx: &Ctx, steps: &[Step]) {
    let done: Mutex<HashSet<&'static str>> = Mutex::new(HashSet::new());
    let cv = Condvar::new();
    let total = steps.len();
    let total_est: u64 = steps.iter().map(|s| meta(s.name).1).sum();
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for st in steps {
            let (done, cv) = (&done, &cv);
            s.spawn(move || {
                let mut g = done.lock().unwrap();
                while !st.after.iter().all(|d| g.contains(d)) { g = cv.wait(g).unwrap(); }
                drop(g);
                let _apt = st.apt.then(|| {
                    if !ctx.no_pkg { print!("\r\x1b[K  NOTICE: \"{}\" may run apt-get and wait for the dpkg lock. Do not interrupt. Log: {}/main.log\n", meta(st.name).0, ctx.work.display()); }
                    APT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
                });
                RUNNING.lock().unwrap().push(st.name);
                let t = Instant::now();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (st.run)(ctx))).unwrap_or_else(|_| Err("panicked".into()));
                RUNNING.lock().unwrap().retain(|n| *n != st.name);
                let (d, _) = meta(st.name);
                match &r {
                    Ok(()) => println!("\r\x1b[K[ ok ] {d} ({}s)", t.elapsed().as_secs()),
                    Err(e) => { println!("\r\x1b[K[FAIL] {d}: {e}"); ctx.warn(format!("step {} failed: {e}", st.name)); }
                }
                RESULTS.lock().unwrap().push((st.name, r.err()));
                done.lock().unwrap().insert(st.name);
                cv.notify_all();
            });
        }
        loop {
            let (n, fin_est): (usize, u64) = { let g = done.lock().unwrap(); (g.len(), g.iter().map(|x| meta(x).1).sum()) };
            if n >= total { break; }
            let el = t0.elapsed().as_secs();
            let ratio = if fin_est > 0 { (el * 100 / fin_est).clamp(25, 400) } else { 100 };
            let eta = (total_est - fin_est) * ratio / 100;
            let run = RUNNING.lock().unwrap().join(",");
            print!("\r\x1b[K[{n}/{total}] {run} | ETA ~{eta}s");
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    println!("\r\x1b[K\nTotal time: {}s", t0.elapsed().as_secs());
}

fn step_line(name: &str, what: &str) -> String {
    match RESULTS.lock().unwrap().iter().find(|r| r.0 == name) {
        Some((_, None)) => format!("{what}: finished OK"),
        Some((_, Some(e))) => format!("{what}: FAILED ({e})"),
        None => format!("{what}: did not run"),
    }
}

pub fn report(ctx: &Ctx) {
    let mut out = String::new();
    let w = ctx.warnings.lock().unwrap();
    if !w.is_empty() { out.push_str("--- Attention ---\n"); for l in w.iter() { out.push_str(l); out.push('\n'); } }
    out.push_str("--- targeted security upgrade ---\n");
    if ctx.no_pkg { out.push_str("Skipped (--no-apt): no package changes were made. See the REPORT-ONLY lines above.\n"); }
    else { out.push_str(&step_line("upgrade", "upgrade")); out.push('\n'); out.push_str(&step_line("purge", "purge")); out.push('\n'); }
    if let Ok(t) = std::fs::read_to_string(ctx.work.join("skipped_security_upgrades")) {
        if !t.trim().is_empty() { out.push_str(&format!("Security updates NOT applied (not on the threat list), apply manually if needed:\n{}\n", t.split_whitespace().collect::<Vec<_>>().join(" "))); }
    }
    out.push_str(&format!("Logs: {0}/main.log, report: {0}/final_report.txt (tmpfs, gone on reboot)\n", ctx.work.display()));
    print!("{out}");
    let _ = std::fs::write(ctx.work.join("final_report.txt"), &out); // in case the terminal is gone by now
}
