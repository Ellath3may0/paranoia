//! Port of step_check_bootloader and step_remove_schedulers.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};
use std::{fs, path::Path};

fn boot_pkgs() -> Vec<String> { pkg::installed_matching(|p| cf::BOOT_PREFIXES.iter().any(|x| p.starts_with(x))) }
fn first5(v: &[(String, Vec<String>)]) -> String { v.iter().flat_map(|x| x.1.iter()).take(5).cloned().collect::<Vec<_>>().join(";") }

fn strip_params(line: &str) -> String {
    // drop init=, rd.break*, systemd.unit= and "single" inside the quoted value
    let (Some(a), Some(b)) = (line.find('"'), line.rfind('"')) else { return line.to_string() };
    if a >= b { return line.to_string(); }
    let kept: Vec<&str> = line[a + 1..b].split_whitespace()
        .filter(|w| !(w.starts_with("init=") || w.starts_with("rd.break") || w.starts_with("systemd.unit=") || *w == "single")).collect();
    format!("{}\"{}\"{}", &line[..a], kept.join(" "), &line[b + 1..])
}

pub fn bootloader(c: &Ctx) -> Result<(), String> {
    let pk = boot_pkgs();
    let bad = pkg::tampered(&pk);
    let mut reinstalled = false;
    if !bad.is_empty() {
        if c.no_pkg { c.report_only(&format!("bootloader/kernel files failed verification, would reinstall: {} (changed: {})", pk.join(" "), first5(&bad))); }
        else {
            c.warn("bootloader/kernel files failed verification, reinstalling");
            let mut a = vec!["--reinstall", "install"]; a.extend(pk.iter().map(|s| s.as_str()));
            c.log(&pkg::apt(&a, 0).text);
            reinstalled = true;
        }
    }
    let g: String = util::read("/etc/default/grub").lines().map(|l| if l.trim_start().starts_with("GRUB_CMDLINE") { strip_params(l) } else { l.to_string() }).map(|l| l + "\n").collect();
    if !g.is_empty() { let _ = fs::write("/etc/default/grub", g); }
    for f in util::walk("/etc/grub.d") {
        let t = util::read(&f.to_string_lossy());
        if t.contains("init=/") || t.contains("rd.break") { c.warn(format!("suspicious grub.d script: {}", f.display())); }
    }
    let _ = cmd::run("chown", &["root:root", "/boot/grub/grub.cfg"]);
    c.log(&cmd::run_t("update-grub", &[], 300).text);
    c.log(&cmd::run_t("update-initramfs", &["-u", "-k", "all"], 900).text);
    let cfg = util::read("/boot/grub/grub.cfg");
    if cfg.contains("init=/") || cfg.contains("rd.break") || cfg.contains("systemd.unit=") { c.warn("grub.cfg still has suspicious kernel params"); }
    if reinstalled {
        let bad = pkg::tampered(&boot_pkgs());
        if !bad.is_empty() { c.warn(format!("UNFIXABLE bootloader tampering, inspect manually: {}", first5(&bad))); }
    }
    Ok(())
}

fn archive(files_dir: &str, p: &str) {
    if fs::symlink_metadata(p).is_ok() { cmd::run("cp", &["-a", "--parents", p, files_dir]); }
}

pub fn schedulers(c: &Ctx) -> Result<(), String> {
    let home = util::read("/etc/passwd").lines().find_map(|l| { let f: Vec<&str> = l.split(':').collect(); (f.first() == Some(&"root")).then(|| f.get(5).unwrap_or(&"/root").to_string()) }).unwrap_or("/root".into());
    let ts = cmd::run("date", &["+%Y%m%d-%H%M%S"]).text.trim().to_string();
    let top = format!("{home}/scheduled_jobs_archive");
    let dir = format!("{top}/{ts}");
    let files = format!("{dir}/files");
    fs::create_dir_all(&files).map_err(|e| e.to_string())?;
    for d in [&top, &dir, &files] { let _ = fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700)); }

    // 1. summary while atd/cron still run
    let mut sum = String::from("== Active cron-style entries ==\n");
    let mut entries = 0;
    let mut roots: Vec<String> = ["/etc/crontab", "/etc/anacrontab", "/etc/fcrontab"].iter().map(|s| s.to_string()).collect();
    for d in ["/etc/cron.d", "/var/spool/cron", "/var/spool/incron", "/var/spool/fcron", "/etc/incron.d"] { roots.extend(util::walk(d).iter().map(|p| p.display().to_string())); }
    for f in &roots { for l in util::read(f).lines() {
        let t = l.trim(); if t.is_empty() || t.starts_with('#') { continue; }
        entries += 1; sum.push_str(&format!("{f}:{l}\n"));
    } }
    for d in ["hourly", "daily", "weekly", "monthly", "yearly"] { sum.push_str(&format!("\n== /etc/cron.{d} ==\n{}", cmd::run("ls", &["-l", &format!("/etc/cron.{d}")]).text)); }
    let atq = cmd::run("atq", &[]).text;
    sum.push_str(&format!("\n== atq ==\n{atq}\n== at jobs ==\n"));
    for id in atq.lines().filter_map(|l| l.split_whitespace().next()) { sum.push_str(&format!("--- at job {id}\n{}", cmd::run("at", &["-c", id]).text)); }
    sum.push_str(&format!("\n== systemd timers ==\n{}\n== linger ==\n{}", cmd::run("systemctl", &["list-timers", "--all", "--no-pager"]).text, cmd::run("ls", &["-l", "/var/lib/systemd/linger"]).text));
    let sf = format!("{dir}/JOBS_SUMMARY.txt");
    let _ = util::write_file(&sf, &sum, 0o600);

    for p in cf::SCHED_PATHS { archive(&files, p); }
    archive(&files, "/var/lib/systemd/linger");

    // custom (non-symlink) timers
    let mut tdirs: Vec<String> = ["/etc/systemd/system", "/run/systemd/system", "/etc/systemd/user", "/usr/local/lib/systemd/system", "/root/.config/systemd/user"].iter().map(|s| s.to_string()).collect();
    for e in fs::read_dir("/home").into_iter().flatten().flatten() { tdirs.push(format!("{}/.config/systemd/user", e.path().display())); }
    let mut timers = vec![];
    for d in &tdirs { for f in util::walk(d) { if f.extension().map_or(false, |x| x == "timer") { timers.push(f); } } }
    for t in &timers {
        let s = t.to_string_lossy().into_owned();
        archive(&files, &s);
        archive(&files, &s.replace(".timer", ".service"));
        if let Some(u) = util::read(&s).lines().find_map(|l| l.strip_prefix("Unit=")) { archive(&files, &format!("{}/{u}", t.parent().unwrap().display())); }
    }
    c.warn(format!("SCHEDULERS: jobs archived to {dir} (JOBS_SUMMARY.txt lists every entry), {entries} active cron-style entries, {} custom timer files. Review for persistence.", timers.len()));

    // 2. daemons
    for u in cf::SCHED_UNITS { util::kill_unit(u); }
    // 3. custom timers removed, then all timers except the keep list
    for t in &timers { let _ = fs::remove_file(t); }
    if let Ok(rd) = fs::read_dir("/var/lib/systemd/linger") { for e in rd.flatten() { let _ = fs::remove_file(e.path()); } }
    let mut names = std::collections::BTreeSet::new();
    for o in [cmd::run("systemctl", &["list-unit-files", "--type=timer", "--no-legend", "--plain", "--no-pager"]),
              cmd::run("systemctl", &["list-units", "--all", "--type=timer", "--no-legend", "--plain", "--no-pager"])] {
        for l in o.text.lines() { if let Some(n) = l.split_whitespace().next() { if n.ends_with(".timer") { names.insert(n.to_string()); } } }
    }
    for n in names.iter().filter(|n| !cf::KEEP_TIMERS.contains(&n.as_str())) {
        cmd::run("systemctl", &["stop", n]); cmd::run("systemctl", &["disable", n]); cmd::run("systemctl", &["mask", n]);
    }
    // 4. delete job data (archive holds copies)
    for p in cf::SCHED_PATHS { let _ = if Path::new(p).is_dir() { fs::remove_dir_all(p) } else { fs::remove_file(p) }; }

    // 5. purge packages if no scored package would go with them
    let sp = pkg::installed_matching(|p| cf::SCHED_PKGS.contains(&p));
    if !sp.is_empty() {
        if c.no_pkg { c.report_only(&format!("scheduler packages installed, would purge: {}", sp.join(" "))); }
        else {
            let mut a = vec!["-s", "purge"]; a.extend(sp.iter().map(|s| s.as_str()));
            let sim = cmd::run("apt-get", &a).text;
            let rem: Vec<String> = sim.lines().filter(|l| l.starts_with("Remv ")).filter_map(|l| l.split_whitespace().nth(1).map(String::from)).filter(|p| !sp.contains(p)).collect();
            let (blocked, extras): (Vec<String>, Vec<String>) = rem.into_iter().partition(|p| cf::SCHED_SCORED.iter().any(|s| p.contains(s)));
            if !blocked.is_empty() { c.warn(format!("SCHEDULERS: purge SKIPPED, it would also remove scored/auth packages: {}. Daemons masked and binaries disabled instead.", blocked.join(" "))); }
            else {
                let mut a = vec!["purge"]; a.extend(sp.iter().map(|s| s.as_str()));
                if !pkg::apt(&a, 0).ok { c.warn(format!("SCHEDULERS: apt purge of {} failed (see main.log)", sp.join(" "))); }
                if !extras.is_empty() { c.warn(format!("SCHEDULERS: purge also removed: {}", extras.join(" "))); }
                let _ = fs::write("/etc/apt/preferences.d/noscheduler.pref", format!("Package: {}\nPin: release a=*\nPin-Priority: -10\n", cf::SCHED_PKGS.join(" ")));
            }
        }
    }
    // 6. binaries
    for b in cf::SCHED_BINS { if let Some(p) = cmd::find(b) { util::lock_binary(c, &p); } }
    for b in ["crontab", "at", "atd", "cron"] {
        if let Some(p) = cmd::find(b) {
            if fs::metadata(&p).map_or(false, |m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0) { c.warn(format!("SCHEDULERS: {b} still executable")); }
        }
    }
    Ok(())
}
