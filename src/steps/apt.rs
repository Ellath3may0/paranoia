//! Port of step_remove_snap, step_start_background_upgrade (now two apt steps) and the purge list.
//! All of these are registered with apt=true so the runner serialises them.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};
use std::{collections::HashSet, fs};

fn snaps() -> Vec<String> {
    cmd::run_t("snap", &["list"], 15).text.lines().skip(1).filter_map(|l| l.split_whitespace().next().map(String::from)).collect()
}

pub fn remove_snap(c: &Ctx) -> Result<(), String> {
    let have_snapd = pkg::installed().iter().any(|p| p == "snapd");
    if c.no_pkg {
        if cmd::find("snap").is_some() || have_snapd {
            c.report_only(&format!("snap/snapd present, would migrate scored snaps to apt, remove all snaps and purge snapd. Snaps: {}", snaps().join(" ")));
        }
        return Ok(());
    }
    let mut migrated = vec![];
    if cmd::find("snap").is_some() {
        let mut keep = false;
        for s in snaps().into_iter().filter(|s| cf::SCORED_SNAP_REGEX.iter().any(|r| s.contains(r))) {
            let cand = cmd::run("apt-cache", &["policy", &s]).text.lines()
                .any(|l| l.trim().strip_prefix("Candidate:").map_or(false, |v| { let v = v.trim(); !v.is_empty() && !v.starts_with('(') }));
            if cand && pkg::apt(&["install", &s], 0).ok {
                c.warn(format!("migrated snap {s} to apt: copy its config/data manually"));
                migrated.push(s);
            } else { c.warn(format!("scored snap {s} has no apt equivalent: snapd NOT removed")); keep = true; }
        }
        if keep { return Err("scored snap kept".into()); }
        let core = |s: &String| s == "snapd" || s.starts_with("core") || s == "bare";
        for _ in 0..3 {
            let apps: Vec<String> = snaps().into_iter().filter(|s| !core(s)).collect();
            if apps.is_empty() { break; }
            for s in apps { cmd::run_t("snap", &["remove", "--purge", &s], 300); }
        }
        for s in snaps().into_iter().filter(|s| s != "snapd") { cmd::run_t("snap", &["remove", "--purge", &s], 300); }
        cmd::run_t("snap", &["remove", "--purge", "snapd"], 300);
    }
    cmd::run("systemctl", &["disable", "--now", "snapd.service", "snapd.socket", "snapd.seeded.service"]);
    let mut mounts: Vec<String> = util::read("/proc/mounts").lines().filter_map(|l| l.split_whitespace().nth(1)).filter(|m| m.starts_with("/snap/")).map(String::from).collect();
    mounts.sort(); mounts.reverse();
    for m in mounts { cmd::run("umount", &["-l", &m]); }
    pkg::apt(&["purge", "snapd"], 0);
    cmd::run("apt-mark", &["hold", "snapd"]);
    let mut dirs: Vec<String> = ["/snap", "/var/snap", "/var/lib/snapd", "/var/cache/snapd", "/root/snap"].iter().map(|s| s.to_string()).collect();
    for e in fs::read_dir("/home").into_iter().flatten().flatten() { dirs.push(format!("{}/snap", e.path().display())); }
    for d in dirs { let _ = fs::remove_dir_all(&d); }
    let _ = fs::write("/etc/apt/preferences.d/nosnap.pref", "Package: snapd\nPin: release a=*\nPin-Priority: -10\n");
    for s in &migrated { cmd::run("systemctl", &["restart", s]); }
    if cmd::find("snap").is_some() { c.warn("snap binary still present"); return Err("snap remains".into()); }
    Ok(())
}

/// Installed packages with a pending update from a -security pocket (simulated, no changes).
fn pending_security() -> Vec<String> {
    cmd::run("apt-get", &["-s", "--with-new-pkgs", "upgrade"]).text.lines()
        .filter(|l| l.starts_with("Inst ") && l.contains("-security"))
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from)).collect()
}

fn threat(p: &str) -> bool { cf::THREAT_PREFIXES.iter().any(|t| p.starts_with(t)) }

/// Targeted security upgrade only (no full upgrade). New kernels still need a reboot.
pub fn upgrade(c: &Ctx) -> Result<(), String> {
    let sec = pending_security();
    let (tgt, skip): (Vec<String>, Vec<String>) = sec.into_iter().partition(|p| threat(p));
    let _ = fs::write(c.work.join("skipped_security_upgrades"), skip.join("\n"));
    if c.no_pkg {
        c.report_only(&format!("targeted security upgrade skipped, pending (per current lists, no apt update run): {}", if tgt.is_empty() { "none".into() } else { tgt.join(" ") }));
        return Ok(());
    }
    if tgt.is_empty() { return Ok(()); }
    c.log(&format!("targeted security upgrade: {}", tgt.join(" ")));
    let mut a = vec!["install", "--only-upgrade"]; a.extend(tgt.iter().map(|s| s.as_str()));
    let o = pkg::apt(&a, 0);
    c.log(&o.text);
    if o.ok { Ok(()) } else { Err("targeted upgrade failed (see main.log)".into()) }
}

/// Purge unscored remote-access packages (runs after the upgrade).
pub fn purge(c: &Ctx) -> Result<(), String> {
    let inst: HashSet<String> = pkg::installed().into_iter().collect();
    let targets: Vec<&str> = cf::PURGE_PACKAGES.iter().copied().filter(|p| inst.contains(*p)).collect();
    if c.no_pkg {
        if !targets.is_empty() { c.report_only(&format!("unscored remote-access packages installed, would purge: {}", targets.join(" "))); }
        return Ok(());
    }
    if !targets.is_empty() {
        let mut a = vec!["purge"]; a.extend(targets.iter());
        let o = pkg::apt(&a, 0); c.log(&o.text);
        if !o.ok { c.warn("purge of remote-access packages failed (see main.log)"); }
    }
    let o = pkg::apt(&["autoremove", "--purge"], 0); c.log(&o.text);
    Ok(())
}
