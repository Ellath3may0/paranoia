//! Port of step_reset_shell_profiles + reinstall_shell_packages. Runs BEFORE preflight.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};
use std::{ffi::CString, fs};

fn modified() -> Vec<String> {
    let mut v: Vec<String> = pkg::tampered(&["bash".into(), "base-files".into()]).into_iter()
        .flat_map(|(_, f)| f).collect();
    for l in cmd::run("dpkg", &["--verify", "bash", "base-files"]).text.lines() {
        if l.contains(" c /etc/profile") || l.contains(" c /etc/bash.bashrc") || l.contains(" c /etc/skel/") { v.push(l.to_string()); }
    }
    v.sort(); v.dedup(); v
}

fn reinstall(c: &Ctx) {
    println!("[reset] apt-get update");
    let o = pkg::apt_quick(&["update"], 120);
    if !o.ok { c.warn("apt-get update failed in profile reset step (lock held or mirror unreachable; see main.log)"); c.log(&o.text); }
    println!("[reset] reinstalling bash and base-files");
    let o = pkg::apt_quick(&["--reinstall", "install", "bash", "base-files"], 150);
    if !o.ok { c.warn("could not reinstall bash/base-files defaults (lock held, stale lists or mirror unreachable; see main.log)"); c.log(&o.text); }
    let m = modified();
    if !m.is_empty() { c.warn(format!("bash/base-files STILL modified after reinstall: {}", m.iter().take(5).cloned().collect::<Vec<_>>().join(";"))); }
}

/// (name, uid, gid, home) of local accounts that matter: uid 0, uid >= 1000, and configured admins. Weakness 9.
fn local_accounts() -> Vec<(String, u32, u32, String)> {
    util::read("/etc/passwd").lines().filter_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 { return None; }
        let (uid, gid): (u32, u32) = (f[2].parse().ok()?, f[3].parse().ok()?);
        let want = uid == 0 || (uid >= 1000 && uid < 65534) || cf::LOCAL_ADMIN_ACCOUNTS.contains(&f[0]);
        let home = f[5];
        (want && home.starts_with('/') && home != "/" && fs::metadata(home).map_or(false, |m| m.is_dir()))
            .then(|| (f[0].to_string(), uid, gid, home.to_string()))
    }).collect()
}

pub fn run(c: &Ctx) -> Result<(), String> {
    println!("[reset] scanning bash and base-files");
    let m = modified();
    if m.is_empty() { println!("[reset] scan clean, skipping apt-get"); }
    else {
        c.warn(format!("bash/base-files failed dpkg verification: {}", m.iter().take(5).cloned().collect::<Vec<_>>().join(";")));
        if c.no_pkg { c.report_only("bash/base-files failed verification, would run: apt-get update; apt-get --reinstall install bash base-files"); }
        else { reinstall(c); }
    }
    if !std::path::Path::new("/etc/skel/.bashrc").exists() { c.warn("/etc/skel/.bashrc missing"); }

    let pre = util::read("/etc/ld.so.preload");
    if !pre.trim().is_empty() { c.finding(format!("/etc/ld.so.preload existed (removed by shell reset): {}", pre.replace('\n', " "))); }
    util::chattr("/etc/ld.so.preload", false);
    let _ = fs::remove_file("/etc/ld.so.preload");

    // /etc/environment keeps only PATH
    let keep: String = util::read("/etc/environment").lines().filter(|l| l.starts_with("PATH=")).map(|l| format!("{l}\n")).collect();
    let _ = util::write_file("/etc/environment", &keep, 0o644);

    for f in util::files_in("/etc/profile.d") {
        let p = f.to_string_lossy().into_owned();
        if p.ends_with(".sh") {
            let t = util::read(&p);
            if t.contains("PROMPT_COMMAND") {
                let n: String = t.lines().filter(|l| !l.contains("PROMPT_COMMAND")).map(|l| format!("{l}\n")).collect();
                let _ = fs::write(&p, n);
            }
        }
        if !c.is_owned(&p) { c.warn(format!("PERSIST: unpackaged /etc/profile.d file: {p}")); }
    }

    for (name, uid, gid, home) in local_accounts() {
        for f in [".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".inputrc", ".pam_environment"] {
            let _ = fs::remove_file(format!("{home}/{f}"));
        }
        for f in [".bashrc", ".profile", ".bash_logout"] {
            let dst = format!("{home}/{f}");
            if fs::copy(format!("/etc/skel/{f}"), &dst).is_err() { continue; }
            if let Ok(cp) = CString::new(dst.as_str()) { unsafe { libc::chown(cp.as_ptr(), uid, gid); } }
            let _ = fs::set_permissions(&dst, std::os::unix::fs::PermissionsExt::from_mode(0o644));
        }
        c.log(&format!("shell profile reset for {name}"));
    }
    Ok(())
}
