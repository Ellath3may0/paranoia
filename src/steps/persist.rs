//! P3 persistence sweep (weakness 8). Report-only: unpackaged files in places that execute or load code.
use crate::{ctx::Ctx, util};
use std::{fs, path::Path};

fn unpackaged(c: &Ctx, dir: &str, tag: &str, grep: &[&str]) {
    for p in util::walk(dir) {
        if fs::symlink_metadata(&p).map_or(true, |m| m.file_type().is_symlink()) { continue; } // masks and wants links
        let s = p.display().to_string();
        if c.is_owned(&s) { continue; }
        let hits: Vec<String> = util::read(&s).lines().map(str::trim).filter(|l| grep.iter().any(|g| l.starts_with(g))).take(2).map(String::from).collect();
        c.warn(format!("PERSIST[{tag}]: unpackaged {s}{}", if hits.is_empty() { String::new() } else { format!(" ({})", hits.join(" | ")) }));
    }
}

pub fn run(c: &Ctx) -> Result<(), String> {
    for d in ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/etc/systemd/user", "/etc/systemd/network"] { unpackaged(c, d, "systemd", &["Exec"]); }
    unpackaged(c, "/etc/ld.so.conf.d", "ld", &[]);
    if Path::new("/etc/ld.so.conf").exists() && !c.is_owned("/etc/ld.so.conf") { c.warn("PERSIST[ld]: unpackaged /etc/ld.so.conf"); }
    for d in ["/etc/udev/rules.d", "/usr/lib/udev/rules.d"] { unpackaged(c, d, "udev", &["RUN", "PROGRAM"]); }
    for d in ["/etc/modules-load.d", "/etc/init.d", "/etc/update-motd.d", "/etc/xdg/autostart", "/etc/fish", "/etc/apparmor.d/local", "/etc/pm"] { unpackaged(c, d, "boot/login", &[]); }
    for f in ["/etc/rc.local", "/etc/modules", "/etc/environment.d"] { if Path::new(f).exists() && !c.is_owned(f) && !util::read(f).trim().is_empty() { c.warn(format!("PERSIST[boot]: {f} has content")); } }
    // python startup hooks
    for base in ["/usr/lib", "/usr/local/lib"] {
        for e in fs::read_dir(base).into_iter().flatten().flatten() {
            if !e.file_name().to_string_lossy().starts_with("python") { continue; }
            for p in util::walk(&e.path().to_string_lossy()) {
                let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let s = p.display().to_string();
                if (n.ends_with(".pth") || n == "sitecustomize.py" || n == "usercustomize.py") && !c.is_owned(&s) { c.warn(format!("PERSIST[python]: unpackaged startup hook {s}")); }
            }
        }
    }
    // per-user login hooks beyond bash (bash rc files are reset in shell.rs)
    let mut homes = vec!["/root".to_string()];
    for e in fs::read_dir("/home").into_iter().flatten().flatten() { homes.push(e.path().display().to_string()); }
    for h in homes {
        for f in [".ssh/rc", ".ssh/environment", ".zshrc", ".zprofile", ".xprofile", ".pam_environment", ".config/fish/config.fish", ".config/environment.d", ".config/autostart", ".config/systemd/user"] {
            let p = format!("{h}/{f}");
            if fs::symlink_metadata(&p).is_ok() { c.warn(format!("PERSIST[user]: {p} exists, review")); }
        }
    }
    Ok(())
}
