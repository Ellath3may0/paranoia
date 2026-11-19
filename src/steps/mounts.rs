//! P3 mount hardening: /tmp, /var/tmp, /dev/shm noexec,nosuid,nodev and /proc hidepid=2. Live now plus fstab for next boot.
use crate::{cmd, ctx::Ctx, util};

fn mounted(p: &str) -> bool { util::read("/proc/mounts").lines().any(|l| l.split_whitespace().nth(1) == Some(p)) }

pub fn run(c: &Ctx) -> Result<(), String> {
    let opts = "noexec,nosuid,nodev";
    for p in ["/dev/shm", "/tmp", "/var/tmp"] {
        if !std::path::Path::new(p).is_dir() { continue; }
        if !mounted(p) && p != "/dev/shm" && !cmd::run("mount", &["--bind", p, p]).ok { c.warn(format!("MOUNT: could not bind {p}")); continue; }
        let o = cmd::run("mount", &["-o", &format!("remount,bind,{opts}"), p]);
        let o = if o.ok { o } else { cmd::run("mount", &["-o", &format!("remount,{opts}"), p]) };
        if !o.ok { c.warn(format!("MOUNT: remount {p} failed: {}", o.text.trim())); }
    }
    if !cmd::run("mount", &["-o", "remount,hidepid=2", "/proc"]).ok { c.warn("MOUNT: /proc hidepid=2 not applied"); }
    // persist (reboot): only add lines for mountpoints fstab does not already define
    let ft = util::read("/etc/fstab");
    let has = |mp: &str| ft.lines().any(|l| !l.trim_start().starts_with('#') && l.split_whitespace().nth(1) == Some(mp));
    let mut add = String::new();
    if !has("/dev/shm") { add.push_str(&format!("tmpfs /dev/shm tmpfs defaults,{opts} 0 0\n")); }
    if !has("/tmp") { add.push_str(&format!("tmpfs /tmp tmpfs defaults,{opts},mode=1777 0 0\n")); }
    if !has("/proc") { add.push_str("proc /proc proc defaults,hidepid=2 0 0\n"); }
    if !add.is_empty() {
        let _ = util::write_file("/etc/fstab", &format!("{ft}{}# paranoia mounts\n{add}", if ft.ends_with('\n') || ft.is_empty() { "" } else { "\n" }), 0o644);
        c.warn("MOUNT: fstab lines added for next boot (/tmp becomes tmpfs, noexec). Check installers that run from /tmp.");
    }
    Ok(())
}
