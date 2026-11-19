//! Small fs helpers shared by steps.
use crate::cmd;
use std::{fs, path::PathBuf};

pub fn read(p: &str) -> String { fs::read_to_string(p).unwrap_or_default() }

/// Regular files (not dirs) directly inside `dir`, sorted. Missing dir gives empty.
pub fn files_in(dir: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path())
        .filter(|p| fs::symlink_metadata(p).map(|m| !m.is_dir()).unwrap_or(false)).collect();
    v.sort();
    v
}

/// Every non-directory under `dir`, no symlink following.
pub fn walk(dir: &str) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(_) => out.push(p),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// Remove or set the immutable bit (best effort).
pub fn chattr(path: &str, immutable: bool) {
    let _ = cmd::run("chattr", &[if immutable { "+i" } else { "-i" }, path]);
}

/// Atomic-ish write: temp file in same dir then rename. Clears immutable first.
pub fn write_file(path: &str, data: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    chattr(path, false);
    let tmp = format!("{path}.mh.tmp");
    fs::write(&tmp, data)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

/// Host part of "scheme://user@host:port/path" or "host:port".
pub fn host_of(u: &str) -> String {
    let u = u.split_once("://").map_or(u, |x| x.1);
    let u = u.rsplit_once('@').map_or(u, |x| x.1);
    u.split([':', '/']).next().unwrap_or("").to_lowercase()
}

pub fn is_fqdn(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2 && !s.chars().all(|c| c.is_ascii_digit() || c == '.')
        && parts.iter().all(|p| !p.is_empty() && !p.starts_with('-') && !p.ends_with('-')
            && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
}

pub fn unit_exists(name: &str) -> bool { cmd::run("systemctl", &["cat", name]).ok }

/// Stop, disable and mask a unit if it exists.
pub fn kill_unit(name: &str) {
    if unit_exists(name) { cmd::run("systemctl", &["disable", "--now", name]); cmd::run("systemctl", &["mask", name]); }
}

/// chattr -i -a on a path (symlinks resolved). Best effort.
pub fn unlock(path: &str) {
    let r = fs::canonicalize(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string());
    if std::path::Path::new(&r).exists() { let _ = cmd::run("chattr", &["-i", "-a", &r]); }
}

/// Make a file unexecutable in a way a package upgrade cannot silently revert (weakness 14):
/// packaged files get a dpkg-statoverride, others a plain chmod.
pub fn lock_binary(c: &crate::ctx::Ctx, path: &str) {
    let Ok(r) = fs::canonicalize(path) else { return };
    let r = r.display().to_string();
    if c.is_owned(&r) {
        cmd::run("dpkg-statoverride", &["--remove", &r]);
        let o = cmd::run("dpkg-statoverride", &["--update", "--add", "root", "root", "0000", &r]);
        if !o.ok { c.log(&format!("statoverride {r}: {}", o.text)); }
    }
    let _ = fs::set_permissions(&r, std::os::unix::fs::PermissionsExt::from_mode(0o000));
}

pub fn lchown(path: &std::path::Path, uid: u32, gid: u32) {
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) { unsafe { libc::lchown(c.as_ptr(), uid, gid); } }
}
pub fn chmod(path: impl AsRef<std::path::Path>, mode: u32) { let _ = fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode)); }
pub const NOID: u32 = u32::MAX; // "leave unchanged" for chown

/// (uid, gid) from /etc/passwd only (never NSS/sssd).
pub fn user_ids(name: &str) -> Option<(u32, u32)> {
    read("/etc/passwd").lines().find_map(|l| { let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))? })
}
pub fn group_id(name: &str) -> Option<u32> {
    read("/etc/group").lines().find_map(|l| { let f: Vec<&str> = l.split(':').collect(); (f.len() > 2 && f[0] == name).then(|| f[2].parse().ok())? })
}

/// Visit every entry under `root` without following symlinks or leaving the filesystem of `root` (find -xdev).
pub fn visit_xdev(root: &str, f: &mut dyn FnMut(&std::path::Path, &fs::Metadata)) {
    use std::os::unix::fs::MetadataExt;
    let Ok(rm) = fs::symlink_metadata(root) else { return };
    let dev = rm.dev();
    f(std::path::Path::new(root), &rm);
    let mut stack = vec![PathBuf::from(root)];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let Ok(m) = fs::symlink_metadata(&p) else { continue };
            if m.dev() != dev { continue; }
            f(&p, &m);
            if m.is_dir() { stack.push(p); }
        }
    }
}
