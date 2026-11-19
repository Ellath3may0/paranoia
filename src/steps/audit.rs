//! P3: content audits of ssh, authorized_keys, sudo, accounts, PAM, capabilities, apt hooks.
//! Mostly report-only; the only automatic fixes are locking empty-password accounts and
//! disabling unpackaged apt hooks (.disabled is ignored by apt).
use crate::{cmd, ctx::Ctx, util};
use std::{collections::HashMap, fs, os::unix::fs::MetadataExt};

struct Acct { name: String, uid: u32, shell: String, home: String }

fn accounts() -> Vec<Acct> {
    util::read("/etc/passwd").lines().filter_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7).then(|| Some(Acct { name: f[0].into(), uid: f[2].parse().ok()?, home: f[5].into(), shell: f[6].into() }))?
    }).collect()
}
fn login_shell(s: &str) -> bool { !(s.is_empty() || s.ends_with("nologin") || s.ends_with("/false") || s.ends_with("/sync") || s.ends_with("/halt") || s.ends_with("/shutdown")) }

fn sshd(c: &Ctx) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    let o = cmd::run("sshd", &["-T"]);
    if !o.ok { c.log(&format!("sshd -T failed: {}", o.text)); return m; }
    for l in o.text.lines() { if let Some((k, v)) = l.split_once(' ') { m.entry(k.to_lowercase()).or_default().push(v.trim().to_string()); } }
    m
}

fn ssh_config(c: &Ctx, cfg: &HashMap<String, Vec<String>>) {
    if cfg.is_empty() { return; }
    let one = |k: &str| cfg.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    if one("permitrootlogin") != "no" { c.warn(format!("SSHD: PermitRootLogin is {}", one("permitrootlogin"))); }
    for k in ["permitemptypasswords", "permituserenvironment", "gatewayports"] { if matches!(one(k).as_str(), "yes" | "clientspecified") { c.warn(format!("SSHD: {k} is {}", one(k))); } }
    if one("authorizedkeyscommand") != "none" && !one("authorizedkeyscommand").is_empty() { c.warn(format!("SSHD: AuthorizedKeysCommand = {}", one("authorizedkeyscommand"))); }
    if one("forcecommand") != "none" && !one("forcecommand").is_empty() { c.warn(format!("SSHD: ForceCommand = {}", one("forcecommand"))); }
    if let Some(v) = cfg.get("acceptenv") { let odd: Vec<&String> = v.iter().filter(|e| !(e.starts_with("LANG") || e.starts_with("LC_"))).collect(); if !odd.is_empty() { c.warn(format!("SSHD: AcceptEnv beyond LANG/LC_*: {}", odd.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))); } }
    if one("allowtcpforwarding") == "yes" { c.warn("SSHD: AllowTcpForwarding yes (tunnels possible)"); }
    for f in std::iter::once("/etc/ssh/sshd_config".into()).chain(util::files_in("/etc/ssh/sshd_config.d").iter().map(|p| p.display().to_string())) {
        if f.contains("sshd_config.d") && !c.is_owned(&f) { c.warn(format!("SSHD: unpackaged config drop-in {f}")); }
        for l in util::read(&f).lines() { if l.trim_start().to_lowercase().starts_with("match ") { c.warn(format!("SSHD: Match block in {f}: {}", l.trim())); } }
    }
}

fn authorized_keys(c: &Ctx, cfg: &HashMap<String, Vec<String>>) {
    let pats: Vec<String> = cfg.get("authorizedkeysfile").map(|v| v.iter().flat_map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>()).collect())
        .unwrap_or_else(|| vec![".ssh/authorized_keys".into(), ".ssh/authorized_keys2".into()]);
    for a in accounts().into_iter().filter(|a| a.uid == 0 || (login_shell(&a.shell) && a.uid >= 1000) || login_shell(&a.shell)) {
        let mut files: Vec<String> = pats.iter().map(|p| { let p = p.replace("%h", &a.home).replace("%u", &a.name).replace("%%", "%"); if p.starts_with('/') { p } else { format!("{}/{p}", a.home) } }).collect();
        files.push(format!("{}/.ssh/authorized_keys2", a.home));
        files.sort(); files.dedup();
        for f in files {
            let Ok(m) = fs::metadata(&f) else { continue };
            if m.mode() & 0o022 != 0 { c.warn(format!("AUTHKEYS: {f} is group/world writable")); }
            for l in util::read(&f).lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                let t: Vec<&str> = l.split_whitespace().collect();
                let ki = t.iter().position(|w| w.starts_with("ssh-") || w.starts_with("ecdsa-") || w.starts_with("sk-")).unwrap_or(0);
                let opts = if ki > 0 { format!(" OPTIONS: {}", t[..ki].join(" ")) } else { String::new() };
                c.warn(format!("AUTHKEYS: {} -> {}: {} {}{opts}", a.name, f, t.get(ki).unwrap_or(&"?"), t.get(ki + 2..).map(|r| r.join(" ")).unwrap_or_default()));
            }
        }
    }
}

fn sudo(c: &Ctx) {
    let mut files = vec!["/etc/sudoers".to_string()];
    for p in util::files_in("/etc/sudoers.d") { let s = p.display().to_string(); if !s.ends_with("README") && !c.is_owned(&s) { c.warn(format!("SUDO: unpackaged sudoers.d file {s}")); } files.push(s); }
    for f in files { for l in util::read(&f).lines() {
        let t = l.trim();
        if t.is_empty() || (t.starts_with('#') && !t.starts_with("#include")) { continue; }
        if t.contains("NOPASSWD") || t.contains("!authenticate") || t.contains("SETENV") || t.contains("LD_PRELOAD") || t.contains("env_keep") { c.warn(format!("SUDO: {f}: {t}")); }
    } }
    let mut members = vec![];
    for l in util::read("/etc/group").lines() { let f: Vec<&str> = l.split(':').collect(); if f.len() > 3 && ["sudo", "admin", "wheel"].contains(&f[0]) { members.push(format!("{}={}", f[0], f[3])); } }
    c.warn(format!("SUDO: privileged groups: {}", members.join(" ")));
}

fn accts(c: &Ctx) {
    let acc = accounts();
    for a in acc.iter().filter(|a| a.uid == 0 && a.name != "root") { c.warn(format!("ACCOUNTS: extra UID 0 account: {}", a.name)); }
    for a in acc.iter().filter(|a| a.uid != 0 && a.uid < 1000 && login_shell(&a.shell)) { c.warn(format!("ACCOUNTS: system account with login shell: {} ({})", a.name, a.shell)); }
    let mut other = vec![];
    for l in util::read("/etc/shadow").lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 2 { continue; }
        let Some(a) = acc.iter().find(|a| a.name == f[0]) else { continue };
        if f[1].is_empty() {
            if cmd::run("passwd", &["-l", f[0]]).ok { c.warn(format!("ACCOUNTS: {} had an EMPTY password, locked", f[0])); } else { c.warn(format!("ACCOUNTS: {} has an EMPTY password, lock failed", f[0])); }
        } else if !f[1].starts_with(['!', '*']) && login_shell(&a.shell) && a.name != "root" && a.name != c.user { other.push(a.name.clone()); }
    }
    if !other.is_empty() { c.warn(format!("ACCOUNTS: other local users with usable passwords (NOT changed): {}", other.join(" "))); }
}

fn pam(c: &Ctx) {
    for f in util::files_in("/etc/pam.d") { for l in util::read(&f.to_string_lossy()).lines() {
        let t = l.trim(); if t.starts_with('#') { continue; }
        if t.contains("nullok") || (t.starts_with("auth") && t.contains("pam_permit.so") && t.contains("sufficient")) { c.warn(format!("PAM: {}: {t}", f.display())); }
    } }
}

fn caps(c: &Ctx) {
    if cmd::find("getcap").is_none() { return; }
    for l in cmd::run_t("getcap", &["-r", "/"], 180).text.lines() {
        let p = l.split_whitespace().next().unwrap_or("");
        if p.starts_with('/') && !c.is_owned(p) { c.warn(format!("CAPS: file capabilities on unpackaged file: {l}")); }
    }
}

/// Run BEFORE any apt call (weakness 3): unpackaged hooks are renamed to *.disabled, unpackaged keys are reported.
pub fn apt_hooks(c: &Ctx) {
    const KEYS: &[&str] = &["pre-invoke", "post-invoke", "pre-install-pkgs", "update::pre-invoke", "update::post-invoke", "dpkg::tools::options", "apt::update::"];
    let mut files: Vec<String> = util::files_in("/etc/apt/apt.conf.d").iter().map(|p| p.display().to_string()).collect();
    files.push("/etc/apt/apt.conf".into());
    for f in files {
        let t = util::read(&f).to_lowercase();
        if t.is_empty() || !KEYS.iter().any(|k| t.contains(k)) || c.is_owned(&f) { continue; }
        if fs::rename(&f, format!("{f}.disabled")).is_ok() { c.warn(format!("APT: unpackaged apt hook file disabled: {f} (now {f}.disabled)")); }
        else { c.warn(format!("APT: unpackaged apt hook file, could not disable: {f}")); }
    }
    for d in ["/etc/apt/trusted.gpg.d", "/etc/apt/keyrings", "/usr/share/keyrings"] {
        for f in util::files_in(d) { let s = f.display().to_string(); if !c.is_owned(&s) { c.warn(format!("APT: unpackaged signing key (trusted for packages?): {s}")); } }
    }
    if util::files_in("/etc/apt/trusted.gpg.d").is_empty() && std::path::Path::new("/etc/apt/trusted.gpg").exists() { c.warn("APT: legacy /etc/apt/trusted.gpg keyring present"); }
}

pub fn run(c: &Ctx) -> Result<(), String> {
    let cfg = sshd(c);
    ssh_config(c, &cfg);
    authorized_keys(c, &cfg);
    sudo(c); accts(c); pam(c); caps(c);
    Ok(())
}
