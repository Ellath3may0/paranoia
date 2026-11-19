//! Port of step_fix_permissions and step_check_binary_integrity.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util::{self, chmod, lchown, NOID}};
use std::{fs, os::unix::fs::{MetadataExt, PermissionsExt}, path::Path};

pub fn permissions(c: &Ctx) -> Result<(), String> {
    c.reindex(); // packages installed since startup must count as owned
    let root = Path::new("/");
    lchown(root, 0, 0); lchown(Path::new("/etc"), 0, 0); lchown(Path::new("/root"), 0, 0);
    chmod("/", 0o755); chmod("/etc", 0o755); chmod("/root", 0o700);
    // authorized_keys is no longer skipped (weakness 5): ownership is fixed, content is audited in P3
    util::visit_xdev("/root", &mut |p, _| lchown(p, 0, 0));

    // /etc: root-owned, nothing group/world writable
    util::visit_xdev("/etc", &mut |p, m| {
        if m.uid() != 0 { lchown(p, 0, NOID); }
        if !m.file_type().is_symlink() && m.mode() & 0o022 != 0 { chmod(p, m.mode() & 0o7777 & !0o022); }
    });

    // account databases and sudo
    chmod("/etc/passwd", 0o644); chmod("/etc/group", 0o644);
    let shadow = util::group_id("shadow").unwrap_or(0);
    for f in ["/etc/shadow", "/etc/gshadow"] { lchown(Path::new(f), 0, shadow); chmod(f, 0o640); }
    chmod("/etc/sudoers", 0o440); chmod("/etc/sudoers.d", 0o750);
    for f in util::files_in("/etc/sudoers.d") { chmod(f, 0o440); }

    // ssh, kerberos, sssd
    for f in ["/etc/ssh/sshd_config", "/etc/krb5.keytab", "/etc/sssd/sssd.conf"] { chmod(f, 0o600); }
    for f in util::files_in("/etc/ssh") {
        let n = f.file_name().unwrap().to_string_lossy().into_owned();
        if n.starts_with("ssh_host_") && n.ends_with("_key") { chmod(&f, 0o600); }
        if n.starts_with("ssh_host_") && n.ends_with("_key.pub") { chmod(&f, 0o644); }
    }
    chmod("/etc/sssd", 0o700);

    // dovecot
    for f in ["/etc/dovecot/dovecot-ldap.conf.ext", "/etc/dovecot/dovecot-sql.conf.ext"] { chmod(f, 0o640); }
    if let Some(g) = util::group_id("dovecot") { lchown(Path::new("/etc/dovecot/dovecot-ldap.conf.ext"), 0, g); }

    // roundcube: config holds credentials, web group may read
    if Path::new("/etc/roundcube").is_dir() {
        let g = util::group_id("www-data").unwrap_or(0);
        util::visit_xdev("/etc/roundcube", &mut |p, m| { lchown(p, 0, g); if m.is_dir() { chmod(p, 0o750); } else if m.is_file() { chmod(p, 0o640); } });
    }
    if cmd::find("postfix").is_some() { cmd::run("postfix", &["set-permissions"]); }
    for f in util::files_in("/var/spool/cron/crontabs") { chmod(f, 0o600); }
    chmod("/etc/crontab", 0o644);

    // homes: owned by their user, private
    for e in fs::read_dir("/home").into_iter().flatten().flatten() {
        let h = e.path();
        if !fs::symlink_metadata(&h).map_or(false, |m| m.is_dir()) { continue; }
        let name = h.file_name().unwrap().to_string_lossy().into_owned();
        let (uid, gid) = match util::user_ids(&name) {
            Some(x) => x,
            None => { c.warn(format!("home without user: {}", h.display())); (0, 0) }
        };
        util::visit_xdev(&h.to_string_lossy(), &mut |p, _| lchown(p, uid, gid));
        chmod(&h, 0o700);
    }

    // whole filesystem, one pass: o+w files, o+w non-sticky dirs, unpackaged suid/sgid
    let mut strip = vec![];
    util::visit_xdev("/", &mut |p, m| {
        let mode = m.mode();
        if m.is_dir() { if mode & 0o002 != 0 && mode & 0o1000 == 0 { chmod(p, mode & 0o7777 & !0o002); } return; }
        if !m.is_file() { return; }
        if mode & 0o002 != 0 { chmod(p, mode & 0o7777 & !0o002); }
        if mode & 0o6000 != 0 { strip.push(p.to_path_buf()); }
    });
    for p in strip {
        let s = p.to_string_lossy().into_owned();
        if c.is_owned(&s) { continue; }
        if let Ok(m) = fs::symlink_metadata(&p) { let _ = fs::set_permissions(&p, fs::Permissions::from_mode(m.mode() & 0o7777 & !0o6000)); }
        c.warn(format!("stripped suid/sgid from unpackaged file: {s}"));
    }
    Ok(())
}

pub fn integrity(c: &Ctx) -> Result<(), String> {
    let pk = pkg::installed_matching(|p| cf::CRITICAL_PACKAGES.contains(&p));
    let bad = pkg::tampered(&pk);
    if bad.is_empty() { return Ok(()); }
    let names: Vec<String> = bad.iter().map(|b| b.0.clone()).collect();
    let show = |b: &(String, Vec<String>)| b.1.iter().take(3).map(|x| x.rsplit(' ').next().unwrap_or("").to_string()).collect::<Vec<_>>().join(" ");
    if c.no_pkg {
        for b in &bad { c.report_only(&format!("binary integrity failed, would reinstall: {} ({})", b.0, show(b))); }
        return Ok(());
    }
    c.warn(format!("binary integrity failed, reinstalling: {}", names.join(" ")));
    let mut a = vec!["--reinstall", "install"]; a.extend(names.iter().map(|s| s.as_str()));
    c.log(&pkg::apt(&a, 0).text);
    for b in pkg::tampered(&names) { c.warn(format!("STILL TAMPERED after reinstall: {} ({})", b.0, show(&b))); }
    Ok(())
}
