//! Port of step_mitigate_kernel_lpes, step_check_mail_and_php, step_stop_memory_only_processes.
use crate::{cmd, config as cf, ctx::Ctx, util};
use std::{fs, path::Path};

pub fn lpe(c: &Ctx) -> Result<(), String> {
    let rel = util::read("/proc/sys/kernel/osrelease").trim().to_string();
    let builtin = util::read(&format!("/lib/modules/{rel}/modules.builtin"));
    let conf = "/run/modprobe.d/disable-kernel-lpe-modules.conf";
    let _ = fs::create_dir_all("/run/modprobe.d");
    let (mut usable, mut built) = (vec![], vec![]);
    let mut t = String::from("# Temporary kernel LPE mitigations, cleared on reboot (paranoia)\n");
    for (m, why) in cf::LPE_MODULES {
        if builtin.contains(&format!("/{m}.ko")) { built.push(*m); continue; }
        usable.push(*m);
        t.push_str(&format!("# {why}\ninstall {m} /bin/false\nblacklist {m}\n"));
    }
    t.push_str("# Januscape CVE-2026-53359: no nested virtualization\noptions kvm_intel nested=0\noptions kvm_amd nested=0\n");
    util::write_file(conf, &t, 0o644).map_err(|e| e.to_string())?;
    let loaded = || util::read("/proc/modules").lines().filter_map(|l| l.split_whitespace().next().map(String::from)).collect::<Vec<_>>();
    for m in &usable { if loaded().contains(&m.to_string()) { cmd::run("modprobe", &["-r", m]); } }
    cmd::run("modprobe", &["-r", "kvm_intel", "kvm_amd"]);

    let now = loaded();
    let still: Vec<&str> = usable.iter().copied().filter(|m| now.contains(&m.to_string())).collect();
    let unblocked: Vec<&str> = usable.iter().copied().filter(|m| !cmd::run("modprobe", &["-n", "-v", m]).text.contains("/bin/false")).collect();
    for f in ["/sys/module/kvm_intel/parameters/nested", "/sys/module/kvm_amd/parameters/nested"] {
        if matches!(util::read(f).trim(), "1" | "Y") { c.warn(format!("KERNEL-LPE: KVM nested virtualization still on ({f}), Januscape not mitigated until reboot or module reload")); }
    }
    if !built.is_empty() { c.warn(format!("KERNEL-LPE: built into the running kernel, cannot be blocked: {}. Boot a patched kernel or add initcall_blacklist=<module>_init to the kernel command line.", built.join(" "))); }
    if !still.is_empty() { c.warn(format!("KERNEL-LPE: blocked but still loaded (in use): {}. Reboot into a patched kernel.", still.join(" "))); }
    if !unblocked.is_empty() { c.warn(format!("KERNEL-LPE: block check FAILED for: {}", unblocked.join(" "))); }
    c.warn(format!("KERNEL-LPE: {} modules blocked until reboot ({conf}). Install a patched kernel before rebooting. Not covered: GhostLock CVE-2026-43499 and any bug with no module to block.", usable.len()));
    Ok(())
}

fn broad_net(s: &str) -> bool {
    s.split([' ', ',']).filter(|t| !t.is_empty()).any(|t| {
        t == "0.0.0.0/0" || t == "::/0" || (t.contains('.') && t.split_once('/').and_then(|x| x.1.parse::<u8>().ok()).map_or(false, |n| n < 16))
    })
}

fn has_phpinfo(t: &str) -> bool {
    t.match_indices("phpinfo").any(|(i, _)| t[i + 7..].trim_start().starts_with('('))
}

pub fn mail_php(c: &Ctx) -> Result<(), String> {
    if cmd::find("postconf").is_some() {
        let mn = cmd::run("postconf", &["-h", "mynetworks"]).text;
        if broad_net(&mn) { c.warn(format!("POSTFIX mynetworks is very broad (possible open relay): {}", mn.trim())); }
        if !cmd::run("postconf", &["-h", "smtpd_relay_restrictions", "smtpd_recipient_restrictions"]).text.contains("reject_unauth_destination") {
            c.warn("POSTFIX: reject_unauth_destination not in relay/recipient restrictions (possible open relay)");
        }
        let tls = cmd::run("postconf", &["-h", "smtpd_tls_security_level"]).text;
        if !(tls.contains("may") || tls.contains("encrypt")) { c.warn("POSTFIX: smtpd TLS not enabled"); }
    }
    if cmd::find("doveconf").is_some() {
        if cmd::run("doveconf", &["-h", "ssl"]).text.trim() == "no" { c.warn("DOVECOT: ssl = no"); }
        if cmd::run("doveconf", &["-h", "disable_plaintext_auth"]).text.trim() == "no" { c.warn("DOVECOT: disable_plaintext_auth = no"); }
    }
    for f in util::walk("/etc/php").into_iter().filter(|p| p.file_name().map_or(false, |n| n == "php.ini")) {
        for l in util::read(&f.to_string_lossy()).lines() {
            let Some((k, v)) = l.split_once('=') else { continue };
            let (k, v) = (k.trim().to_lowercase(), v.trim().to_lowercase());
            let on = matches!(v.as_str(), "on" | "1");
            if k == "expose_php" && on { c.warn(format!("PHP expose_php is On: {}", f.display())); }
            if k == "display_errors" && (on || v == "stdout") { c.warn(format!("PHP display_errors is On: {}", f.display())); }
            if k == "allow_url_include" && on { c.warn(format!("PHP allow_url_include is On: {}", f.display())); }
        }
    }
    for root in ["/usr/share/roundcube", "/var/lib/roundcube", "/var/www", "/opt"] {
        for f in util::walk(root) {
            let Some(d) = f.parent() else { continue };
            if d.file_name().map_or(false, |n| n == "installer") && d.parent().map_or(false, |p| p.join("program/include/iniset.php").exists() || d.to_string_lossy().contains("oundcube")) {
                let w = format!("ROUNDCUBE installer dir present: {}", d.display());
                if !c.warnings.lock().unwrap().contains(&w) { c.warn(w); }
            }
            if f.extension().map_or(false, |e| e == "php") && (root == "/var/www" || root == "/usr/share/roundcube") && has_phpinfo(&util::read(&f.to_string_lossy())) {
                c.warn(format!("phpinfo() found: {}", f.display()));
            }
        }
    }
    for f in util::files_in("/etc/roundcube") {
        if util::read(&f.to_string_lossy()).lines().any(|l| l.contains("enable_installer") && l.contains("true")) { c.warn("ROUNDCUBE enable_installer is true"); break; }
    }
    Ok(())
}

/// Deleted/memfd binaries, plus (new) unpackaged binaries running from tmp/home dirs. Packaged-but-updated binaries are only reported.
pub fn memory_only(c: &Ctx) -> Result<(), String> {
    let ps = super::accounts::procs();
    let keep = super::accounts::protected(c, &ps);
    for p in ps {
        if keep.contains(&p.pid) { continue; }
        let Ok(link) = fs::read_link(format!("/proc/{}/exe", p.pid)) else { continue };
        let exe = link.to_string_lossy().into_owned();
        let bin = exe.strip_suffix(" (deleted)").unwrap_or(&exe).to_string();
        let memfd = exe.starts_with("/memfd:");
        let deleted = exe.ends_with(" (deleted)");
        let suspect_dir = cf::SUSPECT_EXE_DIRS.iter().any(|d| bin.starts_with(d));
        if !(memfd || deleted || suspect_dir) { continue; }
        let packaged = !memfd && (c.is_owned(&bin) || cmd::run("dpkg", &["-S", &bin]).ok);
        if deleted && packaged && !suspect_dir { c.warn(format!("packaged binary updated, restart needed: pid {} ({bin})", p.pid)); continue; }
        if packaged { continue; }
        if Path::new("/proc").join(p.pid.to_string()).exists() {
            unsafe { libc::kill(p.pid as i32, libc::SIGKILL); }
            c.warn(format!("killed {} process {} ({exe})", if suspect_dir && !memfd && !deleted { "unpackaged tmp/home" } else { "memory-only" }, p.pid));
        }
    }
    Ok(())
}
