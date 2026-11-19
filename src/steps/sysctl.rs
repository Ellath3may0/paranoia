use crate::{cmd, ctx::Ctx};
use std::{fs, os::unix::fs::PermissionsExt};

// Leading '-' = optional key (not present on every kernel).
const CONF: &str = "\
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
-dev.tty.legacy_tiocsti = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
-net.mptcp.enabled = 0
-net.ipv4.tcp_migrate_req = 0
-kernel.kexec_load_disabled = 1
-kernel.perf_event_paranoid = 3
-kernel.io_uring_disabled = 2
-kernel.apparmor_restrict_unprivileged_userns = 1
";

pub fn run(c: &Ctx) -> Result<(), String> {
    fs::write("/etc/sysctl.d/99-paranoia.conf", CONF).map_err(|e| e.to_string())?;
    let _ = fs::set_permissions("/etc/sysctl.d/99-paranoia.conf", fs::Permissions::from_mode(0o644));
    let _ = fs::write("/etc/security/limits.d/99-nocore.conf", "* hard core 0\n");
    let o = cmd::run("sysctl", &["--system"]);
    if !o.ok { c.warn("sysctl --system reported errors (see main.log)"); c.log(&o.text); }
    // Weakness 15: verify the live values, later files may override ours.
    for line in CONF.lines() {
        let (optional, line) = match line.strip_prefix('-') { Some(l) => (true, l), None => (false, line) };
        let Some((k, want)) = line.split_once('=') else { continue };
        let (k, want) = (k.trim(), want.trim());
        match fs::read_to_string(format!("/proc/sys/{}", k.replace('.', "/"))) {
            Ok(v) if v.trim() == want => {}
            Ok(v) => c.warn(format!("SYSCTL: {k} is {} not {want} (overridden elsewhere?)", v.trim())),
            Err(_) if optional => {}
            Err(_) => c.warn(format!("SYSCTL: {k} unreadable")),
        }
    }
    Ok(())
}
