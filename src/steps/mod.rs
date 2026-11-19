use crate::runner::Step;
pub mod accounts; pub mod apt; pub mod audit; pub mod mounts; pub mod persist; pub mod strict; pub mod firewall; pub mod misc; pub mod network; pub mod perms;
pub mod reload; pub mod sched; pub mod shell; pub mod sysctl; pub mod temp;

fn s(name: &'static str, after: &'static [&'static str], apt: bool, run: fn(&crate::ctx::Ctx) -> Result<(), String>) -> Step {
    Step { name, after, apt, run }
}

/// Order mirrors megascript's groups. Apt steps share one lock; the firewall waits for all of them
/// (it flushes rules mid-run); permissions/audits run after the network re-check.
pub fn all(want_strict: bool) -> Vec<Step> {
    let mut v = vec![
        s("passwords", &[], false, accounts::passwords),
        s("kill_sessions", &[], false, accounts::kill_sessions),
        s("remote_tools", &["kill_sessions"], false, firewall::remote_tools),
        s("integrity", &["kill_sessions"], true, perms::integrity),
        s("sysctl", &["kill_sessions"], false, sysctl::run),
        s("lpe", &["kill_sessions"], false, misc::lpe),
        s("fish", &["integrity"], true, accounts::install_fish),
        s("root_shell", &["fish"], false, accounts::root_shell),
        s("snap", &["root_shell"], true, apt::remove_snap),
        s("bootloader", &["integrity"], true, sched::bootloader),
        s("schedulers", &["bootloader", "snap"], true, sched::schedulers),
        s("upgrade", &["schedulers"], true, apt::upgrade),
        s("purge", &["upgrade"], true, apt::purge),
        s("firewall", &["purge", "remote_tools", "sysctl", "lpe", "passwords"], true, firewall::run),
        s("network_recheck", &["firewall"], false, network::run),
        s("permissions", &["network_recheck"], false, perms::permissions),
        s("mail_php", &["network_recheck"], false, misc::mail_php),
        s("temp_files", &["network_recheck"], false, temp::run),
        s("memory_only", &["network_recheck"], false, misc::memory_only),
        s("audit", &["permissions"], false, audit::run),
        s("persistence", &["network_recheck"], false, persist::run),
        s("mounts", &["memory_only", "temp_files"], false, mounts::run),
        s("daemon_reload", &["permissions", "mail_php", "temp_files", "memory_only", "audit", "persistence", "mounts"], false, reload::run),
    ];
    if want_strict { v.insert(13, s("strict", &["purge"], true, strict::run)); }
    v
}
