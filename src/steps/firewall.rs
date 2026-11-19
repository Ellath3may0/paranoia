//! Port of step_build_nftables_firewall and step_disable_remote_access_tools.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};

fn ports(p: &[u16]) -> String { p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ") }

fn conf() -> String {
    format!("#!/usr/sbin/nft -f
flush ruleset

table inet filter {{
  chain input {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif \"lo\" accept
    ip protocol icmp accept
    tcp dport {{ {} }} ct state new accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}
", ports(cf::ALLOWED_TCP))
}

pub fn run(c: &Ctx) -> Result<(), String> {
    if cmd::find("nft").is_none() {
        if c.no_pkg { c.report_only("nft not installed, would run: apt-get install nftables"); return Ok(()); }
        if !pkg::apt(&["install", "nftables"], 0).ok { c.warn("nftables install failed, no firewall applied"); return Err("no nft".into()); }
    }
    for u in ["ufw", "firewalld", "iptables", "ip6tables", "ebtables", "netfilter-persistent", "shorewall"] { util::kill_unit(u); }
    cmd::run("systemctl", &["unmask", "nftables"]);
    for b in ["iptables", "iptables-legacy", "ip6tables", "ip6tables-legacy"] {
        if cmd::find(b).is_none() { continue; }
        for ch in ["INPUT", "FORWARD", "OUTPUT"] { cmd::run(b, &["-P", ch, "ACCEPT"]); }
        for t in ["filter", "nat", "mangle", "raw", "security"] { for f in ["-F", "-X", "-Z"] { cmd::run(b, &["-t", t, f]); } }
    }
    for b in ["ebtables", "arptables"] { if cmd::find(b).is_some() { cmd::run(b, &["-F"]); cmd::run(b, &["-X"]); } }
    cmd::run("nft", &["flush", "ruleset"]);
    for p in ["/etc", "/etc/nftables.conf", "/etc/systemd/system/nftables.service", "/lib/systemd/system/nftables.service", "/usr/lib/systemd/system/nftables.service"] { util::unlock(p); }

    let path = "/etc/nftables.conf";
    util::write_file(path, &conf(), 0o600).map_err(|e| e.to_string())?;
    let v = cmd::run("nft", &["-c", "-f", path]);
    if !v.ok { c.warn("nftables config failed validation, no firewall applied"); c.log(&v.text); return Err("validation".into()); }
    let a = cmd::run("nft", &["-f", path]);
    if !a.ok { c.warn(format!("nft failed to apply {path}")); c.log(&a.text); return Err("apply".into()); }
    if !cmd::run("systemctl", &["enable", "--now", "nftables"]).ok { c.warn("could not enable nftables service"); }
    Ok(())
}

pub fn remote_tools(c: &Ctx) -> Result<(), String> {
    for u in cf::REMOTE_UNITS { util::kill_unit(u); }
    for b in cf::REMOTE_BINS { if let Some(p) = cmd::find(b) { util::lock_binary(c, &p); } }
    Ok(())
}
