//! Port of step_fix_network. Idempotent; runs first and again as a final re-check.
use crate::{cmd, config as cf, ctx::Ctx, util};
use std::{collections::BTreeSet, fs};

fn pick_iface() -> Option<String> {
    let mut names: Vec<String> = fs::read_dir("/sys/class/net").ok()?.flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    if let Some(n) = names.iter().find(|n| std::path::Path::new(&format!("/sys/class/net/{n}/device")).exists()) { return Some(n.clone()); }
    cmd::run("ip", &["-4", "-o", "route", "show", "default"]).text.lines()
        .find_map(|l| l.split_whitespace().nth(4).map(String::from))
}

fn lines(o: cmd::Out) -> Vec<String> { o.text.lines().map(String::from).collect() }

pub fn run(c: &Ctx) -> Result<(), String> {
    let Some(iface) = pick_iface() else { c.warn("NETWORK: no usable interface found, nothing changed"); return Err("no iface".into()) };
    let (cidr, net, gw, dns) = (cf::WANT_CIDR, cf::WANT_NET, cf::WANT_GW, cf::WANT_DNS);
    cmd::run("ip", &["link", "set", &iface, "up"]);

    // exactly one address
    let mut have = false;
    for l in lines(cmd::run("ip", &["-4", "-o", "addr", "show", "dev", &iface])) {
        let Some(a) = l.split_whitespace().nth(3) else { continue };
        if a == cidr { have = true; continue; }
        if cmd::run("ip", &["addr", "del", a, "dev", &iface]).ok { c.warn(format!("NETWORK: removed unexpected address {a} from {iface}")); }
    }
    if !have { cmd::run("ip", &["addr", "add", cidr, "dev", &iface]); c.warn(format!("NETWORK: {cidr} was missing on {iface}, restored")); }

    // routes: connected net and the one gateway only
    cmd::run("ip", &["route", "replace", "default", "via", gw, "dev", &iface]);
    let (keep_def, keep_net) = (format!("default via {gw} dev {iface}"), format!("{net} dev {iface} proto kernel"));
    for l in lines(cmd::run("ip", &["-4", "route", "show", "table", "main"])) {
        if l.starts_with(&keep_def) || l.starts_with(&keep_net) || l.trim().is_empty() { continue; }
        let mut a = vec!["route", "del"]; a.extend(l.split_whitespace());
        if cmd::run("ip", &a).ok { c.warn(format!("NETWORK: removed route: {l}")); }
    }
    for l in lines(cmd::run("ip", &["-6", "route", "show", "default"])) {
        let mut a = vec!["-6", "route", "del"]; a.extend(l.split_whitespace());
        if cmd::run("ip", &a).ok { c.warn(format!("NETWORK: removed IPv6 default route: {l}")); }
    }
    // policy routing
    for l in lines(cmd::run("ip", &["-4", "rule", "show"])) {
        let Some(p) = l.split(':').next().and_then(|x| x.trim().parse::<u32>().ok()) else { continue };
        if p == 0 || p == 32766 || p == 32767 { continue; }
        if cmd::run("ip", &["rule", "del", "priority", &p.to_string()]).ok { c.warn(format!("NETWORK: removed ip rule priority {p}")); }
    }
    if cmd::run("ip", &["-4", "route", "show", "table", "all"]).text.lines()
        .any(|l| l.contains("table ") && !l.contains("table local") && !l.contains("table main")) {
        c.warn("NETWORK: routes exist in non-main tables: ip route show table all");
    }
    // other live interfaces
    for e in fs::read_dir("/sys/class/net").into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n == "lo" || n == iface { continue; }
        if util::read(&format!("/sys/class/net/{n}/operstate")).trim() == "down" { continue; }
        let a: Vec<String> = lines(cmd::run("ip", &["-4", "-o", "addr", "show", "dev", &n])).iter()
            .filter_map(|l| l.split_whitespace().nth(3).map(String::from)).collect();
        c.warn(format!("NETWORK: extra interface up: {n} ({})", a.join(" ")));
    }

    // ARP
    let nf = "/etc/sysctl.d/98-paranoia-net.conf";
    let _ = util::write_file(nf, "net.ipv4.conf.all.arp_ignore = 1\nnet.ipv4.conf.all.arp_announce = 2\nnet.ipv4.conf.all.arp_filter = 1\nnet.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0\n", 0o644);
    cmd::run("sysctl", &["-qp", nf]);
    cmd::run("ip", &["neigh", "flush", "dev", &iface]);
    if !cmd::run_t("ping", &["-c1", "-W2", gw], 6).ok { c.warn(format!("NETWORK: gateway {gw} not answering ping (or ICMP blocked)")); }
    let mac = cmd::run("ip", &["neigh", "show", gw, "dev", &iface]).text.split_whitespace().nth(4).unwrap_or("unknown").to_string();
    c.warn(format!("NETWORK: gateway MAC is {mac}, check it against the known-good one"));

    // DNS
    cmd::run("systemctl", &["disable", "--now", "systemd-resolved"]);
    cmd::run("systemctl", &["mask", "systemd-resolved"]);
    util::chattr("/etc/resolv.conf", false);
    let _ = fs::remove_file("/etc/resolv.conf");
    let _ = util::write_file("/etc/resolv.conf", &format!("nameserver {dns}\n"), 0o644);
    util::chattr("/etc/resolv.conf", true);
    let ns = util::read("/etc/nsswitch.conf");
    let ns: String = ns.lines().map(|l| if l.starts_with("hosts:") { "hosts:          files dns".to_string() } else { l.to_string() }).collect::<Vec<_>>().join("\n") + "\n";
    let _ = util::write_file("/etc/nsswitch.conf", &ns, 0o644);

    pin_hosts(c);
    if !cmd::run_t("getent", &["hosts", "archive.ubuntu.com"], 5).ok { c.warn(format!("NETWORK: DNS test via {dns} failed (upstream blocked?)")); }

    netplan(c, &iface);
    audit(c);
    Ok(())
}

const AD_KEYS: &[&str] = &["kdc", "admin_server", "master_kdc", "default_domain", "ad_domain", "ad_server",
    "ad_backup_server", "krb5_server", "ldap_uri", "uris", "hosts"];

fn pin_hosts(c: &Ctx) {
    let mut names: BTreeSet<String> = cf::AD_EXTRA_NAMES.iter().map(|s| s.to_lowercase()).collect();
    let mut srcs = vec!["/etc/krb5.conf".to_string(), "/etc/sssd/sssd.conf".to_string(), "/etc/dovecot/dovecot-ldap.conf.ext".to_string()];
    for d in ["/etc/krb5.conf.d", "/etc/sssd/conf.d", "/etc/dovecot/conf.d"] {
        for p in util::files_in(d) {
            let s = p.to_string_lossy().into_owned();
            if d != "/etc/dovecot/conf.d" || s.contains("ldap") { srcs.push(s); }
        }
    }
    for s in &srcs {
        for l in util::read(s).lines() {
            let Some((k, v)) = l.split_once('=') else { continue };
            let k = k.trim().to_lowercase();
            if k == "default_realm" { let r = v.trim().to_lowercase(); if util::is_fqdn(&r) { names.insert(r); } }
            if !AD_KEYS.contains(&k.as_str()) { continue; }
            for tok in v.split([',', ' ', '\t', '\r']).filter(|t| !t.is_empty()) {
                let h = util::host_of(tok);
                if util::is_fqdn(&h) { names.insert(h); }
            }
        }
    }
    let names: Vec<String> = names.into_iter().filter(|n| util::is_fqdn(n)).collect();
    if names.is_empty() { c.warn("NETWORK: no AD hostnames found in krb5/sssd/dovecot configs, /etc/hosts NOT pinned. Set AD_EXTRA_NAMES in config.rs."); return; }
    util::chattr("/etc/hosts", false);
    let (mut out, mut skip) = (vec![], false);
    for l in util::read("/etc/hosts").lines() {
        if l.contains("# paranoia AD begin") { skip = true; continue; }
        if l.contains("# paranoia AD end") { skip = false; continue; }
        if skip { continue; }
        let body = l.split('#').next().unwrap_or("");
        // exact-token match, so evil-ccdc.net does not collide with ccdc.net
        if body.split_whitespace().skip(1).any(|t| names.contains(&t.to_lowercase())) {
            c.warn(format!("NETWORK: removed conflicting /etc/hosts entry: {l}")); continue;
        }
        out.push(l.to_string());
    }
    out.push(format!("# paranoia AD begin\n{} {}\n# paranoia AD end", cf::AD_IP, names.join(" ")));
    let _ = util::write_file("/etc/hosts", &(out.join("\n") + "\n"), 0o644);
    c.warn(format!("NETWORK: /etc/hosts pins {} -> {}", cf::AD_IP, names.join(" ")));
    let got = cmd::run("getent", &["-s", "files", "hosts", &names[0]]).text;
    if got.split_whitespace().next() != Some(cf::AD_IP) { c.warn(format!("NETWORK: hosts lookup of {} did not return {}", names[0], cf::AD_IP)); }
    for l in util::read("/etc/hosts").lines() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') || ["127.", "::1", "ff0", "fe00"].iter().any(|p| t.starts_with(p)) || t.starts_with(&format!("{} ", cf::AD_IP)) { continue; }
        c.warn(format!("NETWORK: /etc/hosts entry to verify: {t}"));
    }
    util::chattr("/etc/hosts", true);
}

fn netplan(c: &Ctx, iface: &str) {
    let renderer = if cmd::run("systemctl", &["is-active", "--quiet", "NetworkManager"]).ok { "NetworkManager" } else { "networkd" };
    let mine = "/etc/netplan/01-paranoia.yaml";
    if !std::path::Path::new(mine).exists() {
        let b = format!("/root/netplan_backup_{}", cmd::run("date", &["+%Y%m%d-%H%M%S"]).text.trim());
        let _ = fs::create_dir_all(&b);
        cmd::run("cp", &["-a", "/etc/netplan/.", &b]);
    }
    for p in util::files_in("/etc/netplan") { if p.extension().map_or(false, |e| e == "yaml") { let _ = fs::remove_file(p); } }
    let y = format!("network:\n  version: 2\n  renderer: {renderer}\n  ethernets:\n    {iface}:\n      dhcp4: false\n      dhcp6: false\n      accept-ra: false\n      addresses: [{}]\n      routes:\n        - to: default\n          via: {}\n      nameservers:\n        addresses: [{}]\n", cf::WANT_CIDR, cf::WANT_GW, cf::WANT_DNS);
    let _ = util::write_file(mine, &y, 0o600);
    if !cmd::run("netplan", &["generate"]).ok { c.warn("NETWORK: netplan generate failed, config will not persist"); }
    if util::files_in("/etc/systemd/network").iter().any(|p| p.extension().map_or(false, |e| e == "network")) {
        c.warn("NETWORK: leftover /etc/systemd/network/*.network files, review");
    }
}

fn audit(c: &Ctx) {
    // unpackaged hooks that can rewrite network state
    let mut hooks = vec![];
    for d in ["/etc/dhcp/dhclient-enter-hooks.d", "/etc/dhcp/dhclient-exit-hooks.d", "/etc/NetworkManager/dispatcher.d",
              "/etc/network/if-up.d", "/etc/network/if-down.d", "/etc/network/if-pre-up.d", "/etc/network/if-post-down.d"] {
        hooks.extend(util::files_in(d));
    }
    hooks.extend(util::walk("/etc/networkd-dispatcher"));
    for h in hooks { let s = h.to_string_lossy().into_owned(); if !c.is_owned(&s) { c.warn(format!("NETWORK: unpackaged network hook: {s}")); } }
    // proxies that can MitM apt
    let mut files = vec!["/etc/apt/apt.conf".into(), "/etc/environment".into(), "/etc/wgetrc".into(), "/etc/curlrc".into()];
    for d in ["/etc/apt/apt.conf.d", "/etc/profile.d"] { files.extend(util::files_in(d).iter().map(|p| p.to_string_lossy().into_owned())); }
    for f in files { for l in util::read(&f).lines() {
        if !l.trim_start().starts_with('#') && l.to_lowercase().contains("proxy") { c.warn(format!("NETWORK: proxy setting: {f}: {l}")); }
    } }
    // apt sources: real host match (old check `grep ubuntu.com` also matched evilubuntu.com)
    let mut srcs = vec!["/etc/apt/sources.list".to_string()];
    srcs.extend(util::files_in("/etc/apt/sources.list.d").iter().map(|p| p.to_string_lossy().into_owned()));
    for f in srcs { for l in util::read(&f).lines() {
        let t = l.trim();
        let uri = if t.starts_with("deb ") || t.starts_with("deb-src ") {
            t.split_whitespace().skip(1).find(|w| w.contains("://") && !w.starts_with('['))
        } else { t.strip_prefix("URIs:").and_then(|r| r.split_whitespace().next()) };
        let Some(u) = uri else { continue };
        let h = util::host_of(u);
        if !(h == "ubuntu.com" || h.ends_with(".ubuntu.com")) { c.warn(format!("NETWORK: non-Ubuntu apt source: {f}: {t}")); }
    } }
}
