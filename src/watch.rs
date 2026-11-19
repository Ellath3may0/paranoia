//! P3 `--watch[=SECS]`: re-check the cheap, idempotent things forever and print only NEW warnings.
use crate::{cmd, ctx::Ctx, preflight, steps::{audit, firewall, misc, network, persist, sysctl}};
use std::{collections::HashSet, time::Duration};

pub fn run(c: &Ctx, secs: u64) -> ! {
    let mut seen: HashSet<String> = c.warnings.lock().unwrap().iter().cloned().collect();
    println!("\n--watch: re-checking every {secs}s (Ctrl-C to stop)");
    loop {
        std::thread::sleep(Duration::from_secs(secs));
        c.findings.lock().unwrap().clear();
        preflight::quick(c);
        let _ = misc::memory_only(c);
        let _ = network::run(c);
        let _ = sysctl::run(c);
        let _ = audit::run(c);
        let _ = persist::run(c);
        if !cmd::run("nft", &["list", "ruleset"]).text.contains("hook input") {
            c.warn("WATCH: nftables ruleset missing, reapplying");
            let _ = firewall::run(c);
        }
        let w = c.warnings.lock().unwrap().clone();
        for m in w { if seen.insert(m.clone()) { println!("[watch {}] {m}", cmd::run("date", &["+%T"]).text.trim()); } }
    }
}
