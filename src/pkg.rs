//! Native dpkg helpers: installed list, owned-path index, md5sums verification.
use md5::{Digest, Md5};
use crate::cmd;
use std::{collections::HashSet, fs::File, io::Read};

const INFO: &str = "/var/lib/dpkg/info";

pub fn build_owned_index() -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(rd) = std::fs::read_dir(INFO) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map_or(false, |x| x == "list") {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    for l in t.lines() {
                        set.insert(l.strip_prefix("/usr").filter(|_| l.starts_with("/usr/")).unwrap_or(l).to_string());
                    }
                }
            }
        }
    }
    set
}

/// Names of packages with status "install ok installed".
pub fn installed() -> Vec<String> {
    let t = std::fs::read_to_string("/var/lib/dpkg/status").unwrap_or_default();
    let mut out = vec![];
    for stanza in t.split("\n\n") {
        let (mut name, mut ok) = (None, false);
        for l in stanza.lines() {
            if let Some(n) = l.strip_prefix("Package: ") { name = Some(n.trim().to_string()); }
            if l == "Status: install ok installed" { ok = true; }
        }
        if let (Some(n), true) = (name, ok) { out.push(n); }
    }
    out
}

pub fn installed_matching(f: impl Fn(&str) -> bool) -> Vec<String> {
    installed().into_iter().filter(|p| f(p)).collect()
}

pub fn md5_file(p: &str) -> Option<String> { md5_of(p) }
fn md5_of(p: &str) -> Option<String> {
    let mut f = File::open(p).ok()?;
    let mut h = Md5::new();
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b).ok()?;
        if n == 0 { break; }
        h.update(&b[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn md5sums_path(pkg: &str) -> Option<String> {
    let exact = format!("{INFO}/{pkg}.md5sums");
    if std::path::Path::new(&exact).exists() { return Some(exact); }
    let prefix = format!("{pkg}:");
    std::fs::read_dir(INFO).ok()?.flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(&prefix) && n.ends_with(".md5sums"))
        .map(|n| format!("{INFO}/{n}"))
}

/// Returns "changed /path" or "missing /path" lines. Conffiles are not in md5sums (same as `dpkg --verify` minus ' c ').
pub fn verify(pkg: &str) -> Vec<String> {
    let Some(f) = md5sums_path(pkg) else { return vec![] };
    let t = std::fs::read_to_string(f).unwrap_or_default();
    let mut bad = vec![];
    for l in t.lines() {
        let Some((hash, rel)) = l.split_once("  ") else { continue };
        let path = format!("/{rel}");
        if ["/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/locale/", "/usr/share/lintian/"]
            .iter().any(|p| path.starts_with(p)) { continue; }
        if std::fs::symlink_metadata(&path).is_err() { bad.push(format!("missing {path}")); continue; }
        if md5_of(&path).as_deref() != Some(hash) { bad.push(format!("changed {path}")); }
    }
    bad
}

/// Parallel verify. Returns (package, first few bad files) for each failing package.
pub fn tampered(pkgs: &[String]) -> Vec<(String, Vec<String>)> {
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    let chunk = pkgs.len().div_ceil(n).max(1);
    let mut out = vec![];
    std::thread::scope(|s| {
        let hs: Vec<_> = pkgs.chunks(chunk).map(|c| s.spawn(move || {
            c.iter().filter_map(|p| { let b = verify(p); (!b.is_empty()).then(|| (p.clone(), b)) }).collect::<Vec<_>>()
        })).collect();
        for h in hs { if let Ok(mut v) = h.join() { out.append(&mut v); } }
    });
    out.sort();
    out
}

/// apt-get with the standard non-interactive options (waits up to 30 min for the dpkg lock).
pub fn apt(args: &[&str], secs: u64) -> cmd::Out {
    let mut a: Vec<&str> = crate::config::APT_OPTS.to_vec();
    a.extend(args);
    cmd::run_t("apt-get", &a, secs)
}

/// Short-leash apt-get for early steps: 90 s lock wait, no pty, caller supplies the total cap.
pub fn apt_quick(args: &[&str], secs: u64) -> cmd::Out {
    let mut a = vec!["-y", "-o", "Dpkg::Options::=--force-confnew", "-o", "DPkg::Lock::Timeout=90", "-o", "Dpkg::Use-Pty=0",
        "-o", "Acquire::Retries=0", "-o", "Acquire::http::Timeout=15", "-o", "Acquire::https::Timeout=15"];
    a.extend(args);
    cmd::run_t("apt-get", &a, secs)
}
