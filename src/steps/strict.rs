//! P3 `--strict`: do not trust /var/lib/dpkg/info md5sums. Download the installed version of each critical package,
//! extract it, and compare every file with what is on disk. Relies on apt's signed-repo chain, not on local dpkg state.
use crate::{cmd, config as cf, ctx::Ctx, pkg, util};
use std::{fs, path::Path};

pub fn run(c: &Ctx) -> Result<(), String> {
    let dir = c.work.join("strict");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let d = dir.to_string_lossy().into_owned();
    let mut bad = 0;
    for p in pkg::installed_matching(|p| cf::CRITICAL_PACKAGES.contains(&p) || cf::AUTH_PACKAGES.contains(&p)) {
        let ver = cmd::run("dpkg-query", &["-W", "-f=${Version}", &p]).text.trim().to_string();
        let arch = cmd::run("dpkg-query", &["-W", "-f=${Architecture}", &p]).text.trim().to_string();
        let spec = format!("{p}={ver}");
        let dl = cmd::run_cwd("apt-get", &["-o", "APT::Sandbox::User=root", "download", &spec], &d, 120);
        if !dl.ok { c.warn(format!("STRICT: cannot download {spec} ({arch}), not verified")); continue; }
        let deb = util::files_in(&d).into_iter().find(|f| f.to_string_lossy().contains(&format!("/{p}_")) && f.extension().map_or(false, |e| e == "deb"));
        let Some(deb) = deb else { continue };
        let out = dir.join(format!("x_{p}"));
        let _ = fs::create_dir_all(&out);
        if !cmd::run("dpkg-deb", &["-x", &deb.to_string_lossy(), &out.to_string_lossy()]).ok { c.warn(format!("STRICT: cannot unpack {spec}")); continue; }
        let root = out.to_string_lossy().into_owned();
        for f in util::walk(&root) {
            let rel = f.strip_prefix(&out).unwrap().to_string_lossy().into_owned();
            if rel.starts_with("etc/") || rel.starts_with("usr/share/doc") || rel.starts_with("usr/share/man") || rel.starts_with("usr/share/locale") { continue; }
            let Ok(m) = fs::symlink_metadata(&f) else { continue };
            if !m.is_file() { continue; }
            let live = format!("/{rel}");
            if !Path::new(&live).exists() { continue; }
            if pkg::md5_file(&f.to_string_lossy()) != pkg::md5_file(&live) { bad += 1; c.warn(format!("STRICT: {live} differs from the signed {p} {ver} package")); }
        }
        let _ = fs::remove_dir_all(&out);
        let _ = fs::remove_file(&deb);
    }
    if bad == 0 { c.log("strict verify clean"); }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
