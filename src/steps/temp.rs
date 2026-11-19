use crate::ctx::Ctx;
use std::{fs, path::Path};

fn wipe(dir: &str, keep: &[&str]) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if keep.iter().any(|k| n.starts_with(k)) { continue; }
        let p = e.path();
        // symlink_metadata: never follow links
        let is_dir = fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false);
        let _ = if is_dir { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
    }
}

pub fn run(_c: &Ctx) -> Result<(), String> {
    let keep = ["systemd-private-", "mkinitramfs", "dpkg", "apt", "needrestart"];
    wipe("/tmp", &keep);
    wipe("/var/tmp", &keep);
    wipe("/dev/shm", &[]);
    wipe("/var/crash", &[]);
    if Path::new("/root/.cache").exists() { let _ = fs::remove_dir_all("/root/.cache"); }
    Ok(())
}
