use std::{collections::HashSet, fs::{File, OpenOptions}, io::Write, os::unix::fs::PermissionsExt,
          path::PathBuf, sync::{Mutex, RwLock}};

pub struct Ctx {
    pub no_pkg: bool,
    pub work: PathBuf,
    pub user: String,
    pub ancestors: Vec<u32>,
    pub warnings: Mutex<Vec<String>>,
    pub pw_user: Mutex<Option<String>>,
    pub pw_root: Mutex<Option<String>>,
    pub findings: Mutex<Vec<String>>,
    log: Mutex<File>,
    owned: RwLock<Option<HashSet<String>>>,
}

impl Ctx {
    pub fn new(no_pkg: bool, user: String) -> std::io::Result<Self> {
        let work = PathBuf::from(crate::config::WORK_DIR);
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))?;
        let log = OpenOptions::new().create(true).append(true).open(work.join("main.log"))?;
        Ok(Ctx {
            no_pkg, work, user, ancestors: ancestors(),
            warnings: Mutex::new(vec![]), pw_user: Mutex::new(None), pw_root: Mutex::new(None), findings: Mutex::new(vec![]),
            log: Mutex::new(log), owned: RwLock::new(None),
        })
    }
    pub fn log(&self, m: &str) {
        if let Ok(mut f) = self.log.lock() { let _ = writeln!(f, "{m}"); }
    }
    pub fn warn(&self, m: impl Into<String>) {
        let m = m.into();
        self.log(&format!("WARN {m}"));
        if let Ok(mut w) = self.warnings.lock() { w.push(m); }
    }
    /// Preflight finding: kept separately (gates the password prompt) and also shown in the final report.
    pub fn finding(&self, m: impl Into<String>) {
        let m = m.into();
        if let Ok(mut f) = self.findings.lock() { f.push(m.clone()); }
        self.warn(format!("PREFLIGHT: {m}"));
    }
    pub fn is_ancestor(&self, pid: u32) -> bool { self.ancestors.contains(&pid) }
    pub fn report_only(&self, m: &str) { self.warn(format!("REPORT-ONLY (not done): {m}")); }
    /// Rebuild the owned-path index (call after packages were installed or removed).
    pub fn reindex(&self) { *self.owned.write().unwrap() = Some(crate::pkg::build_owned_index()); }
    /// True if an installed package ships PATH (symlinks resolved, /usr merged).
    pub fn is_owned(&self, p: &str) -> bool {
        let r = std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        let s = r.to_string_lossy();
        let s: &str = s.strip_prefix("/usr").unwrap_or(&*s);
        if let Some(set) = self.owned.read().unwrap().as_ref() { return set.contains(s); }
        self.reindex();
        self.owned.read().unwrap().as_ref().map_or(false, |x| x.contains(s))
    }
}

fn ancestors() -> Vec<u32> {
    let mut v = vec![];
    let mut pid = std::process::id();
    while pid > 1 {
        v.push(pid);
        let st = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        pid = st.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|x| x.trim().parse().ok()).unwrap_or(0);
    }
    v
}
