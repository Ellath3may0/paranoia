//! Safe command execution: absolute paths from root-owned dirs, cleared env, optional timeout.
use std::{io::Write, path::Path, process::{Command, Stdio}, sync::mpsc, thread, time::Duration};

#[allow(dead_code)]
pub struct Out { pub ok: bool, pub code: i32, pub text: String }

const DIRS: [&str; 6] = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn find(name: &str) -> Option<String> {
    DIRS.iter().map(|d| format!("{d}/{name}")).find(|p| Path::new(p).is_file())
}
pub fn run(name: &str, args: &[&str]) -> Out { exec(name, args, None, 0, None) }
pub fn run_t(name: &str, args: &[&str], secs: u64) -> Out { exec(name, args, None, secs, None) }
pub fn run_in(name: &str, args: &[&str], input: &str) -> Out { exec(name, args, Some(input), 0, None) }

pub fn run_cwd(name: &str, args: &[&str], dir: &str, secs: u64) -> Out { exec(name, args, None, secs, Some(dir)) }

fn exec(name: &str, args: &[&str], input: Option<&str>, secs: u64, cwd: Option<&str>) -> Out {
    let Some(bin) = find(name) else {
        return Out { ok: false, code: 127, text: format!("{name}: not found") };
    };
    let mut c = Command::new(bin);
    if let Some(d) = cwd { c.current_dir(d); }
    c.args(args).env_clear()
        .env("PATH", PATH).env("LANG", "C.UTF-8")
        .env("DEBIAN_FRONTEND", "noninteractive").env("NEEDRESTART_SUSPEND", "1")
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => return Out { ok: false, code: 126, text: e.to_string() },
    };
    if let Some(i) = input {
        if let Some(mut s) = ch.stdin.take() { let _ = s.write_all(i.as_bytes()); }
    }
    let pid = ch.id() as i32;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || { let _ = tx.send(ch.wait_with_output()); });
    let res = if secs > 0 {
        match rx.recv_timeout(Duration::from_secs(secs)) {
            Ok(r) => r,
            Err(_) => {
                unsafe { libc::kill(pid, libc::SIGKILL); }
                rx.recv().unwrap_or_else(|_| Err(std::io::Error::other("timeout")))
            }
        }
    } else {
        rx.recv().unwrap_or_else(|_| Err(std::io::Error::other("channel closed")))
    };
    match res {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            Out { ok: o.status.success(), code: o.status.code().unwrap_or(-1), text: t }
        }
        Err(e) => Out { ok: false, code: -1, text: e.to_string() },
    }
}
