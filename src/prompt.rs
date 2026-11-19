//! Hidden-input prompts on /dev/tty (termios). Never touches stdin, never echoes.
use std::{fs::OpenOptions, io::{BufRead, BufReader, Write}, os::fd::AsRawFd};

fn tty() -> Option<std::fs::File> { OpenOptions::new().read(true).write(true).open("/dev/tty").ok() }

fn read_line(echo: bool, prompt: &str) -> Option<String> {
    let mut t = tty()?;
    let fd = t.as_raw_fd();
    let _ = write!(t, "{prompt}");
    let _ = t.flush();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if have && !echo {
        let mut n = old;
        n.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &n); }
    }
    let mut s = String::new();
    let r = BufReader::new(&t).read_line(&mut s);
    if have { unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old); } }
    if !echo { let _ = writeln!(t); }
    r.ok().filter(|n| *n > 0).map(|_| s.trim_end_matches(['\n', '\r']).to_string())
}

pub fn confirm(prompt: &str) -> bool {
    read_line(true, prompt).map_or(false, |a| a.starts_with(['y', 'Y']))
}

/// Ask twice, loop until non-empty and matching. None if there is no tty.
pub fn new_password(user: &str) -> Option<String> {
    loop {
        let a = read_line(false, &format!("New password for {user}: "))?;
        let b = read_line(false, "Confirm: ")?;
        if !a.is_empty() && a == b { return Some(a); }
        eprintln!("Empty or mismatch, again.");
    }
}

/// Two lines (user password, root password) from an inherited fd, for non-interactive installs.
pub fn from_fd(fd: i32) -> (Option<String>, Option<String>) {
    use std::os::fd::FromRawFd;
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut r = BufReader::new(f);
    let mut line = || { let mut s = String::new(); r.read_line(&mut s).ok().filter(|n| *n > 0).map(|_| s.trim_end_matches(['\n', '\r']).to_string()).filter(|s| !s.is_empty()) };
    (line(), line())
}
