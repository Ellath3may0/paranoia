use crate::{cmd, ctx::Ctx};
pub fn run(_c: &Ctx) -> Result<(), String> {
    let o = cmd::run("systemctl", &["daemon-reload"]);
    if o.ok { Ok(()) } else { Err(o.text) }
}
