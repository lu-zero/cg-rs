use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use pam_cgroup_rs::config::{Config, DEFAULT_CONFIG};
use pam_cgroup_rs::place;
use pam_cgroup_rs::user::User;

fn usage() -> ! {
    eprintln!("usage: pam-cgroup <dry-run|apply|status> [--config PATH] [--user NAME] [--pid PID]");
    std::process::exit(2);
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pam-cgroup: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    let mut config = None;
    let mut user = None;
    let mut pid = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config = Some(args.next().unwrap_or_else(|| usage())),
            "--user" => user = Some(args.next().unwrap_or_else(|| usage())),
            "--pid" => {
                let p = args.next().unwrap_or_else(|| usage());
                pid = Some(
                    p.parse::<u32>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                );
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let config_path = config.unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    match cmd.as_str() {
        "dry-run" | "apply" => {
            let cfg = Config::load(&config_path)?;
            let user = match user {
                Some(n) => User::from_name(&n)?,
                None => User::from_uid(unsafe { libc::geteuid() as u32 })?,
            };
            let pid = pid.unwrap_or_else(std::process::id);
            if cmd == "dry-run" {
                for s in cfg.plan(&user, pid)? {
                    println!(
                        "{path} uid={uid} gid={gid} mode={mode:o} file={file:o} subtree={st:?} attach={att} pid={pid}",
                        path = s.path.display(),
                        uid = s.uid,
                        gid = s.gid,
                        mode = s.mode,
                        file = s.file_mode,
                        st = s.subtree_control,
                        att = s.attach,
                    );
                }
            } else {
                let steps = place::apply(&cfg, &user, pid)?;
                for s in steps {
                    println!("{}", s.path.display());
                }
            }
        }
        "status" => {
            let pid = pid.unwrap_or_else(std::process::id);
            let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
            let mut out = io::stdout();
            out.write_all(text.as_bytes())?;
        }
        _ => usage(),
    }
    Ok(())
}
