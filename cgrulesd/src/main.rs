//! `cgrulesd` — keep processes inside the cgroups /etc/cgrules.conf
//! assigns them to. Poll-based successor of cgred/cgrulesengd for the
//! unified hierarchy: no netlink, no v1.

mod enforce;
mod nss;

use std::io;
use std::path::PathBuf;

use cgconfig::{parse_cgconfig_in, parse_cgrules};

fn usage() -> ! {
    eprintln!(
        "usage: cgrulesd [--config FILE] [--cgconfig FILE]
                 [--interval SECS] [--once] [--verbose]

  --config FILE    rules file (default /etc/cgrules.conf)
  --cgconfig FILE  optional cgconfig.conf providing groups/templates
  --interval SECS  seconds between passes (default 5; implies not --once)
  --once           run a single pass and exit"
    );
    std::process::exit(2)
}

struct Opts {
    config: PathBuf,
    cgconfig: Option<PathBuf>,
    interval: u64,
    once: bool,
    verbose: bool,
}

fn parse_opts() -> Opts {
    let mut o = Opts {
        config: PathBuf::from("/etc/cgrules.conf"),
        cgconfig: None,
        interval: 5,
        once: false,
        verbose: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val =
            |name: &str| -> String { it.next().unwrap_or_else(|| panic!("{name} needs a value")) };
        match a.as_str() {
            "--config" => o.config = val("--config").into(),
            "--cgconfig" => o.cgconfig = Some(val("--cgconfig").into()),
            "--interval" => o.interval = val("--interval").parse().unwrap_or_else(|_| usage()),
            "--once" => o.once = true,
            "--verbose" => o.verbose = true,
            _ => usage(),
        }
    }
    o
}

fn main() -> std::process::ExitCode {
    let opts = parse_opts();
    match run(&opts) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cgrulesd: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

fn load(opts: &Opts) -> io::Result<(Vec<cgconfig::Rule>, cgconfig::ConfigFile)> {
    let text = std::fs::read_to_string(&opts.config)?;
    let rules = parse_cgrules(&text).map_err(io::Error::other)?;
    let cfg = match &opts.cgconfig {
        Some(f) => {
            let t = std::fs::read_to_string(f)?;
            parse_cgconfig_in(f.display().to_string(), &t).map_err(io::Error::other)?
        }
        None => cgconfig::ConfigFile::default(),
    };
    Ok((rules, cfg))
}

fn run(opts: &Opts) -> io::Result<()> {
    loop {
        match load(opts) {
            Ok((rules, cfg)) => {
                let mount = cgfs::find_mount()?;
                let rows = gather(std::process::id());
                let out = enforce::enforce_once(&mount, &rules, &cfg, &rows, opts.verbose)?;
                if opts.verbose {
                    eprintln!(
                        "cgrulesd: moved {} placed {} ruleless {} nodest {}",
                        out.moved, out.already_placed, out.no_rule, out.missing_destination
                    );
                }
            }
            // A missing/invalid rules file must not kill the daemon.
            Err(e) => eprintln!("cgrulesd: {e}"),
        }
        if opts.once {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(opts.interval));
    }
}

/// Scan /proc for candidate processes (own pid skipped).
fn gather(self_pid: u32) -> Vec<enforce::ProcRow> {
    let mut cache = enforce::GroupCache::default();
    let mut rows = Vec::new();
    let Ok(dirs) = std::fs::read_dir("/proc") else {
        return rows;
    };
    for entry in dirs.filter_map(Result::ok) {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let p = entry.path();
        let Some((uid, gid)) = status_ids(&p.join("status")) else {
            continue; // kernel threads race away constantly
        };
        let Some(comm) = read_first_line(&p.join("comm")) else {
            continue;
        };
        let Some(cgroup) = cgroup_rel(&p.join("cgroup")) else {
            continue;
        };
        let user = nss::name_from_uid(uid);
        let groups = cache.groups_for(&user, gid);
        rows.push(enforce::ProcRow {
            pid,
            user,
            uid,
            gid,
            groups,
            comm,
            cgroup,
        });
    }
    rows
}

fn read_first_line(p: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned())
}

/// `(real uid, real gid)` from a `status:` file's `Uid:`/`Gid:` lines.
fn status_ids(status: &std::path::Path) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(status).ok()?;
    let uid_line = find_field(&text, "Uid:")?;
    let gid_line = find_field(&text, "Gid:")?;
    let uid = uid_line.split_whitespace().next()?.parse().ok()?;
    let gid = gid_line.split_whitespace().next()?.parse().ok()?;
    Some((uid, gid))
}

fn find_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
    text.lines()
        .find(|l| l.starts_with(field))
        .map(|l| l.trim_start_matches(|c: char| !c.is_ascii_digit()))
}

/// The `0::…` unified-hierarchy path of a process.
fn cgroup_rel(file: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
}
