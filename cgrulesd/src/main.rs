//! `cgrulesd` — keep processes inside the cgroups /etc/cgrules.conf
//! assigns them to. Poll-based successor of cgred/cgrulesengd for the
//! unified hierarchy: no netlink, no v1.

mod enforce;
mod nss;

use std::collections::HashSet;
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
        let mut val = |name: &str| -> String {
            it.next().unwrap_or_else(|| {
                eprintln!("cgrulesd: {name} needs a value");
                usage()
            })
        };
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
    // Destinations enforce_once created via a template match, tracked
    // across the daemon's whole lifetime so reap_idle_templates can
    // notice when one goes idle. A --once run never reaps in practice
    // (see that function's doc comment for why), so there's no need to
    // persist this anywhere beyond the current process either way.
    let mut tracked_templates = HashSet::new();
    // Cleared whenever the loaded (rules, cgconfig) changes, so a
    // destination that used to be a template match but is now an
    // admin-declared `group` (or vice versa) doesn't keep the stale
    // classification from before the reload — enforce_once re-derives
    // and re-inserts the correct entries on the very next pass via the
    // already-placed path, so clearing here costs nothing but a pass of
    // rediscovery.
    let mut last_loaded: Option<(Vec<cgconfig::Rule>, cgconfig::ConfigFile)> = None;
    loop {
        match load(opts) {
            Ok((rules, cfg)) => {
                let changed = match &last_loaded {
                    Some((r, c)) => *r != rules || *c != cfg,
                    None => true,
                };
                if changed {
                    tracked_templates.clear();
                    last_loaded = Some((rules.clone(), cfg.clone()));
                }
                let mount = match cgfs::find_mount() {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("cgrulesd: find_mount: {e}");
                        if opts.once {
                            return Err(e);
                        }
                        std::thread::sleep(std::time::Duration::from_secs(opts.interval));
                        continue;
                    }
                };
                let rows = gather(std::process::id());
                let out = match enforce::enforce_once(
                    &mount,
                    &rules,
                    &cfg,
                    &rows,
                    opts.verbose,
                    still_same_process,
                    &mut tracked_templates,
                ) {
                    Ok(o) => o,
                    Err(e) => {
                        eprintln!("cgrulesd: enforce: {e}");
                        if opts.once {
                            return Err(e);
                        }
                        std::thread::sleep(std::time::Duration::from_secs(opts.interval));
                        continue;
                    }
                };
                if !opts.once {
                    enforce::reap_idle_templates(&mut tracked_templates, opts.verbose);
                }
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

/// Re-read `/proc/<pid>` immediately before it would be attached, to
/// narrow the window a recycled pid has to slip past `gather()`'s
/// once-per-pass scan: `enforce_once` may reach this row long after (up to
/// one full pass's worth of processes later) `gather()` read it, and the
/// original process could have exited and had its pid reused by an
/// unrelated one in the meantime. Uid and comm both matching what was
/// scanned is not a guarantee (a race remains between this check and the
/// write), but it turns "reused anywhere in the last poll interval" into
/// "reused between this stat and the cgfs::apply call right after it" —
/// which still runs the full leaf create/chown/chmod/attach sequence, not
/// a single write, so the residual window is on the order of tens of
/// syscalls, not one.
fn still_same_process(row: &enforce::ProcRow) -> bool {
    let p = std::path::Path::new("/proc").join(row.pid.to_string());
    let Some((uid, _gid)) = status_ids(&p.join("status")) else {
        return false;
    };
    if uid != row.uid {
        return false;
    }
    read_first_line(&p.join("comm")).as_deref() == Some(row.comm.as_str())
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
