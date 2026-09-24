//! `cgctl` — one binary for the cgroupfs v2 tasks libcgroup spread across
//! cgconfigparser/cgcreate/cgset/cgget/cgexec/cgclassify/cgdelete/lscgroup/
//! cgsnapshot.

mod snapshot;

use std::io::{self, Write};
use std::process::ExitCode;

use cgfs::{Cgroup, Hierarchy};

fn usage() -> ! {
    eprintln!(
        "usage: cgctl <command> [args]

  config <FILE>                     apply a cgconfig.conf (groups only)
  ls [<rel-path>]                   list cgroups under the mount/point
  get <path> [key…]                 print control files (all or named)
  set <path> <key=value>…           write control files
  classify <path> <pid>…            move pids into a cgroup
  exec <path> <cmd> [args…]         run a command inside a cgroup
  delete [-r] <path>                remove a cgroup (-r: with children)
  snapshot [<rel-path>]             live tree as cgconfig.conf"
    );
    std::process::exit(2)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cgctl: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    let mut rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "config" => config(std::mem::take(&mut rest)),
        "ls" => ls(&mut rest),
        "get" => get(&mut rest),
        "set" => set(&mut rest),
        "classify" => classify(&mut rest),
        "exec" => exec(&mut rest),
        "delete" => delete(&mut rest),
        "snapshot" => snapshot_cmd(rest),
        _ => usage(),
    }
}

fn hierarchy() -> io::Result<Hierarchy> {
    Hierarchy::discover()
}

/// Pop the next argument as a path under the cgroup2 mount.
///
/// Only `..` and a Windows-style prefix are rejected here — unlike
/// `is_safe_relative_path`, an explicit `/` (the mount root itself) stays
/// legal: `cgctl get /` inspecting the root cgroup is a normal, explicit
/// admin action, not a destination a rule/template placeholder could ever
/// silently resolve to. `get`/`set`/`classify`/`delete`/`exec`/`snapshot`
/// all go through this.
fn take_path(rest: &mut Vec<String>) -> io::Result<Cgroup> {
    let raw = match rest.first() {
        Some(r) => r.clone(),
        None => usage(),
    };
    rest.remove(0);
    let rel = raw.strip_prefix('/').unwrap_or(&raw);
    if rel.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {raw:?} contains an empty component"),
        ));
    }
    hierarchy()?.at_path(rel)
}

// ------------------------------------------------------------------ config

fn config(mut rest: Vec<String>) -> io::Result<()> {
    if rest.len() != 1 {
        usage();
    }
    let file = rest.pop().unwrap_or_else(|| usage());
    let text = std::fs::read_to_string(&file)?;
    let cfg = cgconfig::parse_cgconfig_in(&file, &text).map_err(io::Error::other)?;
    let hierarchy = hierarchy()?;
    // Shallow-first so parents exist before children re-assert on them.
    let mut nodes = cfg.groups.clone();
    nodes.sort_by_key(|n| n.name.split('/').count());
    for node in &nodes {
        if node.name == "." {
            continue; // the root cgroup exists by definition
        }
        let perm = cfg.effective_perm(node);
        let plan = cgconfig::LeafPlan {
            path: node.name.clone(),
            task_uid: perm.task.uid.clone(),
            task_gid: perm.task.gid.clone(),
            tasks_file_mode: perm.task.fperm,
            owner_uid: perm.admin.uid.clone(),
            owner_gid: perm.admin.gid.clone(),
            dir_mode: perm.admin.dperm,
            file_mode: perm.admin.fperm,
            subtree_control: node.controllers.clone(),
            params: node.params.clone(),
        };
        cgcore::apply_plan(&hierarchy, &plan, None)?;
        println!("{}", node.name);
    }
    Ok(())
}

// ---------------------------------------------------------------------- ls

fn ls(rest: &mut Vec<String>) -> io::Result<()> {
    let base = match rest.first() {
        Some(_) => take_path(rest)?,
        None => hierarchy()?.root(),
    };
    if !rest.is_empty() {
        usage();
    }
    let base_path = base.path().as_relative();
    for group in base.list_groups()? {
        let relative = group
            .as_relative()
            .strip_prefix(base_path)
            .unwrap_or_else(|_| group.as_relative());
        println!("{}", relative.display());
    }
    Ok(())
}

// --------------------------------------------------------------------- get

fn get(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    let keys: Vec<String> = if rest.is_empty() {
        // Enumerate single-line writable knobs plus control files, similar to snapshot.
        let mut ks: Vec<String> = cgfs::CONTROL_FILES.iter().map(|s| s.to_string()).collect();
        for entry in path.entries()? {
            let name = entry.name.to_string_lossy().to_string();
            if entry.kind == cgfs::EntryKind::Other
                && !ks.contains(&name)
                && !name.starts_with("cgroup.")
            {
                let Ok(control) = path.control(&name) else {
                    continue;
                };
                let Ok(text) = control.read_string() else {
                    continue;
                };
                if !text.contains('\n') || text.trim_end().lines().count() == 1 {
                    ks.push(name);
                }
            }
        }
        ks
    } else {
        rest.clone()
    };
    for key in &keys {
        dump(&path, key)?;
    }
    Ok(())
}

fn dump(cgroup: &Cgroup, key: &str) -> io::Result<()> {
    match cgroup.control(key)?.read_string() {
        Ok(text) => {
            print!(
                "{}:\n{}\n",
                cgroup
                    .hierarchy()
                    .mount_path()
                    .join(cgroup.path().as_relative())
                    .join(key)
                    .display(),
                text.trim_end()
            );
            io::stdout().flush()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()), // controller off
        Err(e) => Err(e),
    }
}

// --------------------------------------------------------------------- set

fn set(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    if rest.is_empty() {
        usage();
    }
    for kv in rest {
        let (k, v) = kv.split_once('=').unwrap_or_else(|| usage());
        if k.contains('/') || k.contains("..") || k.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad key {k:?}"),
            ));
        }
        path.control(k)?.write(v)?;
        println!("{k} <- {v}");
    }
    Ok(())
}

// ---------------------------------------------------------------- classify

fn classify(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    if rest.is_empty() {
        usage();
    }
    for pid in rest {
        let pid: u32 = pid.parse().map_err(|_| bad_pid(pid))?;
        path.attach(pid)?;
    }
    Ok(())
}

fn bad_pid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("bad pid {s}"))
}

// -------------------------------------------------------------------- exec

fn exec(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    let procs = path.control("cgroup.procs")?.open_for_write()?;
    let fd = procs.as_raw_fd();
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let err = unsafe {
        std::process::Command::new(rest.first().unwrap_or_else(|| usage()))
            .args(&rest[1..])
            .pre_exec(move || {
                // Only async-signal-safe operations between fork and exec.
                let buf = b"0\n";
                let ret = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
                if ret != buf.len() as isize {
                    return Err(if ret < 0 {
                        io::Error::last_os_error()
                    } else {
                        io::Error::new(io::ErrorKind::WriteZero, "short write to cgroup.procs")
                    });
                }
                Ok(())
            })
            .exec()
    };
    Err(err) // exec only returns on failure
}

// ------------------------------------------------------------------ delete

fn delete(rest: &mut Vec<String>) -> io::Result<()> {
    let recursive = matches!(rest.first(), Some(f) if f == "-r");
    if recursive {
        rest.remove(0);
    }
    let path = take_path(rest)?;
    if !rest.is_empty() {
        usage();
    }
    if recursive {
        path.delete_tree()
    } else {
        path.delete_leaf()
    }
}

// ---------------------------------------------------------------- snapshot

fn snapshot_cmd(mut rest: Vec<String>) -> io::Result<()> {
    if rest.len() > 1 {
        usage();
    }
    let root = if rest.is_empty() {
        hierarchy()?.root()
    } else {
        take_path(&mut rest)?
    };
    let cfg = snapshot::snapshot(&root)?;
    // Render to a String first: `write!` on an `io::Write` target *panics*
    // if the Display impl itself returns Err (std::io::Write::write_fmt's
    // documented behaviour when the error didn't come from the
    // underlying stream) — not the clean io::Error this function's
    // signature promises. A group/template name, controller name, or
    // param key can come straight from a live cgroup a delegatee
    // controls (see cgconfig::display's module doc comment), so this is
    // reachable, not hypothetical. `write!` on a `String` uses
    // `fmt::Write` instead, which returns the error properly.
    use std::fmt::Write as _;
    let mut rendered = String::new();
    write!(rendered, "{cfg}").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "a live cgroup's name, controller, or parameter key is not representable in \
             cgconfig.conf syntax (contains a literal '\"', or a controller name contains \
             whitespace/punctuation with no way to quote it)",
        )
    })?;
    let mut out = io::stdout().lock();
    writeln!(out, "# generated by cgctl snapshot")?;
    write!(out, "{rendered}")
}
