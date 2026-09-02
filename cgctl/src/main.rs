//! `cgctl` — one binary for the cgroupfs v2 tasks libcgroup spread across
//! cgconfigparser/cgcreate/cgset/cgget/cgexec/cgclassify/cgdelete/lscgroup/
//! cgsnapshot.

mod nss;
mod snapshot;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cgfs::LeafSpec;

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

fn mount() -> io::Result<PathBuf> {
    cgfs::find_mount()
}

/// Pop the next argument as a path under the cgroup2 mount.
fn take_path(rest: &mut Vec<String>) -> io::Result<PathBuf> {
    let raw = match rest.first() {
        Some(r) => r.clone(),
        None => usage(),
    };
    rest.remove(0);
    Ok(cgfs::join(
        &mount()?,
        Path::new(raw.trim_start_matches('/')),
    ))
}

// ------------------------------------------------------------------ config

fn config(mut rest: Vec<String>) -> io::Result<()> {
    if rest.len() != 1 {
        usage();
    }
    let file = rest.pop().unwrap_or_else(|| usage());
    let text = std::fs::read_to_string(&file)?;
    let cfg = cgconfig::parse_cgconfig_in(&file, &text).map_err(io::Error::other)?;
    let mount = mount()?;
    // Shallow-first so parents exist before children re-assert on them.
    let mut nodes = cfg.groups.clone();
    nodes.sort_by_key(|n| n.name.split('/').count());
    for node in &nodes {
        if node.name == "." {
            continue; // the root cgroup exists by definition
        }
        if !cgconfig::model::is_safe_relative_path(&node.name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("group name {:?} has illegal path components", node.name),
            ));
        }
        let perm = cfg.effective_perm(node);
        let spec = LeafSpec {
            path: cgfs::join(&mount, Path::new(&node.name)),
            uid: try_resolve("user", perm.admin.uid.as_deref()),
            gid: try_resolve("group", perm.admin.gid.as_deref()),
            dperm: perm.admin.dperm,
            fperm: perm.admin.fperm,
            task_fperm: perm.task.fperm,
            task_uid: try_resolve("user", perm.task.uid.as_deref()),
            task_gid: try_resolve("group", perm.task.gid.as_deref()),
            subtree_control: node.controllers.clone(),
        };
        cgfs::apply(&spec, None)?;
        println!("{}", node.name);
    }
    Ok(())
}

fn try_resolve(kind: &str, name: Option<&str>) -> Option<u32> {
    name.and_then(|n| match nss::resolve(kind, n) {
        Ok(id) => Some(id),
        Err(e) => {
            eprintln!("cgctl: {e}; leaving owner unchanged");
            None
        }
    })
}

// ---------------------------------------------------------------------- ls

fn ls(rest: &mut Vec<String>) -> io::Result<()> {
    let base = match rest.first() {
        Some(_) => take_path(rest)?,
        None => mount()?,
    };
    if !rest.is_empty() {
        usage();
    }
    for g in cgfs::list_groups(&base)? {
        println!("{}", g.display());
    }
    Ok(())
}

// --------------------------------------------------------------------- get

fn get(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    let keys: Vec<String> = if rest.is_empty() {
        // Enumerate single-line writable knobs plus control files, similar to snapshot.
        let mut ks: Vec<String> = cgfs::CONTROL_FILES.iter().map(|s| s.to_string()).collect();
        if let Ok(rd) = std::fs::read_dir(&path) {
            for e in rd.filter_map(Result::ok) {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !ks.contains(&name) && !name.starts_with("cgroup.") {
                        if let Ok(text) = std::fs::read_to_string(e.path()) {
                            if !text.contains('\n') || text.trim_end().lines().count() == 1 {
                                // single-line knob; include
                                ks.push(name);
                            }
                        }
                    }
                }
            }
        }
        ks
    } else {
        rest.clone()
    };
    for k in &keys {
        if k.contains('/') || k.contains("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad key {k:?}"),
            ));
        }
        dump(&path.join(k))?;
    }
    Ok(())
}

fn dump(file: &Path) -> io::Result<()> {
    match std::fs::read_to_string(file) {
        Ok(text) => {
            print!("{}:\n{}\n", file.display(), text.trim_end());
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
        cgfs::write_file(path.join(k), v)?;
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
        cgfs::attach(&path, pid)?;
    }
    Ok(())
}

fn bad_pid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("bad pid {s}"))
}

// -------------------------------------------------------------------- exec

fn exec(rest: &mut Vec<String>) -> io::Result<()> {
    let path = take_path(rest)?;
    let procs = path.join("cgroup.procs");
    use std::os::unix::process::CommandExt;
    let err = unsafe {
        std::process::Command::new(rest.first().unwrap_or_else(|| usage()))
            .args(&rest[1..])
            .pre_exec(move || {
                // Only async-signal-safe operations between fork and exec.
                let cstr = std::ffi::CString::new(procs.as_os_str().as_encoded_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
                let fd = libc::open(cstr.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let buf = b"0\n";
                let ret = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
                libc::close(fd);
                if ret < 0 {
                    return Err(io::Error::last_os_error());
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
        cgfs::delete_tree(&path)
    } else {
        cgfs::delete_leaf(&path)
    }
}

// ---------------------------------------------------------------- snapshot

fn snapshot_cmd(rest: Vec<String>) -> io::Result<()> {
    if rest.len() > 1 {
        usage();
    }
    let rel = PathBuf::from(
        rest.first()
            .map(|p| p.trim_start_matches('/'))
            .unwrap_or("/"),
    );
    let cfg = snapshot::snapshot(&mount()?, &rel)?;
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
    writeln!(
        out,
        "# generated by cgctl snapshot; parameters not included"
    )?;
    write!(out, "{rendered}")
}
