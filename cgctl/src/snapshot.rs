//! `cgctl snapshot`: rebuild a cgconfig.conf view of the live tree.
//!
//! Faithful to layout, ownership, modes and enabled controllers. Parameter
//! dumping is deliberately out of scope for now (cgsnapshot's blacklist
//! machinery is its own project); emitted controller blocks are empty.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use cgconfig::model::{ConfigFile, Node, Perm, PermSet};

use crate::nss;

/// Control files that must never come back as parameters: read-only
/// counters, volatile gauges and write-only triggers — reapplying them
/// would either fail or lie.
const SKIP_PARAM_SUFFIX: [&str; 9] = [
    ".stat",
    ".events",
    ".pressure",
    ".current",
    ".peak",
    ".numa_stat",
    ".effective",
    ".reclaim",
    ".idle",
];

fn is_param(name: &str) -> bool {
    !name.starts_with("cgroup.") && !SKIP_PARAM_SUFFIX.iter().any(|s| name.ends_with(s))
}

/// Walk `mount`/`rel_root` (default `/`) and describe every cgroup found.
///
/// The base directory itself is not described; use `group . { … }` in a
/// hand-written config if you need its perm section.
pub fn snapshot(mount: &Path, rel_root: &Path) -> io::Result<ConfigFile> {
    let base = if rel_root == Path::new("/") {
        mount.to_path_buf()
    } else {
        mount.join(rel_root.strip_prefix("/").unwrap_or(rel_root))
    };
    let mut groups = Vec::new();
    walk(&base, rel_root, &mut groups)?;

    Ok(ConfigFile {
        // The unified hierarchy has no per-controller mount points to record.
        mounts: Vec::new(),
        default_perm: None,
        groups,
        templates: Vec::new(),
    })
}

fn walk(dir: &Path, rel: &Path, out: &mut Vec<Node>) -> io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let child_rel = rel.join(entry.file_name());
        out.push(describe(&entry.path(), &child_rel)?);
        walk(&entry.path(), &child_rel, out)?;
    }
    Ok(())
}

/// perm mapping (mirrors cgfs::LeafSpec): `admin` owns the directory and
/// its control files, `task` owns `cgroup.procs`.
fn describe(path: &Path, rel: &Path) -> io::Result<Node> {
    let dir_meta = fs::metadata(path)?;
    let procs_path = path.join("cgroup.procs");
    let procs_meta = fs::metadata(&procs_path).ok();

    let controllers = fs::read_to_string(path.join("cgroup.subtree_control"))
        .map(|s| {
            s.split_whitespace()
                .map(|c| c.trim_start_matches('+').to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let params = collect_params(path);

    let name = rel
        .strip_prefix("/")
        .unwrap_or(rel)
        .to_string_lossy()
        .into_owned();
    let perm = procs_meta.map(|pm| Perm {
        task: PermSet {
            uid: Some(nss::name_from_uid(pm.uid())),
            gid: Some(nss::name_from_gid(pm.gid())),
            fperm: Some(pm.permissions().mode() & 0o777),
            dperm: None,
        },
        admin: PermSet {
            uid: Some(nss::name_from_uid(dir_meta.uid())),
            gid: Some(nss::name_from_gid(dir_meta.gid())),
            // Representative control file; per-file modes are not expressible.
            fperm: fs::metadata(path.join("cgroup.subtree_control"))
                .ok()
                .map(|m| m.permissions().mode() & 0o777),
            dperm: Some(dir_meta.permissions().mode() & 0o777),
        },
    });

    Ok(Node {
        name,
        perm,
        controllers,
        params,
    })
}

/// Single-line writable knobs become `(controller, file, value)` triples;
/// the controller is the filename prefix (`memory.max` → `memory`). The
/// Display layer emits a block for param controllers even when they are
/// absent from `subtree_control`.
fn collect_params(path: &Path) -> Vec<(String, String, String)> {
    let mut entries: Vec<_> = match fs::read_dir(path) {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(_) => return Vec::new(),
    };
    entries.sort_by_key(|e| e.file_name());
    let mut out = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) || !is_param(&name) {
            continue;
        }
        let Ok(value) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.contains('\n') {
            continue; // multi-line tables (stats) are not config
        }
        let controller = name.split('.').next().unwrap_or("misc").to_owned();
        out.push((controller, name.into_owned(), value.to_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nss;
    use cgconfig::parse_cgconfig;
    use std::path::PathBuf;

    #[test]
    fn snapshots_layout_owners_controllers() {
        let tmp = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let gid = unsafe { libc::getegid() } as u32;
        let spec = cgfs::LeafSpec {
            path: PathBuf::from(tmp.path()).join("users/lu_zero/session"),
            uid: Some(uid),
            gid: Some(gid),
            dperm: Some(0o750),
            fperm: Some(0o640),
            task_fperm: Some(0o604),
            task_uid: None,
            task_gid: None,
            subtree_control: vec!["cpu".into()],
        };
        // A real cgroupfs ships control files with every directory; fake
        // that here so apply() has something to own and chmod.
        for rel in ["users", "users/lu_zero", "users/lu_zero/session"] {
            let d = tmp.path().join(rel);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cgroup.procs"), "").unwrap();
            std::fs::write(d.join("cgroup.subtree_control"), "").unwrap();
        }
        cgfs::apply(&spec, None).unwrap();

        // Writable knobs plus the volatile/read-only families that must
        // never become parameters.
        let session = tmp.path().join("users/lu_zero/session");
        std::fs::write(session.join("memory.max"), "max\n").unwrap();
        std::fs::write(session.join("cpu.max"), "100000 100000\n").unwrap();
        std::fs::write(session.join("pids.max"), "512\n").unwrap();
        std::fs::write(session.join("memory.current"), "4096\n").unwrap();
        std::fs::write(
            session.join("cpu.stat"),
            "usage_usec 1\nuser_usec 0\nsystem_usec 0\n",
        )
        .unwrap();

        let cfg = snapshot(tmp.path(), Path::new("/")).unwrap();
        let rendered = cfg.to_string();
        assert!(
            rendered.contains("group users/lu_zero/session {"),
            "{rendered}"
        );
        assert!(rendered.contains("dperm = 750;"), "{rendered}");
        assert!(rendered.contains("fperm = 604;"), "{rendered}");
        assert!(rendered.contains("\tcpu {"), "{rendered}");
        assert!(rendered.contains("memory.max = max;"), "{rendered}");
        assert!(
            rendered.contains("cpu.max = \"100000 100000\";"),
            "{rendered}"
        );
        assert!(rendered.contains("pids.max = 512;"), "{rendered}");
        assert!(!rendered.contains("memory.current"), "{rendered}");
        assert!(!rendered.contains("cpu.stat"), "{rendered}");

        // The snapshot is itself valid config that plans back to the same tree.
        let reparsed = parse_cgconfig(&rendered).unwrap();
        let leaf = reparsed.find_group("users/lu_zero/session").unwrap();
        let perm = reparsed.effective_perm(leaf);
        assert_eq!(perm.admin.dperm, Some(0o750));
        assert_eq!(perm.task.fperm, Some(0o604));
        assert_eq!(leaf.controllers, vec!["cpu".to_owned()]);
        assert!(leaf.params.contains(&(
            "memory".to_owned(),
            "memory.max".to_owned(),
            "max".to_owned()
        )));
        assert_eq!(
            nss::uid_from_name(perm.task.uid.as_deref().unwrap()).unwrap(),
            uid
        );
    }
}
