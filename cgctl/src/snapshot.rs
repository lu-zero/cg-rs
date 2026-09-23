//! `cgctl snapshot`: rebuild a cgconfig.conf view of the live tree.
//!
//! Faithful to layout, ownership, modes, enabled controllers, and
//! single-line writable knobs. Volatile/read-only families (`.stat`,
//! `.current`, `.pressure`, …) are skipped so a round-trip apply would
//! not write gauges or counters.

use std::io;
use std::path::Path;

use cgconfig::model::{ConfigFile, Node, Perm, PermSet};
use cgfs::{Cgroup, EntryKind};

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

/// Walk `root` and describe every cgroup found.
///
/// The root cgroup itself is not described; use `group . { … }` in a
/// hand-written config if you need its perm section.
pub fn snapshot(root: &Cgroup) -> io::Result<ConfigFile> {
    let rel_root = root.path().as_relative().to_path_buf();
    let mut groups = Vec::new();
    walk(root, &rel_root, &mut groups)?;

    Ok(ConfigFile {
        // The unified hierarchy has no per-controller mount points to record.
        mounts: Vec::new(),
        default_perm: None,
        groups,
        templates: Vec::new(),
    })
}

fn walk(cgroup: &Cgroup, rel: &Path, out: &mut Vec<Node>) -> io::Result<()> {
    for entry in cgroup.entries()? {
        if entry.kind != EntryKind::Directory {
            continue;
        }
        let child_rel = rel.join(&entry.name);
        let child = cgroup.child(&entry.name)?;
        out.push(describe(&child, &child_rel)?);
        walk(&child, &child_rel, out)?;
    }
    Ok(())
}

/// perm mapping (mirrors `cgfs::LeafSpec`): `admin` owns the directory and
/// its control files, `task` owns `cgroup.procs`.
fn describe(cgroup: &Cgroup, rel: &Path) -> io::Result<Node> {
    let dir_meta = cgroup.metadata()?;
    let procs = cgroup.control("cgroup.procs").ok();
    let procs_meta = procs.as_ref().and_then(|file| file.metadata().ok());

    let controllers = cgroup
        .control("cgroup.subtree_control")
        .ok()
        .and_then(|file| file.read_string().ok())
        .map(|s| {
            s.split_whitespace()
                .map(|c| c.trim_start_matches('+').to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let params = collect_params(cgroup);
    let name = rel.to_string_lossy().into_owned();
    let perm = procs_meta.map(|pm| Perm {
        task: PermSet {
            uid: Some(cgcore::name_from_uid(pm.uid)),
            gid: Some(cgcore::name_from_gid(pm.gid)),
            fperm: Some(pm.mode & 0o777),
            dperm: None,
        },
        admin: PermSet {
            uid: Some(cgcore::name_from_uid(dir_meta.uid)),
            gid: Some(cgcore::name_from_gid(dir_meta.gid)),
            // Representative control file; per-file modes are not expressible.
            fperm: cgroup
                .control("cgroup.subtree_control")
                .ok()
                .and_then(|file| file.metadata().ok())
                .map(|m| m.mode & 0o777),
            dperm: Some(dir_meta.mode & 0o777),
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
fn collect_params(cgroup: &Cgroup) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for entry in cgroup.entries().unwrap_or_default() {
        if entry.kind != EntryKind::Other {
            continue;
        }
        let name = entry.name.to_string_lossy().into_owned();
        if !is_param(&name) {
            continue;
        }
        let Ok(value) = cgroup.control(&name).and_then(|file| file.read_string()) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.contains('\n') {
            continue; // multi-line tables (stats) are not config
        }
        let controller = name.split('.').next().unwrap_or("misc").to_owned();
        out.push((controller, name, value.to_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgconfig::parse_cgconfig;
    use std::fs;

    #[test]
    fn snapshots_layout_owners_controllers() {
        let tmp = tempfile::tempdir().unwrap();
        let hierarchy = unsafe { cgfs::Hierarchy::open_for_test(tmp.path()) }.unwrap();
        let uid = unsafe { libc::geteuid() } as u32;
        let gid = unsafe { libc::getegid() } as u32;

        for rel in ["users", "users/lu_zero", "users/lu_zero/session"] {
            let path = tmp.path().join(rel);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("cgroup.procs"), "").unwrap();
            fs::write(path.join("cgroup.subtree_control"), "").unwrap();
        }
        let session = hierarchy.at_path("users/lu_zero/session").unwrap();
        let spec = cgfs::LeafSpec::new()
            .dperm(0o750)
            .fperm(0o640)
            .task_fperm(0o604)
            .subtree_control(&["cpu".to_owned()]);
        session.apply(&spec, None).unwrap();

        // Writable knobs plus the volatile/read-only families that must
        // never become parameters.
        let session_path = tmp.path().join("users/lu_zero/session");
        fs::write(session_path.join("memory.max"), "max\n").unwrap();
        fs::write(session_path.join("cpu.max"), "100000 100000\n").unwrap();
        fs::write(session_path.join("pids.max"), "512\n").unwrap();
        fs::write(session_path.join("memory.current"), "4096\n").unwrap();
        fs::write(
            session_path.join("cpu.stat"),
            "usage_usec 1\nuser_usec 0\nsystem_usec 0\n",
        )
        .unwrap();

        let cfg = snapshot(&hierarchy.root()).unwrap();
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
        assert_eq!(
            cgcore::uid_from_name(perm.task.uid.as_deref().unwrap()).unwrap(),
            uid
        );
        assert_eq!(
            cgcore::gid_from_name(perm.admin.gid.as_deref().unwrap()).unwrap(),
            gid
        );
    }
}
