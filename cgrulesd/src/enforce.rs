//! Enforcement core: match processes against cgrules and move them.
//!
//! Pure-ish by design — process rows are supplied by the caller so the
//! matching/moving logic is testable without a live `/proc`.

use std::collections::{HashMap, HashSet};
use std::io;

use cgconfig::model::{first_rule_names, ConfigFile, Identity};
use cgfs::{Cgroup, CgroupPath, Hierarchy, LeafSpec};

/// One process as seen by the poller.
#[derive(Clone, Debug)]
pub struct ProcRow {
    pub pid: u32,
    /// Real uid owner's name (numeric string if unresolved).
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    /// Supplementary group names, for `@group` subjects.
    pub groups: Vec<String>,
    pub comm: String,
    /// Current cgroup path relative to the hierarchy (`0::` line).
    pub cgroup: String,
    /// `/proc/<pid>/exe` target, when readable.
    pub exe: Option<String>,
    /// `/proc/<pid>/stat` starttime, used to pin identity across reuse.
    pub starttime: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub moved: usize,
    pub already_placed: usize,
    pub no_rule: usize,
    pub missing_destination: usize,
    pub ignored: usize,
}

/// One enforcement pass. Creates destinations from exact `group` entries
/// or same-named `template`s; unmatched destinations are skipped loudly.
///
/// `revalidate` is checked immediately before a matched process is
/// actually attached — not at match time — to narrow the classic
/// `/proc`-scan pid-reuse race: `procs` was read once, up front, and a
/// pid can exit and be recycled for an unrelated (possibly privileged)
/// process before its turn to be moved comes up, potentially hundreds of
/// rows later. A `false` here means "no longer the process we scanned";
/// the row is skipped, not attached. Production wires this to a fresh
/// `/proc/<pid>` re-read (see `main::still_same_process`); tests pass a
/// stub so the matching/moving logic stays testable without a live
/// `/proc` (the module doc comment's "pure-ish by design").
///
/// `tracked_templates` accumulates every destination reached via a
/// *template* match (see [`leaf_spec`]) across calls, so the caller can
/// later pass it to [`reap_idle_templates`]. Owned by the caller (one
/// `HashSet` for the life of the daemon), not reset each pass.
pub fn enforce_once(
    hierarchy: &Hierarchy,
    rules: &[cgconfig::Rule],
    cfg: &ConfigFile,
    procs: &[ProcRow],
    verbose: bool,
    revalidate: impl Fn(&ProcRow) -> bool,
    tracked_templates: &mut HashSet<CgroupPath>,
) -> io::Result<Outcome> {
    let mut out = Outcome::default();
    let mut missing: Vec<String> = Vec::new();
    for row in procs {
        let names = process_names(row);
        let Some(rule) = first_rule_names(rules, &row.user, &row.groups, &names) else {
            out.no_rule += 1;
            continue;
        };
        if rule.ignores() || (rule.ignores_rt() && is_rt_task(row.pid)) {
            out.ignored += 1;
            continue;
        };
        let identity = Identity {
            name: row.user.clone(),
            uid: row.uid.to_string(),
            gid: row.gid.to_string(),
            group: cgcore::name_from_gid(row.gid),
            proc_name: row.comm.clone(),
            pid: row.pid.to_string(),
        };
        let dest = identity.expand(&rule.destination);
        let dest = dest.trim_matches('/').to_owned();
        // %p expands from /proc/<pid>/comm, which the process itself
        // controls; refuse a destination a crafted comm walked out of the
        // cgroup mount tree instead of building a path from it.
        if !cgconfig::model::is_safe_relative_path(&dest) {
            out.missing_destination += 1;
            eprintln!(
                "cgrulesd: pid {} rule destination {:?} has illegal path components after expansion, skipping",
                row.pid, dest
            );
            continue;
        }
        let destination = match leaf_spec(hierarchy, cfg, &dest, &rule.destination.0, &identity) {
            Ok(destination) => destination,
            Err(e) => {
                out.missing_destination += 1;
                eprintln!(
                    "cgrulesd: pid {} cannot resolve destination {:?}: {e}",
                    row.pid, dest
                );
                if !missing.contains(&dest) {
                    missing.push(dest.clone());
                }
                continue;
            }
        };
        let Some((target, spec, is_template)) = destination else {
            out.missing_destination += 1;
            if !missing.contains(&dest) {
                missing.push(dest.clone());
            }
            continue;
        };
        // Track even if apply fails after mkdir, or a restart orphans
        // the dest from this in-memory set.
        if is_template {
            tracked_templates.insert(target.path().clone());
        }
        if norm(&row.cgroup) == dest {
            out.already_placed += 1;
            continue;
        }
        if !revalidate(row) {
            if verbose {
                eprintln!(
                    "cgrulesd: pid {} no longer matches its scanned identity (recycled?), skipping",
                    row.pid
                );
            }
            continue;
        }
        if let Err(e) = target.apply(&spec, Some(row.pid)) {
            if e.kind() == io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ESRCH)
                || e.raw_os_error() == Some(libc::ENOENT)
            {
                if verbose {
                    eprintln!("cgrulesd: pid {} vanished: {e}", row.pid);
                }
                continue;
            }
            eprintln!("cgrulesd: apply pid {} -> /{}: {e}", row.pid, dest);
            continue;
        }
        out.moved += 1;
        if verbose {
            eprintln!("cgrulesd: pid {} ({}) -> /{}", row.pid, row.comm, dest);
        }
    }
    if !missing.is_empty() {
        eprintln!(
            "cgrulesd: {} pids skipped, no group/template for: {}",
            out.missing_destination,
            missing.join(", ")
        );
    }
    Ok(out)
}

/// Remove a template-created destination once `cgroup.procs` is empty.
///
/// `delete_leaf` is a plain `rmdir`; the kernel returns `EBUSY` if the
/// cgroup is populated or has children, so a path that gains a member
/// between the empty-check and the delete stays tracked. A missing path
/// is untracked rather than retried. Call after `enforce_once` only when
/// polling continuously — `--once` never reaps.
pub fn reap_idle_templates(
    hierarchy: &Hierarchy,
    tracked_templates: &mut HashSet<CgroupPath>,
    verbose: bool,
) {
    tracked_templates.retain(|path| {
        let cgroup = hierarchy.at(path.clone());
        // A `cgroup.procs` that can't be read (missing entirely, say) is
        // treated the same as empty rather than as "still occupied": the
        // real safety check is delete_leaf's rmdir below, which the
        // kernel refuses on genuine occupants regardless of what this
        // read said, so there's nothing to lose by attempting it.
        let empty = cgroup
            .control("cgroup.procs")
            .ok()
            .and_then(|file| file.read_string().ok())
            .map(|text| text.trim().is_empty())
            .unwrap_or(true);
        if !empty {
            return true; // still occupied: keep tracking
        }
        match cgroup.delete_leaf() {
            Ok(()) => {
                if verbose {
                    eprintln!("cgrulesd: reaped idle destination {path}");
                }
                false // removed: stop tracking
            }
            // Already gone (we reaped it before, or something else
            // did, or it was never created): nothing left to track.
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            // cgroup2's rmdir returns EBUSY for a populated cgroup or
            // one with online children, not ENOTEMPTY — this is the
            // expected "still in use" outcome, not worth logging.
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => true,
            Err(e) => {
                eprintln!("cgrulesd: reap {path}: {e}");
                true // unexpected error: keep tracking, retry next call
            }
        }
    });
}

fn process_names(row: &ProcRow) -> Vec<&str> {
    let mut names = vec![row.comm.as_str()];
    if let Some(exe) = row.exe.as_deref() {
        names.push(exe);
        if let Some(base) = exe.rsplit('/').next() {
            if !base.is_empty() && base != row.comm {
                names.push(base);
            }
        }
    }
    names
}

fn is_rt_task(pid: u32) -> bool {
    let pol = unsafe { libc::sched_getscheduler(pid as libc::pid_t) };
    pol == libc::SCHED_FIFO || pol == libc::SCHED_RR
}

/// A resolved destination, and whether it's eligible for reaping once idle.
///
/// Only a *template* match is: cgrulesd materialised it on demand. A
/// `group` persists by design; the ownership-gated fallback only ever
/// matches a directory that already existed. A shallow `template %p`
/// that names an existing sibling is treated as admin intent.
fn leaf_spec(
    hierarchy: &Hierarchy,
    cfg: &ConfigFile,
    dest: &str,
    template_name: &str,
    identity: &Identity,
) -> io::Result<Option<(Cgroup, LeafSpec, bool)>> {
    // Exact group wins by expanded name; otherwise the template named by
    // the *raw* rule destination provides owners/modes/controllers.
    if let Some((plan, is_template)) =
        cgconfig::plan_destination(cfg, dest, template_name, identity)
    {
        let (target, spec) = cgcore::resolve_plan(hierarchy, &plan)?;
        return Ok(Some((target, spec, is_template)));
    }

    let target = match hierarchy.at_path(dest) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // No config entry: an existing directory (created by PAM or the
    // admin) is still a valid destination, but only when its
    // cgroup.procs is *already* owned by the identity being placed.
    // Without that check, a destination containing an attacker-facing
    // placeholder (%p is /proc/<pid>/comm, which any process controls)
    // could name any existing sibling cgroup just by matching its path —
    // e.g. a rule destination of "%p" with comm = "system.slice" — and
    // get moved into whatever limits that cgroup happens to carry,
    // instead of only ever reaching a cgroup that was already theirs.
    let owned_by_identity = identity.uid.parse::<u32>().ok().is_some_and(|uid| {
        target
            .control("cgroup.procs")
            .ok()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|metadata| metadata.uid == uid)
    });
    Ok(owned_by_identity.then(|| (target, LeafSpec::new(), false)))
}

fn norm(rel: &str) -> String {
    rel.trim_matches('/').to_owned()
}

/// Supplementary groups for a user via getgrouplist(3).
pub(crate) fn groups_of(user: &str, gid: u32) -> Vec<String> {
    cgcore::supplementary_groups(user, gid).unwrap_or_default()
}

/// Cache wrapper for repeated lookups during one pass.
#[derive(Default)]
pub struct GroupCache(HashMap<(u32, String), Vec<String>>);

impl GroupCache {
    pub fn groups_for(&mut self, user: &str, gid: u32) -> Vec<String> {
        self.0
            .entry((gid, user.to_owned()))
            .or_insert_with(|| groups_of(user, gid))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgconfig::{parse_cgconfig, parse_cgrules};
    use std::fs;
    use std::path::Path;

    fn test_hierarchy(path: &Path) -> Hierarchy {
        unsafe { cgfs::Hierarchy::open_for_test(path) }.unwrap()
    }

    fn prep_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        fs::write(path.join("cgroup.subtree_control"), "").unwrap();
    }

    fn me() -> (u32, u32, String) {
        let uid = unsafe { libc::geteuid() } as u32;
        let gid = unsafe { libc::getegid() } as u32;
        (uid, gid, cgcore::name_from_uid(uid))
    }

    #[test]
    fn moves_pid_into_exact_group() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        prep_dir(&tmp.path().join(format!("students/{uname}")));

        let rules = parse_cgrules("@students * students/%u").unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![ProcRow {
            pid: 4242,
            user: uname.clone(),
            uid,
            gid,
            groups: vec!["students".to_owned()],
            comm: "sh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];

        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(out.moved, 1, "{out:?}");
        let procs =
            fs::read_to_string(tmp.path().join(format!("students/{uname}/cgroup.procs"))).unwrap();
        assert_eq!(procs, "4242\n");
    }

    #[test]
    fn skips_a_pid_that_no_longer_revalidates() {
        // A `revalidate` returning false means the pid was recycled between
        // the /proc scan and this row's turn to be moved — the row must be
        // skipped, not attached.
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        prep_dir(&tmp.path().join(format!("students/{uname}")));

        let rules = parse_cgrules("@students * students/%u").unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![ProcRow {
            pid: 4242,
            user: uname.clone(),
            uid,
            gid,
            groups: vec!["students".to_owned()],
            comm: "sh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];

        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| false,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(out.moved, 0, "{out:?}");
        let procs =
            fs::read_to_string(tmp.path().join(format!("students/{uname}/cgroup.procs"))).unwrap();
        assert_eq!(procs, "", "pid must not have been attached");
    }

    #[test]
    fn no_config_fallback_requires_matching_ownership() {
        // The existing-directory fallback (no cgconfig.conf entry) must
        // not let a process join a cgroup it doesn't already own —
        // otherwise a rule destination containing %p could pick any
        // existing sibling cgroup just by matching its name (comm is
        // fully process-controlled).
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, _uname) = me();
        // Owned by the test process itself, not by the row below.
        prep_dir(&tmp.path().join("existing"));

        let rules = parse_cgrules("@students * existing").unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![ProcRow {
            pid: 4242,
            user: "someone_else".into(),
            uid: uid.wrapping_add(1), // deliberately not the directory's owner
            gid,
            groups: vec!["students".to_owned()],
            comm: "sh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];

        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(out.moved, 0, "{out:?}");
        assert_eq!(out.missing_destination, 1, "{out:?}");
        let procs = fs::read_to_string(tmp.path().join("existing/cgroup.procs")).unwrap();
        assert_eq!(procs, "", "must not attach to a cgroup it doesn't own");
    }

    #[test]
    fn skips_traversal_in_expanded_proc_name() {
        // %p expands from the process's own comm, which it fully controls.
        // A rule destination that embeds %p must not let a crafted comm
        // walk the destination out of the (sandboxed, here tmp) mount tree.
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let rules = parse_cgrules(&format!("{uname} * apps/%p")).unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![ProcRow {
            pid: 9999,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "../../../etc".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];

        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(
            out,
            Outcome {
                moved: 0,
                already_placed: 0,
                no_rule: 0,
                missing_destination: 1,
                ignored: 0,
            }
        );
        // Nothing was ever created anywhere under the sandboxed mount.
        assert!(fs::read_dir(tmp.path()).unwrap().next().is_none());
    }

    #[test]
    fn skips_already_placed_and_ruleless() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        prep_dir(&tmp.path().join("placed"));
        let rules = parse_cgrules("@students * placed").unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![
            ProcRow {
                pid: 1,
                user: uname.clone(),
                uid,
                gid,
                groups: vec!["students".to_owned()],
                comm: "sh".into(),
                cgroup: "/placed".into(),
                exe: None,
                starttime: 0,
            },
            ProcRow {
                pid: 2,
                user: uname.clone(),
                uid,
                gid,
                groups: vec![],
                comm: "sh".into(),
                cgroup: "/".into(),
                exe: None,
                starttime: 0,
            },
        ];
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(
            out,
            Outcome {
                moved: 0,
                already_placed: 1,
                no_rule: 1,
                missing_destination: 0,
                ignored: 0,
            }
        );
    }

    #[test]
    fn ignore_option_skips_attach() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        prep_dir(&tmp.path().join("sshd"));
        let rules = parse_cgrules(&format!("{uname}:sshd * sshd ignore")).unwrap();
        let cfg = parse_cgconfig("").unwrap();
        let rows = vec![ProcRow {
            pid: 99,
            user: uname,
            uid,
            gid,
            groups: vec![],
            comm: "sshd".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(out.ignored, 1);
        assert_eq!(out.moved, 0);
    }

    #[test]
    fn template_destination_creates_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let cfg_text = format!(
            "template students/%u {{\n perm {{ task {{ uid = {uid}; gid = {gid}; }} admin {{ dperm = 750; }} }}\n cpu {{}}\n}}\n"
        );
        let cfg = parse_cgconfig(&cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * students/%u")).unwrap();

        let rows = vec![ProcRow {
            pid: 777,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            true,
            |_| true,
            &mut Default::default(),
        )
        .unwrap();
        assert_eq!(out.moved, 1, "{out:?}");

        // destination expands with the user's own name:
        let dir = tmp.path().join(format!("students/{uname}"));
        let meta = fs::metadata(&dir).unwrap();
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(meta.permissions().mode() & 0o777, 0o750);
        assert_eq!(meta.uid(), uid);
        let procs = fs::read_to_string(dir.join("cgroup.procs")).unwrap();
        assert_eq!(procs, "777\n");
    }

    #[test]
    fn template_destination_is_tracked_and_reaped_when_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        // No controller block: apply() then never writes
        // cgroup.subtree_control, so cgroup.procs is the only file this
        // fake tmpdir-backed leaf ends up with (see the comment below on
        // why that file has to be removed, not just emptied, to let the
        // sandboxed rmdir succeed).
        let cfg_text = format!(
            "template students/%u {{\n perm {{ task {{ uid = {uid}; gid = {gid}; }} admin {{ dperm = 750; }} }}\n}}\n"
        );
        let cfg = parse_cgconfig(&cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * students/%u")).unwrap();
        let target = tmp.path().join(format!("students/{uname}"));
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("cgroup.procs"), "").unwrap();

        let rows = vec![ProcRow {
            pid: 778,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];
        let mut tracked = HashSet::new();
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut tracked,
        )
        .unwrap();
        assert_eq!(out.moved, 1, "{out:?}");

        let dir = tmp.path().join(format!("students/{uname}"));
        assert!(
            tracked.contains(&CgroupPath::parse(format!("students/{uname}")).unwrap()),
            "template match must be tracked"
        );

        // The process exits: cgroup.procs goes empty. On a real cgroupfs
        // the kernel's own rmdir for a cgroup directory only cares about
        // live tasks/children — control files are kernel-synthesized,
        // not ordinary directory entries for emptiness purposes, so an
        // idle leaf's rmdir succeeds despite them. This fake tmpdir-backed
        // leaf has those files as genuine regular entries, which *would*
        // block a plain rmdir regardless of content — remove them too,
        // to simulate what the kernel actually allows.
        for name in cgfs::CONTROL_FILES {
            fs::remove_file(dir.join(name)).unwrap();
        }
        reap_idle_templates(&test_hierarchy(tmp.path()), &mut tracked, false);

        assert!(tracked.is_empty(), "reaped path must stop being tracked");
        assert!(!dir.exists(), "idle template destination must be removed");
    }

    /// The load-bearing safety property, previously asserted nowhere:
    /// a tracked path that's still occupied must never be removed.
    #[test]
    fn occupied_tracked_path_is_not_reaped() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("occupied");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.procs"), "1234\n").unwrap();

        let mut tracked = HashSet::new();
        tracked.insert(CgroupPath::parse("occupied").unwrap());
        reap_idle_templates(&test_hierarchy(tmp.path()), &mut tracked, false);

        assert!(
            tracked.contains(&CgroupPath::parse("occupied").unwrap()),
            "an occupied path must stay tracked"
        );
        assert!(dir.exists(), "an occupied path must not be removed");
    }

    #[test]
    fn template_destination_is_tracked_even_when_apply_fails_after_mkdir() {
        // chown to uid 0 fails unprivileged; as root (or a userns that
        // maps uid 0) apply would succeed and this would no longer pin
        // the "tracked despite mkdir-then-fail" path.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let cfg_text =
            "template students/%u {\n perm { admin { uid = 0; gid = 0; dperm = 750; } }\n}\n";
        let cfg = parse_cgconfig(cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * students/%u")).unwrap();

        let rows = vec![ProcRow {
            pid: 782,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];
        let mut tracked = HashSet::new();
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut tracked,
        )
        .unwrap();
        assert_eq!(
            out.moved, 0,
            "chown to uid 0 must fail unprivileged: {out:?}"
        );

        let dir = tmp.path().join(format!("students/{uname}"));
        assert!(dir.exists(), "mkdir must have run before the chown failure");
        assert!(
            tracked.contains(&CgroupPath::parse(format!("students/{uname}")).unwrap()),
            "must be tracked despite apply failing after mkdir"
        );
    }

    #[test]
    fn already_placed_template_destination_is_still_tracked() {
        // A process already correctly placed (from a previous poll, or
        // a previous daemon restart — tracked_templates is in-memory
        // only) must still register its destination, or a restart
        // permanently orphans every existing template destination from
        // the reaper's point of view.
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let cfg_text = format!(
            "template students/%u {{\n perm {{ task {{ uid = {uid}; gid = {gid}; }} admin {{ dperm = 750; }} }}\n}}\n"
        );
        let cfg = parse_cgconfig(&cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * students/%u")).unwrap();

        let dest_rel = format!("students/{uname}");
        let rows = vec![ProcRow {
            pid: 783,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: dest_rel.clone(), // already there
            exe: None,
            starttime: 0,
        }];
        let mut tracked = HashSet::new();
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut tracked,
        )
        .unwrap();
        assert_eq!(out.already_placed, 1, "{out:?}");
        assert!(
            tracked.contains(&CgroupPath::parse(&dest_rel).unwrap()),
            "already-placed template destination must still be tracked"
        );
    }

    #[test]
    fn group_destination_is_never_tracked_or_reaped() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let cfg_text = format!(
            "group pool {{\n perm {{ admin {{ uid = {uid}; gid = {gid}; dperm = 750; }} }}\n cpu {{}}\n}}\n"
        );
        let cfg = parse_cgconfig(&cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * pool")).unwrap();

        let rows = vec![ProcRow {
            pid: 779,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: "/".into(),
            exe: None,
            starttime: 0,
        }];
        let mut tracked = HashSet::new();
        let out = enforce_once(
            &test_hierarchy(tmp.path()),
            &rules,
            &cfg,
            &rows,
            false,
            |_| true,
            &mut tracked,
        )
        .unwrap();
        assert_eq!(out.moved, 1, "{out:?}");
        assert!(
            tracked.is_empty(),
            "an admin-declared group must never be tracked for reaping"
        );

        let dir = tmp.path().join("pool");
        fs::write(dir.join("cgroup.procs"), "").unwrap();
        reap_idle_templates(&test_hierarchy(tmp.path()), &mut tracked, false); // nothing tracked: no-op
        assert!(
            dir.exists(),
            "a group destination must persist regardless of occupancy"
        );
    }
}
