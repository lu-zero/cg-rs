//! Enforcement core: match processes against cgrules and move them.
//!
//! Pure-ish by design — process rows are supplied by the caller so the
//! matching/moving logic is testable without a live `/proc`.

use std::collections::HashMap;
use std::fs;
use std::io::{self};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cgconfig::model::{first_rule, ConfigFile, Identity};
use cgfs::LeafSpec;

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
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub moved: usize,
    pub already_placed: usize,
    pub no_rule: usize,
    pub missing_destination: usize,
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
    mount: &Path,
    rules: &[cgconfig::Rule],
    cfg: &ConfigFile,
    procs: &[ProcRow],
    verbose: bool,
    revalidate: impl Fn(&ProcRow) -> bool,
    tracked_templates: &mut std::collections::HashSet<PathBuf>,
) -> io::Result<Outcome> {
    let mut out = Outcome::default();
    let mut missing: Vec<String> = Vec::new();
    for row in procs {
        let Some(rule) = first_rule(rules, &row.user, &row.groups, Some(&row.comm)) else {
            out.no_rule += 1;
            continue;
        };
        let identity = Identity {
            name: row.user.clone(),
            uid: row.uid.to_string(),
            gid: row.gid.to_string(),
            group: nss_name_from_gid(row.gid),
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
        if norm(&row.cgroup) == dest {
            out.already_placed += 1;
            continue;
        }

        let Some((spec, is_template)) =
            leaf_spec(cfg, &dest, &rule.destination.0, &identity, mount)
        else {
            out.missing_destination += 1;
            if !missing.contains(&dest) {
                missing.push(dest.clone());
            }
            continue;
        };
        if !revalidate(row) {
            if verbose {
                eprintln!(
                    "cgrulesd: pid {} no longer matches its scanned identity (recycled?), skipping",
                    row.pid
                );
            }
            continue;
        }
        if let Err(e) = cgfs::apply(&spec, Some(row.pid)) {
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
        if is_template {
            tracked_templates.insert(spec.path.clone());
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

/// Remove a template-created destination once its `cgroup.procs` is
/// empty, going further than real cgrulesengd/cgred — the reference
/// implementation's own man page documents on-demand creation and never
/// mentions cleanup, so a template destination there grows without bound
/// for the life of the daemon. Reaps eagerly: the first pass that
/// observes a tracked path empty tries to remove it, rather than waiting
/// for sustained emptiness across several passes.
///
/// `cgfs::delete_leaf` is a plain `rmdir`, which the kernel already
/// refuses on a non-empty directory (live tasks or child cgroups) — so a
/// path that gains a new member between this function's own empty-check
/// and the delete simply fails to delete and stays tracked for the next
/// call; nothing gets destroyed out from under a live occupant. Call
/// once per poll, after `enforce_once`, only when polling continuously —
/// a `--once` run's `tracked_templates` starts and ends empty in the
/// same process, so there is never anything meaningful to reap there.
pub fn reap_idle_templates(tracked_templates: &mut std::collections::HashSet<PathBuf>) {
    tracked_templates.retain(|path| {
        // A `cgroup.procs` that can't be read (missing entirely, say) is
        // treated the same as empty rather than as "still occupied": the
        // real safety check is delete_leaf's rmdir below, which the
        // kernel refuses on genuine occupants regardless of what this
        // read said, so there's nothing to lose by attempting it.
        let empty = fs::read_to_string(path.join("cgroup.procs"))
            .map(|s| s.trim().is_empty())
            .unwrap_or(true);
        if !empty {
            return true; // still occupied: keep tracking
        }
        // Ok(()): removed, stop tracking. Err: still has children, or a
        // race with a new occupant — keep tracking, retry next call.
        cgfs::delete_leaf(path).is_err()
    });
}

fn dest_path(mount: &Path, dest: &str) -> PathBuf {
    let mut p = mount.to_path_buf();
    for part in dest.split('/') {
        if !part.is_empty() {
            p.push(part);
        }
    }
    p
}

/// A resolved destination, and whether it's eligible for reaping once idle.
///
/// Only a *template* match is: it's a destination cgrulesd itself
/// materialised on demand (real libcgroup's cgrulesengd does the same,
/// and — per its own man page — never cleans one up either, which is
/// exactly the unbounded-growth problem this crate goes further than the
/// reference implementation to avoid). A `group` entry is admin-declared
/// and meant to persist regardless of occupancy; the ownership-gated
/// fallback (no config entry at all) only ever matches something that
/// already existed before cgrulesd touched it, so there's nothing of
/// cgrulesd's own to reap there either.
fn leaf_spec(
    cfg: &ConfigFile,
    dest: &str,
    template_name: &str,
    identity: &Identity,
    mount: &Path,
) -> Option<(LeafSpec, bool)> {
    // Exact group wins by expanded name; otherwise the template named by
    // the *raw* rule destination provides owners/modes/controllers.
    let is_group = cfg.find_group(dest).is_some();
    let plan = if is_group {
        cgconfig::plan_group(cfg, dest, identity)
    } else {
        cgconfig::plan_template(cfg, template_name, identity)
    };
    if let Some(plan) = plan {
        return Some((
            LeafSpec {
                path: dest_path(mount, dest),
                uid: resolve_user(plan.owner_uid.as_deref()),
                gid: resolve_group(plan.owner_gid.as_deref()),
                dperm: plan.dir_mode,
                fperm: plan.file_mode,
                task_fperm: plan.tasks_file_mode,
                task_uid: resolve_user(plan.task_uid.as_deref()),
                task_gid: resolve_group(plan.task_gid.as_deref()),
                subtree_control: plan.subtree_control.clone(),
            },
            !is_group,
        ));
    }

    // No config entry: an existing directory (created by PAM or the
    // admin) is still a valid destination, but only when its
    // cgroup.procs is *already* owned by the identity being placed.
    // Without that check, a destination containing an attacker-facing
    // placeholder (%p is /proc/<pid>/comm, which any process controls)
    // could name any existing sibling cgroup just by matching its path —
    // e.g. a rule destination of "%p" with comm = "system.slice" — and
    // get moved into whatever limits that cgroup happens to carry,
    // instead of only ever reaching a cgroup that was already theirs.
    // This means a literal, placeholder-free destination shared by
    // several different users (e.g. "@devs * shared_pool") now needs a
    // real cgconfig.conf group/template entry: no single uid owns a
    // genuinely shared cgroup.procs, so this fallback can no longer
    // serve that case.
    let path = dest_path(mount, dest);
    let procs = path.join("cgroup.procs");
    let owned_by_identity = identity.uid.parse::<u32>().ok().is_some_and(|uid| {
        fs::metadata(&procs)
            .map(|m| m.uid() == uid)
            .unwrap_or(false)
    });
    owned_by_identity.then(|| (LeafSpec::new(path), false))
}

fn resolve_user(name: Option<&str>) -> Option<u32> {
    name.and_then(|n| crate::nss::resolve("user", n).ok())
}
fn resolve_group(name: Option<&str>) -> Option<u32> {
    name.and_then(|n| crate::nss::resolve("group", n).ok())
}
fn norm(rel: &str) -> String {
    rel.trim_matches('/').to_owned()
}

pub(crate) fn nss_name_from_gid(gid: u32) -> String {
    crate::nss::name_from_gid(gid)
}

/// Supplementary groups for a user via getgrouplist(3).
pub(crate) fn groups_of(user: &str, gid: u32) -> Vec<String> {
    let cuser = match std::ffi::CString::new(user) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut gids: Vec<libc::gid_t> = vec![0; 32];
    loop {
        let mut n: libc::c_int = gids.len() as libc::c_int;
        let rc = unsafe {
            libc::getgrouplist(
                cuser.as_ptr(),
                gid as libc::gid_t,
                gids.as_mut_ptr(),
                &mut n,
            )
        };
        if rc >= 0 {
            gids.truncate(n as usize);
            break;
        }
        if gids.len() > 4096 {
            return Vec::new();
        }
        gids.resize(n.max(1) as usize * 2, 0);
    }
    gids.iter().map(|g| crate::nss::name_from_gid(*g)).collect()
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

    fn prep_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        fs::write(path.join("cgroup.subtree_control"), "").unwrap();
    }

    fn me() -> (u32, u32, String) {
        let uid = unsafe { libc::geteuid() } as u32;
        let gid = unsafe { libc::getegid() } as u32;
        (uid, gid, crate::nss::name_from_uid(uid))
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
        }];

        let out = enforce_once(
            tmp.path(),
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
        }];

        let out = enforce_once(
            tmp.path(),
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
        }];

        let out = enforce_once(
            tmp.path(),
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
        }];

        let out = enforce_once(
            tmp.path(),
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
            },
            ProcRow {
                pid: 2,
                user: uname.clone(),
                uid,
                gid,
                groups: vec![],
                comm: "sh".into(),
                cgroup: "/".into(),
            },
        ];
        let out = enforce_once(
            tmp.path(),
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
                missing_destination: 0
            }
        );
    }

    #[test]
    fn template_destination_creates_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid, uname) = me();
        let cfg_text = format!(
            "template students/%u {{\n perm {{ task {{ uid = {uid}; gid = {uid}; }} admin {{ dperm = 750; }} }}\n cpu {{}}\n}}\n"
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
        }];
        let out = enforce_once(
            tmp.path(),
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
            "template students/%u {{\n perm {{ task {{ uid = {uid}; gid = {uid}; }} admin {{ dperm = 750; }} }}\n}}\n"
        );
        let cfg = parse_cgconfig(&cfg_text).unwrap();
        let rules = parse_cgrules(&format!("{uname} * students/%u")).unwrap();

        let rows = vec![ProcRow {
            pid: 778,
            user: uname.clone(),
            uid,
            gid,
            groups: vec![],
            comm: "zsh".into(),
            cgroup: "/".into(),
        }];
        let mut tracked = std::collections::HashSet::new();
        let out = enforce_once(
            tmp.path(),
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
        assert!(tracked.contains(&dir), "template match must be tracked");

        // The process exits: cgroup.procs goes empty. On a real cgroupfs
        // the kernel's own rmdir for a cgroup directory only cares about
        // live tasks/children — cgroup.procs and friends are kernel-
        // synthesized, not ordinary directory entries for emptiness
        // purposes, so an idle leaf's rmdir succeeds despite them. This
        // fake tmpdir-backed leaf has cgroup.procs as a genuine regular
        // file, which *would* block a plain rmdir regardless of its
        // content — remove it too, to simulate what the kernel actually
        // allows rather than what bare POSIX rmdir would.
        fs::remove_file(dir.join("cgroup.procs")).unwrap();
        reap_idle_templates(&mut tracked);

        assert!(tracked.is_empty(), "reaped path must stop being tracked");
        assert!(!dir.exists(), "idle template destination must be removed");
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
        }];
        let mut tracked = std::collections::HashSet::new();
        let out = enforce_once(
            tmp.path(),
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
        reap_idle_templates(&mut tracked); // nothing tracked: no-op
        assert!(
            dir.exists(),
            "a group destination must persist regardless of occupancy"
        );
    }
}
