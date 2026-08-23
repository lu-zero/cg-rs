//! Enforcement core: match processes against cgrules and move them.
//!
//! Pure-ish by design — process rows are supplied by the caller so the
//! matching/moving logic is testable without a live `/proc`.

use std::collections::HashMap;
use std::io::{self};
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
pub fn enforce_once(
    mount: &Path,
    rules: &[cgconfig::Rule],
    cfg: &ConfigFile,
    procs: &[ProcRow],
    verbose: bool,
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
        if norm(&row.cgroup) == dest {
            out.already_placed += 1;
            continue;
        }

        let Some(spec) = leaf_spec(cfg, &dest, &rule.destination.0, &identity, mount) else {
            out.missing_destination += 1;
            if !missing.contains(&dest) {
                missing.push(dest.clone());
            }
            continue;
        };
        cgfs::apply(&spec, Some(row.pid))?;
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

fn leaf_spec(
    cfg: &ConfigFile,
    dest: &str,
    template_name: &str,
    identity: &Identity,
    mount: &Path,
) -> Option<LeafSpec> {
    // Exact group wins by expanded name; otherwise the template named by
    // the *raw* rule destination provides owners/modes/controllers.
    let plan = if cfg.find_group(dest).is_some() {
        cgconfig::plan_group(cfg, dest, identity)
    } else {
        cgconfig::plan_template(cfg, template_name, identity)
    };
    if let Some(plan) = plan {
        let mut path: PathBuf = mount.to_path_buf();
        for part in dest.split('/') {
            if !part.is_empty() {
                path.push(part);
            }
        }
        return Some(LeafSpec {
            path,
            uid: resolve(plan.owner_uid.as_deref()),
            gid: resolve(plan.owner_gid.as_deref()),
            dperm: plan.dir_mode,
            fperm: plan.file_mode,
            task_fperm: plan.tasks_file_mode,
            task_uid: None,
            task_gid: None,
            subtree_control: plan.subtree_control.clone(),
        });
    }

    // No config entry: an existing directory (created by PAM or the admin)
    // is still a valid destination; only ownership stays untouched.
    let mut path: PathBuf = mount.to_path_buf();
    for part in dest.split('/') {
        if !part.is_empty() {
            path.push(part);
        }
    }
    path.join("cgroup.procs")
        .exists()
        .then(|| LeafSpec::new(path))
}

fn resolve(name: Option<&str>) -> Option<u32> {
    name.and_then(|n| {
        crate::nss::resolve("user", n)
            .ok()
            .or_else(|| crate::nss::resolve("group", n).ok())
    })
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

        let out = enforce_once(tmp.path(), &rules, &cfg, &rows, false).unwrap();
        assert_eq!(out.moved, 1, "{out:?}");
        let procs =
            fs::read_to_string(tmp.path().join(format!("students/{uname}/cgroup.procs"))).unwrap();
        assert_eq!(procs, "4242\n");
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
        let out = enforce_once(tmp.path(), &rules, &cfg, &rows, false).unwrap();
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
        let out = enforce_once(tmp.path(), &rules, &cfg, &rows, true).unwrap();
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
}
