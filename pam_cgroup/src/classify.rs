//! Place the login pid using cgrules.conf (+ optional cgrules.d).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cgconfig::model::{first_rule_names, ConfigFile, Identity};
use cgconfig::{load_cgrules, plan_destination};
use cgfs::{Cgroup, Hierarchy, LeafSpec};

use crate::user::User;

/// Match `user`/`pid` against the rules and attach. `Ok(None)` means no
/// matching rule (or `ignore`); the TOML `[[place]]` attach still stands.
pub fn classify(
    hierarchy: &Hierarchy,
    cgrules: &Path,
    cgrules_d: Option<&Path>,
    cgconfig: Option<&Path>,
    user: &User,
    pid: u32,
) -> io::Result<Option<PathBuf>> {
    let rules = load_cgrules(cgrules, cgrules_d)?;
    let cfg = match cgconfig {
        Some(f) => {
            let t = fs::read_to_string(f)?;
            ConfigFile::from_source(miette::NamedSource::new(f.display().to_string(), t))
                .map_err(io::Error::other)?
        }
        None => ConfigFile::default(),
    };
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let mut names = vec![comm.as_str()];
    if let Some(e) = exe.as_deref() {
        names.push(e);
        if let Some(base) = e.rsplit('/').next() {
            if !base.is_empty() && base != comm {
                names.push(base);
            }
        }
    }
    let groups = groups_of(&user.name, user.gid);
    let Some(rule) = first_rule_names(&rules, &user.name, &groups, &names) else {
        return Ok(None);
    };
    if rule.ignores() || (rule.ignores_rt() && is_rt(pid)) {
        return Ok(None);
    }
    let identity = Identity {
        name: user.name.clone(),
        uid: user.uid.to_string(),
        gid: user.gid.to_string(),
        group: user.group.clone(),
        proc_name: comm,
        pid: pid.to_string(),
    };
    let dest = identity.expand(&rule.destination);
    let dest = dest.trim_matches('/').to_owned();
    if !cgconfig::model::is_safe_relative_path(&dest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cgrules destination {dest:?} has illegal path components"),
        ));
    }
    let (target, spec) = leaf_spec(hierarchy, &cfg, &dest, &rule.destination.0, &identity)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no group/template for cgrules destination {dest}"),
            )
        })?;
    let path = hierarchy.mount_path().join(target.path().as_relative());
    target.apply(&spec, Some(pid))?;
    Ok(Some(path))
}

fn leaf_spec(
    hierarchy: &Hierarchy,
    cfg: &ConfigFile,
    dest: &str,
    template_name: &str,
    identity: &Identity,
) -> io::Result<Option<(Cgroup, LeafSpec)>> {
    if let Some((plan, _)) = plan_destination(cfg, dest, template_name, identity) {
        let (target, spec) = cgcore::resolve_plan(hierarchy, &plan)?;
        return Ok(Some((target, spec)));
    }
    let target = match hierarchy.at_path(dest) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let owned = identity.uid.parse::<u32>().ok().is_some_and(|uid| {
        target
            .control("cgroup.procs")
            .ok()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|metadata| metadata.uid == uid)
    });
    Ok(owned.then(|| (target, LeafSpec::new())))
}

fn is_rt(pid: u32) -> bool {
    let pol = unsafe { libc::sched_getscheduler(pid as libc::pid_t) };
    pol == libc::SCHED_FIFO || pol == libc::SCHED_RR
}

fn groups_of(user: &str, gid: u32) -> Vec<String> {
    cgcore::supplementary_groups(user, gid).unwrap_or_default()
}
