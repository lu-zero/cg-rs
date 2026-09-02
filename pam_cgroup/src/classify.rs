//! Place the login pid using cgrules.conf (+ optional cgrules.d).

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cgconfig::model::{first_rule_names, ConfigFile, Identity};
use cgconfig::{load_cgrules, parse_cgconfig_in, plan_destination};
use cgfs::LeafSpec;

use crate::user::User;

/// Match `user`/`pid` against the rules and attach. `Ok(None)` means no
/// matching rule (or `ignore`); the TOML `[[place]]` attach still stands.
pub fn classify(
    mount: &Path,
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
            parse_cgconfig_in(f.display().to_string(), &t).map_err(io::Error::other)?
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
    let spec = leaf_spec(&cfg, mount, &dest, &rule.destination.0, &identity).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no group/template for cgrules destination {dest}"),
        )
    })?;
    cgfs::apply(&spec, Some(pid))?;
    Ok(Some(spec.path))
}

fn leaf_spec(
    cfg: &ConfigFile,
    mount: &Path,
    dest: &str,
    template_name: &str,
    identity: &Identity,
) -> Option<LeafSpec> {
    let path = cgfs::join(mount, Path::new(dest));
    if let Some((plan, _)) = plan_destination(cfg, dest, template_name, identity) {
        return Some(LeafSpec {
            path,
            uid: plan
                .owner_uid
                .as_deref()
                .and_then(|n| cg_nss::resolve("user", n).ok()),
            gid: plan
                .owner_gid
                .as_deref()
                .and_then(|n| cg_nss::resolve("group", n).ok()),
            dperm: plan.dir_mode,
            fperm: plan.file_mode,
            task_fperm: plan.tasks_file_mode,
            task_uid: plan
                .task_uid
                .as_deref()
                .and_then(|n| cg_nss::resolve("user", n).ok()),
            task_gid: plan
                .task_gid
                .as_deref()
                .and_then(|n| cg_nss::resolve("group", n).ok()),
            subtree_control: plan.subtree_control,
        });
    }
    let procs = path.join("cgroup.procs");
    let owned = identity.uid.parse::<u32>().ok().is_some_and(|uid| {
        fs::metadata(&procs)
            .map(|m| m.uid() == uid)
            .unwrap_or(false)
    });
    owned.then(|| LeafSpec::new(path))
}

fn is_rt(pid: u32) -> bool {
    let pol = unsafe { libc::sched_getscheduler(pid as libc::pid_t) };
    pol == libc::SCHED_FIFO || pol == libc::SCHED_RR
}

fn groups_of(user: &str, gid: u32) -> Vec<String> {
    let Ok(cuser) = std::ffi::CString::new(user) else {
        return Vec::new();
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
    gids.iter().map(|g| cg_nss::name_from_gid(*g)).collect()
}
