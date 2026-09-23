//! Shared identity and cgroup v2 leaf-application glue.
//!
//! This crate is the small integration layer between [`cgconfig`]'s
//! symbolic [`LeafPlan`] values and [`cgfs`]'s verified write side. It
//! resolves owner names through the platform NSS database and turns a plan
//! into a descriptor-bound [`LeafSpec`]. Rule matching, destination
//! lifecycle, and application-specific policy intentionally remain in the
//! consumers.

#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("cgcore supports Linux cgroup v2 only");

use std::ffi::CString;
use std::io;

pub use cgconfig::LeafPlan;
pub use cgfs::{Cgroup, Hierarchy, LeafSpec};

use nix::unistd::{getgrouplist, Gid, Group, Uid, User as NixUser};

/// The NSS namespace used by an owner field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerKind {
    /// A passwd database entry (`uid`).
    User,
    /// A group database entry (`gid`).
    Group,
}

/// The passwd identity fields needed by the PAM and rules consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    /// The passwd name.
    pub name: String,
    /// The numeric user id.
    pub uid: u32,
    /// The numeric primary group id.
    pub gid: u32,
    /// The primary group name, or its numeric spelling when unresolved.
    pub group: String,
}

impl User {
    /// Look up a passwd entry by name.
    pub fn from_name(name: &str) -> io::Result<Self> {
        c_string(name)?;
        let user = NixUser::from_name(name)
            .map_err(nss_error)?
            .ok_or_else(|| not_found("user", name))?;
        Ok(Self::from_nix(user))
    }

    /// Look up a passwd entry by uid.
    pub fn from_uid(uid: u32) -> io::Result<Self> {
        let user = NixUser::from_uid(Uid::from_raw(uid))
            .map_err(nss_error)?
            .ok_or_else(|| not_found("uid", &uid.to_string()))?;
        Ok(Self::from_nix(user))
    }

    fn from_nix(user: NixUser) -> Self {
        let gid = user.gid.as_raw();
        Self {
            name: user.name,
            uid: user.uid.as_raw(),
            gid,
            group: name_from_gid(gid),
        }
    }
}

/// Resolve a symbolic or numeric owner to its numeric id.
///
/// Numeric values are accepted without consulting NSS. Non-numeric values
/// are looked up in the passwd or group database selected by `kind`.
pub fn resolve_owner(kind: OwnerKind, name: &str) -> io::Result<u32> {
    match kind {
        OwnerKind::User => uid_from_name(name),
        OwnerKind::Group => gid_from_name(name),
    }
}

/// Resolve a passwd name (or numeric uid) to a uid.
pub fn uid_from_name(name: &str) -> io::Result<u32> {
    if let Ok(uid) = name.parse() {
        return Ok(uid);
    }
    c_string(name)?;
    NixUser::from_name(name)
        .map_err(nss_error)?
        .map(|user| user.uid.as_raw())
        .ok_or_else(|| not_found("user", name))
}

/// Resolve a group name (or numeric gid) to a gid.
pub fn gid_from_name(name: &str) -> io::Result<u32> {
    if let Ok(gid) = name.parse() {
        return Ok(gid);
    }
    c_string(name)?;
    Group::from_name(name)
        .map_err(nss_error)?
        .map(|group| group.gid.as_raw())
        .ok_or_else(|| not_found("group", name))
}

/// Return the passwd name for `uid`, falling back to its numeric spelling.
pub fn name_from_uid(uid: u32) -> String {
    match NixUser::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => user.name,
        _ => uid.to_string(),
    }
}

/// Return the group name for `gid`, falling back to its numeric spelling.
pub fn name_from_gid(gid: u32) -> String {
    match Group::from_gid(Gid::from_raw(gid)) {
        Ok(Some(group)) => group.name,
        _ => gid.to_string(),
    }
}

/// Return the primary and supplementary group names for `user`.
///
/// The lookup is delegated to NSS through `getgrouplist(3)`, rather than
/// approximating membership with a process-local `/etc/group` scan.
pub fn supplementary_groups(user: &str, gid: u32) -> io::Result<Vec<String>> {
    let cuser = c_string(user)?;
    let groups = getgrouplist(&cuser, Gid::from_raw(gid)).map_err(nss_error)?;
    Ok(groups
        .into_iter()
        .map(|gid| name_from_gid(gid.as_raw()))
        .collect())
}

/// Resolve a `LeafPlan` into a verified target and an owned `LeafSpec`.
///
/// `params` are intentionally not applied here: their interpretation is
/// controller- and consumer-specific. The path is resolved only by
/// `Hierarchy::at_path`, and the returned target cannot escape that
/// hierarchy. Owner fields are strict: a non-numeric name that cannot be
/// resolved is an error rather than silently leaving ownership unchanged.
pub fn resolve_plan(hierarchy: &Hierarchy, plan: &LeafPlan) -> io::Result<(Cgroup, LeafSpec)> {
    let target = hierarchy.at_path(&plan.path)?;
    let spec = spec_from_plan(plan)?;
    Ok((target, spec))
}

/// Resolve and apply a `LeafPlan` through the verified cgroup API.
pub fn apply_plan(
    hierarchy: &Hierarchy,
    plan: &LeafPlan,
    attach_pid: Option<u32>,
) -> io::Result<()> {
    let (target, spec) = resolve_plan(hierarchy, plan)?;
    target.apply(&spec, attach_pid)
}

fn spec_from_plan(plan: &LeafPlan) -> io::Result<LeafSpec> {
    let mut spec = LeafSpec::new()
        .dperm_if_some(plan.dir_mode)
        .fperm_if_some(plan.file_mode)
        .task_fperm_if_some(plan.tasks_file_mode)
        .subtree_control(&plan.subtree_control);

    if let Some(name) = plan.owner_uid.as_deref() {
        spec = spec.uid(resolve_owner(OwnerKind::User, name)?);
    }
    if let Some(name) = plan.owner_gid.as_deref() {
        spec = spec.gid(resolve_owner(OwnerKind::Group, name)?);
    }
    if let Some(name) = plan.task_uid.as_deref() {
        spec = spec.task_uid(resolve_owner(OwnerKind::User, name)?);
    }
    if let Some(name) = plan.task_gid.as_deref() {
        spec = spec.task_gid(resolve_owner(OwnerKind::Group, name)?);
    }

    Ok(spec)
}

fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in NSS name"))
}

fn not_found(kind: &str, name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no such {kind} {name}"))
}

fn nss_error(error: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ids_bypass_nss() {
        assert_eq!(resolve_owner(OwnerKind::User, "1000").unwrap(), 1000);
        assert_eq!(resolve_owner(OwnerKind::Group, "1000").unwrap(), 1000);
    }

    #[test]
    fn nul_is_rejected_before_nss() {
        assert_eq!(
            resolve_owner(OwnerKind::User, "bad\0name")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn reverse_lookups_fall_back_to_numbers() {
        assert_eq!(name_from_uid(u32::MAX), u32::MAX.to_string());
        assert_eq!(name_from_gid(u32::MAX), u32::MAX.to_string());
    }

    #[test]
    fn invalid_owner_is_not_silently_ignored() {
        let plan = LeafPlan {
            owner_uid: Some("bad\0name".into()),
            ..LeafPlan::default()
        };
        assert_eq!(
            spec_from_plan(&plan).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn plan_fields_become_a_validated_spec() {
        let plan = LeafPlan {
            path: "leaf".into(),
            task_uid: Some("1000".into()),
            task_gid: Some("1001".into()),
            tasks_file_mode: Some(0o640),
            owner_uid: Some("0".into()),
            owner_gid: Some("0".into()),
            dir_mode: Some(0o750),
            file_mode: Some(0o660),
            subtree_control: vec!["cpu".into()],
            params: vec![("memory".into(), "memory.max".into(), "max".into())],
        };
        let spec = spec_from_plan(&plan).unwrap();
        assert_eq!(
            spec,
            LeafSpec::new()
                .uid(0)
                .gid(0)
                .dperm(0o750)
                .fperm(0o660)
                .task_fperm(0o640)
                .task_uid(1000)
                .task_gid(1001)
                .subtree_control(&["cpu".to_owned()])
        );
    }
}
