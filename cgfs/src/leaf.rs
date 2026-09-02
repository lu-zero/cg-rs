//! Create and delegate a cgroup leaf: mkdir, ownership, modes,
//! `cgroup.subtree_control`, attach.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::chown;
use rustix::process::{Gid, Uid};

use crate::raw::refuse_symlink;
use crate::CONTROL_FILES;

/// One leaf to create under the mount point, with resolved numeric owners.
///
/// Field names follow cgconfig.conf: `dperm` is the directory mode, `fperm`
/// the mode for control files, `task_fperm` an optional override for
/// `cgroup.procs`/`cgroup.threads` (falls back to `fperm`). Ownership/modes
/// are applied even when the directory already exists — delegation wants the
/// re-assertion libcgroup never did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafSpec {
    pub path: std::path::PathBuf,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub dperm: Option<u32>,
    pub fperm: Option<u32>,
    /// Mode override for `cgroup.procs`/`cgroup.threads`.
    pub task_fperm: Option<u32>,
    /// Owners for `cgroup.procs`/`cgroup.threads` when they differ from
    /// `uid`/`gid` (cgconfig.conf's split of `task {}` vs `admin {}`).
    pub task_uid: Option<u32>,
    pub task_gid: Option<u32>,
    /// Controllers to enable for children: written as `+cpu +memory …`.
    pub subtree_control: Vec<String>,
}

impl LeafSpec {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    pub fn dperm(mut self, mode: u32) -> Self {
        self.dperm = Some(mode);
        self
    }

    pub fn fperm(mut self, mode: u32) -> Self {
        self.fperm = Some(mode);
        self
    }

    pub fn subtree_control(mut self, controllers: &[&str]) -> Self {
        self.subtree_control = controllers.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Create / chown / chmod / enable controllers / optionally attach `pid`.
///
/// Ownership and `dperm` apply to *every* directory this call creates, not
/// just the leaf: a root-run daemon materialising `users/lu_zero/session`
/// must not leave `users/` and `lu_zero/` root-owned (delegation wants the
/// re-assertion libcgroup skipped).
pub fn apply(spec: &LeafSpec, attach_pid: Option<u32>) -> io::Result<()> {
    if !spec.path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("leaf path must be absolute: {:?}", spec.path),
        ));
    }
    if spec.path == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to apply on filesystem root",
        ));
    }
    for c in &spec.subtree_control {
        if c.is_empty()
            || !c
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid controller name {c:?}"),
            ));
        }
    }
    // Collect not-yet-existing components before create_dir_all so they can
    // be owned/moded afterwards; deepest last. TOCTOU on concurrent creator
    // is benign — the directory will be owned on the next explicit re-apply.
    //
    // Every component is checked with `symlink_metadata`, not `exists()`:
    // a delegated leaf is owned by the user it was created for, and this
    // call re-asserts ownership on every re-apply, so a user who swapped
    // their own (already-existing) leaf for a symlink to some other
    // directory must not have that directory silently adopted here.
    let mut created: Vec<PathBuf> = Vec::new();
    let mut cur = spec.path.clone();
    loop {
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("refusing to operate through a symlink: {}", cur.display()),
                    ));
                }
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                created.push(cur.clone());
                let Some(parent) = cur.parent() else {
                    break;
                };
                cur = parent.to_path_buf();
            }
            Err(e) => return Err(e),
        }
    }
    fs::create_dir_all(&spec.path)?;

    for dir in created.iter().rev() {
        set_owner(dir, spec.uid, spec.gid)?;
        if let Some(mode) = spec.dperm {
            set_mode(dir, mode)?;
        }
    }
    set_owner(&spec.path, spec.uid, spec.gid)?;
    if let Some(mode) = spec.dperm {
        set_mode(&spec.path, mode)?;
    }
    for name in CONTROL_FILES {
        let f = spec.path.join(name);
        if f.exists() {
            // task files may have owners distinct from admin's.
            let (uid, gid) = match name {
                "cgroup.procs" | "cgroup.threads" => {
                    (spec.task_uid.or(spec.uid), spec.task_gid.or(spec.gid))
                }
                _ => (spec.uid, spec.gid),
            };
            set_owner(&f, uid, gid)?;
            let mode = match name {
                "cgroup.procs" | "cgroup.threads" => spec.task_fperm.or(spec.fperm),
                _ => spec.fperm,
            };
            if let Some(mode) = mode {
                set_mode(&f, mode)?;
            }
        }
    }
    if !spec.subtree_control.is_empty() {
        enable_subtree_control(&spec.path, &spec.subtree_control)?;
    }
    if let Some(pid) = attach_pid {
        attach(&spec.path, pid)?;
    }
    Ok(())
}

/// Write `+ctrl +ctrl …\n` into `path/cgroup.subtree_control`.
pub fn enable_subtree_control(path: &Path, controllers: &[String]) -> io::Result<()> {
    let body = controllers
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    write(path.join("cgroup.subtree_control"), body)
}

/// Move `pid` into this cgroup via `cgroup.procs`.
pub fn attach(path: &Path, pid: u32) -> io::Result<()> {
    write(path.join("cgroup.procs"), pid.to_string())
}

/// Change ownership of an existing path; `None` leaves the side unchanged.
/// Refuses to follow a symlink.
pub fn set_owner(path: &Path, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    refuse_symlink(path)?;
    chown(path, uid.map(Uid::from_raw), gid.map(Gid::from_raw)).map_err(io::Error::from)
}

/// chmod an existing path (octal mode bits). Refuses to follow a symlink.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    refuse_symlink(path)?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

fn write(path: impl AsRef<Path>, body: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    refuse_symlink(path)?;
    let bytes = body.as_ref();
    let s = String::from_utf8_lossy(bytes);
    let trimmed = s.trim_end_matches(['\n', '\r']);
    fs::write(path, format!("{trimmed}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_full_spec_on_a_fake_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        // chown to *self* works unprivileged; euid/egid keep the test honest.
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();

        let leaf_rel = "users/lu_zero/session";
        let spec = LeafSpec {
            path: root.join(leaf_rel),
            uid: Some(uid),
            gid: Some(gid),
            dperm: Some(0o750),
            fperm: Some(0o640),
            task_fperm: Some(0o604),
            task_uid: None,
            task_gid: None,
            subtree_control: vec!["cpu".into(), "memory".into()],
        };
        apply(&spec, Some(4242)).unwrap();

        let meta = fs::metadata(root.join(leaf_rel)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o750);

        // subtree_control is written on the leaf itself (delegated-parent
        // semantics, matching libcgroup/pam_cgroup layouts).
        let st = fs::read_to_string(root.join(leaf_rel).join("cgroup.subtree_control")).unwrap();
        assert_eq!(st, "+cpu +memory\n");

        let procs = fs::read_to_string(root.join(leaf_rel).join("cgroup.procs")).unwrap();
        assert_eq!(procs, "4242\n");

        // Every created component got owners AND dperm — a plain mkdir
        // chain would leave 0o755&~umask on the intermediates.
        use std::os::unix::fs::MetadataExt;
        for rel in ["users", "users/lu_zero", leaf_rel] {
            let m = fs::metadata(root.join(rel)).unwrap();
            assert_eq!(m.uid(), uid, "{rel}");
            assert_eq!(m.gid(), gid, "{rel}");
            assert_eq!(m.permissions().mode() & 0o777, 0o750, "{rel}");
        }

        // Re-apply with no attach: idempotent on existing dirs.
        apply(&spec, None).unwrap();
    }

    /// The attack this guards against: a re-apply against a leaf a user
    /// swapped for a symlink must not chown/chmod/attach through it.
    #[test]
    fn refuses_to_reapply_through_a_symlinked_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();

        // A directory the "attacker" does not own and must not be able to
        // get chowned/chmoded/attached-into via the leaf below.
        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        let victim_mode_before = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;

        let leaf_rel = "users/lu_zero/session";
        let leaf = root.join(leaf_rel);
        fs::create_dir_all(leaf.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &leaf).unwrap();

        let spec = LeafSpec {
            path: leaf.clone(),
            uid: Some(uid),
            gid: Some(gid),
            dperm: Some(0o777),
            fperm: Some(0o666),
            task_fperm: None,
            task_uid: None,
            task_gid: None,
            subtree_control: vec![],
        };
        let err = apply(&spec, Some(4242)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // The symlink is untouched and the victim directory was never
        // chowned/chmoded/written into.
        assert!(fs::symlink_metadata(&leaf)
            .unwrap()
            .file_type()
            .is_symlink());
        let victim_meta = fs::metadata(&victim).unwrap();
        assert_eq!(victim_meta.permissions().mode() & 0o777, victim_mode_before);
        assert!(!victim.join("cgroup.procs").exists());
    }
}
