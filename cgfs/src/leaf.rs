//! Create and delegate a cgroup leaf: mkdir, ownership, modes,
//! `cgroup.subtree_control`, attach.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

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
/// Only `spec.path` itself — the leaf — is chowned to `spec.uid`/`spec.gid`.
/// Directories created along the way to reach it get `dperm` (so they stay
/// traversable regardless of the caller's umask) but keep their creator's
/// ownership: a shared ancestor (e.g. `users/`, the parent of every
/// `users/{user}` leaf) must not end up owned by whichever leaf happens to
/// materialise it first — that would hand that one delegatee structural
/// control (mkdir/rmdir/rename) over every sibling leaf under it. A caller
/// that wants an *intermediate* directory delegated too (as pam_cgroup's
/// `users/{user}` config entry does) applies it as its own leaf, separately.
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
    // `..` must not appear anywhere. `Path::components()` preserves each
    // `..` as a literal `ParentDir` without trying to lexically cancel it
    // against an earlier component, so this check is reliable for it.
    if spec
        .path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("leaf path must not contain '..': {:?}", spec.path),
        ));
    }
    // A literal "." segment — anywhere, including a bare trailing "/" —
    // is checked on the raw bytes instead of `.components()`, which
    // normalizes *both* away silently before this function ever sees
    // them (confirmed: `Path::new("a/.").components()` and
    // `Path::new("a/").components()` both yield just `[Normal("a")]`,
    // with nothing marking the "." or trailing "/" at all). That
    // normalization matters here because `symlink_metadata` — which the
    // ancestor walk below and `set_owner`/`set_mode` rely on to refuse a
    // symlink — only inspects a path's *final* component, and `lstat` on
    // a path ending in "/" or "/." is specified to resolve that final
    // component as a directory, transparently following it if it's a
    // symlink. So the non-normalized spelling has to be rejected before
    // any lstat happens, not detected by one.
    let raw = spec.path.as_os_str().as_encoded_bytes();
    if raw.last() == Some(&b'/') || raw.split(|&b| b == b'/').any(|seg| seg == b".") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "leaf path must not contain '.' or a trailing slash: {:?}",
                spec.path
            ),
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
    // be moded afterwards; deepest last. TOCTOU on concurrent creator is
    // benign — the directory will be there on the next explicit re-apply.
    //
    // Every ancestor up to `/` is checked with `symlink_metadata`, not just
    // the deepest existing one: `symlink_metadata` on a path only reports
    // whether its *final* component is a symlink, so a directory reached by
    // transparently resolving a symlinked ancestor can still look like an
    // ordinary already-existing leaf. Stopping at the first "exists" would
    // walk straight through a symlinked ancestor without ever lstat'ing it
    // directly; continuing the walk all the way up is what actually lstats
    // that ancestor's own path component and catches it.
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
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                created.push(cur.clone());
            }
            Err(e) => return Err(e),
        }
        let Some(parent) = cur.parent() else {
            break;
        };
        cur = parent.to_path_buf();
    }
    fs::create_dir_all(&spec.path)?;

    for dir in created.iter().rev() {
        if let Some(mode) = spec.dperm {
            set_mode(dir, ancestor_dperm(mode))?;
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

/// Mode for a newly created ancestor of the leaf.
///
/// Ancestors stay root-owned, so the leaf's `task` owner is `other` on
/// them. Strip group/other write so a delegated user cannot mkdir/rmdir
/// siblings, but force execute so they can still walk to their own leaf
/// even when `dperm` is `0750` (no `o+x` as written).
fn ancestor_dperm(dperm: u32) -> u32 {
    (dperm & !0o022) | 0o011
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

        // Every created ancestor got dperm — a plain mkdir chain would leave
        // 0o755&~umask on the intermediates. (uid/gid on the ancestors are
        // *not* asserted here: `apply` deliberately leaves them at their
        // creator's identity rather than the leaf's owner — see the doc
        // comment on `apply` — but this test runs unprivileged, where the
        // creator's identity and `spec.uid`/`gid` are the same value, so an
        // ownership assertion here couldn't distinguish the two behaviours
        // anyway.)
        use std::os::unix::fs::MetadataExt;
        for rel in ["users", "users/lu_zero"] {
            let m = fs::metadata(root.join(rel)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o751, "{rel}");
        }
        let leaf_meta = fs::metadata(root.join(leaf_rel)).unwrap();
        assert_eq!(leaf_meta.uid(), uid);
        assert_eq!(leaf_meta.gid(), gid);
        assert_eq!(leaf_meta.permissions().mode() & 0o777, 0o750);

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

    /// Same attack, one level up: an *ancestor* (not the leaf itself) is
    /// the symlink, and the path beneath it already exists — so
    /// `symlink_metadata(spec.path)` alone finds an ordinary-looking
    /// existing directory and never lstats the symlinked ancestor unless
    /// the walk keeps going past the first "exists" boundary.
    #[test]
    fn refuses_to_reapply_through_a_symlinked_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();

        // victim/session already exists — the path an attacker-controlled
        // symlinked ancestor resolves into looks like a legitimate,
        // already-materialised leaf.
        let victim = tmp.path().join("victim");
        fs::create_dir_all(victim.join("session")).unwrap();
        let victim_session_mode_before = fs::metadata(victim.join("session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        fs::create_dir_all(root.join("users")).unwrap();
        std::os::unix::fs::symlink(&victim, root.join("users/lu_zero")).unwrap();

        let spec = LeafSpec {
            path: root.join("users/lu_zero/session"),
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

        assert!(fs::symlink_metadata(root.join("users/lu_zero"))
            .unwrap()
            .file_type()
            .is_symlink());
        let after = fs::metadata(victim.join("session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(after, victim_session_mode_before);
        assert!(!victim.join("session/cgroup.procs").exists());
    }

    /// `lstat`'s "final component" is defined by trailing-slash/`/.`
    /// resolution rules, not by the literal string: a path ending in `/`
    /// or `/.` forces that component to resolve as a directory, silently
    /// following it if it's a symlink — so `symlink_metadata` alone never
    /// sees a symlinked leaf spelled this way. `apply` must reject the
    /// non-normalized spelling itself, before any lstat.
    #[test]
    fn refuses_a_leaf_path_with_a_trailing_slash_or_dot() {
        let tmp = tempfile::tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();

        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        let victim_mode_before = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;

        let root = tmp.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        let link = root.join("evil");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        for tail in ["evil/", "evil/."] {
            let spec = LeafSpec {
                path: root.join(tail),
                uid: Some(uid),
                gid: Some(gid),
                dperm: Some(0o777),
                fperm: None,
                task_fperm: None,
                task_uid: None,
                task_gid: None,
                subtree_control: vec![],
            };
            let err = apply(&spec, None).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "tail={tail:?}");
        }

        let after = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(after, victim_mode_before, "victim must be untouched");
    }

    /// A shared ancestor gets dperm's read/execute (so delegatees can
    /// traverse through it) but never group/other write, regardless of
    /// what dperm says — a permissive dperm must not let every delegatee
    /// mkdir/rmdir/rename siblings under it.
    #[test]
    fn strips_write_bits_from_ancestor_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();

        let spec = LeafSpec {
            path: root.join("users/lu_zero/session"),
            uid: Some(uid),
            gid: Some(gid),
            dperm: Some(0o777),
            fperm: None,
            task_fperm: None,
            task_uid: None,
            task_gid: None,
            subtree_control: vec![],
        };
        apply(&spec, None).unwrap();

        for ancestor in ["users", "users/lu_zero"] {
            let mode = fs::metadata(root.join(ancestor))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "{ancestor}: dperm's write bits leaked");
        }
        // The leaf itself keeps the full configured dperm.
        let leaf_mode = fs::metadata(root.join("users/lu_zero/session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(leaf_mode, 0o777);
    }

    #[test]
    fn ancestor_dperm_0750_is_still_traversable() {
        // The students template uses `dperm = 750`; without forcing o+x
        // the task owner cannot walk a root-owned `students/` parent.
        assert_eq!(ancestor_dperm(0o750), 0o751);
        assert_eq!(ancestor_dperm(0o777), 0o755);
        assert_eq!(ancestor_dperm(0o700), 0o711);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let spec = LeafSpec {
            path: root.join("students/alice"),
            uid: Some(uid),
            gid: Some(gid),
            dperm: Some(0o750),
            fperm: None,
            task_fperm: None,
            task_uid: None,
            task_gid: None,
            subtree_control: vec![],
        };
        apply(&spec, None).unwrap();
        let parent = fs::metadata(root.join("students"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent, 0o751);
        let leaf = fs::metadata(root.join("students/alice"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(leaf, 0o750);
    }
}
