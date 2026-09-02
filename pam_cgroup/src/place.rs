use std::io;
use std::path::{Path, PathBuf};

use cgfs::LeafSpec;

use crate::config::{Config, Place};
use crate::user::{expand, resolve_id, User};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub path: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub file_mode: u32,
    pub subtree_control: Vec<String>,
    pub attach: bool,
}

impl Config {
    pub fn plan(&self, user: &User, _pid: u32) -> io::Result<Vec<Step>> {
        self.place
            .iter()
            .map(|p| step_for(&self.mount, p, user))
            .collect()
    }
}

impl Step {
    fn to_spec(&self) -> LeafSpec {
        LeafSpec {
            path: self.path.clone(),
            uid: Some(self.uid),
            gid: Some(self.gid),
            dperm: Some(self.mode),
            fperm: Some(self.file_mode),
            task_fperm: Some(self.file_mode),
            task_uid: None,
            task_gid: None,
            subtree_control: self.subtree_control.clone(),
        }
    }
}

fn step_for(mount: &Path, place: &Place, user: &User) -> io::Result<Step> {
    let rel = expand(&place.path, user);
    let rel = rel.trim_start_matches('/');
    // A bare "." (or, after the trim above, "" or "/") resolves to the
    // mount root itself, not a leaf under it — same illegal-target class
    // as `..`/absolute, just via the no-op component instead of an
    // escaping one, so it needs the same rejection.
    let mut has_normal = false;
    for comp in std::path::Path::new(rel).components() {
        match comp {
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "place path {:?} contains illegal component {:?}",
                        place.path, comp
                    ),
                ))
            }
            std::path::Component::Normal(_) => has_normal = true,
            std::path::Component::CurDir => {}
        }
    }
    if !has_normal {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "place path {:?} resolves to empty (would be mount root)",
                place.path
            ),
        ));
    }
    Ok(Step {
        path: mount.join(rel),
        uid: resolve_id(&place.uid, user, false)?,
        gid: resolve_id(&place.gid, user, true)?,
        mode: place.mode,
        file_mode: place.file_mode,
        subtree_control: place.subtree_control.clone(),
        attach: place.attach,
    })
}

/// Create / chown / chmod / enable controllers / attach — via [`cgfs`].
/// Re-applies ownership if the cgroup already exists (libcgroup skips that).
pub fn apply(cfg: &Config, user: &User, pid: u32) -> io::Result<Vec<Step>> {
    let steps = cfg.plan(user, pid)?;
    for step in &steps {
        cgfs::apply(&step.to_spec(), step.attach.then_some(pid))?;
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Place;

    fn user() -> User {
        User {
            name: "lu_zero".into(),
            uid: 1000,
            gid: 10,
            group: "wheel".into(),
        }
    }

    fn place(path: &str) -> Place {
        Place {
            path: path.into(),
            uid: "{uid}".into(),
            gid: "{gid}".into(),
            mode: 0o775,
            file_mode: 0o664,
            subtree_control: vec![],
            attach: false,
        }
    }

    #[test]
    fn rejects_paths_that_resolve_to_the_mount_root() {
        for path in [".", "", "/"] {
            let err = step_for(Path::new("/sys/fs/cgroup"), &place(path), &user()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "path={path:?}");
        }
    }

    #[test]
    fn accepts_an_ordinary_place() {
        let step = step_for(Path::new("/sys/fs/cgroup"), &place("users/{user}"), &user()).unwrap();
        assert_eq!(step.path, Path::new("/sys/fs/cgroup/users/lu_zero"));
    }
}
