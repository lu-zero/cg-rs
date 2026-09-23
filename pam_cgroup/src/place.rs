use std::io;

use cgfs::{Cgroup, CgroupPath, Hierarchy, LeafSpec};

use crate::config::{Config, Place};
use crate::user::{expand, resolve_id, User};

#[derive(Clone, Debug)]
pub struct Step {
    /// Target handle, already bound to the hierarchy used for planning.
    pub cgroup: Cgroup,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub file_mode: u32,
    pub subtree_control: Vec<String>,
    pub attach: bool,
}

impl Config {
    pub fn plan(&self, hierarchy: &Hierarchy, user: &User, _pid: u32) -> io::Result<Vec<Step>> {
        self.place
            .iter()
            .map(|p| step_for(hierarchy, p, user))
            .collect()
    }
}

impl Step {
    fn to_spec(&self) -> LeafSpec {
        LeafSpec::new()
            .uid(self.uid)
            .gid(self.gid)
            .dperm(self.mode)
            .fperm(self.file_mode)
            .task_fperm(self.file_mode)
            .subtree_control(&self.subtree_control)
    }
}

fn step_for(hierarchy: &Hierarchy, place: &Place, user: &User) -> io::Result<Step> {
    let expanded = expand(&place.path, user);
    let relative = expanded.trim_start_matches('/');
    let path = CgroupPath::parse(relative).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("place path {:?} is invalid: {e}", place.path),
        )
    })?;
    if path.as_relative().as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("place path {:?} resolves to the hierarchy root", place.path),
        ));
    }
    Ok(Step {
        cgroup: hierarchy.at(path),
        uid: resolve_id(&place.uid, user, false)?,
        gid: resolve_id(&place.gid, user, true)?,
        mode: place.mode,
        file_mode: place.file_mode,
        subtree_control: place.subtree_control.clone(),
        attach: place.attach,
    })
}

/// Create / chown / chmod / enable controllers / attach through a verified
/// hierarchy handle. Re-applies ownership if the cgroup already exists.
pub fn apply(cfg: &Config, hierarchy: &Hierarchy, user: &User, pid: u32) -> io::Result<Vec<Step>> {
    let steps = cfg.plan(hierarchy, user, pid)?;
    for step in &steps {
        step.cgroup
            .apply(&step.to_spec(), step.attach.then_some(pid))?;
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

    fn test_hierarchy() -> (tempfile::TempDir, Hierarchy) {
        let tmp = tempfile::tempdir().unwrap();
        let hierarchy = unsafe { cgfs::Hierarchy::open_for_test(tmp.path()) }.unwrap();
        (tmp, hierarchy)
    }

    #[test]
    fn rejects_paths_that_resolve_to_the_hierarchy_root() {
        let (_tmp, hierarchy) = test_hierarchy();
        for path in [".", "", "/"] {
            let err = step_for(&hierarchy, &place(path), &user()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "path={path:?}");
        }
    }

    #[test]
    fn accepts_an_ordinary_place() {
        let (_tmp, hierarchy) = test_hierarchy();
        let step = step_for(&hierarchy, &place("users/{user}"), &user()).unwrap();
        assert_eq!(
            step.cgroup.path().as_relative(),
            std::path::Path::new("users/lu_zero")
        );
    }

    #[test]
    fn rejects_a_trailing_dot_or_slash_past_a_real_segment() {
        let (_tmp, hierarchy) = test_hierarchy();
        for path in ["users/{user}/session/.", "users/{user}/session/"] {
            let err = step_for(&hierarchy, &place(path), &user()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "path={path:?}");
        }
    }
}
