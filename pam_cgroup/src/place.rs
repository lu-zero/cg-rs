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
            subtree_control: self.subtree_control.clone(),
        }
    }
}

fn step_for(mount: &Path, place: &Place, user: &User) -> io::Result<Step> {
    let rel = expand(&place.path, user);
    let rel = rel.trim_start_matches('/');
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
