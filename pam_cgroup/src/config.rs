use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default path on Gentoo; override with `config=` PAM arg or `--config`.
pub const DEFAULT_CONFIG: &str = "/etc/cgroup/pam_cgroup.toml";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_mount")]
    pub mount: PathBuf,
    /// PAM returns `PAM_SESSION_ERR` on apply failure.
    #[serde(default)]
    pub fail_closed: bool,
    pub place: Vec<Place>,
}

fn default_mount() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Place {
    /// Relative to [`Config::mount`]. `{user}` `{uid}` `{gid}` `{group}`.
    pub path: String,
    /// `{user}` / `{uid}` / numeric / passwd name.
    #[serde(default = "root_id")]
    pub uid: String,
    #[serde(default = "root_id")]
    pub gid: String,
    #[serde(default = "default_dir_mode")]
    pub mode: u32,
    #[serde(default = "default_file_mode")]
    pub file_mode: u32,
    /// Written as `+cpu +memory` to `cgroup.subtree_control`.
    #[serde(default)]
    pub subtree_control: Vec<String>,
    /// Write the session pid to `cgroup.procs`.
    #[serde(default)]
    pub attach: bool,
}

fn root_id() -> String {
    "0".into()
}

fn default_dir_mode() -> u32 {
    0o755
}

fn default_file_mode() -> u32 {
    0o644
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> io::Result<Self> {
        let cfg: Config =
            toml::from_str(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if cfg.place.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "config has no [[place]] entries",
            ));
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example() {
        let cfg = Config::parse(include_str!("../examples/pam_cgroup.toml")).unwrap();
        assert_eq!(cfg.mount, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(cfg.place.len(), 2);
        assert_eq!(cfg.place[0].path, "users/{user}");
        assert_eq!(cfg.place[0].mode, 0o775);
        assert_eq!(cfg.place[0].subtree_control, ["cpu", "memory"]);
        assert!(cfg.place[1].attach);
        assert!(!cfg.place[0].attach);
    }
}
