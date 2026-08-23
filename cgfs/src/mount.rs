//! cgroup2 mount point and self-hierarchy discovery.

use std::io;
use std::path::{Path, PathBuf};

/// Conventional mount point, used when mountinfo says nothing.
pub const DEFAULT_MOUNT: &str = "/sys/fs/cgroup";

/// Find the cgroup2 unified hierarchy mount point.
///
/// Reads `/proc/self/mountinfo` first (handles non-standard mounts), then
/// falls back to [`DEFAULT_MOUNT`] if it looks like a cgroup2 root.
pub fn find_mount() -> io::Result<PathBuf> {
    if let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") {
        for line in text.lines() {
            if let Some(mp) = parse_mountinfo_line(line) {
                return Ok(mp);
            }
        }
    }
    let fallback = PathBuf::from(DEFAULT_MOUNT);
    if fallback.join("cgroup.controllers").is_file() {
        return Ok(fallback);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no cgroup2 filesystem",
    ))
}

/// One `mountinfo` line: `id parent dev root mountpoint opts - fstype …`.
pub(crate) fn parse_mountinfo_line(line: &str) -> Option<PathBuf> {
    if !line.contains(" - cgroup2 ") {
        return None;
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields.get(4).map(PathBuf::from)
}

/// This process's cgroup path *relative to* the cgroup2 hierarchy
/// (`0::/…` line of `/proc/self/cgroup`).
pub fn self_relative() -> io::Result<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    parse_v2_rel(&text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not in a cgroup v2 hierarchy"))
}

pub(crate) fn parse_v2_rel(text: &str) -> Option<PathBuf> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = rest.trim();
            return Some(if p.is_empty() {
                PathBuf::from("/")
            } else {
                PathBuf::from(p)
            });
        }
    }
    None
}

/// Append a hierarchy-relative path to the mount point; `/` collapses away.
pub fn join(mount: &Path, rel: &Path) -> PathBuf {
    match rel.strip_prefix("/") {
        Ok(r) if !r.as_os_str().is_empty() => mount.join(r),
        _ => mount.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mountinfo_lines() {
        let line = "40 27 0:36 / /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup2 rw,nsdelegate";
        assert_eq!(
            parse_mountinfo_line(line).unwrap(),
            PathBuf::from("/sys/fs/cgroup")
        );
        assert!(parse_mountinfo_line("1 2 3:4 / /proc rw - proc proc rw").is_none());
    }

    #[test]
    fn parses_self_cgroup() {
        assert_eq!(
            parse_v2_rel("0::/openrc.sshd\n").unwrap(),
            PathBuf::from("/openrc.sshd")
        );
        assert_eq!(parse_v2_rel("0::/\n").unwrap(), PathBuf::from("/"));
        assert_eq!(
            parse_v2_rel("12:pids:/\n0::/foo/bar\n").unwrap(),
            PathBuf::from("/foo/bar")
        );
        assert!(parse_v2_rel("1:cpu:/a\n").is_none());
    }

    #[test]
    fn join_strips_root() {
        let m = Path::new("/sys/fs/cgroup");
        assert_eq!(join(m, Path::new("/")), m);
        assert_eq!(join(m, Path::new("/")), m);
        assert_eq!(
            join(m, Path::new("/openrc.sshd")),
            PathBuf::from("/sys/fs/cgroup/openrc.sshd")
        );
    }

    #[test]
    fn find_mount_succeeds_or_is_clean_not_found() {
        // Either we are on a v2 system or we get a clean NotFound.
        match find_mount() {
            Ok(m) => assert!(m.is_absolute()),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }
}
