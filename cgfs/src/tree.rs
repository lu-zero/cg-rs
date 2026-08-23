//! Tree operations: list groups, delete leaves/trees.

use std::fs;
use std::io;

use crate::mount::find_mount;

/// All cgroup directories under `root`, relative to it, depth-first, sorted.
/// The root itself is not included.
pub fn list_groups(root: &std::path::Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let path = entry.path();
            out.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            walk(root, &path, out)?;
        }
    }
    Ok(())
}

/// Remove a single (empty) cgroup directory.
pub fn delete_leaf(path: &std::path::Path) -> io::Result<()> {
    fs::remove_dir(path)
}

/// Remove `path` and every cgroup below it, children first.
///
/// Refuses to remove the cgroup2 mount point itself.
pub fn delete_tree(path: &std::path::Path) -> io::Result<()> {
    let canon = path.canonicalize()?;
    if let Ok(mount) = find_mount() {
        if canon == mount {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to remove the cgroup mount point",
            ));
        }
    }
    remove_children(&canon)
}

fn remove_children(dir: &std::path::Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_children(&entry.path())?;
        }
    }
    fs::remove_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn mk(root: &Path, rel: &str) -> std::path::PathBuf {
        let p = root.join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn lists_sorted_relative() {
        let tmp = tempfile::tempdir().unwrap();
        mk(tmp.path(), "b");
        mk(tmp.path(), "a/x");
        mk(tmp.path(), "a/y");

        let got = list_groups(tmp.path()).unwrap();
        assert_eq!(
            got,
            vec![
                PathBuf::from("a"),
                PathBuf::from("a/x"),
                PathBuf::from("a/y"),
                PathBuf::from("b"),
            ]
        );
    }

    #[test]
    fn deletes_children_first() {
        let tmp = tempfile::tempdir().unwrap();
        mk(tmp.path(), "users/u/session");

        delete_tree(&tmp.path().join("users")).unwrap();
        assert!(!tmp.path().join("users").exists());
        assert!(tmp.path().exists(), "root untouched");
    }

    #[test]
    fn refuses_non_empty_dir_like_the_kernel() {
        // cgroupfs directories hold no regular files; deletion stays as
        // strict as `rmdir`.
        let tmp = tempfile::tempdir().unwrap();
        let inner = mk(tmp.path(), "users/u/session");
        fs::write(inner.join("stray"), "").unwrap();

        assert!(delete_tree(&tmp.path().join("users")).is_err());
        assert!(tmp.path().join("users").exists());
    }

    #[test]
    fn refuses_mount_point() {
        if let Ok(mount) = find_mount() {
            let e = delete_tree(&mount).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        }
    }
}
