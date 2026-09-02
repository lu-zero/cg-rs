//! Raw control-file access: the `cgset`/`cgget` layer. No controller
//! opinions — keys are whatever cgroupfs exposes.

use std::fs;
use std::io;
use std::path::Path;

/// Refuse to act on `path` if it is a symlink; a missing path is fine (the
/// caller is about to create it).
///
/// A delegated leaf is owned by the user it was created for, and every
/// write here (`chown`, `chmod`, `cgroup.procs`/`cgroup.subtree_control`
/// writes) idempotently re-asserts itself against a path that already
/// exists, on every re-apply. Without this check, a user who owns their own
/// leaf could swap it for a symlink to an arbitrary existing directory or
/// file and have the next root-run re-apply (a PAM session, a cgrulesd poll)
/// `chown`/`chmod`/write through the symlink instead of failing.
pub(crate) fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to operate through a symlink: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whole contents of a control file, trimmed.
pub fn read_string(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

/// Parse a flat-keyed file (`cpu.stat`, `memory.events`, …) into pairs.
/// Later duplicate keys win; nested-keyed files (io.stat) come back with
/// their remainder as one value string.
pub fn read_kv(path: impl AsRef<Path>) -> io::Result<Vec<(String, String)>> {
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            let (k, v) = l.split_once(char::is_whitespace)?;
            Some((k.to_owned(), v.trim().to_owned()))
        })
        .collect())
}

/// Single unsigned value file (`memory.current`, `pids.current`, …).
/// `Ok(None)` when the file is missing (controller not enabled).
pub fn read_u64(path: impl AsRef<Path>) -> io::Result<Option<u64>> {
    match fs::read_to_string(path.as_ref()) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Overwrite a control file (`cgset` primitive). Appends a trailing newline
/// if the value does not already end with one. Refuses to write through a
/// symlink.
pub fn write_file(path: impl AsRef<Path>, value: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    refuse_symlink(path)?;
    let mut body = value.as_ref().to_vec();
    if !body.ends_with(b"\n") {
        body.push(b'\n');
    }
    fs::write(path, body)
}

/// Pids currently in this cgroup.
pub fn procs(path: impl AsRef<Path>) -> io::Result<Vec<u32>> {
    let text = fs::read_to_string(path.as_ref())?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let pid: u32 = l.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad pid {l:?}: {e}"))
        })?;
        out.push(pid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cpu.stat");
        fs::write(&p, "usage_usec 123\nuser_usec 100\nsystem_usec 23\n\n").unwrap();

        let kv = read_kv(&p).unwrap();
        assert_eq!(kv[0], ("usage_usec".into(), "123".into()));
        assert_eq!(kv.len(), 3);
    }

    #[test]
    fn u64_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_u64(tmp.path().join("memory.current")).unwrap(), None);

        let p = tmp.path().join("memory.current");
        fs::write(&p, "4096\n").unwrap();
        assert_eq!(read_u64(&p).unwrap(), Some(4096));
    }

    #[test]
    fn write_appends_newline_and_procs_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cgroup.procs");
        write_file(&p, "12").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "12\n");
        assert_eq!(procs(&p).unwrap(), vec![12]);
    }

    #[test]
    fn write_file_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere");
        fs::write(&target, "untouched").unwrap();
        let link = tmp.path().join("cgroup.procs");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = write_file(&link, "12").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    }
}
