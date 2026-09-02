//! cgroup2 mount point and self-hierarchy discovery.

use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::statfs;

/// Conventional mount point, used when mountinfo says nothing.
pub const DEFAULT_MOUNT: &str = "/sys/fs/cgroup";

/// `statfs(2)` superblock magic for cgroup2; a stable kernel ABI value
/// (linux-raw-sys carries it, rustix does not re-export it).
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// True when `path` lives on a cgroup2 filesystem (verified via
/// `statfs(2)`, not just file presence).
pub(crate) fn is_cgroup2(path: &Path) -> bool {
    matches!(statfs(path), Ok(st) if st.f_type as u64 == CGROUP2_SUPER_MAGIC)
}

/// Find the cgroup2 unified hierarchy mount point.
///
/// Reads `/proc/self/mountinfo` first (handles non-standard mounts, each
/// candidate verified by superblock magic), then falls back to
/// [`DEFAULT_MOUNT`] if it really is a cgroup2 filesystem.
pub fn find_mount() -> io::Result<PathBuf> {
    if let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") {
        for line in text.lines() {
            if let Some(mp) = parse_mountinfo_line(line) {
                // mountinfo says cgroup2; statfs confirms it is.
                if is_cgroup2(&mp) {
                    return Ok(mp);
                }
            }
        }
    }
    let fallback = PathBuf::from(DEFAULT_MOUNT);
    if fallback.join("cgroup.controllers").is_file() && is_cgroup2(&fallback) {
        return Ok(fallback);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no cgroup2 filesystem",
    ))
}

/// Decode `\NNN` octal escapes. The kernel escapes each *byte* independently,
/// so a multi-byte UTF-8 mount path arrives as consecutive `\NNN` sequences
/// (e.g. `é` as `\303\251`) — collect into a byte buffer and decode the
/// whole thing as UTF-8 at the end, rather than mapping each escaped byte to
/// its own `char` (which would treat every escaped byte as a lone Latin-1-ish
/// codepoint and mangle anything non-ASCII).
fn unescape_mount(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut oct = String::new();
            for _ in 0..3 {
                if let Some(&o) = chars.peek() {
                    if ('0'..='7').contains(&o) {
                        oct.push(o);
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
            if oct.len() == 3 {
                if let Ok(v) = u8::from_str_radix(&oct, 8) {
                    out.push(v);
                    continue;
                }
            }
            out.push(b'\\');
            out.extend_from_slice(oct.as_bytes());
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One `mountinfo` line: `id parent dev root mountpoint opts - fstype …`.
pub(crate) fn parse_mountinfo_line(line: &str) -> Option<PathBuf> {
    let sep = " - ";
    let idx = line.find(sep)?;
    let (pre, post) = line.split_at(idx);
    let post = &post[sep.len()..];
    let fstype = post.split_whitespace().next()?;
    if fstype != "cgroup2" {
        return None;
    }
    // pre: id parent dev root mountpoint opts...
    // mountpoint is field 4 (0-indexed) before the separator, with octal escapes.
    let mut fields: Vec<&str> = Vec::new();
    // split pre into whitespace fields; mountpoint may contain escaped spaces,
    // but find separator ensures we are before '-'; escapes remain as \040.
    for f in pre.split_whitespace() {
        fields.push(f);
    }
    let raw = fields.get(4)?;
    Some(PathBuf::from(unescape_mount(raw)))
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
/// Relative inputs without a leading `/` are also appended.
pub fn join(mount: &Path, rel: &Path) -> PathBuf {
    if rel.as_os_str().is_empty() || rel == Path::new("/") {
        return mount.to_path_buf();
    }
    if let Ok(r) = rel.strip_prefix("/") {
        if r.as_os_str().is_empty() {
            return mount.to_path_buf();
        }
        return mount.join(r);
    }
    mount.join(rel)
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
    fn unescapes_multibyte_utf8_octal_sequences() {
        // "café" — the kernel escapes each raw byte independently, so "é"
        // (0xC3 0xA9 in UTF-8) shows up as two consecutive \NNN escapes that
        // must be reassembled into one codepoint, not decoded byte-by-byte.
        assert_eq!(unescape_mount("caf\\303\\251"), "café");
        assert_eq!(unescape_mount("plain\\040space"), "plain space");
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
            Ok(m) => {
                assert!(m.is_absolute());
                assert!(is_cgroup2(&m), "returned mount verified by statfs");
            }
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn tmpfs_is_not_cgroup2() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!is_cgroup2(tmp.path()));
    }
}
