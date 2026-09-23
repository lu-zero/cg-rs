//! cgroup2 mount point discovery.

use std::io;
use std::path::{Path, PathBuf};

use rustix::fs::statfs;

/// Conventional mount point, used when mountinfo says nothing.
pub(crate) const DEFAULT_MOUNT: &str = "/sys/fs/cgroup";

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
pub(crate) fn find_mount() -> io::Result<PathBuf> {
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

/// Decode `\NNN` octal escapes (the kernel's `seq_path` only escapes
/// ` \t\n\\`; other bytes, non-ASCII UTF-8 included, pass through raw).
/// Collects into a byte buffer and decodes the whole thing as UTF-8 at the
/// end, rather than mapping each escaped byte straight to its own `char` —
/// correct for the escaped bytes themselves either way (they're single
/// ASCII bytes), but the byte-buffer form is also right in the general
/// case of a `\NNN` run that happens to spell out a multi-byte sequence,
/// instead of quietly mangling it into one Latin-1-ish codepoint per byte.
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
        // The kernel only escapes " \t\n\\", so a real "café" mount path
        // arrives with "é" (0xC3 0xA9 in UTF-8) raw, not escaped — this
        // pins the general property instead: *if* consecutive \NNN escapes
        // spell out a multi-byte sequence, they must reassemble into one
        // codepoint, not decode byte-by-byte into two Latin-1-ish ones.
        assert_eq!(unescape_mount("caf\\303\\251"), "café");
        // The realistic case: non-ASCII passes through raw; only the
        // space gets escaped.
        assert_eq!(unescape_mount("caf\u{e9}\\040dir"), "café dir");
        assert_eq!(unescape_mount("plain\\040space"), "plain space");
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
