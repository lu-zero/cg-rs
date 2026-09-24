//! Load `cgrules.conf` plus an optional drop-in directory (`cgrules.d`).
//!
//! Each file is parsed on its own, so `%` ditto does not span files.
//! Drop-ins are regular files (symlinks to files included), skip names
//! starting with `.`, sorted by file name. A missing directory is empty,
//! not an error — matching libcgroup's backward-compat path. Unlike
//! libcgroup's `readdir` order, the sort makes first-match deterministic.

use std::fs;
use std::io;
use std::path::Path;

use crate::cgrules::{CrError, Rules};
use crate::error::FileError;

/// libcgroup's `CGRULES_CONF_FILE`.
pub const DEFAULT_CGRULES: &str = "/etc/cgrules.conf";
/// libcgroup's `CGRULES_CONF_DIR`.
pub const DEFAULT_CGRULES_DIR: &str = "/etc/cgrules.d";

/// Parse `main`, then every eligible file in `dir` (if it exists).
///
/// Read and parse failures retain the relevant path in [`FileError`].
pub fn load_cgrules(main: &Path, dir: Option<&Path>) -> Result<Rules, FileError<CrError>> {
    let mut rules = Rules::from_path(main)?;
    if let Some(dir) = dir {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut files = Vec::new();
                for entry in entries {
                    let entry = entry.map_err(|source| FileError::Read {
                        path: dir.to_path_buf(),
                        source,
                    })?;
                    let path = entry.path();
                    if drop_in_file(&path) {
                        files.push(path);
                    }
                }
                files.sort();
                for file in files {
                    rules.extend(Rules::from_path(file)?);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(FileError::Read {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(rules)
}

fn drop_in_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name.starts_with('.') {
        return false;
    }
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn main_then_sorted_drop_ins() {
        let tmp = tempfile::tempdir().unwrap();
        let main = write(tmp.path(), "cgrules.conf", "alice * dest-a\n");
        let d = tmp.path().join("cgrules.d");
        fs::create_dir(&d).unwrap();
        write(&d, "10-later.conf", "bob * dest-b\n");
        write(&d, "00-first.conf", "carol * dest-c\n");
        write(&d, ".hidden", "hidden * dest-h\n");
        fs::create_dir(d.join("subdir")).unwrap();

        let rules = load_cgrules(&main, Some(&d)).unwrap();
        let dests: Vec<_> = rules.iter().map(|r| r.destination.0.as_str()).collect();
        assert_eq!(dests, ["dest-a", "dest-c", "dest-b"]);
    }

    #[test]
    fn missing_dir_is_just_the_main_file() {
        let tmp = tempfile::tempdir().unwrap();
        let main = write(tmp.path(), "cgrules.conf", "alice * dest-a\n");
        let rules = load_cgrules(&main, Some(&tmp.path().join("no-such"))).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn ditto_does_not_span_files() {
        let tmp = tempfile::tempdir().unwrap();
        let main = write(tmp.path(), "cgrules.conf", "alice * dest-a\n");
        let d = tmp.path().join("d");
        fs::create_dir(&d).unwrap();
        write(&d, "extra.conf", "% * dest-b\n");
        let err = load_cgrules(&main, Some(&d)).unwrap_err();
        assert!(matches!(err, FileError::Parse { .. }));
    }
}
