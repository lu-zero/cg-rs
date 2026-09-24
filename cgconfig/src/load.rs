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

use crate::cgrules::Rules;

/// libcgroup's `CGRULES_CONF_FILE`.
pub const DEFAULT_CGRULES: &str = "/etc/cgrules.conf";
/// libcgroup's `CGRULES_CONF_DIR`.
pub const DEFAULT_CGRULES_DIR: &str = "/etc/cgrules.d";

/// Parse `main`, then every eligible file in `dir` (if it exists).
pub fn load_cgrules(main: &Path, dir: Option<&Path>) -> io::Result<Rules> {
    let mut rules = load_one(main)?;
    if let Some(dir) = dir {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut files: Vec<_> = entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| drop_in_file(p))
                    .collect();
                files.sort();
                for f in files {
                    rules.extend(load_one(&f)?);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
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

fn load_one(path: &Path) -> io::Result<Rules> {
    let text = fs::read_to_string(path)?;
    Rules::from_source(miette::NamedSource::new(path.display().to_string(), text))
        .map_err(io::Error::other)
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
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
