//! miette integration: named sources, spans, and graphical rendering.
//! Uses the `fancy` renderer (dev-dependency only).

use cgconfig::{CgError, ConfigFile, CrError, FileError, Rules};
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme};
use std::error::Error as StdError;
use std::fs;
use std::io;
use std::str::FromStr;

fn render(err: &dyn Diagnostic) -> String {
    let handler = GraphicalReportHandler::new_themed(GraphicalTheme::none()).without_cause_chain();
    let mut out = String::new();
    handler.render_report(&mut out, err).unwrap();
    out
}

#[test]
fn renders_cgconfig_snippet() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.conf");
    let text = "# c\n\nmount {}\nbogus {}\n";
    fs::write(&path, text).unwrap();

    let err = ConfigFile::from_path(&path).unwrap_err();
    let source = match &err {
        FileError::Parse { source, .. } => source,
        other => panic!("expected parse error, got {other:?}"),
    };
    assert_eq!(err.code().unwrap().to_string(), "cgconfig::parse");
    let (off, end) = (source.offset, source.end);
    assert_eq!(&text[off..end], "bogus", "label covers the bad keyword");

    let out = render(&err);
    assert!(out.contains("test.conf"), "file name: {out}");
    assert!(out.contains("bogus"), "snippet: {out}");
    assert!(out.contains("4"), "line number: {out}");
    assert!(out.contains("`mount`"), "expected-context help: {out}");
    assert_eq!(out.matches("cgconfig::parse").count(), 1, "{out}");
}

#[test]
fn renders_cgrules_ditto_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("rules.conf");
    fs::write(&path, "% * x/").unwrap();

    let err = Rules::from_path(&path).unwrap_err();
    assert_eq!(err.code().unwrap().to_string(), "cgconfig::rules");
    let out = render(&err);
    assert!(out.contains("rules.conf"), "{out}");
    assert!(out.contains("ditto"), "{out}");
    assert_eq!(out.matches("cgconfig::rules").count(), 1, "{out}");
}

#[test]
fn default_name_and_display() {
    let err = ConfigFile::from_str("group x { cpu { a = ; } }").unwrap_err();
    // Source attached under the default name, for later rendering.
    assert!(err.source_code().is_some());
    let s = err.to_string();
    assert!(s.starts_with("1:21: "), "{s}");
    assert!(s.contains("entry"), "{s}");
}

#[test]
fn read_errors_keep_the_path() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("missing.conf");
    let err = ConfigFile::from_path(&path).unwrap_err();

    assert!(matches!(&err, FileError::Read { path: error_path, .. } if error_path == &path));
    assert_eq!(err.path(), path);
    assert!(StdError::source(&err)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .is_some());
}

#[test]
fn file_errors_keep_their_immediate_causes() {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("bad.conf");
    fs::write(&config_path, "bogus {}\n").unwrap();
    let config_error = ConfigFile::from_path(&config_path).unwrap_err();
    assert!(StdError::source(&config_error)
        .and_then(|source| source.downcast_ref::<CgError>())
        .is_some());

    let rules_path = tmp.path().join("bad.rules");
    let rules_error = Rules::from_path(&rules_path).unwrap_err();
    assert_eq!(rules_error.path(), rules_path);
    assert!(StdError::source(&rules_error)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .is_some());

    let rules_path = tmp.path().join("bad-rules.conf");
    fs::write(&rules_path, "% * x/\n").unwrap();
    let rules_error = Rules::from_path(&rules_path).unwrap_err();
    assert!(StdError::source(&rules_error)
        .and_then(|source| source.downcast_ref::<CrError>())
        .is_some());
}
