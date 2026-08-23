//! miette integration: named sources, spans, and graphical rendering.
//! Uses the `fancy` renderer (dev-dependency only).

use cgconfig::{parse_cgconfig_in, parse_cgrules_in};
use miette::{Diagnostic, GraphicalReportHandler, GraphicalTheme};

fn render(err: &dyn Diagnostic) -> String {
    let handler = GraphicalReportHandler::new_themed(GraphicalTheme::none());
    let mut out = String::new();
    handler.render_report(&mut out, err).unwrap();
    out
}

#[test]
fn renders_cgconfig_snippet() {
    let text = "# c\n\nmount {}\nbogus {}\n";
    let err = parse_cgconfig_in("test.conf", text).unwrap_err();

    assert_eq!(err.code().unwrap().to_string(), "cgconfig::parse");
    let (off, end) = (err.offset, err.end);
    assert_eq!(&text[off..end], "bogus", "label covers the bad keyword");

    let out = render(&err);
    assert!(out.contains("test.conf"), "file name: {out}");
    assert!(out.contains("bogus"), "snippet: {out}");
    assert!(out.contains("4"), "line number: {out}");
    assert!(out.contains("`mount`"), "expected-context help: {out}");
}

#[test]
fn renders_cgrules_ditto_error() {
    let err = parse_cgrules_in("rules.conf", "% * x/").unwrap_err();
    assert_eq!(err.code().unwrap().to_string(), "cgconfig::rules");
    let out = render(&err);
    assert!(out.contains("rules.conf"), "{out}");
    assert!(out.contains("ditto"), "{out}");
}

#[test]
fn default_name_and_display() {
    let err = cgconfig::parse_cgconfig("group x { cpu { a = ; } }").unwrap_err();
    // Source attached under the default name, for later rendering.
    assert!(err.source_code().is_some());
    let s = err.to_string();
    assert!(s.starts_with("1:21: "), "{s}");
    assert!(s.contains("entry"), "{s}");
}
