//! Serialize [`ConfigFile`] back to cgconfig.conf syntax.
//!
//! Round-trip guarantee: parsing the output of `Display` yields an equal
//! [`ConfigFile`], *provided* every value is representable. Tokens that
//! would not survive bare (whitespace, structural punctuation) are
//! double-quoted, mirroring the parser's optional-quote support. A value
//! containing a literal `"` is not representable — this format has no
//! escape syntax (matching real cgconfig.conf) — so `Display::fmt` returns
//! `Err` rather than emit a quoted token that a `"` inside it would break
//! out of, injecting unintended structure into the output. That matters
//! because a group/template name, or a controller/param key here, can
//! come from a live cgroup directory name or control-file name
//! (`cgctl snapshot`), which an unprivileged delegatee inside their own
//! subtree fully controls.
//!
//! A controller *block name* (`cpu { … }`) has no quoted form at all in
//! this grammar (the parser's `ctl_block` only accepts a bare word) — it
//! is refused outright when it wouldn't survive as one, since there is no
//! way to represent it safely by quoting instead.

use std::fmt;

use crate::model::{ConfigFile, Node, Perm, PermSet};

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.mounts.is_empty() {
            writeln!(f, "mount {{")?;
            for m in &self.mounts {
                writeln!(f, "\t{} = {};", token(&m.controller)?, token(&m.path)?)?;
            }
            writeln!(f, "}}\n")?;
        }

        if let Some(p) = &self.default_perm {
            writeln!(f, "default {{")?;
            write_perm(f, p)?;
            writeln!(f, "}}\n")?;
        }

        for g in &self.groups {
            write_node(f, g)?;
        }
        for t in &self.templates {
            writeln!(f, "template {} {{", token(&t.name)?)?;
            write_node_body(f, t)?;
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Quote a token when bare form would be ambiguous to the parser. `Err` for
/// a value containing a literal `"` — see the module doc comment.
fn token(s: &str) -> Result<String, fmt::Error> {
    if s.contains('"') {
        return Err(fmt::Error);
    }
    let bare_ok = !s.is_empty()
        && s.chars()
            .all(|c| !c.is_whitespace() && !"{};=#".contains(c));
    Ok(if bare_ok {
        s.to_owned()
    } else {
        format!("\"{s}\"")
    })
}

/// A controller block name (`{c} { … }`): must already be a valid bare
/// word — the parser's `ctl_block` has no quoted form to fall back to, so
/// unlike [`token`] there is no way to escape this by quoting.
fn bare_token(s: &str) -> Result<&str, fmt::Error> {
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| !c.is_whitespace() && !"{};=\"#".contains(c));
    if ok {
        Ok(s)
    } else {
        Err(fmt::Error)
    }
}

fn octal(v: u32) -> String {
    format!("{v:o}")
}

fn write_node(f: &mut fmt::Formatter<'_>, n: &Node) -> fmt::Result {
    writeln!(f, "group {} {{", token(&n.name)?)?;
    write_node_body(f, n)?;
    writeln!(f)?;
    Ok(())
}

fn write_node_body(f: &mut fmt::Formatter<'_>, n: &Node) -> fmt::Result {
    if let Some(p) = &n.perm {
        writeln!(f, "\tperm {{")?;
        write_set_block(f, "task", &p.task)?;
        write_set_block(f, "admin", &p.admin)?;
        writeln!(f, "\t}}")?;
    }
    // Attachment markers stay empty: a block carrying values would re-parse
    // as stored state rather than subtree_control intent.
    for c in &n.controllers {
        writeln!(f, "\t{} {{", bare_token(c)?)?;
        writeln!(f, "\t}}")?;
    }
    // Parameter groups by filename-prefix controller.
    let mut done: Vec<&str> = Vec::new();
    for (c, _, _) in &n.params {
        if done.contains(&c.as_str()) {
            continue;
        }
        done.push(c);
        writeln!(f, "\t{} {{", bare_token(c)?)?;
        for (pc, k, v) in &n.params {
            if pc == c {
                writeln!(f, "\t\t{} = {};", token(k)?, token(v)?)?;
            }
        }
        writeln!(f, "\t}}")?;
    }
    writeln!(f, "}}")
}

fn write_perm(f: &mut fmt::Formatter<'_>, p: &Perm) -> fmt::Result {
    writeln!(f, "\tperm {{")?;
    write_set_block(f, "task", &p.task)?;
    write_set_block(f, "admin", &p.admin)?;
    writeln!(f, "\t}}")
}

fn write_set_block(f: &mut fmt::Formatter<'_>, kind: &str, s: &PermSet) -> fmt::Result {
    writeln!(f, "\t\t{kind} {{")?;
    if let Some(uid) = &s.uid {
        writeln!(f, "\t\t\tuid = {};", token(uid)?)?;
    }
    if let Some(gid) = &s.gid {
        writeln!(f, "\t\t\tgid = {};", token(gid)?)?;
    }
    if let Some(d) = s.dperm {
        writeln!(f, "\t\t\tdperm = {};", octal(d))?;
    }
    if let Some(x) = s.fperm {
        writeln!(f, "\t\t\tfperm = {};", octal(x))?;
    }
    writeln!(f, "\t\t}}")
}

#[cfg(test)]
mod tests {

    use crate::model::ConfigFile;
    use std::str::FromStr;

    fn round_trip(text: &str) {
        let cfg = ConfigFile::from_str(text).unwrap();
        let rendered = cfg.to_string();
        let reparsed = ConfigFile::from_str(&rendered).unwrap_or_else(|e| {
            panic!("re-parse failed ({e}):\n--- source ---\n{text}\n--- rendered ---\n{rendered}")
        });
        assert_eq!(cfg, reparsed, "round trip diverged:\n{rendered}");
    }

    #[test]
    fn man_page_examples_round_trip() {
        round_trip(include_str!("../examples/daemons.cgconfig.conf"));
        round_trip(include_str!("../examples/students.cgconfig.conf"));
    }

    #[test]
    fn tricky_values_and_empty_blocks_round_trip() {
        let text = r#"
mount {
	"name=noctrl" = "/mnt/weird path";
}
default {
	perm {
		admin { dperm = 755; }
	}
}
group . {
	cpu {}
}
template students/%u {
	perm {
		task { uid = "%u"; gid = "has space"; fperm = 664; }
		admin { uid = root; dperm = 750; fperm = 640; }
	}
	cpu { cpu.shares = "1000"; }
}
"#;
        round_trip(text);
    }

    #[test]
    fn embedded_quote_in_a_name_refuses_to_render() {
        // Group/template names can come from a live cgroup directory name
        // (cgctl snapshot), which an unprivileged delegatee inside their
        // own subtree fully controls — including a literal `"`. This
        // format has no escape syntax, so emitting it unescaped would let
        // that `"` close the quoted token early and inject arbitrary
        // config structure into everything after it. Display must refuse
        // rather than emit that.
        use crate::model::{ConfigFile, Node};
        use std::fmt::Write as _;
        let cfg = ConfigFile {
            mounts: Vec::new(),
            default_perm: None,
            groups: vec![Node {
                name: "x\" { } group \"users/victim".into(),
                perm: None,
                controllers: Vec::new(),
                params: Vec::new(),
            }],
            templates: Vec::new(),
        };
        let mut out = String::new();
        assert!(write!(out, "{cfg}").is_err());
    }

    #[test]
    fn embedded_quote_in_a_param_key_refuses_to_render() {
        // Same injection on the (controller, key, value) triple: a param
        // key must go through token() so a `"` inside it cannot close a
        // quoted token and inject extra group blocks.
        use crate::model::{ConfigFile, Node};
        use std::fmt::Write as _;
        let cfg = ConfigFile {
            mounts: Vec::new(),
            default_perm: None,
            groups: vec![Node {
                name: "victimless".into(),
                perm: None,
                controllers: Vec::new(),
                params: vec![(
                    "cpu".into(),
                    "x\" } } group \"users/victim".into(),
                    "1".into(),
                )],
            }],
            templates: Vec::new(),
        };
        let mut out = String::new();
        assert!(write!(out, "{cfg}").is_err());
    }

    #[test]
    fn illegal_controller_name_refuses_to_render() {
        // A controller block name has no quoted form in this grammar at
        // all (ctl_block only accepts a bare word) — there is nothing
        // token() could safely quote it into, so it must refuse outright.
        use crate::model::{ConfigFile, Node};
        use std::fmt::Write as _;
        let cfg = ConfigFile {
            mounts: Vec::new(),
            default_perm: None,
            groups: vec![Node {
                name: "g".into(),
                perm: None,
                controllers: vec!["cpu shares".into()],
                params: Vec::new(),
            }],
            templates: Vec::new(),
        };
        let mut out = String::new();
        assert!(write!(out, "{cfg}").is_err());
    }

    #[test]
    fn rendered_output_is_valid_conf_shape() {
        let cfg = ConfigFile::from_str("group a/b { perm { task { uid = x; } } cpu { p = 1; } }\n")
            .unwrap();
        let out = cfg.to_string();
        assert!(out.contains("group a/b {"));
        assert!(out.contains("\tcpu {"));
        assert!(out.ends_with("\n"));
    }
}
