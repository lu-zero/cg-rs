//! Serialize [`ConfigFile`] back to cgconfig.conf syntax.
//!
//! Round-trip guarantee: parsing the output of `Display` yields an equal
//! [`ConfigFile`]. Tokens that would not survive bare (whitespace,
//! structural punctuation) are double-quoted, mirroring the parser's
//! optional-quote support.

use std::fmt;

use crate::model::{ConfigFile, Mount, Node, Perm, PermSet};

impl fmt::Display for ConfigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.mounts.is_empty() {
            writeln!(f, "mount {{")?;
            for m in &self.mounts {
                writeln!(f, "\t{} = {};", token(&m.controller), token(&m.path))?;
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
            writeln!(f, "template {} {{", token(&t.name))?;
            write_node_body(f, t)?;
            writeln!(f)?;
        }
        Ok(())
    }
}

/// Quote a token when bare form would be ambiguous to the parser.
fn token(s: &str) -> String {
    let bare_ok = !s.is_empty()
        && s.chars()
            .all(|c| !c.is_whitespace() && !"{};=\"#".contains(c));
    if bare_ok {
        s.to_owned()
    } else {
        format!("\"{s}\"")
    }
}

fn octal(v: u32) -> String {
    format!("{v:o}")
}

fn write_node(f: &mut fmt::Formatter<'_>, n: &Node) -> fmt::Result {
    writeln!(f, "group {} {{", token(&n.name))?;
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
    // Controller blocks in declaration order; controllers recorded without
    // params (empty blocks) come out as empty blocks too.
    let mut done: Vec<&str> = Vec::new();
    for c in &n.controllers {
        done.push(c);
        writeln!(f, "\t{c} {{")?;
        for (pc, k, v) in &n.params {
            if pc == c {
                writeln!(f, "\t\t{k} = {};", token(v))?;
            }
        }
        writeln!(f, "\t}}")?;
    }
    // Param triples whose controller never got a block (defensive; the
    // parser cannot produce this today).
    for (c, k, v) in &n.params {
        if !done.contains(&c.as_str()) {
            done.push(c);
            writeln!(f, "\t{c} {{")?;
            writeln!(f, "\t\t{k} = {};", token(v))?;
            writeln!(f, "\t}}")?;
        }
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
        writeln!(f, "\t\t\tuid = {};", token(uid))?;
    }
    if let Some(gid) = &s.gid {
        writeln!(f, "\t\t\tgid = {};", token(gid))?;
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
    use super::*;
    use crate::parse_cgconfig;

    fn round_trip(text: &str) {
        let cfg = parse_cgconfig(text).unwrap();
        let rendered = cfg.to_string();
        let reparsed = parse_cgconfig(&rendered).unwrap_or_else(|e| {
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
    fn rendered_output_is_valid_conf_shape() {
        let cfg =
            parse_cgconfig("group a/b { perm { task { uid = x; } } cpu { p = 1; } }\n").unwrap();
        let out = cfg.to_string();
        assert!(out.contains("group a/b {"));
        assert!(out.contains("\tcpu {"));
        assert!(out.ends_with("\n"));
    }
}
