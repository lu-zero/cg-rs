//! winnow parser for libcgroup [`cgconfig.conf(5)`].
//!
//! Sections (`mount`, `group`, `template`, `default`) appear in any order.
//! Comments run from `#` to end of line. Values may be double-quoted
//! (libcgroup itself does not implement quotes; we accept them because the
//! man page examples show `"1000"`).
//!
//! Parsers return [`ModalResult`] so committed branches (`cut_err`) and
//! `.context` labels compose freely.
//!
//! [`cgconfig.conf(5)`]: https://manpages.debian.org/cgconfig.conf.5

use winnow::ascii::{multispace1, till_line_ending};
use winnow::combinator::{alt, cut_err, eof, fail, opt, repeat, terminated};
use winnow::error::StrContext;
use winnow::prelude::*;
use winnow::token::{take_till, take_while};

use crate::model::{ConfigFile, Mount, Node, Perm, PermSet};

/// Parse failure location plus the underlying message.
#[derive(Clone, Debug)]
pub struct CgError {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
    pub msg: String,
}

impl std::fmt::Display for CgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.msg)
    }
}

impl std::error::Error for CgError {}

/// Parse a complete cgconfig.conf document.
pub fn parse_cgconfig(text: &str) -> Result<ConfigFile, CgError> {
    match config_file.parse(text) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            let off = e.offset().min(text.len());
            let head = &text[..off];
            Err(CgError {
                offset: e.offset(),
                line: 1 + head.matches('\n').count(),
                column: head.chars().rev().take_while(|&c| c != '\n').count() + 1,
                msg: e.inner().to_string(),
            })
        }
    }
}

// ---------------------------------------------------------------- primitives

/// Whitespace and comments.
fn ws(input: &mut &str) -> ModalResult<()> {
    repeat(
        0..,
        alt((multispace1.void(), ('#', till_line_ending).void())),
    )
    .parse_next(input)
}

/// Bare word: anything but whitespace and structural punctuation.
fn bare(input: &mut &str) -> ModalResult<String> {
    take_while(1.., |c: char| !c.is_whitespace() && !"{};=\"".contains(c))
        .map(str::to_owned)
        .parse_next(input)
}

/// Double-quoted string (no escapes in this format).
fn quoted(input: &mut &str) -> ModalResult<String> {
    ('"', take_till(0.., '"'), '"')
        .map(|(_, s, _): (char, &str, char)| s.to_owned())
        .parse_next(input)
}

/// Token: quoted string or bare word.
fn tok(input: &mut &str) -> ModalResult<String> {
    alt((quoted, bare)).parse_next(input)
}

fn open_brace(input: &mut &str) -> ModalResult<()> {
    ('{', ws)
        .void()
        .context(StrContext::Expected('{'.into()))
        .parse_next(input)
}

fn close_brace(input: &mut &str) -> ModalResult<()> {
    ('}', ws)
        .void()
        .context(StrContext::Expected('}'.into()))
        .parse_next(input)
}

/// `key = value ;`. Once the key is seen the rest is committed (`cut_err`),
/// so garbage inside a block reports at the offending token. Keys may be
/// quoted (`"name=noctrl" = /mnt/…;`).
fn assign(input: &mut &str) -> ModalResult<(String, String)> {
    let key = tok.context(StrContext::Label("key")).parse_next(input)?;
    let (_, _, _, value, _): ((), char, (), String, char) = cut_err((ws, '=', ws, tok, ';'))
        .context(StrContext::Label("`key = value;` entry"))
        .parse_next(input)?;
    Ok((key, value))
}

// ------------------------------------------------------------------ sections

enum Body {
    Perm(Perm),
    Ctl(String, Vec<NodeParam>),
}

/// `(controller, param, value)` triple as stored on [`crate::model::Node`].
pub type NodeParam = (String, String, String);

fn config_file(input: &mut &str) -> ModalResult<ConfigFile> {
    let mut cfg = ConfigFile::default();
    ws(input)?;
    while !input.is_empty() {
        section(input, &mut cfg)?;
        ws(input)?;
    }
    eof.parse_next(input)?;
    Ok(cfg)
}

fn section(input: &mut &str, cfg: &mut ConfigFile) -> ModalResult<()> {
    let kw = bare
        .context(StrContext::Label("section"))
        .parse_next(input)?;
    ws(input)?;
    match kw.as_str() {
        "mount" => mount_section(input, cfg),
        "group" => node_body(input).map(|n| {
            cfg.groups.push(n);
        }),
        "template" => node_body(input).map(|n| {
            cfg.templates.push(n);
        }),
        "default" => default_section(input, cfg),
        _ => fail
            .context(StrContext::Label("section"))
            .context(StrContext::Expected("`mount`".into()))
            .context(StrContext::Expected("`group`".into()))
            .context(StrContext::Expected("`template`".into()))
            .context(StrContext::Expected("`default`".into()))
            .parse_next(input),
    }
}

fn mount_section(input: &mut &str, cfg: &mut ConfigFile) -> ModalResult<()> {
    open_brace(input)?;
    let mounts: Vec<Mount> = repeat(0.., terminated(mount_entry, ws)).parse_next(input)?;
    close_brace(input)?;
    cfg.mounts.extend(mounts);
    Ok(())
}

fn mount_entry(input: &mut &str) -> ModalResult<Mount> {
    assign
        .map(|(controller, path)| Mount { controller, path })
        .parse_next(input)
}

fn node_body(input: &mut &str) -> ModalResult<Node> {
    let name = tok(input)?;
    ws(input)?;
    let items: Vec<Body> = cut_err((
        open_brace,
        repeat(0.., terminated(body_item, ws)),
        close_brace,
    ))
    .map(|(_, v, ())| v)
    .context(StrContext::Label("group body"))
    .parse_next(input)?;

    let mut node = Node {
        name,
        ..Default::default()
    };
    for item in items {
        match item {
            Body::Perm(p) => merge_perm(&mut node.perm, p),
            Body::Ctl(c, params) => {
                if !node.controllers.contains(&c) {
                    node.controllers.push(c.clone());
                }
                node.params.extend(params);
            }
        }
    }
    Ok(node)
}

fn body_item(input: &mut &str) -> ModalResult<Body> {
    alt((
        perm_block.map(Body::Perm),
        ctl_block.map(|(c, ps)| Body::Ctl(c, ps)),
    ))
    .context(StrContext::Label("`perm` or controller block"))
    .parse_next(input)
}

fn merge_perm(slot: &mut Option<Perm>, add: Perm) {
    match slot {
        // Later blocks override individual fields they restate.
        Some(p) => p.merge(add),
        None => *slot = Some(add),
    }
}

type OwnerSets = Vec<(bool, PermSet)>;

fn perm_block(input: &mut &str) -> ModalResult<Perm> {
    (
        (bare.verify(|s: &str| s == "perm"), ws),
        open_brace,
        repeat(0.., terminated(owner_block, ws)),
        close_brace,
    )
        .map(|((_, _), _, sets, _): ((String, ()), (), OwnerSets, ())| {
            let mut perm = Perm::default();
            for (is_task, set) in sets {
                if is_task {
                    perm.task.merge(set);
                } else {
                    perm.admin.merge(set);
                }
            }
            perm
        })
        .context(StrContext::Label("`perm` block"))
        .parse_next(input)
}

/// One `task { … }` or `admin { … }` sub-block. Returns `(is_task, set)`.
fn owner_block(input: &mut &str) -> ModalResult<(bool, PermSet)> {
    let kw = bare.parse_next(input)?;
    ws(input)?;
    let is_task = if kw == "task" {
        true
    } else if kw == "admin" {
        false
    } else {
        return fail
            .context(StrContext::Expected("`task`".into()))
            .context(StrContext::Expected("`admin`".into()))
            .parse_next(input);
    };
    let assigns: Vec<(String, String)> =
        cut_err((open_brace, repeat(0.., terminated(assign, ws)), close_brace))
            .map(|(_, v, ())| v)
            .parse_next(input)?;

    let mut set = PermSet::default();
    for (k, v) in assigns {
        match k.as_str() {
            "uid" => set.uid = Some(v),
            "gid" => set.gid = Some(v),
            "dperm" => set.dperm = octal(&v),
            "fperm" => set.fperm = octal(&v),
            _ => {} // libcgroup ignores unknown keys
        }
    }
    Ok((is_task, set))
}

fn ctl_block(input: &mut &str) -> ModalResult<(String, Vec<NodeParam>)> {
    let name = bare(input)?;
    ws(input)?;
    let params: Vec<(String, String)> =
        cut_err((open_brace, repeat(0.., terminated(assign, ws)), close_brace))
            .map(|(_, v, ())| v)
            .context(StrContext::Label("controller block"))
            .parse_next(input)?;
    Ok((
        name.clone(),
        params
            .into_iter()
            .map(|(k, v)| (name.clone(), k, v))
            .collect(),
    ))
}

fn default_section(input: &mut &str, cfg: &mut ConfigFile) -> ModalResult<()> {
    open_brace(input)?;
    cfg.default_perm = opt(terminated(perm_block, ws)).parse_next(input)?;
    close_brace(input)
}

/// `770` / `0770` style octal mode.
fn octal(s: &str) -> Option<u32> {
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        Some(0)
    } else {
        u32::from_str_radix(t, 8).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_man_page_example_2() {
        let cfg = parse_cgconfig(include_str!("../examples/daemons.cgconfig.conf")).unwrap();
        assert_eq!(cfg.mounts.len(), 3);
        assert_eq!(
            cfg.mounts[0],
            Mount {
                controller: "cpu".into(),
                path: "/mnt/cgroups/cpu".into(),
            }
        );
        assert_eq!(
            cfg.mounts[2].controller, "name=noctrl",
            "quoted pseudo-controller"
        );

        let www = cfg.find_group("daemons/www").unwrap();
        let perm = cfg.effective_perm(www);
        assert_eq!(perm.admin.dperm, Some(0o775));
        assert_eq!(perm.admin.fperm, Some(0o744));
        assert_eq!(perm.task.uid.as_deref(), Some("root"));
        assert_eq!(perm.task.gid.as_deref(), Some("webmaster"));
        assert_eq!(perm.task.fperm, Some(0o770));
        assert_eq!(
            www.params,
            vec![("cpu".to_owned(), "cpu.shares".to_owned(), "1000".to_owned())]
        );

        let ftp = cfg.find_group("daemons/ftp").unwrap();
        assert_eq!(cfg.effective_perm(ftp).admin.dperm, Some(0o755));
    }

    #[test]
    fn parses_templates_and_root_group() {
        let cfg = parse_cgconfig(include_str!("../examples/students.cgconfig.conf")).unwrap();
        assert_eq!(cfg.groups.len(), 2, "students plus root");
        assert_eq!(cfg.templates.len(), 1);

        let tpl = cfg.find_template("students/%u").unwrap();
        let perm = cfg.effective_perm(tpl);
        assert_eq!(perm.task.uid.as_deref(), Some("%u"));
        assert_eq!(perm.task.fperm, Some(0o775));
        assert_eq!(perm.admin.dperm, Some(0o750));

        let students = cfg.find_group("students").unwrap();
        assert_eq!(
            students.controllers,
            vec!["cpuacct".to_owned(), "cpu".to_owned()],
            "empty blocks still register their controller"
        );
    }

    #[test]
    fn sections_in_any_order_and_comments_anywhere() {
        let text = "# leading comment\n\ngroup g {\n# why here\n cpu {}\n}\nmount {\ncpu=/x;\n}\n";
        let cfg = parse_cgconfig(text).unwrap();
        assert_eq!(cfg.find_group("g").unwrap().name, "g");
        assert_eq!(cfg.mounts[0].path, "/x");
    }

    #[test]
    fn default_section_perm() {
        let text = "default { perm { task { uid = nobody; gid = nobody; fperm = 660; } } }\ngroup a { cpu {} }";
        let cfg = parse_cgconfig(text).unwrap();
        let dp = cfg.default_perm.as_ref().unwrap();
        assert_eq!(dp.task.uid.as_deref(), Some("nobody"));
        assert_eq!(dp.task.fperm, Some(0o660));

        let a = cfg.find_group("a").unwrap();
        assert_eq!(cfg.effective_perm(a).task.uid.as_deref(), Some("nobody"));
    }

    #[test]
    fn rejects_garbage_with_position() {
        let e = parse_cgconfig("group x { cpu { a = ; } }").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.column >= 16, "points at the bad token: {e}");
        assert!(e.msg.contains("entry"), "unexpected: {e}");
    }

    #[test]
    fn empty_document_ok() {
        assert_eq!(parse_cgconfig("").unwrap(), ConfigFile::default());
        assert_eq!(
            parse_cgconfig("# only a comment\n").unwrap(),
            ConfigFile::default()
        );
    }

    #[test]
    fn unknown_section_reports_line() {
        let e = parse_cgconfig("# c\n\nmount {}\nbogus {}\n").unwrap_err();
        assert_eq!(e.line, 4, "{e}");
        assert!(e.msg.contains("`mount`"), "{e}");
    }
}
