//! Parser for libcgroup [`cgrules.conf(5)`].
//!
//! Rules are strictly line-oriented
//! (`<user>[:<process>] <controllers> <destination> [options…]`), so this
//! module splits lines/tokens and validates them instead of building a full
//! stream parser like [`crate::cgconfig`]. `%` (ditto) inherits the subject of
//! the previous rule and is resolved here, matching libcgroup semantics.
//!
//! [`cgrules.conf(5)`]: https://manpages.debian.org/cgrules.conf.5

use std::fs;
use std::iter::FromIterator;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;

use winnow::combinator::{alt, repeat, terminated};
use winnow::prelude::*;
use winnow::token::{one_of, take_while};

use crate::error::FileError;
use crate::model::{Controllers, Rule, Subject, Template};

/// Rule failure with byte span, position, and (through
/// [`Rules::from_path`]) the named source for [miette] rendering.
///
/// [miette]: https://docs.rs/miette
#[derive(Clone, Debug)]
pub struct CrError {
    pub line: usize,
    pub column: usize,
    /// Byte span of the offending rule line, trimmed.
    pub offset: usize,
    pub end: usize,
    pub msg: String,
    /// Boxed to keep `Result<_, CrError>` small.
    source: Box<miette::NamedSource<String>>,
}

impl std::fmt::Display for CrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.msg)
    }
}

impl std::error::Error for CrError {}

impl miette::Diagnostic for CrError {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new("cgconfig::rules"))
    }

    fn severity(&self) -> Option<miette::Severity> {
        Some(miette::Severity::Error)
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        Some(self.source.as_ref() as &dyn miette::SourceCode)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        let label = self.msg.lines().next().unwrap_or("invalid rule");
        Some(Box::new(
            [miette::LabeledSpan::at(self.offset..self.end, label)].into_iter(),
        ))
    }
}

/// An ordered collection of parsed `cgrules.conf` rules.
///
/// The wrapper gives the rules document a local type on which [`FromStr`] can
/// be implemented, while dereferencing to a slice keeps rule matching and
/// iteration convenient.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    /// Construct a rule collection from its owned rules.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Borrow the rules as a slice.
    pub fn as_slice(&self) -> &[Rule] {
        &self.rules
    }

    /// Consume the collection and return its owned rules.
    pub fn into_vec(self) -> Vec<Rule> {
        self.rules
    }

    /// Read and parse a cgrules.conf file, retaining its path in diagnostics.
    ///
    /// Read failures are returned as [`FileError::Read`], and syntax failures
    /// as [`FileError::Parse`].
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, FileError<CrError>> {
        let path = path.as_ref().to_path_buf();
        let text = fs::read_to_string(&path).map_err(|source| FileError::Read {
            path: path.clone(),
            source,
        })?;
        Self::from_source(miette::NamedSource::new(path.display().to_string(), text))
            .map_err(|source| FileError::Parse { path, source })
    }

    fn from_source(source: miette::NamedSource<String>) -> Result<Self, CrError> {
        let text = source.inner().as_str();
        let mut rules: Vec<Rule> = Vec::new();
        let mut byte_offset = 0usize;
        for (n, raw) in text.split_inclusive('\n').enumerate() {
            let line_no = n + 1;
            let line_start = byte_offset;
            byte_offset += raw.len();

            let indent = raw.len() - raw.trim_start().len();
            let content_start = line_start + indent;
            let content = raw.trim();
            if content.is_empty() || content.starts_with('#') {
                continue;
            }
            // Span of the trimmed rule text, for error labels.
            let (span_start, span_end) = (content_start, content_start + content.trim_end().len());
            let err = |msg: String| {
                let head = &text[..span_start];
                CrError {
                    line: line_no,
                    column: head.chars().rev().take_while(|&c| c != '\n').count() + 1,
                    offset: span_start,
                    end: span_end,
                    msg,
                    source: Box::new(source.clone()),
                }
            };

            let toks = match rule_fields(content) {
                Ok(t) => t,
                Err(msg) => return Err(err(msg)),
            };
            if toks.len() < 3 {
                return Err(err(format!("need at least 3 fields, got {}", toks.len())));
            }

            let (subject_tok, process) = match toks[0].split_once(':') {
                Some((u, p)) => (u.to_owned(), Some(unquote(p))),
                None => (toks[0].clone(), None),
            };

            let subject = if subject_tok == "%" {
                match rules.last() {
                    Some(prev) => prev.subject.clone(),
                    None => {
                        return Err(err(
                            "`%` ditto on the first rule has nothing to repeat".into()
                        ))
                    }
                }
            } else {
                parse_subject(&subject_tok)
            };

            let controllers = if toks[1] == "*" {
                Controllers::All
            } else {
                let list: Vec<String> = toks[1].split(',').map(str::to_owned).collect();
                if list.iter().any(String::is_empty) {
                    return Err(err(format!("bad controller list {:?}", toks[1])));
                }
                Controllers::List(list)
            };

            let dest_tok = &toks[2];
            let dest = terminated(dest_token, winnow::combinator::eof)
                .parse(dest_tok.as_str())
                .map_err(|_| err(format!("bad destination {dest_tok:?}")))?;
            if dest.contains('\\') {
                return Err(err(format!("bad destination {dest_tok:?}")));
            }
            rules.push(Rule {
                subject,
                process,
                controllers,
                destination: Template(dest),
                options: toks[3..].iter().map(|s| unescape(s)).collect(),
            });
        }
        Ok(Self { rules })
    }
}

impl FromStr for Rules {
    type Err = CrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_source(miette::NamedSource::new("cgrules.conf", text.to_owned()))
    }
}

impl Deref for Rules {
    type Target = [Rule];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[Rule]> for Rules {
    fn as_ref(&self) -> &[Rule] {
        self.as_slice()
    }
}

impl From<Vec<Rule>> for Rules {
    fn from(rules: Vec<Rule>) -> Self {
        Self::new(rules)
    }
}

impl FromIterator<Rule> for Rules {
    fn from_iter<T: IntoIterator<Item = Rule>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl Extend<Rule> for Rules {
    fn extend<T: IntoIterator<Item = Rule>>(&mut self, iter: T) {
        self.rules.extend(iter);
    }
}

impl IntoIterator for Rules {
    type Item = Rule;
    type IntoIter = std::vec::IntoIter<Rule>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.into_iter()
    }
}

impl<'a> IntoIterator for &'a Rules {
    type Item = &'a Rule;
    type IntoIter = std::slice::Iter<'a, Rule>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.iter()
    }
}

/// `user` | `@group` | `*`
fn parse_subject(s: &str) -> Subject {
    match s {
        "*" => Subject::Any,
        _ if s.starts_with('@') => Subject::Group(s[1..].to_owned()),
        _ => Subject::User(s.to_owned()),
    }
}

/// Whitespace-separated fields that keep quoted spans (including spaces)
/// as one field. `#` starts a comment only outside quotes.
fn rule_fields(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut s = line;
    loop {
        s = s.trim_start_matches([' ', '\t']);
        if s.is_empty() || s.starts_with('#') {
            break;
        }
        let (field, rest) = next_field(s)?;
        out.push(field);
        s = rest;
    }
    Ok(out)
}

fn next_field(s: &str) -> Result<(String, &str), String> {
    if let Some(inner) = s.strip_prefix('"') {
        let end = inner
            .find('"')
            .ok_or_else(|| "unterminated quote".to_string())?;
        return Ok((inner[..end].to_owned(), &inner[end + 1..]));
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'#' => break,
            b'"' => {
                let rel = s[i + 1..]
                    .find('"')
                    .ok_or_else(|| "unterminated quote".to_string())?;
                i += 2 + rel;
            }
            _ => i += 1,
        }
    }
    Ok((s[..i].to_owned(), &s[i..]))
}

fn unquote(s: &str) -> String {
    s.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(s)
        .to_owned()
}

/// One destination/options token: `\%` becomes literal `%`,
/// `%u`-style placeholders are kept verbatim. Lone `\` is rejected by
/// requiring `eof` at call site.
fn dest_token(input: &mut &str) -> ModalResult<String> {
    repeat(
        0..,
        alt((
            ('\\', one_of('%')).map(|_| "%".to_owned()),
            take_while(1.., |c: char| c != '\\').map(str::to_owned),
        )),
    )
    .map(|pieces: Vec<String>| pieces.concat())
    .parse_next(input)
}

/// Convenience wrapper for non-destination tokens (`nore` etc.).
fn unescape(s: &str) -> String {
    dest_token.parse(s).unwrap_or_else(|_| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{first_rule, Subject};

    #[test]
    fn parses_man_page_examples() {
        let rules = Rules::from_str(include_str!("../examples/cgrules.conf")).expect("valid rules");
        assert_eq!(rules.len(), 7);

        assert_eq!(
            first_rule(&rules, "student", &[], None)
                .unwrap()
                .destination
                .0,
            "/usergroup/students"
        );
        assert_eq!(
            first_rule(&rules, "student", &[], Some("cp"))
                .unwrap()
                .destination
                .0,
            "/usergroup/students/cp"
        );

        // @admin group membership, all controllers.
        let r = first_rule(&rules, "bob", &["admin".to_owned()], None).unwrap();
        assert_eq!(r.destination.0, "admingroup/");
        assert_eq!(r.controllers, Controllers::All);
        // No @group match for bob, but the catch-all still applies.
        assert_eq!(
            first_rule(&rules, "bob", &[], None).unwrap().destination.0,
            "default/"
        );

        // Ditto inherits peter from the previous line.
        let cpu_r = first_rule(&rules, "peter", &[], None).unwrap();
        assert_eq!(cpu_r.destination.0, "test1/");
        let mem_r = rules
            .iter()
            .find(|r| r.controllers == Controllers::List(vec!["memory".to_owned()]))
            .unwrap();
        assert_eq!(mem_r.subject, Subject::User("peter".into()));

        // Catch-all.
        let any = first_rule(&rules, "whoever", &[], Some("vim")).unwrap();
        assert_eq!(any.destination.0, "default/");
    }

    #[test]
    fn process_and_options_and_escape() {
        let rules = Rules::from_str(include_str!("../examples/cgrules.conf")).unwrap();
        let last = rules.last().unwrap();
        assert_eq!(last.subject, Subject::Any);
        assert_eq!(last.process.as_deref(), Some("*"));
        assert_eq!(last.options, vec![String::from("nore")]);
        assert!(last.destination.vars().next().is_some(), "has %U/%P");
        let id = crate::model::Identity {
            uid: "1000".into(),
            pid: "4242".into(),
            ..Default::default()
        };
        assert_eq!(id.expand(&last.destination), "jobs/1000-4242");
    }

    #[test]
    fn escaped_percent_is_literal() {
        let rules = Rules::from_str("u * dir/100\\%done").unwrap();
        assert_eq!(rules[0].destination.0, "dir/100%done");
        assert_eq!(rules[0].destination.vars().count(), 0);
    }

    #[test]
    fn ditto_on_first_line_rejected() {
        let e = Rules::from_str("% * x/").unwrap_err();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn short_rule_rejected() {
        let e = Rules::from_str("# ok comment\n\nonly two\n").unwrap_err();
        assert_eq!(e.line, 3);
    }

    #[test]
    fn comments_and_blanks_skipped() {
        assert!(Rules::from_str("").unwrap().is_empty());
        assert!(Rules::from_str("# a\n   \n\t#b\nc * d/\n").unwrap().len() == 1);
    }

    #[test]
    fn quoted_fields_with_spaces() {
        let rules =
            Rules::from_str(r#"@students:"Web Browser" cpu "/usergroup/students/Internet Apps""#)
                .unwrap();
        assert_eq!(rules[0].subject, Subject::Group("students".into()));
        assert_eq!(rules[0].process.as_deref(), Some("Web Browser"));
        assert_eq!(rules[0].destination.0, "/usergroup/students/Internet Apps");
    }

    #[test]
    fn ignore_options_parse() {
        let rules = Rules::from_str("root:sshd * * ignore").unwrap();
        assert!(rules[0].ignores());
        let rules = Rules::from_str("*:irqbalance * * ignore_rt").unwrap();
        assert!(rules[0].ignores_rt());
        assert!(!rules[0].ignores());
    }
}
