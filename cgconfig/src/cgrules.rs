//! Parser for libcgroup [`cgrules.conf(5)`].
//!
//! Rules are strictly line-oriented
//! (`<user>[:<process>] <controllers> <destination> [options…]`), so this
//! module splits lines/tokens and validates them instead of building a full
//! stream parser like [`crate::cgconfig`]. `%` (ditto) inherits the subject of
//! the previous rule and is resolved here, matching libcgroup semantics.
//!
//! [`cgrules.conf(5)`]: https://manpages.debian.org/cgrules.conf.5

use winnow::combinator::{alt, repeat};
use winnow::prelude::*;
use winnow::token::{one_of, take_while};

use crate::model::{Controllers, Rule, Subject, Template};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrError {
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for CrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.line, self.msg)
    }
}

impl std::error::Error for CrError {}

/// Parse a complete cgrules.conf document.
pub fn parse_cgrules(text: &str) -> Result<Vec<Rule>, CrError> {
    let mut rules: Vec<Rule> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line_no = n + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 3 {
            return Err(CrError {
                line: line_no,
                msg: format!("need at least 3 fields, got {}", toks.len()),
            });
        }

        let (subject_tok, process) = match toks[0].split_once(':') {
            Some((u, p)) => (u, Some(p.to_owned())),
            None => (toks[0], None),
        };

        let subject = if subject_tok == "%" {
            match rules.last() {
                Some(prev) => prev.subject.clone(),
                None => {
                    return Err(CrError {
                        line: line_no,
                        msg: "`%` ditto on the first rule has nothing to repeat".into(),
                    })
                }
            }
        } else {
            parse_subject(subject_tok)
        };

        let controllers = if toks[1] == "*" {
            Controllers::All
        } else {
            let list: Vec<String> = toks[1].split(',').map(str::to_owned).collect();
            if list.iter().any(String::is_empty) {
                return Err(CrError {
                    line: line_no,
                    msg: format!("bad controller list {:?}", toks[1]),
                });
            }
            Controllers::List(list)
        };

        rules.push(Rule {
            subject,
            process,
            controllers,
            destination: Template(dest_token.parse(toks[2]).map_err(|_| CrError {
                line: line_no,
                msg: format!("bad destination {:?}", toks[2]),
            })?),
            options: toks[3..].iter().map(|s| unescape(s)).collect(),
        });
    }
    Ok(rules)
}

/// `user` | `@group` | `*`
fn parse_subject(s: &str) -> Subject {
    match s {
        "*" => Subject::Any,
        _ if s.starts_with('@') => Subject::Group(s[1..].to_owned()),
        _ => Subject::User(s.to_owned()),
    }
}

/// One destination/options token: `\%` becomes literal `%`,
/// `%u`-style placeholders are kept verbatim.
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
        let rules = parse_cgrules(include_str!("../examples/cgrules.conf")).expect("valid rules");
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
        let rules = parse_cgrules(include_str!("../examples/cgrules.conf")).unwrap();
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
        let rules = parse_cgrules("u * dir/100\\%done").unwrap();
        assert_eq!(rules[0].destination.0, "dir/100%done");
        assert_eq!(rules[0].destination.vars().count(), 0);
    }

    #[test]
    fn ditto_on_first_line_rejected() {
        let e = parse_cgrules("% * x/").unwrap_err();
        assert_eq!(e.line, 1);
    }

    #[test]
    fn short_rule_rejected() {
        let e = parse_cgrules("# ok comment\n\nonly two\n").unwrap_err();
        assert_eq!(e.line, 3);
    }

    #[test]
    fn comments_and_blanks_skipped() {
        assert!(parse_cgrules("").unwrap().is_empty());
        assert!(parse_cgrules("# a\n   \n\t#b\nc * d/\n").unwrap().len() == 1);
    }
}
