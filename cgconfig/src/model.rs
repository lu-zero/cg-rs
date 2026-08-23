//! Data model shared by both parsers, plus `%`-placeholder expansion.
//!
//! The crate is deliberately libc-free: user/group resolution stays with the
//! consumer (see [`Identity`]), so this parses and expands but never calls
//! NSS.

use std::fmt;

/// A string containing libcgroup placeholders: `%u` `%U` `%g` `%G` `%p` `%P`.
/// `\%` escapes a literal percent sign.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Template(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Var {
    /// `%u` — user name, uid if name resolution fails.
    User,
    /// `%U` — uid.
    Uid,
    /// `%g` — group name, gid if name resolution fails.
    Group,
    /// `%G` — gid.
    Gid,
    /// `%p` — process name, pid if not available.
    ProcName,
    /// `%P` — pid.
    Pid,
}

impl Var {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'u' => Some(Self::User),
            'U' => Some(Self::Uid),
            'g' => Some(Self::Group),
            'G' => Some(Self::Gid),
            'p' => Some(Self::ProcName),
            'P' => Some(Self::Pid),
            _ => None,
        }
    }
}

impl fmt::Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            Self::User => 'u',
            Self::Uid => 'U',
            Self::Group => 'g',
            Self::Gid => 'G',
            Self::ProcName => 'p',
            Self::Pid => 'P',
        };
        write!(f, "%{c}")
    }
}

impl Template {
    /// Unescaped placeholders in document order.
    pub fn vars(&self) -> impl Iterator<Item = Var> + '_ {
        let s = self.0.as_bytes();
        let mut i = 0;
        std::iter::from_fn(move || {
            while i + 1 < s.len() {
                if s[i] == b'\\' && s[i + 1] == b'%' {
                    i += 2;
                    continue;
                }
                if s[i] == b'%' {
                    if let Some(v) = Var::from_char(s[i + 1] as char) {
                        i += 2;
                        return Some(v);
                    }
                }
                i += 1;
            }
            None
        })
    }

    /// Expand placeholders. `resolve` returning `None` leaves the placeholder
    /// verbatim (libcgroup falls back `%u`→`%U`; callers can do the same).
    pub fn expand<R: Resolve>(&self, resolve: &R) -> String {
        let b = self.0.as_bytes();
        let mut out = String::with_capacity(self.0.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() && b[i + 1] == b'%' {
                out.push('%');
                i += 2;
                continue;
            }
            if b[i] == b'%' && i + 1 < b.len() {
                if let Some(v) = Var::from_char(b[i + 1] as char) {
                    match resolve.resolve(v) {
                        Some(s) => out.push_str(&s),
                        None => out.push_str(&self.0[i..i + 2]),
                    }
                    i += 2;
                    continue;
                }
            }
            // Input is UTF-8, byte-indexed scanning keeps multi-byte chars intact.
            let step = utf8_step(&b[i..]);
            out.push_str(std::str::from_utf8(&b[i..i + step]).unwrap_or("\u{FFFD}"));
            i += step;
        }
        out
    }
}

fn utf8_step(b: &[u8]) -> usize {
    match b[0] {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2.min(b.len()),
        0xE0..=0xEF => 3.min(b.len()),
        _ => 4.min(b.len()),
    }
}

/// Resolved identity of a subject, supplied by the caller (passwd/group lookups).
#[derive(Clone, Debug, Default)]
pub struct Identity {
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub group: String,
    pub proc_name: String,
    pub pid: String,
}

impl Identity {
    pub fn expand(&self, t: &Template) -> String {
        t.expand(self)
    }
}

/// Anything that can answer placeholder lookups: [`Identity`] or a closure.
pub trait Resolve {
    fn resolve(&self, v: Var) -> Option<String>;
}

impl Resolve for Identity {
    fn resolve(&self, v: Var) -> Option<String> {
        let s = match v {
            Var::User => &self.name,
            Var::Uid => &self.uid,
            Var::Group => &self.group,
            Var::Gid => &self.gid,
            Var::ProcName => &self.proc_name,
            Var::Pid => &self.pid,
        };
        (!s.is_empty()).then(|| s.to_owned())
    }
}

impl<F> Resolve for F
where
    F: Fn(Var) -> Option<String>,
{
    fn resolve(&self, v: Var) -> Option<String> {
        self(v)
    }
}

/// One `mount { ... }` entry. `controller` keeps the raw left-hand side:
/// a bare name (`cpu`), a comma list with mount options
/// (`"cpu,nodev,nosuid,noexec"`), or a `name=…` pseudo-controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub controller: String,
    pub path: String,
}

/// uid/gid owner set of one `task`/`admin` block. `dperm`/`fperm` are octal
/// modes as written (e.g. `0o775`). Missing keys are `None` (libcgroup
/// defaults to `root:root` and kernel defaults).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermSet {
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub dperm: Option<u32>,
    pub fperm: Option<u32>,
}

impl PermSet {
    /// Restated fields override, absent fields keep the base value.
    pub fn merge(&mut self, add: PermSet) {
        if add.uid.is_some() {
            self.uid = add.uid;
        }
        if add.gid.is_some() {
            self.gid = add.gid;
        }
        if add.dperm.is_some() {
            self.dperm = add.dperm;
        }
        if add.fperm.is_some() {
            self.fperm = add.fperm;
        }
    }
}

/// The `perm { task {} admin {} }` section of a group/template/default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Perm {
    pub task: PermSet,
    pub admin: PermSet,
}

impl Perm {
    /// Restated fields override, absent fields keep the base value.
    pub fn merge(&mut self, add: Perm) {
        self.task.merge(add.task);
        self.admin.merge(add.admin);
    }
}

/// One `group <name>` / `template <name>` definition. Template names carry
/// `%` placeholders; group names may be `.` (the root cgroup) or contain `/`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub perm: Option<Perm>,
    /// Controllers named by any block on this node, file order, deduped.
    /// Empty blocks (`cpu {}`) count: under v2 they still mean
    /// `cgroup.subtree_control`.
    pub controllers: Vec<String>,
    /// `(controller, param, value)` triples from controller blocks, in file
    /// order.
    pub params: Vec<(String, String, String)>,
}

/// Parsed cgconfig.conf: sections in file order collapsed into typed fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigFile {
    pub mounts: Vec<Mount>,
    /// `default { perm { … } }` — applies to groups without their own perm
    /// (never to templates).
    pub default_perm: Option<Perm>,
    pub groups: Vec<Node>,
    pub templates: Vec<Node>,
}

impl ConfigFile {
    pub fn find_group(&self, name: &str) -> Option<&Node> {
        self.groups.iter().find(|g| g.name == name)
    }

    pub fn find_template(&self, name: &str) -> Option<&Node> {
        self.templates.iter().find(|g| g.name == name)
    }

    /// Effective perm of a group: its own, else [`ConfigFile::default_perm`],
    /// else none.
    pub fn effective_perm(&self, node: &Node) -> Perm {
        node.perm
            .clone()
            .or_else(|| self.default_perm.clone())
            .unwrap_or_default()
    }
}

/// Subject field of a cgrules.conf rule. `%` (ditto) is resolved at parse time
/// and never appears in parsed rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    User(String),
    /// `@group`
    Group(String),
    /// `*`
    Any,
}

/// Controllers field: `*` or a comma-separated list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Controllers {
    All,
    List(Vec<String>),
}

/// One cgrules.conf line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub subject: Subject,
    /// `<user>:<process name>` form.
    pub process: Option<String>,
    pub controllers: Controllers,
    /// Destination path relative to the hierarchy, placeholders intact.
    pub destination: Template,
    /// Optional trailing options tokens (e.g. `nore`).
    pub options: Vec<String>,
}

impl Rule {
    /// libcgroup first-match semantics over user name, supplementary groups
    /// and process name (`None` matches rules without a `:process` part).
    pub fn matches(&self, user: &str, user_groups: &[String], process: Option<&str>) -> bool {
        let subject_ok = match &self.subject {
            Subject::Any => true,
            Subject::User(u) => u == user,
            Subject::Group(g) => user_groups.iter().any(|ug| ug == g),
        };
        if !subject_ok {
            return false;
        }
        match (&self.process, process) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(rp), Some(p)) => rp == p || p.ends_with(rp),
        }
    }

    pub fn matches_controllers(&self, controller: &str) -> bool {
        match &self.controllers {
            Controllers::All => true,
            Controllers::List(l) => l.iter().any(|c| c == controller),
        }
    }
}

/// First rule matching user/groups/process, libcgroup precedence: rules
/// naming a process win over user-only rules; otherwise document order.
pub fn first_rule<'r>(
    rules: &'r [Rule],
    user: &str,
    user_groups: &[String],
    process: Option<&str>,
) -> Option<&'r Rule> {
    if process.is_some() {
        if let Some(r) = rules
            .iter()
            .find(|r| r.process.is_some() && r.matches(user, user_groups, process))
        {
            return Some(r);
        }
    }
    rules
        .iter()
        .find(|r| r.process.is_none() && r.matches(user, user_groups, process))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_and_expansion() {
        let t = Template("users/%u/%g \\%u end".into());
        let vs: Vec<_> = t.vars().collect();
        assert_eq!(vs, [Var::User, Var::Group]);
        let id = Identity {
            name: "lu_zero".into(),
            gid: "10".into(),
            group: "wheel".into(),
            ..Default::default()
        };
        assert_eq!(t.expand(&id), "users/lu_zero/wheel %u end");
    }

    #[test]
    fn unresolved_stays_verbatim() {
        let t = Template("%U-%G-%P".into());
        let id = Identity::default();
        assert_eq!(t.expand(&id), "%U-%G-%P");
    }
}
