//! Place the login pid using cgrules.conf (+ optional cgrules.d).

use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use cgconfig::model::{first_rule_names, ConfigFile, Identity};
use cgconfig::{load_cgrules, plan_destination, CgError, CrError, FileError};
use cgfs::{Cgroup, Hierarchy, LeafSpec};
use miette::Diagnostic;

use crate::user::User;

/// Failure while classifying a process or loading its cgroup configuration.
#[derive(Debug)]
pub enum ClassifyError {
    /// A filesystem or cgroup operation failed.
    Io(io::Error),
    /// The cgrules document could not be read or parsed.
    Rules(FileError<CrError>),
    /// The cgconfig document could not be read or parsed.
    Config(FileError<CgError>),
}

impl From<io::Error> for ClassifyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FileError<CrError>> for ClassifyError {
    fn from(error: FileError<CrError>) -> Self {
        Self::Rules(error)
    }
}

impl From<FileError<CgError>> for ClassifyError {
    fn from(error: FileError<CgError>) -> Self {
        Self::Config(error)
    }
}

impl fmt::Display for ClassifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Rules(error) => error.fmt(f),
            Self::Config(error) => error.fmt(f),
        }
    }
}

impl StdError for ClassifyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Rules(error) => Some(error),
            Self::Config(error) => Some(error),
        }
    }
}

impl Diagnostic for ClassifyError {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.code(),
            Self::Config(error) => error.code(),
        }
    }

    fn severity(&self) -> Option<miette::Severity> {
        match self {
            Self::Io(_) => Some(miette::Severity::Error),
            Self::Rules(error) => error.severity(),
            Self::Config(error) => error.severity(),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.help(),
            Self::Config(error) => error.help(),
        }
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.url(),
            Self::Config(error) => error.url(),
        }
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.source_code(),
            Self::Config(error) => error.source_code(),
        }
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.labels(),
            Self::Config(error) => error.labels(),
        }
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.related(),
            Self::Config(error) => error.related(),
        }
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        match self {
            Self::Io(_) => None,
            Self::Rules(error) => error.diagnostic_source(),
            Self::Config(error) => error.diagnostic_source(),
        }
    }
}

/// Match `user`/`pid` against the rules and attach. `Ok(None)` means no
/// matching rule (or `ignore`); the TOML `[[place]]` attach still stands.
pub fn classify(
    hierarchy: &Hierarchy,
    cgrules: &Path,
    cgrules_d: Option<&Path>,
    cgconfig: Option<&Path>,
    user: &User,
    pid: u32,
) -> Result<Option<PathBuf>, ClassifyError> {
    let rules = load_cgrules(cgrules, cgrules_d)?;
    let cfg = match cgconfig {
        Some(f) => ConfigFile::from_path(f)?,
        None => ConfigFile::default(),
    };
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let mut names = vec![comm.as_str()];
    if let Some(e) = exe.as_deref() {
        names.push(e);
        if let Some(base) = e.rsplit('/').next() {
            if !base.is_empty() && base != comm {
                names.push(base);
            }
        }
    }
    let groups = groups_of(&user.name, user.gid);
    let Some(rule) = first_rule_names(&rules, &user.name, &groups, &names) else {
        return Ok(None);
    };
    if rule.ignores() || (rule.ignores_rt() && is_rt(pid)) {
        return Ok(None);
    }
    let identity = Identity {
        name: user.name.clone(),
        uid: user.uid.to_string(),
        gid: user.gid.to_string(),
        group: user.group.clone(),
        proc_name: comm,
        pid: pid.to_string(),
    };
    let dest = identity.expand(&rule.destination);
    let dest = dest.trim_matches('/').to_owned();
    if !cgconfig::model::is_safe_relative_path(&dest) {
        return Err(ClassifyError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("cgrules destination {dest:?} has illegal path components"),
        )));
    }
    let (target, spec) = leaf_spec(hierarchy, &cfg, &dest, &rule.destination.0, &identity)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no group/template for cgrules destination {dest}"),
            )
        })?;
    let path = hierarchy.mount_path().join(target.path().as_relative());
    target.apply(&spec, Some(pid))?;
    Ok(Some(path))
}

fn leaf_spec(
    hierarchy: &Hierarchy,
    cfg: &ConfigFile,
    dest: &str,
    template_name: &str,
    identity: &Identity,
) -> io::Result<Option<(Cgroup, LeafSpec)>> {
    if let Some((plan, _)) = plan_destination(cfg, dest, template_name, identity) {
        let (target, spec) = cgcore::resolve_plan(hierarchy, &plan)?;
        return Ok(Some((target, spec)));
    }
    let target = match hierarchy.at_path(dest) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let owned = identity.uid.parse::<u32>().ok().is_some_and(|uid| {
        target
            .control("cgroup.procs")
            .ok()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|metadata| metadata.uid == uid)
    });
    Ok(owned.then(|| (target, LeafSpec::new())))
}

fn is_rt(pid: u32) -> bool {
    let pol = unsafe { libc::sched_getscheduler(pid as libc::pid_t) };
    pol == libc::SCHED_FIFO || pol == libc::SCHED_RR
}

fn groups_of(user: &str, gid: u32) -> Vec<String> {
    cgcore::supplementary_groups(user, gid).unwrap_or_default()
}
