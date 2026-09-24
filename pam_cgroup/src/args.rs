//! PAM module arguments (`config=`, `cgrules=`, `cgrules.d=`, `cgconfig=`).

use crate::config::DEFAULT_CONFIG;
use cgconfig::DEFAULT_CGRULES_DIR;

/// Paths the module should read. `config` is the TOML layout; the
/// `cgrules*` fields are optional and enable libcgroup-style classify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PamArgs {
    pub config: String,
    pub cgrules: Option<String>,
    pub cgrules_d: Option<String>,
    pub cgconfig: Option<String>,
}

impl Default for PamArgs {
    fn default() -> Self {
        Self {
            config: DEFAULT_CONFIG.to_string(),
            cgrules: None,
            cgrules_d: None,
            cgconfig: None,
        }
    }
}

impl PamArgs {
    /// Parse `key=value` tokens as PAM `argv` (and the CLI). Unknown
    /// keys are collected so the caller can log them.
    pub fn parse<'a, I>(tokens: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut args = Self::default();
        let mut unknown = Vec::new();
        let mut cgrules_d_set = false;
        for tok in tokens {
            if let Some(v) = tok.strip_prefix("config=") {
                args.config = v.to_string();
            } else if let Some(v) = tok.strip_prefix("cgrules=") {
                args.cgrules = Some(v.to_string());
            } else if let Some(v) = tok.strip_prefix("cgrules.d=") {
                cgrules_d_set = true;
                args.cgrules_d = if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                };
            } else if let Some(v) = tok.strip_prefix("cgconfig=") {
                args.cgconfig = Some(v.to_string());
            } else if tok == "debug" {
                // Accepted for libcgroup pam_cgroup.so drop-in stacks.
            } else if !tok.is_empty() {
                unknown.push(tok.to_string());
            }
        }
        if args.cgrules.is_some() && !cgrules_d_set {
            args.cgrules_d = Some(DEFAULT_CGRULES_DIR.to_string());
        }
        (args, unknown)
    }

    /// Drop-in directory to pass to [`cgconfig::load_cgrules`].
    pub fn rules_dir(&self) -> Option<&str> {
        self.cgrules_d.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_toml_only() {
        let (a, u) = PamArgs::parse([]);
        assert_eq!(a.config, DEFAULT_CONFIG);
        assert!(a.cgrules.is_none());
        assert!(a.cgrules_d.is_none());
        assert!(u.is_empty());
    }

    #[test]
    fn cgrules_implies_default_drop_in_dir() {
        let (a, _) = PamArgs::parse(["cgrules=/etc/cgrules.conf"]);
        assert_eq!(a.cgrules.as_deref(), Some("/etc/cgrules.conf"));
        assert_eq!(a.cgrules_d.as_deref(), Some(DEFAULT_CGRULES_DIR));
    }

    #[test]
    fn empty_cgrules_d_disables_drop_ins() {
        let (a, _) = PamArgs::parse(["cgrules=/tmp/r.conf", "cgrules.d="]);
        assert_eq!(a.cgrules.as_deref(), Some("/tmp/r.conf"));
        assert!(a.cgrules_d.is_none());
    }

    #[test]
    fn unknown_tokens_are_reported() {
        let (a, u) = PamArgs::parse(["config=/x.toml", "nope", "cgconfig=/c.conf"]);
        assert_eq!(a.config, "/x.toml");
        assert_eq!(a.cgconfig.as_deref(), Some("/c.conf"));
        assert_eq!(u, ["nope"]);
    }
}
