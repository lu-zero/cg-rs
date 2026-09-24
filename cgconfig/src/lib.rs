//! Parsers for the libcgroup configuration formats, on [winnow]:
//!
//! * [`cgconfig`] — [`cgconfig.conf(5)`]: `mount` / `group` / `template` /
//!   `default` sections with `perm { task admin }` and controller blocks.
//! * [`cgrules`] — [`cgrules.conf(5)`]: user → controllers → destination
//!   rules, `%u %U %g %G %p %P` placeholders, `\%` escapes, ditto `%`.
//! * [`model`] — the shared data model and placeholder expansion.
//! * [`v2`] — translate legacy definitions into a cgroup **v2** leaf plan
//!   (`LeafPlan`) for filesystem and application consumers.
//!
//! The crate is libc-free: user/group resolution stays with the caller via
//! [`model::Identity`]. The workspace's `cgcore` crate supplies that layer
//! for the Linux tools.
//!
//! [`ConfigFile`] and [`Rules`] implement [`std::str::FromStr`]. For a filename-aware
//! diagnostic, pass a [`miette::NamedSource`] to their `from_source` methods.
//!
//! # Example
//!
//! ```
//! use cgconfig::{ConfigFile, Identity, plan_template};
//!
//! let cfg: ConfigFile = "template users/%u { perm { task { gid = students; } } cpu {} }".parse().unwrap();
//! let me = Identity {
//!     name: "laura".into(),
//!     uid: "1001".into(),
//!     ..Default::default()
//! };
//! let leaf = plan_template(&cfg, "users/%u", &me).unwrap();
//! assert_eq!(leaf.path, "users/laura");
//! assert_eq!(leaf.task_gid.as_deref(), Some("students"));
//! assert_eq!(leaf.subtree_control, ["cpu"]);
//! ```
//!
//! [winnow]: https://docs.rs/winnow
//! [`cgconfig.conf(5)`]: https://manpages.debian.org/cgconfig.conf.5
//! [`cgrules.conf(5)`]: https://manpages.debian.org/cgrules.conf.5

pub mod cgconfig;
pub mod cgrules;
pub mod display;
pub mod load;
pub mod model;
pub mod v2;

pub use cgconfig::CgError;
pub use cgrules::{CrError, Rules};
pub use load::{load_cgrules, DEFAULT_CGRULES, DEFAULT_CGRULES_DIR};
pub use model::{
    first_rule, first_rule_names, is_safe_relative_path, ConfigFile, Controllers, Identity, Mount,
    Node, Perm, PermSet, Rule, Subject, Template, Var,
};
pub use v2::{plan_destination, plan_group, plan_template, LeafPlan};
