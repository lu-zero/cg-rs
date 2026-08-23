//! Parsers for the libcgroup configuration formats, on [winnow]:
//!
//! * [`cgconfig`] — [`cgconfig.conf(5)`]: `mount` / `group` / `template` /
//!   `default` sections with `perm { task admin }` and controller blocks.
//! * [`cgrules`] — [`cgrules.conf(5)`]: user → controllers → destination
//!   rules, `%u %U %g %G %p %P` placeholders, `\%` escapes, ditto `%`.
//! * [`model`] — the shared data model and placeholder expansion.
//! * [`v2`] — translate legacy definitions into a cgroup **v2** leaf plan
//!   (`LeafPlan`) usable by `pam_cgroup` and `jobacct`.
//!
//! The crate is libc-free: user/group resolution stays with the caller via
//! [`model::Identity`].
//!
//! # Example
//!
//! ```
//! use cgconfig::{parse_cgconfig, Identity, plan_template};
//!
//! let cfg = parse_cgconfig(
//!     "template users/%u {\n  perm {\n    task { uid = %u; gid = users; fperm = 664; }\n\
//!      admin { uid = root; dperm = 750; }\n  }\n  cpu { }\n}\n",
//! )
//! .unwrap();
//! let me = Identity {
//!     name: "laura".into(),
//!     uid: "1001".into(),
//!     ..Default::default()
//! };
//! let leaf = plan_template(&cfg, "users/%u", &me).unwrap();
//! assert_eq!(leaf.path, "users/laura");
//! assert_eq!(leaf.task_gid.as_deref(), Some("users"));
//! assert_eq!(leaf.subtree_control, ["cpu"]);
//! ```
//!
//! [winnow]: https://docs.rs/winnow
//! [`cgconfig.conf(5)`]: https://manpages.debian.org/cgconfig.conf.5
//! [`cgrules.conf(5)`]: https://manpages.debian.org/cgrules.conf.5

pub mod cgconfig;
pub mod cgrules;
pub mod display;
pub mod model;
pub mod v2;

pub use cgconfig::{parse_cgconfig, parse_cgconfig_in, CgError};
pub use cgrules::{parse_cgrules, parse_cgrules_in, CrError};
pub use model::{
    first_rule, ConfigFile, Controllers, Identity, Mount, Node, Perm, PermSet, Rule, Subject,
    Template, Var,
};
pub use v2::{plan_group, plan_template, LeafPlan};
