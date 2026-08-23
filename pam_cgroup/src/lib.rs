//! Place a login session into a delegated cgroup v2 hierarchy (no libcgroup).
//!
//! The cdylib exports `pam_sm_open_session`. The same apply path is the
//! `pam-cgroup` CLI.

pub mod config;
pub mod place;
pub mod user;

mod pam_mod;

pub use config::{Config, Place, DEFAULT_CONFIG};
pub use place::{apply, Step};
pub use user::User;
