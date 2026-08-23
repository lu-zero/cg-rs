//! Place a login session into a delegated cgroup v2 hierarchy (no libcgroup).
//!
//! The cdylib exports `pam_sm_open_session`. The same apply path is the
//! `pam-cgroup` CLI.

#[cfg(not(target_os = "linux"))]
compile_error!("pam_cgroup places logins in Linux cgroup v2 leaves");

pub mod config;
pub mod place;
pub mod user;

// PAM entry points compile only for the cargo-c cdylib build (cargo-c turns
// the `capi` feature on), so plain cargo check/test/clippy never touch
// libpam symbols.
#[cfg(feature = "capi")]
mod pam_mod;

pub use config::{Config, Place, DEFAULT_CONFIG};
pub use place::{apply, Step};
pub use user::User;
