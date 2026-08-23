//! cgroupfs **v2** management primitives: the write half of the cgroup
//! filesystem, libc-only.
//!
//! The read/stats half lives elsewhere (below's `cgroupfs`, `cgroups-rs`);
//! this crate is deliberately the mirror image — create, delegate, attach,
//! delete, walk, and raw control-file access, with no opinions about
//! controllers:
//!
//! ```no_run
//! use cgfs::{find_mount, join, LeafSpec};
//! use std::path::Path;
//!
//! let mount = find_mount()?;
//! let spec = LeafSpec {
//!     path: join(&mount, Path::new("users/lu_zero/session")),
//!     uid: Some(1000),
//!     gid: Some(1000),
//!     dperm: Some(0o775),
//!     fperm: Some(0o664),
//!     task_fperm: None,
//!     subtree_control: vec!["cpu".into(), "memory".into()],
//! };
//! cgfs::apply(&spec, Some(4242))?; // mkdir, chown, chmod, +cpu +memory, attach
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Ownership/mode application is idempotent and re-applied when the cgroup
//! already exists (libcgroup skips that; delegation wants it).

use std::io;

#[cfg(not(target_os = "linux"))]
compile_error!("cgfs supports Linux cgroup v2 only");

pub mod leaf;
pub mod mount;
pub mod raw;
pub mod tree;

pub use leaf::{apply, attach, enable_subtree_control, LeafSpec};
pub use mount::{find_mount, join, self_relative, DEFAULT_MOUNT};
pub use raw::{procs, read_kv, read_string, read_u64, write_file};
pub use tree::{delete_leaf, delete_tree, list_groups};

/// Control files every non-root v2 cgroup exposes.
pub const CONTROL_FILES: [&str; 3] = ["cgroup.procs", "cgroup.subtree_control", "cgroup.threads"];

pub type Result<T> = std::result::Result<T, io::Error>;
