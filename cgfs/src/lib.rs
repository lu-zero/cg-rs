//! cgroupfs **v2** management primitives: the write half of the cgroup
//! filesystem, libc-only.
//!
//! The read/stats half lives elsewhere (below's `cgroupfs`, `cgroups-rs`);
//! this crate is deliberately the mirror image — create, delegate, attach,
//! delete, walk, and validated control-file access, with no opinions about
//! controllers:
//!
//! ```no_run
//! use cgfs::{Hierarchy, LeafSpec};
//!
//! let hierarchy = Hierarchy::discover()?;
//! let leaf = hierarchy.at_path("users/lu_zero/session")?;
//! let spec = LeafSpec::new()
//!     .uid(1000)
//!     .gid(1000)
//!     .dperm(0o775)
//!     .fperm(0o664)
//!     .subtree_control(&["cpu".to_owned(), "memory".to_owned()]);
//! leaf.apply(&spec, Some(4242))?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! Ownership/mode application is idempotent and re-applied when the cgroup
//! already exists (libcgroup skips that; delegation wants it).

use std::io;

#[cfg(not(target_os = "linux"))]
compile_error!("cgfs supports Linux cgroup v2 only");

mod hierarchy;
mod mount;

pub use hierarchy::{
    self_relative, Cgroup, CgroupEntry, CgroupMetadata, CgroupPath, ControlFile, EntryKind,
    Hierarchy, LeafSpec,
};

/// Control files every non-root v2 cgroup exposes.
pub const CONTROL_FILES: [&str; 3] = ["cgroup.procs", "cgroup.subtree_control", "cgroup.threads"];

pub type Result<T> = std::result::Result<T, io::Error>;
