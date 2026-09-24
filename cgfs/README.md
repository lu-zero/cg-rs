# cgfs

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cgfs.svg)](https://crates.io/crates/cgfs)
[![docs.rs](https://docs.rs/cgfs/badge.svg)](https://docs.rs/cgfs)

cgroupfs **v2** management primitives — the *write* half of the cgroup
filesystem. Every mutating operation is rooted at a verified `Hierarchy` and
uses descriptor-relative resolution, so an arbitrary absolute path cannot be
passed to an apply/delete/write operation.

Companion to [`cgconfig`](../cgconfig) (parsers for the legacy libcgroup
formats) and the read/stats crates (`below/cgroupfs`, `cgroups-rs`).

```rust
use cgfs::{Hierarchy, LeafSpec};

fn main() -> std::io::Result<()> {
    let hierarchy = Hierarchy::discover()?;
    let session = hierarchy.at_path("users/lu_zero/session")?;
    let spec = LeafSpec::new()
        .uid(1000)
        .gid(1000)
        .dperm(0o775)
        .fperm(0o664)
        .subtree_control(&["cpu".to_owned(), "memory".to_owned()]);
    session.apply(&spec, Some(std::process::id()))?;
    Ok(())
}
```

- **Hierarchy / Cgroup** — `discover()` verifies cgroup2 with `statfs`; cgroup
  paths are validated relative components and resolved with `openat2` using
  `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`, `RESOLVE_NO_SYMLINKS`, and
  `RESOLVE_NO_MAGICLINKS`.
- **Cgroup::apply** — creates missing ancestors, applies ownership/modes,
  configures controllers, and optionally attaches a pid. Existing ancestors
  keep their creator ownership and never receive group/other write bits.
- **ControlFile** — direct, validated control-file reads/writes (`read_string`,
  `read_kv`, `read_u64`, `write`, and `procs`).
- **Cgroup::delete_leaf / delete_tree** — descriptor-relative, children-first
  removal that refuses the hierarchy root and symlink traversal.
- **Cgroup::entries / list_groups / metadata** — read-only traversal and
  inspection through the verified handle.
- **self_relative** — parse `/proc/self/cgroup` into a validated `CgroupPath`.

The safe API requires Linux `openat2` support (Linux 5.6+); it fails
explicitly rather than falling back to weaker path checks. Linux only.

License: MIT OR Apache-2.0
