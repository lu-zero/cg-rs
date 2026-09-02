# cgfs

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cgfs.svg)](https://crates.io/crates/cgfs)
[![docs.rs](https://docs.rs/cgfs/badge.svg)](https://docs.rs/cgfs)

cgroupfs **v2** management primitives — the *write* half of the cgroup
filesystem. rustix-backed, no controller opinions.

Companion to [`cgconfig`](../cgconfig) (parsers for the legacy libcgroup
formats) and the read/stats crates (`below/cgroupfs`, `cgroups-rs`).

```rust
use cgfs::{find_mount, join, LeafSpec};
use std::path::Path;

let mount = find_mount()?;
let spec = LeafSpec {
    path: join(&mount, Path::new("users/lu_zero/session")),
    uid: Some(1000),
    gid: Some(1000),
    dperm: Some(0o775),
    fperm: Some(0o664),
    task_fperm: None,
    task_uid: None,
    task_gid: None,
    subtree_control: vec!["cpu".into(), "memory".into()],
};
cgfs::apply(&spec, Some(std::process::id()))?;
```

- **apply** — mkdir, chown, chmod (`dperm`/`fperm`/`task_fperm`),
  `+ctrl +ctrl` into `cgroup.subtree_control`, optional pid attach. Only
  the leaf itself (`spec.path`) is chowned to `uid`/`gid` and re-asserted
  on every re-apply (delegation wants what libcgroup skipped); ancestors
  created along the way get `dperm`'s read/execute but never group/other
  write, and keep their creator's ownership — a shared ancestor must not
  end up delegated to whichever leaf happens to materialise it first.
  Refuses a `path` containing `..`, a literal `.` segment, or a trailing
  `/`, and refuses to operate through a symlink anywhere in the chain.
- **delete_tree / delete_leaf** — children-first rmdir; refuses to remove
  the mount point itself; as strict as the kernel about non-empty dirs.
- **list_groups** — relative, sorted walker.
- **raw layer** — `read_string` / `read_kv` (flat-keyed files) /
  `read_u64` (`Ok(None)` when a controller file is absent) / `write_file`
  (`cgset` primitive) / `procs`.

Linux only. License: MIT OR Apache-2.0.
