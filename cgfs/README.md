# cgfs

cgroupfs **v2** management primitives — the *write* half of the cgroup
filesystem. libc-only, no controller opinions.

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
    subtree_control: vec!["cpu".into(), "memory".into()],
};
cgfs::apply(&spec, Some(std::process::id()))?;
```

- **apply** — mkdir, chown, chmod (`dperm`/`fperm`/`task_fperm`),
  `+ctrl +ctrl` into `cgroup.subtree_control`, optional pid attach.
  Ownership/modes are re-asserted on existing directories (delegation wants
  what libcgroup skipped).
- **delete_tree / delete_leaf** — children-first rmdir; refuses to remove
  the mount point itself; as strict as the kernel about non-empty dirs.
- **list_groups** — relative, sorted walker.
- **raw layer** — `read_string` / `read_kv` (flat-keyed files) /
  `read_u64` (`Ok(None)` when a controller file is absent) / `write_file`
  (`cgset` primitive) / `procs`.

Linux only. License: MIT OR Apache-2.0.
