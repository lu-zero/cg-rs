# cg-rs

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)

Rust reimplementation of the useful parts of **libcgroup**, for
**cgroup v2 / cgroupfs only** — no systemd, no libcgroup library.

| crate | crates.io | docs | replaces | what it does |
|---|---|---|---|---|
| [`cgconfig`](cgconfig) | [![crates.io](https://img.shields.io/crates/v/cgconfig.svg)](https://crates.io/crates/cgconfig) | [![docs](https://docs.rs/cgconfig/badge.svg)](https://docs.rs/cgconfig) | `cgconfigparser`, config parsing | winnow parsers for `cgconfig.conf` + `cgrules.conf`, `%u`-style templates, miette diagnostics, v2 `LeafPlan` bridge |
| [`cgfs`](cgfs) | [![crates.io](https://img.shields.io/crates/v/cgfs.svg)](https://crates.io/crates/cgfs) | [![docs](https://docs.rs/cgfs/badge.svg)](https://docs.rs/cgfs) | libcg fs layer | create/delegate/attach/delete/walk cgroups; raw control-file read/write |
| [`pam_cgroup`](pam_cgroup) | [![crates.io](https://img.shields.io/crates/v/pam_cgroup.svg)](https://crates.io/crates/pam_cgroup) | [![docs](https://docs.rs/pam_cgroup/badge.svg)](https://docs.rs/pam_cgroup) | `pam_cgroup.so` | PAM session module placing logins into delegated user leaves (`users/$USER/session`) |

Planned: `cgctl` (busybox-style CLI: cgcreate/cgdelete/cgset/cgget/
lscgroup/lssubsys/cgexec/cgclassify/cgsnapshot), `cgrulesd`
(rules enforcement daemon).

Not reproduced on purpose: v1 multi-hierarchy mounting, Python bindings,
release_agent plumbing.

```text
/sys/fs/cgroup/users/$USER            # empty, subtree_control, user-owned
/sys/fs/cgroup/users/$USER/session    # login pid (pam_cgroup)
/sys/fs/cgroup/users/$USER/jobacct-*  # accounting leaves (jobacct)
```

License: MIT OR Apache-2.0.
