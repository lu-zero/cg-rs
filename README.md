# cg-rs

[![LICENSE](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Build Status](https://github.com/lu-zero/cg-rs/workflows/CI/badge.svg)](https://github.com/lu-zero/cg-rs/actions?query=workflow:CI)
[![dependency status](https://deps.rs/repo/github/lu-zero/cg-rs/status.svg)](https://deps.rs/repo/github/lu-zero/cg-rs)

Rust reimplementation of the useful parts of **libcgroup**, for
**cgroup v2 / cgroupfs only** — no systemd, no libcgroup library.

| crate | crates.io | docs | replaces | what it does |
|---|---|---|---|---|
| [`cgconfig`](cgconfig) | [![crates.io](https://img.shields.io/crates/v/cgconfig.svg)](https://crates.io/crates/cgconfig) | [![docs](https://docs.rs/cgconfig/badge.svg)](https://docs.rs/cgconfig) | `cgconfigparser`, config parsing | winnow parsers for `cgconfig.conf` + `cgrules.conf`, `%u`-style templates, miette diagnostics, v2 `LeafPlan` bridge |
| [`cgfs`](cgfs) | [![crates.io](https://img.shields.io/crates/v/cgfs.svg)](https://crates.io/crates/cgfs) | [![docs](https://docs.rs/cgfs/badge.svg)](https://docs.rs/cgfs) | libcg fs layer | verified hierarchy handles; create/delegate/attach/delete/walk; validated control-file read/write |
| [`cgcore`](cgcore) | [![crates.io](https://img.shields.io/crates/v/cgcore.svg)](https://crates.io/crates/cgcore) | [![docs](https://docs.rs/cgcore/badge.svg)](https://docs.rs/cgcore) | shared application glue | NSS owner resolution and `cgconfig::LeafPlan` → verified `cgfs` application |
| [`pam_cgroup`](pam_cgroup) | [![crates.io](https://img.shields.io/crates/v/pam_cgroup.svg)](https://crates.io/crates/pam_cgroup) | [![docs](https://docs.rs/pam_cgroup/badge.svg)](https://docs.rs/pam_cgroup) | `pam_cgroup.so` | PAM session module placing logins into delegated user leaves (`users/$USER/session`) |
| [`cgctl`](cgctl) | [![crates.io](https://img.shields.io/crates/v/cgctl.svg)](https://crates.io/crates/cgctl) | [![docs](https://docs.rs/cgctl/badge.svg)](https://docs.rs/cgctl) | the cg\* tools | busybox CLI: `config` `ls` `get` `set` `classify` `exec` `delete` `snapshot` |
| [`cgrulesd`](cgrulesd) | [![crates.io](https://img.shields.io/crates/v/cgrulesd.svg)](https://crates.io/crates/cgrulesd) | [![docs](https://docs.rs/cgrulesd/badge.svg)](https://docs.rs/cgrulesd) | cgred / cgrulesengd | poll-based daemon keeping processes inside their cgrules destinations |

Not reproduced on purpose: v1 multi-hierarchy mounting, Python bindings,
release_agent plumbing.

## Development

```sh
just --list      # recipes
just ci          # fmt + clippy + doc + test (the pre-commit gate set)
just install     # PAM module ($libdir/security) + CLI binaries ($prefix/bin)
```

Packaging works like autotools: `DESTDIR=/tmp/stage just install` stages
everything under the destdir without touching the live system (and skips
sudo); `PREFIX`/`LIBDIR` override `/usr`/`lib64`. `install` needs
[cargo-c](https://crates.io/crates/cargo-c) for the module
(`cargo install cargo-c`).

## Releasing

`./publish.sh` walks the workspace in dependency order, skipping versions
already on crates.io; `--dry-run` packages without uploading (dependents
naturally stop at the first unpublished dependency), `--fast` skips the
gate set.

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
