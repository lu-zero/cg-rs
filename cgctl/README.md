# cgctl

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cgctl.svg)](https://crates.io/crates/cgctl)

A busybox-style command-line interface for cgroup v2. It combines the
configuration, inspection, classification, execution, deletion, and snapshot
operations that libcgroup spreads across several tools.

```text
cgctl config <FILE>
cgctl ls [<path>]
cgctl get <path> [key…]
cgctl set <path> <key=value>…
cgctl classify <path> <pid>…
cgctl exec <path> <command> [args…]
cgctl delete [-r] <path>
cgctl snapshot [<path>]
```

The path is interpreted relative to the discovered cgroup2 mount; `/` refers
to the mount root. This crate is Linux-only.

## Build

```text
cargo build --release
cargo install --path .
```

See the workspace [`cgfs`](../cgfs), [`cgconfig`](../cgconfig), and
[`cgcore`](../cgcore) crates for the underlying filesystem, configuration,
and shared application APIs.

License: MIT OR Apache-2.0
