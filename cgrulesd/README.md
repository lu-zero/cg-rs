# cgrulesd

[![Build Status](https://github.com/lu-zero/cg-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/lu-zero/cg-rs/actions?query=workflow:CI)
[![crates.io](https://img.shields.io/crates/v/cgrulesd.svg?version=0.1.0)](https://crates.io/crates/cgrulesd)

A poll-based cgroup v2 enforcement daemon for `cgrules.conf`. It is the
unified-hierarchy successor to the libcgroup `cgred`/`cgrulesengd` tools and
does not use systemd, D-Bus, or a v1 hierarchy.

It reads `/etc/cgrules.conf` by default, followed by eligible files in
`/etc/cgrules.d` sorted by filename. A matching `group` or `template` from an
optional `cgconfig.conf` supplies ownership, modes, and controllers.
Template-created destinations are reaped when idle in continuous mode.

```text
cgrulesd [--config FILE] [--config-dir DIR] [--no-config-dir]
         [--cgconfig FILE] [--interval SECS] [--once] [--verbose]
```

This crate is Linux-only. See the workspace [`cgconfig`](../cgconfig),
[`cgfs`](../cgfs), and [`cgcore`](../cgcore) crates for the parser, filesystem,
and shared application APIs.

License: MIT OR Apache-2.0
