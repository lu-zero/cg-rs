# cgconfig

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/cgconfig.svg)](https://crates.io/crates/cgconfig)
[![docs.rs](https://docs.rs/cgconfig/badge.svg)](https://docs.rs/cgconfig)

winnow parsers for the legacy libcgroup configuration formats, plus a
translation layer to **cgroup v2** leaves.

- `cgconfig.conf(5)` — `mount` / `group` / `template` / `default` sections,
  `perm { task admin }` with `uid`/`gid`/`dperm`/`fperm`, controller blocks.
- `cgrules.conf(5)` — `<user>[:<process>] <controllers> <destination>` rules
  with `@group`, wildcard, ditto `%`, and `%u %U %g %G %p %P` placeholders
  (`\%` escapes).
- `model` — shared types and placeholder expansion. libc-free: user/group
  resolution stays with the caller (`Identity`).
- `v2` — expand a group/template into a `LeafPlan` (path, owners, modes,
  `subtree_control`) for consumers like `pam_cgroup` and `jobacct`.

```rust
use cgconfig::{parse_cgconfig, parse_cgrules, first_rule, plan_template, Identity};

let cfg = parse_cgconfig("template users/%u { cpu {} }").unwrap();
let me = Identity { name: "laura".into(), ..Default::default() };
let leaf = plan_template(&cfg, "users/%u", &me).unwrap();
assert_eq!(leaf.path, "users/laura");
```

Empty controller blocks (`cpu {}`) count: under the unified hierarchy they
still mean "enable this controller for children".

## Errors are `miette::Diagnostic`

Both error types carry byte spans, line/column, and a named copy of the
source (`parse_cgconfig_in("my.conf", text)` to name it yourself), so
consumers can render rich diagnostics:

```rust
use cgconfig::parse_cgconfig_in;
use miette::GraphicalReportHandler;

let err = parse_cgconfig_in("cgconfig.conf", "group x { cpu { a = ; } }")
    .unwrap_err();
let mut out = String::new();
GraphicalReportHandler::new()
    .render_report(&mut out, &err)
    .unwrap();
```

The library depends on `miette` with `default-features = false` (protocol
types only); enable `miette/features = ["fancy"]` in your binary for the
renderer. Try `cargo run --example render_error`.

License: MIT OR Apache-2.0.
