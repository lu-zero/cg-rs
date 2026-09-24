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
  (`\%` escapes). `load_cgrules` also reads a drop-in directory
  (`/etc/cgrules.d`), files sorted by name.
- `model` — shared types and placeholder expansion. libc-free: user/group
  resolution stays with the caller (`Identity`); the Linux workspace layer
  `cgcore` supplies that integration.
- `v2` — expand a group/template into a `LeafPlan` (path, owners, modes,
  `subtree_control`) for filesystem and application consumers.

```rust
use cgconfig::{ConfigFile, Identity, Rules, first_rule, plan_template};

let cfg = "template users/%u { cpu {} }".parse::<ConfigFile>().unwrap();
let rules = "laura * students/%u".parse::<Rules>().unwrap();
let me = Identity { name: "laura".into(), ..Default::default() };
let leaf = plan_template(&cfg, "users/%u", &me).unwrap();
assert_eq!(leaf.path, "users/laura");
assert_eq!(first_rule(&rules, &me.name, &[], None).is_some(), true);
```

Empty controller blocks (`cpu {}`) count: under the unified hierarchy they
still mean "enable this controller for children".

## Errors are `miette::Diagnostic`

Both error types carry byte spans, line/column, and a named copy of the
source when parsed with `from_path`, so consumers can render rich diagnostics:

```rust
use cgconfig::ConfigFile;
use miette::GraphicalReportHandler;

let err = ConfigFile::from_path("my.conf").unwrap_err();
let mut out = String::new();
GraphicalReportHandler::new()
    .render_report(&mut out, &err)
    .unwrap();
```

The library depends on `miette` with `default-features = false` (protocol
types only); enable `miette/features = ["fancy"]` in your binary for the
renderer. Try `cargo run --example render_error`.

License: MIT OR Apache-2.0.
