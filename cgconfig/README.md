# cgconfig

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

License: MIT OR Apache-2.0.
