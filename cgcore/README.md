# cgcore

[![Build Status](https://github.com/lu-zero/cg-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/lu-zero/cg-rs/actions?query=workflow:CI)
[![crates.io](https://img.shields.io/crates/v/cgcore.svg?version=0.1.0)](https://crates.io/crates/cgcore)
[![docs.rs](https://docs.rs/cgcore/badge.svg?version=0.1.0)](https://docs.rs/cgcore)

Shared cgroup v2 application layer for the `cg-rs` tools. It connects the
`cgconfig` parser's symbolic `LeafPlan` to the verified `cgfs` write API
and supplies the Unix identity lookups needed by the consumers.

The crate deliberately does not own rule matching, destination reaping, CLI
traversal, or PAM-specific TOML policy. Those decisions stay with the leaf
application that is using it.

```rust
use cgcore::{resolve_owner, OwnerKind};

let uid = resolve_owner(OwnerKind::User, "1000")?;
# Ok::<(), std::io::Error>(())
```

`resolve_plan` and `apply_plan` turn a symbolic `LeafPlan` into a
`cgfs::LeafSpec` while keeping the target bound to a verified hierarchy.
Unknown symbolic owners are errors; unresolved reverse lookups fall back to
numeric ids.

Linux/PAM: MIT OR Apache-2.0
