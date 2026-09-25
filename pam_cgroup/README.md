# pam_cgroup

[![Build Status](https://github.com/lu-zero/cg-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/lu-zero/cg-rs/actions?query=workflow:CI)
[![crates.io](https://img.shields.io/crates/v/pam_cgroup.svg?version=0.1.0)](https://crates.io/crates/pam_cgroup)
[![docs.rs](https://docs.rs/pam_cgroup/badge.svg?version=0.1.0)](https://docs.rs/pam_cgroup)

PAM session module that puts the login into a **delegated cgroup v2**
hierarchy via cgroupfs. No libcgroup, no systemd.

```text
/sys/fs/cgroup/users/$USER              # empty, subtree_control = cpu memory, user-owned
/sys/fs/cgroup/users/$USER/session      # PAM pid
/sys/fs/cgroup/users/$USER/jobacct-*    # mkdir by jobacct
```

`{user}` / `{uid}` / `{gid}` / `{group}` expand in **paths and owners**.
Ownership is applied even if the cgroup already exists.

## Build / install

Needs [cargo-c](https://crates.io/crates/cargo-c) (`cargo install cargo-c` or the distro package).

```text
cargo test
cargo cbuild --release --prefix=/usr --libdir=/usr/lib64
sudo cargo cinstall --release --prefix=/usr --libdir=/usr/lib64
```

`install_subdir = "security"` is cargo-c’s plugin mode: the module goes in `$libdir/security/`, not the linker’s default libdir.

```text
/usr/lib64/security/pam_cgroup.so
```

(`versioning = false` so Unix does not add `.so.X` next to it. rustc’s Unix cdylib name still has the `lib` prefix.)

The CLI is a normal Cargo binary:

```text
cargo install --path . --root /usr
# or: cargo build --release && sudo cp target/release/pam-cgroup /usr/bin
```

`DESTDIR` works as usual (`cargo cinstall --destdir="$D" --prefix=/usr --libdir=/usr/lib64`).

## Try without PAM

```text
cargo run -- dry-run --config examples/pam_cgroup.toml --user "$USER"
# probe hierarchy (does not touch users/$USER/session):
sudo cargo run -- apply --config examples/probe.toml --user "$USER" --pid "$PID"
```

## PAM (not enabled by this prototype)

```text
session optional pam_cgroup.so config=/etc/cgroup/pam_cgroup.toml
```

Copy `examples/pam_cgroup.toml` to `/etc/cgroup/pam_cgroup.toml`.
`fail_closed = false` (default) logs failures and still returns success so
an `optional` stack cannot lock you out.

Optional libcgroup-style classify after the TOML `[[place]]` tree is
created — drop-ins default to `/etc/cgrules.d` when `cgrules=` is set;
`cgrules.d=` with an empty value turns them off:

```text
session optional pam_cgroup.so config=/etc/cgroup/pam_cgroup.toml \
    cgrules=/etc/cgrules.conf cgconfig=/etc/cgconfig.conf
```

## License

MIT OR Apache-2.0
