# pam_cgroup

[![CI](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lu_zero/cg-rs/actions/workflows/ci.yml)

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
/usr/lib64/security/libpam_cgroup_rs.so
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
session optional libpam_cgroup_rs.so config=/etc/cgroup/pam_cgroup.toml
```

Copy `examples/pam_cgroup.toml` to `/etc/cgroup/pam_cgroup.toml`.
`fail_closed = false` (default) logs failures and still returns success so
an `optional` stack cannot lock you out.

## License

MIT OR Apache-2.0
