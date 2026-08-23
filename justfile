# cg-rs workspace tasks

default:
    @just --list

# staging/installation knobs (DESTDIR behaves like autotools: stage without
# touching the live system, and no sudo is used while staging)
destdir := env_var_or_default("DESTDIR", "")
prefix := env_var_or_default("PREFIX", "/usr")
libdir := env_var_or_default("LIBDIR", "lib64")
destarg := if destdir == "" { "" } else { "--destdir \"" + destdir + "\"" }
sudo := if destdir == "" { "sudo" } else { "" }
bindir := destdir + prefix + "/bin"

# full pre-commit gate set (see AGENTS.md)
ci: fmt clippy doc test

build *args:
    cargo build --workspace {{args}}

test *args:
    cargo test --workspace {{args}}

clippy:
    cargo clippy --workspace --all-features -- -D warnings

fmt:
    cargo fmt --all -- --check

doc:
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

# release-mode artifacts for every crate (module included)
build-release:
    cargo build --release --workspace
    cargo cbuild -p pam_cgroup --release --prefix {{prefix}}

# install the PAM module as $libdir/security/libpam_cgroup_rs.so
install-pam:
    {{sudo}} cargo cinstall -p pam_cgroup --release {{destarg}} \
        --prefix {{prefix}} --libdir {{libdir}}

# install the CLI binaries into $prefix/bin
install-bins: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    for b in pam-cgroup cgctl cgrulesd; do
        {{sudo}} install -Dm755 "target/release/$b" "{{bindir}}/$b"
        echo "{{bindir}}/$b"
    done

# install everything (PAM module + CLIs), libcgroup's `make install` shape
install: install-bins install-pam
