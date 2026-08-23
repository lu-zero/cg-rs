# cg-rs workspace tasks

default:
    @just --list

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

# build the PAM module without installing (needs cargo-c)
pam-build prefix="/usr":
    cargo cbuild -p pam_cgroup --prefix {{prefix}}

# install the PAM module as $libdir/security/libpam_cgroup_rs.so
install-pam prefix="/usr" libdir="lib64":
    sudo cargo cinstall -p pam_cgroup --prefix {{prefix}} --libdir {{libdir}}

# install the pam-cgroup CLI into $prefix/bin
install-cli prefix="/usr":
    cargo install --path pam_cgroup --root {{prefix}} --locked

# install everything (PAM module + CLI), libcgroup's `make install` shape
install prefix="/usr" libdir="lib64": (install-cli prefix) (install-pam prefix libdir)
