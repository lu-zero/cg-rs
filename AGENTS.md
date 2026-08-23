# AGENTS.md

## Commands

Run from the workspace root; all four must be clean before committing:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo test --workspace
```

`cgfs` is Linux-only by design (compile_error elsewhere); the other two
crates are portable. `pam_cgroup` needs `cargo-c` only for
`cbuild`/`cinstall`, not for the test suite.

## Layout

- `cgconfig/` — parsers + model + `%u` template expansion + v2 planning.
  Depends on winnow and protocol-only miette (`default-features = false`;
  dev-deps add `fancy-no-backtrace` for rendered-output tests).
- `cgfs/` — cgroupfs v2 write side: apply/delete/walk/raw control files.
  libc-only, Linux-gated.
- `pam_cgroup/` — PAM module (cdylib via cargo-c, `panic=abort` in capi
  metadata) + `pam-cgroup` CLI. Consumes `cgfs`; TOML config is its own.

Shared metadata lives in `[workspace.package]`; shared deps in
`[workspace.dependencies]`. Member manifests use `workspace = true`
inheritance — do not re-pin versions locally.

## Notes

- The family targets **cgroup v2 unified hierarchy** only. No v1
  hierarchies, no systemd D-Bus, no release_agent.
- `miette` stays renderer-free at the library level: binaries opt into
  `features = ["fancy"]`.
- Roadmap crates: `cgctl` (busybox CLI replacing the cg* tools),
  `cgrulesd` (cgrules enforcement daemon). Do not start them inside an
  unrelated commit.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — new functionality
- `fix:` — bug fix
- `refactor:` — code restructuring without behaviour change
- `docs:` — documentation only
- `test:` — adding or updating tests
- `ci:` — CI/CD changes
- `chore:` — maintenance (dependencies, tooling)

Hard limits: no body line over **150 characters**, no paragraph over
**5 lines** (3 is better). Subject follows Conventional Commits'
~50/72 convention.

When a commit was significantly assisted by an AI tool, note it with an
`Assisted-by:` trailer rather than a `Co-Authored-By:` trailer. Use the
kernel's format (`AGENT_NAME:MODEL_VERSION`, colon-separated, e.g.
`Assisted-by: Maki:glm-5.2`). Only list specialized analysis tools after
the model version if any were used; basic dev tools (git, cargo,
editors) are not listed. The agent never adds a `Signed-off-by` (DCO) —
that is the human's.
