#!/usr/bin/env bash
# Publish the cg-rs workspace to crates.io in dependency order.
#
# Usage:
#   ./publish.sh              # full gate check, then publish what's missing
#   ./publish.sh --dry-run    # package/verify only, no uploads
#   ./publish.sh --fast       # skip the `just ci` gate set
#
# Idempotent: a crate whose version is already visible on the index is
# skipped, so re-running after a network hiccup picks up where it left
# off. After each successful upload the script waits until the sparse
# index serves the new version before moving on (dependents must be able
# to resolve it).
set -euo pipefail

cd "$(dirname "$0")"

CRATES=(cgconfig cgfs cgctl cgrulesd pam_cgroup)

DRY_RUN=0
FAST=0
for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=1 ;;
        --fast) FAST=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if (( ! FAST )); then
    echo "== gate set =="
    just ci
fi

# Sparse-index path for a crate name (crates.io routing rules).
index_path() {
    local name=$1
    case ${#name} in
        1) echo "/1/$name" ;;
        2) echo "/2/$name" ;;
        3) echo "/3/${name:0:1}/$name" ;;
        4) echo "/3/${name:0:2}/$name" ;;
        *) echo "/${name:0:2}/${name:2:2}/$name" ;;
    esac
}

version_of() {
    # pkgid forms vary (`name@x.y.z`, `path+…#x.y.z`); take the trailing semver.
    cargo pkgid -p "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([-+][a-zA-Z0-9.-]+)?$'
}

is_published() {
    local name=$1 version=$2 url
    url="https://index.crates.io$(index_path "$name")"
    curl -sfL "$url" | grep -q "\"vers\":\"$version\"" 2>/dev/null
}

wait_visible() {
    local name=$1 version=$2 try
    for try in $(seq 1 12); do
        is_published "$name" "$version" && return 0
        sleep 5
    done
    echo "WARNING: $name@$version still invisible after 60s" >&2
    return 1
}

for crate in "${CRATES[@]}"; do
    version=$(version_of "$crate")
    if is_published "$crate" "$version"; then
        echo "== $crate $version: already on crates.io, skipping"
        continue
    fi

    echo "== publishing $crate $version =="
    if (( DRY_RUN )); then
        # Dependents cannot resolve until their dependencies are really
        # uploaded; a dry run therefore stops there by design.
        cargo publish --dry-run -p "$crate" ||
            { echo "(dry run stopped at $crate; expected before first publish)" >&2; exit 0; }
    else
        cargo publish -p "$crate"
        wait_visible "$crate" "$version"
    fi
done

if (( DRY_RUN )); then
    echo "dry run complete (nothing uploaded)"
fi
