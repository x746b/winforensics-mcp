#!/usr/bin/env bash
# Explicit opt-in build; runtime never fetches or builds executables.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sidr_commit=c7d3744d598ea38401c8694451c6467badbb508c
sidr_build="$(mktemp -d)"
trap 'rm -rf -- "$sidr_build"' EXIT
git clone https://github.com/strozfriedberg/sidr.git "$sidr_build/src"
git -C "$sidr_build/src" checkout --detach "$sidr_commit"
test "$(git -C "$sidr_build/src" rev-parse HEAD)" = "$sidr_commit"
test -f "$sidr_build/src/Cargo.lock"
cargo build --manifest-path "$sidr_build/src/Cargo.toml" --locked --release --bin sidr
mkdir -p "$repo_root/.tools"
install -m 0755 "$sidr_build/src/target/release/sidr" "$repo_root/.tools/sidr"
"$repo_root/.tools/sidr" --version
sha256sum "$repo_root/.tools/sidr"
