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
strip --strip-unneeded "$repo_root/.tools/sidr"
"$repo_root/.tools/sidr" --version
sidr_sha256="$(sha256sum "$repo_root/.tools/sidr" | awk '{print $1}')"
sidr_size="$(stat -c %s "$repo_root/.tools/sidr")"
sidr_target="$(rustc -vV | awk '/^host:/ {print $2}')"
cat > "$repo_root/.tools/sidr.manifest.json" <<EOF
{
  "name": "sidr",
  "version": "0.9.2",
  "source": "https://github.com/strozfriedberg/sidr.git",
  "commit": "$sidr_commit",
  "target": "$sidr_target",
  "profile": "release",
  "cargo_locked": true,
  "stripped": true,
  "sha256": "$sidr_sha256",
  "size_bytes": $sidr_size,
  "build_command": "cargo build --locked --release --bin sidr"
}
EOF
printf '%s  %s\n' "$sidr_sha256" "$repo_root/.tools/sidr"
