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
host_target="$(rustc -vV | awk '/^host:/ {print $2}')"
sidr_target="${SIDR_TARGET:-$host_target}"
cargo build --manifest-path "$sidr_build/src/Cargo.toml" --locked --release --bin sidr \
  --target "$sidr_target"
case "$sidr_target" in
  aarch64-unknown-linux-gnu)
    output_name=sidr
    default_strip=strip
    ;;
  x86_64-unknown-linux-gnu)
    output_name=sidr_x86
    if [ "$host_target" = "$sidr_target" ]; then
      default_strip=strip
    else
      default_strip=x86_64-linux-gnu-strip
    fi
    ;;
  *)
    echo "unsupported bundled SIDR target: $sidr_target" >&2
    exit 1
    ;;
esac
strip_tool="${SIDR_STRIP:-$default_strip}"
mkdir -p "$repo_root/.tools"
sidr_binary="$repo_root/.tools/$output_name"
install -m 0755 "$sidr_build/src/target/$sidr_target/release/sidr" "$sidr_binary"
"$strip_tool" --strip-unneeded "$sidr_binary"
if [ "$host_target" = "$sidr_target" ]; then
  "$sidr_binary" --version
else
  strings "$sidr_binary" | grep -Fq '0.9.2'
fi
sidr_sha256="$(sha256sum "$sidr_binary" | awk '{print $1}')"
sidr_size="$(stat -c %s "$sidr_binary")"
cat > "$repo_root/.tools/$output_name.manifest.json" <<EOF
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
  "build_command": "cargo build --locked --release --bin sidr --target $sidr_target"
}
EOF
printf '%s  %s\n' "$sidr_sha256" "$sidr_binary"
