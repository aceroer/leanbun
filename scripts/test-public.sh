#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$repository/rust/Cargo.toml"

cargo fmt --manifest-path "$manifest" --all -- --check
cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
cargo test --locked --manifest-path "$manifest" --lib
cargo clippy --locked --manifest-path "$manifest" \
  -p leanbun-inventory-legacy \
  -p leanbun-plan \
  -p leanbun-state \
  -p leanbun-macos-acl-sys \
  -p leanbun-approval-macos \
  --all-targets -- -D warnings
cargo test --locked --manifest-path "$manifest" \
  -p leanbun-inventory-legacy \
  -p leanbun-plan \
  -p leanbun-state \
  -p leanbun-macos-acl-sys \
  -p leanbun-approval-macos
cargo test --locked --manifest-path "$manifest" -p leanbun-evidence --test development_provider
"$repository/scripts/check-public-source"
