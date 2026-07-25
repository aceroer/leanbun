#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$repository/rust/Cargo.toml"

cargo fmt --manifest-path "$manifest" --all -- --check
cargo clippy --locked --manifest-path "$manifest" --workspace --all-targets -- -D warnings
cargo test --locked --manifest-path "$manifest" --workspace --lib
cargo test --locked --manifest-path "$manifest" -p leanbun-evidence --test development_provider
