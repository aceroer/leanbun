# LeanBun

LeanBun is an experimental Rust control layer for Lean/Lake package workflows. It uses Bun's package-management model for locking, deterministic path selection, concurrent fetch, immutable cache publication, transactions, recovery and rollback, while leaving Lean compilation and Lake project interpretation to Lean/Lake.

The current public snapshot is `0.20.0-m48-dev`. It closes the M43--M48 crate-boundary refactor, Reservoir version-to-commit authority model, registered loopback regression, historical-crate disposition and source-only distribution provenance. It is not yet a general-purpose package manager and is not authorized to mutate arbitrary external projects.

## Boundary

- Bun owns external dependency orchestration, final package-path decisions, locking, cache publication and update transactions.
- Lake remains the parser and build executor for Lean project declarations.
- Lean remains the compiler and proof checker.
- The repository contains the Rust lifecycle crates and a redacted patch series that reconstructs the reviewed Bun adapter tree; it does not vendor Bun source.
- All mutation tests use only the registered projects under `test/fixtures/`.

## Build and test

Requirements: macOS, Rust 1.96.0, Cargo and Bun 1.3.14. The default public gate does not require a local Lean checkout or Bun source checkout.

```sh
./scripts/test-public.sh
cargo build --locked --manifest-path rust/Cargo.toml
```

Reconstructing the integrated executable and running deeper fixture acceptance requires separately initialized, revision-locked Bun and Lean/Lake source/toolchain snapshots. See `doc/LEANBUN_SOURCE_INSTALL_M48.adoc` and `doc/LEANBUN_OPERATOR_MANUAL_V1.adoc`; do not point those commands at a personal or production project.

## Repository map

- `rust/crates/`: fifteen audited crates: ten default lifecycle crates and five explicitly isolated historical crates.
- `test/fixtures/`: the only registered Lean/Lake test projects.
- `lean/probes/`: narrow Lean/Lake declaration probes.
- `architecture/`: machine-readable crate-boundary and compatibility snapshots.
- `distribution/bun-fork-patches/`: seven redacted patches that reproduce the paired Bun adapter tree from the pinned upstream commit.
- `config/leanbun-release-m48.json`: source, adapter, toolchain, reader, regression and rollback provenance.
- `config/upstream-bun.lock.json`: exact Bun upstream source identity used by this snapshot.

## Status and security

The code is pre-release and fixture-scoped. Fail-closed checks are intentional. Please report security issues privately as described in `SECURITY.md`.

Licensed under Apache-2.0.
