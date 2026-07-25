# LeanBun

LeanBun is an experimental Rust control layer for Lean/Lake package workflows. It uses Bun's package-management model for locking, deterministic path selection, concurrent fetch, immutable cache publication, transactions, recovery and rollback, while leaving Lean compilation and Lake project interpretation to Lean/Lake.

The current public snapshot is `0.11.0-m42-dev`. It closes the registered fixture workflow; it is not yet a general-purpose package manager and is not authorized to mutate arbitrary external projects.

## Boundary

- Bun owns external dependency orchestration, final package-path decisions, locking, cache publication and update transactions.
- Lake remains the parser and build executor for Lean project declarations.
- Lean remains the compiler and proof checker.
- The repository contains a Rust CLI adapter, not a vendored copy of Bun.
- All mutation tests use only the registered projects under `test/fixtures/`.

## Build and test

Requirements: macOS, Rust 1.96.0 and Cargo. The default public test gate does not require a local Lean or Bun checkout.

```sh
./scripts/test-public.sh
cargo build --locked --manifest-path rust/Cargo.toml -p leanbun
./rust/target/debug/leanbun version
```

The deeper fixture acceptance commands require separately initialized, revision-locked Bun and Lean/Lake source/toolchain snapshots. See `docs/OPERATOR_MANUAL.adoc`; do not point those commands at a personal or production project.

## Repository map

- `rust/crates/`: the nine-crate package lifecycle core and the `leanbun` CLI.
- `test/fixtures/`: the only registered Lean/Lake test projects.
- `lean/probes/`: narrow Lean/Lake declaration probes.
- `docs/architecture/`: implementation decisions from lock projection through supervised builds and managed entry.
- `test-evidence/`: path-free, identity-free summaries derived from the private regression records.
- `config/upstream-bun.lock.json`: exact Bun upstream source identity used by this snapshot.

## Status and security

The code is pre-release and fixture-scoped. Fail-closed checks are intentional. Please report security issues privately as described in `SECURITY.md`.

Licensed under Apache-2.0.
