# LeanBun

LeanBun is an experimental Rust control layer for Lean/Lake package workflows. It uses Bun's package-management model for locking, deterministic path selection, concurrent fetch, immutable cache publication, transactions, recovery and rollback, while leaving Lean compilation and Lake project interpretation to Lean/Lake.

The current development snapshot is `0.22.0-m49-dev`. In addition to the M48 source-only baseline, it adds a strict managed-library registry and an explicit `manage add/list/status` front door for deliberately selected, supported local projects. It is not yet a general-purpose package manager: discovery, URL intake, implicit current-directory adoption, rebind, retarget and removal remain closed.

## Why LeanBun

Lake is Lean's build tool and remains the build executor, but dependency updates can combine mutable manifests, several competing path provenances, network checkout, local cache state and compilation in one workflow. A failure can therefore leave an operator reconstructing which revision and path actually won. LeanBun separates those package-management concerns: it freezes exact dependency identities, makes one deterministic final-path decision, publishes immutable cache objects and generations transactionally, and retains recovery and rollback state. It supplements Lean/Lake; it does not replace Lean elaboration, proof checking or Lake builds.

## Boundary

- Bun owns external dependency orchestration, final package-path decisions, locking, cache publication and update transactions.
- Lake remains the general declaration authority and build executor. M49 intake accepts only a narrow, filesystem-parsed `lakefile.toml` subset and never executes project Lake configuration.
- Lean remains the compiler and proof checker.
- The repository contains the Rust lifecycle crates and a redacted patch series that reconstructs the reviewed Bun adapter tree; it does not vendor Bun source.
- All mutation tests use only the registered projects under `test/fixtures/`.

## Quick start

Requirements: macOS, Rust 1.96.0, Cargo and Bun 1.3.14. The default public gate does not require a local Lean checkout or Bun source checkout.

```sh
./scripts/test-public.sh
cargo build --locked --manifest-path rust/Cargo.toml
```

Reconstructing the integrated executable and running deeper fixture acceptance requires separately initialized, revision-locked Bun and Lean/Lake source/toolchain snapshots. See `docs/operator/LEANBUN_SOURCE_INSTALL_M48.adoc`, then apply the single incremental patch in `distribution/bun-fork-m49-patches/` on top of the M48 tree. Do not point these commands at a personal or production project.

With the paired development binary built, copy the small registered test project and explicitly place that copy under management:

```sh
BIN=.leanbun-dev-rust/release/bun-fork/target/release/leanbun
cp -R test/fixtures/lake-managed-dependency /private/tmp/leanbun-managed-example
$BIN manage add "$PWD" /private/tmp/leanbun-managed-example \
  --target=leanbun_managed_dependency_fixture \
  --explicit-managed-project
$BIN manage list "$PWD"
$BIN manage list "$PWD" --json
$BIN manage status "$PWD" /private/tmp/leanbun-managed-example --json
```

The first path is the explicit repository/configuration argument required by the source-tree development adapter; it is not part of project identity. `manage add` performs a filesystem-only plan, requires the exact confirmation token, then publishes a pending record and one generation before activation. It writes no project source and creates no project `.lake`. `list/status` execute no Lake command, network request, repair or write. Exit 0 means healthy, exit 2 means an attention state such as `drifted` or `unmanaged`, exit 64 is usage failure, and exit 1 is a rejected intake or unsafe authority failure.

## Repository map

- `rust/crates/`: fifteen audited crates: ten default lifecycle crates and five explicitly isolated historical crates.
- `test/fixtures/`: the only registered Lean/Lake test projects.
- `lean/probes/`: narrow Lean/Lake declaration probes.
- `architecture/`: machine-readable crate-boundary and compatibility snapshots.
- `distribution/bun-fork-patches/`: seven redacted patches that reproduce the paired Bun adapter tree from the pinned upstream commit.
- `distribution/bun-fork-m49-patches/`: one redacted unified M49 patch applied after the frozen M48 series.
- `docs/decisions/MANAGED_LIBRARY_INTAKE_REGISTRY_CONTRACT_M49A.adoc`: registry and intake authority contract.
- `docs/milestones/RUST_MANAGED_LIBRARY_REGISTRY_M49B.adoc`: M49B implementation and validation evidence.
- `docs/milestones/RUST_MANAGED_LIBRARY_INTAKE_M49C_M49D.adoc`: M49C/D intake and lifecycle closure evidence.
- `config/leanbun-development-m49.json`: M49 source, patch, binary, intake-boundary and validation provenance.
- `config/leanbun-release-m48.json`: source, adapter, toolchain, reader, regression and rollback provenance.
- `config/upstream-bun.lock.json`: exact Bun upstream source identity used by this snapshot.

## Status and security

The code is pre-release and fixture-scoped. Fail-closed checks are intentional. Please report security issues privately as described in `SECURITY.md`.

Licensed under Apache-2.0.
