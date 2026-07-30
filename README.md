# LeanBun

LeanBun is an experimental Rust control layer for Lean/Lake package workflows. It uses Bun's package-management model for locking, deterministic path selection, concurrent fetch, immutable cache publication, transactions, recovery and rollback, while leaving Lean compilation and Lake project interpretation to Lean/Lake.

The current development snapshot is `0.24.0-m50c-dev`, with the complete M50 source-distribution and lifecycle gate closed. In addition to the M49 managed-library registry and explicit intake, it provides generation-bound managed build and non-interactive run front doors for deliberately selected, supported local projects. It is not yet a general-purpose package manager: discovery, URL intake, implicit current-directory adoption, rebind, retarget and removal remain closed.

## Why LeanBun

Lake is Lean's build tool and remains the build executor, but dependency updates can combine mutable manifests, several competing path provenances, network checkout, local cache state and compilation in one workflow. A failure can therefore leave an operator reconstructing which revision and path actually won. LeanBun separates those package-management concerns: it freezes exact dependency identities, makes one deterministic final-path decision, publishes immutable cache objects and generations transactionally, and retains recovery and rollback state. It supplements Lean/Lake; it does not replace Lean elaboration, proof checking or Lake builds.

## Boundary

- Bun owns external dependency orchestration, final package-path decisions, locking, cache publication and update transactions.
- Lake remains the general declaration authority and build executor. M49 intake accepts only a narrow, filesystem-parsed `lakefile.toml` subset and never executes project Lake configuration.
- Lean remains the compiler and proof checker.
- The repository contains the Rust lifecycle crates and a redacted patch series that reconstructs the reviewed Bun adapter tree; it does not vendor Bun source.
- All mutation acceptance uses repository-maintained copies originating in `test/fixtures/`; it does not target personal or production projects.

## Quick start

Requirements: macOS, Rust 1.96.0, Cargo and Bun 1.3.14. The default public gate does not require a local Lean checkout or Bun source checkout.

```sh
./scripts/test-public.sh
cargo build --locked --manifest-path rust/Cargo.toml
```

Reconstructing the integrated executable and running deeper fixture acceptance requires separately initialized, revision-locked Bun and Lean/Lake source/toolchain snapshots. See `docs/operator/LEANBUN_SOURCE_INSTALL_M48.adoc`, then apply the M49 patch followed by the M50 patch from their respective `distribution/` directories. Do not point these commands at a personal or production project.

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
$BIN build "$PWD" /private/tmp/leanbun-managed-example
# The exact ProjectId printed by manage add/status is accepted too:
$BIN build "$PWD" <project-id>
$BIN run "$PWD" /private/tmp/leanbun-managed-example
$BIN run "$PWD" <project-id> -- argument "two words"
```

The first path is the explicit repository/configuration argument required by the source-tree development adapter; it is not part of project identity. `manage add` performs a filesystem-only plan, requires the exact confirmation token, then publishes a pending record and one generation before activation. It writes no project source and creates no project `.lake`. `list/status` execute no Lake command, network request, repair or write. Exit 0 means healthy, exit 2 means an attention state such as `drifted` or `unmanaged`, exit 64 is usage failure, and exit 1 is a rejected intake or unsafe authority failure.

`build` accepts only the exact registered path or ProjectId. It requires a stable `healthy` selection, holds the per-project operation lease against update/recovery/rollback, reverifies the same active generation and all final paths, and then runs the existing offline supervised Lake build.

`run` accepts the same selectors and requires the recorded target to be exactly one `[[lean_exe]]`. It builds and runs under one operation lease, selects only `.lake/build/bin/<target>`, clears the environment, denies network and project writes, uses null stdin, bounds captured stdout/stderr, and reverifies generation, artifact and executable identities afterward. Program arguments require `--`. This remains a cooperative source-tree development boundary; it does not claim OS-enforced protection from a malicious process running as the same user.

## Repository map

- `rust/crates/`: fifteen audited crates: ten default lifecycle crates and five explicitly isolated historical crates.
- `test/fixtures/`: the only registered Lean/Lake test projects.
- `lean/probes/`: narrow Lean/Lake declaration probes.
- `architecture/`: machine-readable crate-boundary and compatibility snapshots.
- `distribution/bun-fork-patches/`: seven redacted patches that reproduce the paired Bun adapter tree from the pinned upstream commit.
- `distribution/bun-fork-m49-patches/`: one redacted unified M49 patch applied after the frozen M48 series.
- `distribution/bun-fork-m50-patches/`: two redacted M50 build/run front-door patches applied after M49.
- `docs/decisions/MANAGED_LIBRARY_INTAKE_REGISTRY_CONTRACT_M49A.adoc`: registry and intake authority contract.
- `docs/milestones/RUST_MANAGED_LIBRARY_REGISTRY_M49B.adoc`: M49B implementation and validation evidence.
- `docs/milestones/RUST_MANAGED_LIBRARY_INTAKE_M49C_M49D.adoc`: M49C/D intake and lifecycle closure evidence.
- `docs/milestones/RUST_MANAGED_BUILD_FRONT_DOOR_M50B.adoc`: M50A/B selection, operation-lease and real-build closure evidence.
- `docs/milestones/RUST_MANAGED_RUN_FRONT_DOOR_M50C.adoc`: M50C executable classification, supervised run and real-run closure evidence.
- `docs/milestones/RUST_MANAGED_DISTRIBUTION_CLOSURE_M50D.adoc`: clean-clone, patch-replay and update/rollback/build/run lifecycle closure evidence.
- `config/leanbun-development-m50.json`: unified M50 source, paired-patch, binary, lifecycle and clean-clone provenance.
- `config/leanbun-development-m50c.json`: M50C source, paired-patch, binary and validation provenance.
- `config/leanbun-development-m50b.json`: M50B source, paired-patch, binary and validation provenance.
- `config/leanbun-development-m49.json`: M49 source, patch, binary, intake-boundary and validation provenance.
- `config/leanbun-release-m48.json`: source, adapter, toolchain, reader, regression and rollback provenance.
- `config/upstream-bun.lock.json`: exact Bun upstream source identity used by this snapshot.

## Status and security

The code is pre-release and fixture-scoped. Fail-closed checks are intentional. Please report security issues privately as described in `SECURITY.md`.

Licensed under Apache-2.0.
