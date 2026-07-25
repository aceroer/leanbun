# Third-party provenance

This repository does not vendor Bun, Lean, Lake or Mathlib source code.

- Bun upstream identity is pinned in `config/upstream-bun.lock.json`; Bun's own license applies to Bun.
- Lean and Lake fixture toolchains are pinned by `lean-toolchain` files and manifest metadata; their own licenses apply.
- Mathlib dependency identities are recorded in the registered fixture manifest; Mathlib and its dependencies retain their own licenses.
- Rust registry dependencies are resolved by `rust/Cargo.lock` and retain their upstream licenses.
