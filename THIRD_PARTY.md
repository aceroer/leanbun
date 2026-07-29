# Third-party provenance

This repository does not vendor Bun, Lean, Lake or Mathlib source code. It carries a redacted seven-patch adapter series whose replay identity is fixed by the M48 provenance manifest.

- Bun upstream identity is pinned in `config/upstream-bun.lock.json`; Bun's own license applies to Bun and to the reconstructed fork source.
- Lean and Lake fixture toolchains are pinned by `lean-toolchain` files and manifest metadata; their own licenses apply.
- Mathlib dependency identities are recorded in the registered fixture manifest; Mathlib and its dependencies retain their own licenses.
- Rust registry dependencies are resolved by `rust/Cargo.lock` and retain their upstream licenses.
