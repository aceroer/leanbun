# Contributing

Keep changes inside the documented ownership boundary: Bun orchestration, Lake interpretation and Lean compilation. New tests must use repository fixtures and must not depend on a contributor's personal projects or absolute paths.

Before submitting a change, run:

```sh
./scripts/test-public.sh
```

Changes to lock formats, path precedence, transactions, recovery or cache publication should add both a positive fixture and a fail-closed negative case. Never commit generated `.lake`, `.leanbun-dev` or `.leanbun-dev-rust` state.
