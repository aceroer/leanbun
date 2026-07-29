# GitHub publication handoff

Suggested repository name: `leanbun`

Suggested description: `Experimental Rust/Bun transaction and dependency layer for Lean/Lake package workflows.`

Suggested topics: `lean`, `lean4`, `lake`, `bun`, `rust`, `package-manager`, `dependency-management`, `reproducible-builds`

## Public release checklist

1. Run `./scripts/test-public.sh` from a clean checkout.
2. Confirm that `./scripts/check-public-source` passes and the patch replay tree matches the M48 provenance manifest.
3. Push `main`, wait for the `public-gate` workflow, then publish the annotated source tag `leanbun-v0.20.0-m48-dev` only at the validated public snapshot commit.
4. Keep `main` protected, require the public gate and disallow force pushes.
5. Confirm that the GitHub file browser contains no `.leanbun-dev`, `.leanbun-dev-rust`, `.lake`, `rust/target` or local provider configuration.
6. Keep private vulnerability reporting and secret scanning enabled where available.
7. Do not attach a binary release: Developer ID signing, notarization and Gatekeeper acceptance remain outside M48.

The public history is a sanitized snapshot history. Development-history commit identifiers recorded in the provenance manifest remain evidence identities; they are not imported into the public Git history.
