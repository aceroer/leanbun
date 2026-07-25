# GitHub publication handoff

Suggested repository name: `leanbun`

Suggested description: `Experimental Rust/Bun transaction and dependency layer for Lean/Lake package workflows.`

Suggested topics: `lean`, `lean4`, `lake`, `bun`, `rust`, `package-manager`, `dependency-management`, `reproducible-builds`

## Before making the repository public

1. Create an empty GitHub repository without generated README, license or gitignore files.
2. Enable private vulnerability reporting and secret scanning where available.
3. Push this repository's `main` branch and wait for the `public-gate` workflow.
4. Protect `main` with the public gate required and disallow force pushes.
5. Confirm that the GitHub file browser contains no `.leanbun-dev`, `.leanbun-dev-rust`, `.lake` or `rust/target` content.
6. Do not publish a binary release yet: Developer ID signing, notarization and release-tag replay remain separate distribution gates.

This handoff intentionally has no configured remote and performs no GitHub-side mutation.
