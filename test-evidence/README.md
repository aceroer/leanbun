# Sanitized regression evidence

These files summarize the M48 source-release regression closure without publishing machine or operator identity. The three behavioral TSV tables retain the M42 fixture baseline; `validation-summary.json` records the expanded M48 mainline, historical-crate and Bun/Lean validation totals.

Removed fields include absolute paths, usernames, volume names, local repository commits, binary hashes, signing identities, run IDs, job IDs, project IDs, transaction IDs and per-run record digests. The retained fields are behavioral invariants: fixture name, package count, expected rejection code, recovery/rollback outcome, history counts and retention policy.

This is a derived disclosure record, not a substitute for rerunning the public gate. `MANIFEST.sha256` binds the disclosed files themselves.
