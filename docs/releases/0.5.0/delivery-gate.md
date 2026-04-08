# [DELIVERY GATE] helper-mcp 0.5.0

- `baselineUpdated`: yes, via temp-workspace regression tests and the new baseline/changelog flow
- `regressionMatrix`: yes, documented in `docs/releases/0.5.0/regression-matrix.md`
- `oldToNewMapping`: not a rewrite; existing tools remain and new tools were added alongside them
- `ownedDomainsClosed`: `logic`, `brain`, `config`, `workspace`, `regression-proof`
- `openRisks`: hotfix heuristics are conservative and may not rewrite every unsafe Luau pattern; config validation is schema-based and may need project-specific tuning
- `blockedOrReady`: ready after tests and push verification
