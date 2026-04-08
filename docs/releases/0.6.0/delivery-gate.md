# [DELIVERY GATE] helper-mcp 0.6.0

- `baselineUpdated`: yes, via regression tests around false positives, history ordering, and recovery persistence
- `regressionMatrix`: yes, documented in `docs/releases/0.6.0/regression-matrix.md`
- `oldToNewMapping`: stable surface; no canonical tool removals or alias breakage
- `ownedDomainsClosed`: Luau analysis, brain hygiene, workspace recovery, release proof
- `openRisks`: future pattern overrides can still be project-specific, so new false positives should be guarded with fixture tests
- `blockedOrReady`: ready after full-suite verification and push verification

