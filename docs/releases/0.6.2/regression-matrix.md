# regression-matrix

| Path | Covered by | Expected behavior |
|---|---|---|
| `src/luau.mjs` | normalized findings and bridge hooks | finding records carry severity, confidence, brain note IDs, and stable identities |
| `src/brain.mjs` | finding identity, history, graph, and pruning | finding notes can be queried, traced, graphed, and conservatively pruned |
| `src/core.mjs` | MCP surface and versioning | `0.6.2` is exposed through healthcheck and the canonical tool count reaches `66` |
| `test/luau-findings.test.mjs` | normalized findings | `luau.findings` returns bridgeable findings with deterministic note IDs |
| `test/luau-brain-bridge.test.mjs` | auto-persistence | `luau.security_scan` and `luau.brain_sync` write brain notes automatically for findings |
| `test/brain-findings.test.mjs` | brain reading and cleanup | finding notes can be queried, graphed, and pruned without errors |
| `test/mcp.test.mjs` | compatibility and versioning | MCP resources stay intact and the healthcheck reports `0.6.2` with the expanded tool count |
