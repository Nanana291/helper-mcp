# regression-matrix

| Path | Covered by | Expected behavior |
|---|---|---|
| `src/luau.mjs` | intelligence, repair, remote graph, dependency graph, complexity, changelog helpers | Findings carry severity/confidence metadata and `targetPath` filtering works for absolute and relative workspace paths |
| `src/brain.mjs` | graph, advanced query, link, archive, diff, duplicate cleanup | Brain relationships persist, diffs compare against snapshots, and pruning stays explicit |
| `src/workspace.mjs` | diff, rollback, validate, release notes, restore snapshot | Baselines and snapshots round-trip cleanly and restore helpers write back deterministic file content |
| `src/core.mjs` | MCP surface and versioning | `0.6.1` is exposed through healthcheck while canonical tools, aliases, and tool count remain stable |
| `test/luau-intelligence.test.mjs` | Luau intelligence coverage | Graph, taint, flow, handlers, modulegraph, scoring, and diff-context commands return structured output |
| `test/brain-platform.test.mjs` | brain graph and recovery coverage | Graph, link, archive, restore diff, diff, and pruning behavior stay deterministic |
| `test/workspace-automation.test.mjs` | workspace recovery coverage | Diff, validate, release notes, rollback, and restore snapshot commands round-trip a file in a temp workspace |
| `test/mcp.test.mjs` | compatibility and versioning | MCP resources still resolve and the healthcheck reports `0.6.1` with the expected tool count |
| `test/brain-advanced.test.mjs` | history and merge gating | Brain events remain ordered and merge application refuses incomplete inputs |
| `test/luau-advanced.test.mjs` | Luau recovery and metadata | Repair, dependency, remote, complexity, metrics, and changelog paths keep returning structured output |
| `test/workspace.test.mjs` | baseline parity | Baselines and changelogs still round-trip in a temp workspace |
