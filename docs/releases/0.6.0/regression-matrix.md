# regression-matrix

| Path | Covered by | Expected behavior |
|---|---|---|
| `src/luau.mjs` | analysis, repair, remote graph, complexity, changelog helpers | Findings carry severity/confidence metadata; benign snippets stay clean; recovery helpers stay conservative |
| `src/patterns.mjs` | pattern override loading | `.helper-mcp/patterns.json` overrides only the categories it defines and falls back safely on bad input |
| `src/brain.mjs` | history and merge behavior | History is ordered by latest updates and merge application stays explicit |
| `src/metrics.mjs` | trend snapshots | Metric snapshots append to JSONL and trend comparisons are deterministic |
| `src/core.mjs` | MCP surface and versioning | `0.6.0` is exposed through healthcheck while canonical tools and aliases remain stable |
| `test/luau-regex.test.mjs` | false-positive protection | Benign snippets stay below the risk threshold and override files take effect |
| `test/luau-advanced.test.mjs` | Luau recovery and metadata | Repair, dependency, remote, complexity, and metrics paths keep returning structured output |
| `test/brain-advanced.test.mjs` | history and merge gating | Brain events are ordered and merge application refuses incomplete inputs |
| `test/mcp.test.mjs` | compatibility and versioning | MCP resources still resolve and the healthcheck reports `0.6.0` with the expected tool count |
| `test/workspace.test.mjs` | baseline parity | Baselines and changelogs still round-trip in a temp workspace |

