# regression-matrix

| Path | Covered by | Expected behavior |
|---|---|---|
| `src/core.mjs` | MCP tool registry | Existing tools stay visible; new canonical tools are added with underscore aliases |
| `src/luau.mjs` | analysis, hotfix, security, performance, decompile | New analysis helpers return structured findings; hotfix writes before/after snapshots |
| `src/brain.mjs` | brain import | Notes can be imported from markdown, JSON, and text sources |
| `src/workspace.mjs` | baseline and changelog | Baselines serialize current script state and changelogs describe drift |
| `src/config.mjs` | config validate | JSON configs validate against scalar, keybind, and color shapes |
| `test/mcp.test.mjs` | compatibility | Existing aliases still resolve and tool count updates to 19 |
| `test/luau.test.mjs` | analysis parity | Legacy scan/compare still passes while new analyzers report findings |
| `test/workspace.test.mjs` | baseline parity | Baselines and changelogs round-trip in a temp workspace |
| `test/config.test.mjs` | config parity | Invalid config shapes are reported with suggestions |
| `test/brain-import.test.mjs` | import parity | Imported notes are counted and tagged correctly |
