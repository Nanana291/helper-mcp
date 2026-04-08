# [HANDOFF] helper-mcp 0.6.2

- `changed`: `package.json`, `package-lock.json`, `src/core.mjs`, `src/luau.mjs`, `src/brain.mjs`, tests under `test/`, release artifacts under `docs/releases/0.6.2/`
- `release theme`: Luau intelligence now persists into brain automatically
- `new behavior`: `luau.findings`, `luau.brain_sync`, auto-bridged findings for Luau analyzers, `brain.findings`, `brain.finding_history`, `brain.finding_graph`, `brain.finding_prune`
- `must not change next`: deterministic finding IDs, bridge note status mapping, stable aliases, and existing 0.6.1 behavior
- `follow-up`: keep future bridge expansions covered by fixture tests so new finding types cannot write noisy memory unchecked
