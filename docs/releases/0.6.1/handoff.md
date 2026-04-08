# [HANDOFF] helper-mcp 0.6.1

- `changed`: `package.json`, `package-lock.json`, `src/core.mjs`, `src/luau.mjs`, `src/brain.mjs`, `src/workspace.mjs`, tests under `test/`, release artifacts under `docs/releases/0.6.1/`
- `release theme`: large-scale capability expansion with confidence-aware analysis and recoverable workspace behavior
- `new behavior`: Luau taint/flow/handlers/surface/refactor/modulegraph/risk scoring, brain diff and recovery commands, workspace diff/rollback/validation/release notes, and 60 canonical tools on the MCP surface
- `must not change next`: canonical tool names, compatibility aliases, root-path normalization for Luau workspace filters, recovery snapshot formats, and fail-closed override behavior
- `follow-up`: keep new commands covered by fixture-based regression tests and avoid broadening heuristic scope without new proof
