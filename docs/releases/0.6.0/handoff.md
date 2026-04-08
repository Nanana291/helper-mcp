# [HANDOFF] helper-mcp 0.6.0

- `changed`: `package.json`, `package-lock.json`, `src/core.mjs`, `src/luau.mjs`, `src/brain.mjs`, `src/metrics.mjs`, tests under `test/`, release artifacts under `docs/releases/0.6.0/`
- `release theme`: stabilization and trust hardening
- `new behavior`: severity/confidence metadata for Luau findings, explicit merge guards, ordered brain history, append-only metric snapshots
- `must not change next`: canonical tool names, compatibility aliases, recovery artifact paths, and fail-closed pattern override behavior
- `follow-up`: keep false-positive work constrained to the existing pattern engine and guard any future analysis expansion behind the current regression suite

