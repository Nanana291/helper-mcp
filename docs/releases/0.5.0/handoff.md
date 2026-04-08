# [HANDOFF] helper-mcp 0.5.0

- `changed`: `package.json`, `package-lock.json`, `README.md`, `src/core.mjs`, `src/brain.mjs`, `src/luau.mjs`, `src/workspace.mjs`, `src/config.mjs`, tests under `test/`, release artifacts under `docs/releases/0.5.0/`
- `new tools`: `brain_import`, `luau_hotfix`, `luau_decompile`, `luau_security_scan`, `luau_performance_profile`, `luau_dependency_map`, `luau_template`, `workspace_baseline`, `workspace_changelog`, `config_validate`
- `must not change next`: existing aliases for `healthcheck`, `workspace_summary`, `brain_snapshot`, `luau_scan`, `luau_inspect`, `luau_compare`, `luau_note`
- `follow-up`: keep hotfix transforms conservative and preserve the workspace-local storage boundary under `.helper-mcp/`
