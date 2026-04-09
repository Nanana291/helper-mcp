# helper-mcp OpenCode installability

## Goal

Make `helper-mcp` installable in OpenCode as a local MCP server using OpenCode's native project config.

The intent is not to add new server behavior. The server already speaks MCP over stdio and already exposes the tool surface OpenCode can consume. The missing piece is a repo-root OpenCode config plus documentation and a small contract test so the repo can be opened in OpenCode without manual wiring.

## Current state

- `helper-mcp` already runs as a stdio MCP server through `src/index.mjs`.
- The repo already supports Claude Code, Codex, and Qwen in `README.md`.
- There is no `opencode.json` in the repo root yet.
- OpenCode supports local MCP servers through `opencode.json` with `mcp.<name>.type = "local"` and a `command` array.

## Proposed approach

Use a repo-root `opencode.json` that declares `helper-mcp` as a local MCP server.

This is the cleanest option because:

- it matches OpenCode's native config model
- it requires no new runtime code
- it keeps installability tied to the repository itself
- it is easy to verify in tests

## Configuration

Add `opencode.json` at the repository root with a single local MCP server entry:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "helper-mcp": {
      "type": "local",
      "command": ["node", "./src/index.mjs"],
      "enabled": true
    }
  }
}
```

### Why this shape

- `type: "local"` matches OpenCode's documented local server format.
- `command: ["node", "./src/index.mjs"]` uses the existing stdio entrypoint.
- `enabled: true` makes the server available immediately when the repo is opened in OpenCode.

## Documentation changes

Update `README.md` with an OpenCode install section that explains:

- clone the repo
- open the repo in OpenCode
- OpenCode will read `opencode.json` automatically
- the MCP server is exposed as `helper-mcp`

The README should also mention that the server uses stdio and stores workspace-local state in `.helper-mcp/`.

## Test coverage

Add a small contract test that verifies:

- `opencode.json` exists at the repo root
- the config declares `mcp.helper-mcp`
- the entry uses `type: "local"`
- the command points to `./src/index.mjs`

The test should be a file-surface check, not an OpenCode runtime test. The server runtime itself is already covered by the existing MCP test suite.

## Non-goals

- No new transport support.
- No new server commands.
- No global OpenCode installer.
- No wrapper scripts around `src/index.mjs`.

## Risks

- If OpenCode changes its config schema, the repo-root config may need a follow-up adjustment.
- If a user opens the repo from a path where relative commands behave differently, the docs should make it clear that the config is meant to live at the repo root.

## Success criteria

- A fresh clone can be opened in OpenCode and see `helper-mcp` as an available MCP server.
- The README documents the install path clearly.
- Tests fail if the OpenCode config is missing or points at the wrong entrypoint.
