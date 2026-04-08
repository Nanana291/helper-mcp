# helper-mcp

`helper-mcp` is a local MCP server that gives coding agents a Luau-first second brain.

It is designed to help with tasks like:

- scanning Luau scripts for callbacks, remotes, UI wiring, and state patterns
- comparing a script against a baseline
- saving reusable lessons into a workspace-local brain
- searching prior notes before making another pass

## What it exposes

- `workspace.summary`
- `brain.add`
- `brain.search`
- `brain.snapshot`
- `luau.scan`
- `luau.inspect`
- `luau.compare`
- `luau.note`

## Install

Clone the repo:

```bash
git clone https://github.com/Nanana291/helper-mcp.git
cd helper-mcp
npm install
```

The server runs from the repo root and stores its local brain in `.helper-mcp/`.

## Claude Code

Add the server from the cloned path:

```bash
claude mcp add helper-mcp --scope user -- node /absolute/path/to/helper-mcp/src/index.mjs
```

Verify it was added:

```bash
claude mcp get helper-mcp
```

## Codex

Add the server from the cloned path:

```bash
codex mcp add helper-mcp -- node /absolute/path/to/helper-mcp/src/index.mjs
```

Verify it was added:

```bash
codex mcp list
```

## Qwen Code

Add the server to your project config:

```bash
qwen mcp add --scope user --transport stdio helper-mcp node /absolute/path/to/helper-mcp/src/index.mjs
```

Verify it was added:

```bash
qwen mcp list
```

## Notes

- Use a trusted workspace. `helper-mcp` reads local files from the current project root.
- Set `HELPER_MCP_ROOT` if you need the server to point at a different workspace root.
- The write tools only affect the local `.helper-mcp/` brain store.

