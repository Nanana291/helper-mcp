# helper-mcp

`helper-mcp` is a local MCP server that gives coding agents a Luau-first second brain.

It is designed to help with tasks like:

- scanning Luau scripts for callbacks, remotes, UI wiring, and state patterns
- comparing a script against a baseline
- saving reusable lessons into a workspace-local brain
- searching prior notes before making another pass

## What it exposes

- `healthcheck`
- `workspace.summary`
- `brain.add`
- `brain.search`
- `brain.snapshot`
- `luau.scan`
- `luau.inspect`
- `luau.compare`
- `luau.note`

The advertised tool names use underscore-friendly aliases for maximum client compatibility,
for example `brain_snapshot` instead of `brain.snapshot`.

The server still accepts the dotted canonical names internally, but it does not advertise them by default.

The server also exposes read-only resources:

- `helper://workspace/summary`
- `helper://brain/snapshot`
- `helper://luau/scan`

## Install

Clone the repo:

```bash
git clone https://github.com/Nanana291/helper-mcp.git
cd helper-mcp
npm install
```

The server runs from the repo root and stores its local brain in `.helper-mcp/`.
The default transport is stdio, which works with Claude Code and Qwen Code.
For Codex, there is also a local streamable HTTP transport that exposes the same tools and resources.

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

Start the HTTP server in one terminal:

```bash
node /absolute/path/to/helper-mcp/src/http.mjs
```

Add it to Codex as a streamable HTTP server:

```bash
codex mcp add helper-mcp --url http://127.0.0.1:3333/mcp
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
- If a client has trouble with dotted tool names, use the underscore alias with the same behavior.
- For Codex, keep the HTTP server running while the session uses the MCP tools.
