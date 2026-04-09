# helper-mcp Usage Reference

## What it is
Local MCP server that provides Luau-first second brain capabilities for coding agents.

## Location
`/storage/emulated/0/Download/helper-mcp`

## Start Commands
| Command | Transport | Use Case |
|---------|-----------|----------|
| `npm start` | stdio | Claude Code, Qwen Code |
| `npm run start:http` | HTTP | Direct HTTP access |
| `npm run start:tunnel` | HTTPS tunnel | Codex, remote access |

## MCP Tools

### Health & Workspace
- **healthcheck** - Server health and tool availability
- **workspace_summary** - Workspace + Luau coverage summary
- **workspace_risks** - Risk report sorted by risk count
- **workspace_coverage** - Brain note coverage across Luau files
- **workspace_audit** - Combined health audit (pcall, local pressure, legacy API, unbounded loops)

### Brain (Knowledge Storage)
- **brain_add** - Store reusable lesson (title, summary required)
- **brain_teach** - Store structured lesson (mistake→fix→rule format)
- **brain_search** - Search brain notes + workspace files
- **brain_list** - List notes, filter by status/tag
- **brain_snapshot** - Current brain summary
- **brain_promote** - Change note status by ID
- **brain_tag** - Add tags to note by ID
- **brain_update** - Edit title/summary/evidence/scope by ID
- **brain_delete** - Permanently delete note by ID
- **brain_export** - Export all notes to Markdown

### Luau Analysis
- **luau_scan** - Scan workspace for Luau files + pattern summary
- **luau_inspect** - Inspect single file (callbacks, remotes, state, UI, risks, local pressure)
- **luau_compare** - Compare file against baseline (metric delta)
- **luau_diff** - Structural diff (added/removed functions, remote/callback deltas)
- **luau_pattern** - Regex search across all Luau files
- **luau_flags** - Scan for LibSixtyTen Flag definitions/reads (detects duplicates/orphaned)
- **luau_ui_map** - Extract LibSixtyTen Page→Category→Section→Controls hierarchy
- **luau_migration** - Migration checklist between two files (BLOCKED/REVIEW/READY verdict)
- **luau_note** - Store Luau-specific lesson in brain

## Brain Storage
- Location: `.helper-mcp/` in workspace root
- Configurable via `HELPER_MCP_ROOT` env var
- Write tools only affect local brain store

## When to Use
- Before editing Luau scripts: `brain_search` for prior knowledge
- Before making changes: `luau_inspect` or `luau_scan`
- After audits/fixes: `brain_add` or `luau_note` to record findings
- When comparing versions: `luau_compare` or `luau_diff`
- Before migrations: `luau_migration` for checklist
- Periodically: `workspace_audit` for health check

## Read-Only Resources
- `helper://workspace/summary`
- `helper://brain/snapshot`
- `helper://luau/scan`
