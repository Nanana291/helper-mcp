# helper-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local MCP server for Luau work that can scan scripts, compare against baselines, and keep a workspace-local second brain of reusable lessons.

**Architecture:** Keep the server stdio-based and workspace-local. The server will read the current working directory by default, analyze Luau files with pure helper functions, and store notes in `.helper-mcp/` so Claude Code, Codex, and Qwen Code can all reuse the same server without a separate backend.

**Tech Stack:** Node.js ESM, `@modelcontextprotocol/sdk`, plain filesystem utilities, Node test runner.

---

### Task 1: Scaffold the MCP package

**Files:**
- Create: `package.json`
- Create: `README.md`
- Create: `.gitignore`
- Create: `src/index.mjs`
- Create: `src/brain.mjs`
- Create: `src/luau.mjs`
- Create: `src/fs.mjs`

- [ ] **Step 1: Add the package metadata and install surface**

```json
{
  "name": "helper-mcp",
  "version": "0.1.0",
  "type": "module",
  "bin": {
    "helper-mcp": "./src/index.mjs"
  }
}
```

- [ ] **Step 2: Add the workspace README with install commands**

```bash
claude mcp add helper-mcp --scope user -- node /absolute/path/to/helper-mcp/src/index.mjs
codex mcp add helper-mcp -- node /absolute/path/to/helper-mcp/src/index.mjs
qwen mcp add --scope user --transport stdio helper-mcp node /absolute/path/to/helper-mcp/src/index.mjs
```

- [ ] **Step 3: Add the gitignore and local brain storage boundary**

```text
node_modules
.helper-mcp
npm-debug.log*
*.log
```

### Task 2: Implement Luau analysis and brain storage

**Files:**
- Create: `src/fs.mjs`
- Create: `src/brain.mjs`
- Create: `src/luau.mjs`

- [ ] **Step 1: Add workspace discovery and file walking helpers**

```javascript
export function resolveWorkspaceRoot() {
  return process.env.HELPER_MCP_ROOT ? path.resolve(process.env.HELPER_MCP_ROOT) : process.cwd();
}
```

- [ ] **Step 2: Add the local brain note store**

```javascript
export function appendBrainNote(root, note) {
  // write to .helper-mcp/brain/notes.jsonl and rebuild the current snapshot
}
```

- [ ] **Step 3: Add Luau scanning and inspection helpers**

```javascript
export function analyzeLuauText(text, filePath) {
  return {
    callbacks: [],
    remotes: [],
    state: [],
    ui: [],
    risks: [],
  };
}
```

- [ ] **Step 4: Add Luau baseline comparison**

```javascript
export function compareLuauFiles(currentPath, baselinePath) {
  return {
    missingCategories: [],
    addedCategories: [],
    riskDelta: [],
  };
}
```

### Task 3: Wire the MCP server

**Files:**
- Create: `src/index.mjs`

- [ ] **Step 1: Register the tools and resources**

```javascript
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: []
}));
```

- [ ] **Step 2: Route tool calls to the Luau and brain helpers**

```javascript
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
});
```

- [ ] **Step 3: Add workspace and brain resources for quick context fetches**

```javascript
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: []
}));
```

- [ ] **Step 4: Start the stdio transport**

```javascript
await server.connect(new StdioServerTransport());
```

### Task 4: Verify and publish

**Files:**
- Create: `test/*.test.mjs` if needed

- [ ] **Step 1: Add tests for the pure Luau and brain helpers**

```bash
node --test
```

- [ ] **Step 2: Commit the new repository**

```bash
git add .
git commit -m "feat: create helper-mcp"
```

- [ ] **Step 3: Create the GitHub repository and push it**

```bash
gh repo create Nanana291/helper-mcp --private --source . --remote origin --push
```

