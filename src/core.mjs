import path from 'node:path';
import {
  appendBrainNote,
  buildBrainSnapshot,
  deleteBrainNote,
  exportBrainToMarkdown,
  listBrainNotes,
  loadBrainSnapshot,
  promoteBrainNote,
  searchBrainNotes,
  tagBrainNote,
  updateBrainNote,
} from './brain.mjs';
import { analyzeLuauText, compareLuauFiles, diffLuauFiles, formatLuauAnalysis, patternSearchLuau, scanLuauWorkspace } from './luau.mjs';
import { readText } from './fs.mjs';

export const serverName = 'helper-mcp';
export const serverVersion = '0.3.0';

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function textResult(text) {
  return {
    content: [{ type: 'text', text }],
  };
}

function resourceResult(uri, text, mimeType = 'text/plain') {
  return {
    contents: [{ uri, mimeType, text }],
  };
}

function workspaceSummary(workspaceRoot) {
  const scan = scanLuauWorkspace(workspaceRoot);
  return {
    workspaceRoot,
    helperRoot: '.helper-mcp',
    totalLuauFiles: scan.totalFiles,
    totalCallbacks: scan.totalCallbacks,
    totalRemotes: scan.totalRemotes,
    totalRisks: scan.totalRisks,
  };
}

function workspaceRisks(workspaceRoot) {
  const scan = scanLuauWorkspace(workspaceRoot);
  const filesWithRisks = scan.files
    .filter((f) => f.summary.riskCount > 0)
    .sort((a, b) => b.summary.riskCount - a.summary.riskCount)
    .map((f) => ({
      file: f.filePath,
      riskCount: f.summary.riskCount,
      localCount: f.summary.localCount,
      risks: f.categories.risks,
    }));
  return {
    totalFiles: scan.totalFiles,
    filesWithRisks: filesWithRisks.length,
    totalRisks: scan.totalRisks,
    files: filesWithRisks,
  };
}

function workspaceCoverage(workspaceRoot) {
  const scan = scanLuauWorkspace(workspaceRoot);
  const notes = listBrainNotes(workspaceRoot, { limit: 9999 });

  const notesByPath = {};
  for (const note of notes) {
    if (note.sourcePath) {
      if (!notesByPath[note.sourcePath]) notesByPath[note.sourcePath] = [];
      notesByPath[note.sourcePath].push({ title: note.title, status: note.status });
    }
  }

  const files = scan.files.map((f) => ({
    file: f.filePath,
    riskCount: f.summary.riskCount,
    remoteCount: f.summary.remoteCount,
    callbackCount: f.summary.callbackCount,
    localCount: f.summary.localCount,
    covered: !!(notesByPath[f.filePath] && notesByPath[f.filePath].length > 0),
    notes: notesByPath[f.filePath] || [],
  }));

  return {
    totalFiles: scan.totalFiles,
    coveredFiles: files.filter((f) => f.covered).length,
    uncoveredFiles: files.filter((f) => !f.covered).length,
    files,
  };
}

function workspaceAudit(workspaceRoot) {
  const scan = scanLuauWorkspace(workspaceRoot);
  const actions = [];

  let totalRemotes = 0;
  let remotesWithPcall = 0;
  let totalLocals = 0;

  for (const f of scan.files) {
    const remoteCount = f.summary.remoteCount;
    const localCount = f.summary.localCount;
    totalRemotes += remoteCount;
    totalLocals += localCount;

    // Count remotes that have pcall on the same line
    const missingPcall = f.categories.risks.filter((r) => r.label === 'missing-pcall').length;
    remotesWithPcall += Math.max(0, remoteCount - missingPcall);

    // Local pressure
    if (localCount > 180) {
      actions.push({
        priority: 1,
        file: f.filePath,
        issue: 'local-pressure-critical',
        details: `${localCount} local declarations — near the 200-register Luau limit. Wrap page blocks in do...end or group into tables.`,
      });
    } else if (localCount > 150) {
      actions.push({
        priority: 2,
        file: f.filePath,
        issue: 'local-pressure-warning',
        details: `${localCount} local declarations — approaching the 200-register Luau limit.`,
      });
    }

    // Missing pcall
    if (missingPcall > 0) {
      const lines = f.categories.risks.filter((r) => r.label === 'missing-pcall').map((r) => r.line).join(', ');
      actions.push({
        priority: missingPcall >= 3 ? 1 : 2,
        file: f.filePath,
        issue: 'missing-pcall',
        details: `${missingPcall} remote call(s) without pcall at lines: ${lines}.`,
      });
    }

    // Legacy API risks
    const legacyRisks = f.categories.risks.filter((r) => ['wait', 'spawn', 'delay'].includes(r.label));
    if (legacyRisks.length > 0) {
      actions.push({
        priority: 3,
        file: f.filePath,
        issue: 'legacy-api',
        details: `${legacyRisks.length} use(s) of deprecated wait/spawn/delay — replace with task.wait/task.spawn/task.delay.`,
      });
    }

    // Unbounded loops
    const unbounded = f.categories.risks.filter((r) => r.label === 'unbounded-loop');
    if (unbounded.length > 0) {
      actions.push({
        priority: 2,
        file: f.filePath,
        issue: 'unbounded-loop',
        details: `${unbounded.length} while true do loop(s) — verify each has a proper exit condition.`,
      });
    }
  }

  // Sort by priority then file name
  actions.sort((a, b) => a.priority - b.priority || a.file.localeCompare(b.file));

  const pcallCoverage = totalRemotes > 0 ? Math.round((remotesWithPcall / totalRemotes) * 100) : 100;
  const avgLocalPressure = scan.totalFiles > 0 ? Math.round((totalLocals / scan.totalFiles / 200) * 100) : 0;

  return {
    summary: {
      totalFiles: scan.totalFiles,
      filesWithRisks: scan.files.filter((f) => f.summary.riskCount > 0).length,
      totalRisks: scan.totalRisks,
      pcallCoverage: `${pcallCoverage}%`,
      avgLocalPressure: `${avgLocalPressure}%`,
    },
    actionCount: actions.length,
    actions,
  };
}

function toolAnnotations(canonicalName) {
  const readOnlyTools = new Set([
    'healthcheck', 'workspace.summary', 'workspace.risks', 'workspace.coverage', 'workspace.audit',
    'brain.search', 'brain.snapshot', 'brain.list', 'brain.export',
    'luau.scan', 'luau.inspect', 'luau.compare', 'luau.diff', 'luau.pattern',
  ]);
  const readOnly = readOnlyTools.has(canonicalName);
  return {
    title: canonicalName.replace(/\./g, ' '),
    readOnlyHint: readOnly,
    destructiveHint: !readOnly,
    idempotentHint: readOnly,
    openWorldHint: false,
  };
}

const toolDefinitions = [
  // ── Meta ──────────────────────────────────────────────────────────────────
  {
    canonicalName: 'healthcheck',
    aliases: ['healthcheck', 'health_check', 'ping'],
    description: 'Return a compatibility and health summary for the MCP server.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  // ── Workspace ─────────────────────────────────────────────────────────────
  {
    canonicalName: 'workspace.summary',
    aliases: ['workspace.summary', 'workspace_summary'],
    description: 'Summarize the current workspace and Luau coverage.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'workspace.risks',
    aliases: ['workspace.risks', 'workspace_risks'],
    description: 'Return a risk-focused report for all Luau files in the workspace, sorted by risk count.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'workspace.coverage',
    aliases: ['workspace.coverage', 'workspace_coverage'],
    description: 'Show which Luau files have brain notes and which are uncovered.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'workspace.audit',
    aliases: ['workspace.audit', 'workspace_audit'],
    description: 'Combined workspace health audit: pcall coverage, local pressure, legacy API usage, unbounded loops — prioritized action list.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  // ── Brain ──────────────────────────────────────────────────────────────────
  {
    canonicalName: 'brain.add',
    aliases: ['brain.add', 'brain_add'],
    description: 'Store a reusable lesson in the local helper brain.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        summary: { type: 'string' },
        scope: { type: 'string' },
        status: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        sourcePath: { type: 'string' },
        evidence: { type: 'string' },
      },
      required: ['title', 'summary'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.search',
    aliases: ['brain.search', 'brain_search'],
    description: 'Search local helper brain notes and workspace files. Results are ranked by relevance.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'number' },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.list',
    aliases: ['brain.list', 'brain_list'],
    description: 'List brain notes, optionally filtered by status or tag.',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        tag: { type: 'string' },
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.snapshot',
    aliases: ['brain.snapshot', 'brain_snapshot'],
    description: 'Return the current local brain snapshot summary.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'brain.promote',
    aliases: ['brain.promote', 'brain_promote'],
    description: 'Change the status of an existing brain note by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        status: { type: 'string' },
      },
      required: ['id', 'status'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.tag',
    aliases: ['brain.tag', 'brain_tag'],
    description: 'Add tags to an existing brain note by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
      },
      required: ['id', 'tags'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.update',
    aliases: ['brain.update', 'brain_update'],
    description: 'Edit the title, summary, evidence, or scope of an existing brain note by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        title: { type: 'string' },
        summary: { type: 'string' },
        evidence: { type: 'string' },
        scope: { type: 'string' },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.delete',
    aliases: ['brain.delete', 'brain_delete'],
    description: 'Permanently delete a brain note by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.export',
    aliases: ['brain.export', 'brain_export'],
    description: 'Export all brain notes to Markdown, grouped by scope.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  // ── Luau ───────────────────────────────────────────────────────────────────
  {
    canonicalName: 'luau.scan',
    aliases: ['luau.scan', 'luau_scan'],
    description: 'Scan the workspace for Luau files and summarize their patterns.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'luau.inspect',
    aliases: ['luau.inspect', 'luau_inspect'],
    description: 'Inspect a single Luau file for callbacks, remotes, state, UI, risks, and local pressure.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
      },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.compare',
    aliases: ['luau.compare', 'luau_compare'],
    description: 'Compare a Luau file against a baseline file (metric delta).',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        baselinePath: { type: 'string' },
      },
      required: ['filePath', 'baselinePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.diff',
    aliases: ['luau.diff', 'luau_diff'],
    description: 'Structural diff between two Luau files: added/removed functions, remote and callback deltas.',
    inputSchema: {
      type: 'object',
      properties: {
        pathA: { type: 'string' },
        pathB: { type: 'string' },
      },
      required: ['pathA', 'pathB'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.pattern',
    aliases: ['luau.pattern', 'luau_pattern'],
    description: 'Search for a regex pattern across all Luau files. Returns file, line, and matched text.',
    inputSchema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regex pattern or literal string to search for.' },
        maxResults: { type: 'number', description: 'Max matches to return (default 100).' },
        context: { type: 'number', description: 'Lines of context around each match (default 0).' },
        fileFilter: { type: 'string', description: 'Optional filename substring to filter which files are searched.' },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.note',
    aliases: ['luau.note', 'luau_note'],
    description: 'Store a Luau-specific lesson in the local helper brain.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        summary: { type: 'string' },
        sourcePath: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        evidence: { type: 'string' },
      },
      required: ['title', 'summary'],
      additionalProperties: false,
    },
  },
];

export function getToolDefinitions() {
  return toolDefinitions;
}

export function getTools() {
  const tools = [];
  for (const definition of toolDefinitions) {
    const displayName = definition.aliases.find((alias) => !alias.includes('.')) || definition.canonicalName;
    tools.push({
      name: displayName,
      title: definition.canonicalName.replace(/\./g, ' '),
      description: definition.description,
      inputSchema: definition.inputSchema,
      annotations: toolAnnotations(definition.canonicalName),
    });
  }
  return tools;
}

export function getCanonicalToolNames() {
  return toolDefinitions.map((tool) => tool.canonicalName);
}

export function getAliasesByTool() {
  return Object.fromEntries(toolDefinitions.map((tool) => [tool.canonicalName, tool.aliases.slice()]));
}

export function getResources(workspaceRoot) {
  return [
    {
      uri: 'helper://workspace/summary',
      name: 'Workspace summary',
      description: 'Current workspace summary and Luau coverage.',
      mimeType: 'application/json',
    },
    {
      uri: 'helper://brain/snapshot',
      name: 'Brain snapshot',
      description: 'Current local brain snapshot.',
      mimeType: 'application/json',
    },
    {
      uri: 'helper://luau/scan',
      name: 'Luau scan',
      description: 'Current Luau workspace scan.',
      mimeType: 'application/json',
    },
  ];
}

export function readResource(workspaceRoot, uri) {
  switch (uri) {
    case 'helper://workspace/summary':
      return resourceResult(uri, jsonText(workspaceSummary(workspaceRoot)), 'application/json');
    case 'helper://brain/snapshot':
      return resourceResult(uri, jsonText(buildBrainSnapshot(workspaceRoot)), 'application/json');
    case 'helper://luau/scan':
      return resourceResult(uri, jsonText(scanLuauWorkspace(workspaceRoot)), 'application/json');
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
}

export function healthcheckPayload(workspaceRoot) {
  return {
    ok: true,
    name: serverName,
    version: serverVersion,
    workspaceRoot,
    toolCount: getTools().length,
    canonicalToolCount: toolDefinitions.length,
    resourceCount: getResources(workspaceRoot).length,
    canonicalTools: getCanonicalToolNames(),
    aliasesByTool: getAliasesByTool(),
  };
}

export function handleTool(workspaceRoot, requestedName, args = {}) {
  const canonicalName = toolDefinitions.find((tool) => tool.aliases.includes(requestedName))?.canonicalName || requestedName;

  switch (canonicalName) {
    case 'healthcheck':
      return textResult(jsonText(healthcheckPayload(workspaceRoot)));

    case 'workspace.summary':
      return textResult(jsonText(workspaceSummary(workspaceRoot)));

    case 'workspace.risks':
      return textResult(jsonText(workspaceRisks(workspaceRoot)));

    case 'workspace.coverage':
      return textResult(jsonText(workspaceCoverage(workspaceRoot)));

    case 'workspace.audit':
      return textResult(jsonText(workspaceAudit(workspaceRoot)));

    case 'brain.add': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title,
        summary: args.summary,
        scope: args.scope || 'workspace',
        status: args.status || 'candidate',
        tags: args.tags || [],
        sourcePath: args.sourcePath || '',
        evidence: args.evidence || '',
      });
      return textResult(jsonText({ ok: true, message: 'Brain note stored.', counts: snapshot.counts }));
    }

    case 'brain.search': {
      const hits = searchBrainNotes(workspaceRoot, args.query, { limit: args.limit });
      return textResult(jsonText({ query: args.query, total: hits.length, hits }));
    }

    case 'brain.list': {
      const notes = listBrainNotes(workspaceRoot, {
        status: args.status,
        tag: args.tag,
        limit: args.limit,
      });
      return textResult(jsonText({ total: notes.length, notes }));
    }

    case 'brain.snapshot': {
      const snapshot = loadBrainSnapshot(workspaceRoot);
      return textResult(jsonText(snapshot));
    }

    case 'brain.promote': {
      const result = promoteBrainNote(workspaceRoot, args.id, args.status);
      return textResult(jsonText(result));
    }

    case 'brain.tag': {
      const result = tagBrainNote(workspaceRoot, args.id, args.tags || []);
      return textResult(jsonText(result));
    }

    case 'brain.update': {
      const result = updateBrainNote(workspaceRoot, args.id, {
        title: args.title,
        summary: args.summary,
        evidence: args.evidence,
        scope: args.scope,
      });
      return textResult(jsonText(result));
    }

    case 'brain.delete': {
      const result = deleteBrainNote(workspaceRoot, args.id);
      return textResult(jsonText(result));
    }

    case 'brain.export':
      return textResult(exportBrainToMarkdown(workspaceRoot));

    case 'luau.scan': {
      const scan = scanLuauWorkspace(workspaceRoot);
      return textResult(jsonText(scan));
    }

    case 'luau.inspect': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      const report = analyzeLuauText(readText(resolved), resolved);
      return textResult(formatLuauAnalysis(report));
    }

    case 'luau.compare': {
      const report = compareLuauFiles(workspaceRoot, args.filePath, args.baselinePath);
      return textResult(jsonText(report));
    }

    case 'luau.diff': {
      const report = diffLuauFiles(workspaceRoot, args.pathA, args.pathB);
      return textResult(jsonText(report));
    }

    case 'luau.pattern': {
      const result = patternSearchLuau(workspaceRoot, args.pattern, {
        maxResults: args.maxResults,
        context: args.context,
        fileFilter: args.fileFilter,
      });
      return textResult(jsonText(result));
    }

    case 'luau.note': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title,
        summary: args.summary,
        scope: 'luau',
        status: 'active',
        tags: args.tags || ['luau'],
        sourcePath: args.sourcePath || '',
        evidence: args.evidence || '',
      });
      return textResult(jsonText({ ok: true, message: 'Luau lesson stored.', counts: snapshot.counts }));
    }

    default:
      throw new Error(`Unknown tool: ${requestedName}`);
  }
}
