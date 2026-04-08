import path from 'node:path';
import {
  appendBrainNote,
  buildBrainSnapshot,
  exportBrainToMarkdown,
  listBrainNotes,
  loadBrainSnapshot,
  promoteBrainNote,
  searchBrainNotes,
  tagBrainNote,
} from './brain.mjs';
import { analyzeLuauText, compareLuauFiles, diffLuauFiles, formatLuauAnalysis, scanLuauWorkspace } from './luau.mjs';
import { readText } from './fs.mjs';

export const serverName = 'helper-mcp';
export const serverVersion = '0.2.0';

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function textResult(text) {
  return {
    content: [
      {
        type: 'text',
        text,
      },
    ],
  };
}

function resourceResult(uri, text, mimeType = 'text/plain') {
  return {
    contents: [
      {
        uri,
        mimeType,
        text,
      },
    ],
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

function toolAnnotations(canonicalName) {
  const readOnlyTools = new Set([
    'healthcheck', 'workspace.summary', 'workspace.risks', 'workspace.coverage',
    'brain.search', 'brain.snapshot', 'brain.list', 'brain.export',
    'luau.scan', 'luau.inspect', 'luau.compare', 'luau.diff',
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
