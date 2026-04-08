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
  teachBrainLesson,
  updateBrainNote,
} from './brain.mjs';
import {
  analyzeLuauText,
  compareLuauFiles,
  diffLuauFiles,
  extractFlagsFromText,
  extractUIMap,
  formatLuauAnalysis,
  migrationChecklist,
  patternSearchLuau,
  scanLuauWorkspace,
} from './luau.mjs';
import { readText } from './fs.mjs';

export const serverName = 'helper-mcp';
export const serverVersion = '0.4.0';

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function textResult(text) {
  return { content: [{ type: 'text', text }] };
}

function resourceResult(uri, text, mimeType = 'text/plain') {
  return { contents: [{ uri, mimeType, text }] };
}

// ── Workspace helpers ─────────────────────────────────────────────────────────

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
  return {
    totalFiles: scan.totalFiles,
    filesWithRisks: scan.files.filter((f) => f.summary.riskCount > 0).length,
    totalRisks: scan.totalRisks,
    files: scan.files
      .filter((f) => f.summary.riskCount > 0)
      .sort((a, b) => b.summary.riskCount - a.summary.riskCount)
      .map((f) => ({ file: f.filePath, riskCount: f.summary.riskCount, localCount: f.summary.localCount, risks: f.categories.risks })),
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
    totalRemotes += f.summary.remoteCount;
    totalLocals += f.summary.localCount;
    const missingPcall = f.categories.risks.filter((r) => r.label === 'missing-pcall').length;
    remotesWithPcall += Math.max(0, f.summary.remoteCount - missingPcall);

    if (f.summary.localCount > 180) {
      actions.push({ priority: 1, file: f.filePath, issue: 'local-pressure-critical', detail: `${f.summary.localCount} locals — near the 200-register limit. Wrap blocks in do...end or group into tables.` });
    } else if (f.summary.localCount > 150) {
      actions.push({ priority: 2, file: f.filePath, issue: 'local-pressure-warning', detail: `${f.summary.localCount} locals — approaching the 200-register limit.` });
    }
    if (missingPcall > 0) {
      const lines = f.categories.risks.filter((r) => r.label === 'missing-pcall').map((r) => r.line).join(', ');
      actions.push({ priority: missingPcall >= 3 ? 1 : 2, file: f.filePath, issue: 'missing-pcall', detail: `${missingPcall} remote call(s) without pcall at lines: ${lines}.` });
    }
    const legacy = f.categories.risks.filter((r) => ['wait', 'spawn', 'delay'].includes(r.label));
    if (legacy.length > 0) {
      actions.push({ priority: 3, file: f.filePath, issue: 'legacy-api', detail: `${legacy.length} use(s) of deprecated wait/spawn/delay — replace with task.* equivalents.` });
    }
    const unbounded = f.categories.risks.filter((r) => r.label === 'unbounded-loop');
    if (unbounded.length > 0) {
      actions.push({ priority: 2, file: f.filePath, issue: 'unbounded-loop', detail: `${unbounded.length} while true do loop(s) — verify each has a proper exit condition.` });
    }
  }

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

// ── Tool annotations ──────────────────────────────────────────────────────────

function toolAnnotations(canonicalName) {
  const readOnlyTools = new Set([
    'healthcheck',
    'workspace.summary', 'workspace.risks', 'workspace.coverage', 'workspace.audit',
    'brain.search', 'brain.snapshot', 'brain.list', 'brain.export',
    'luau.scan', 'luau.inspect', 'luau.compare', 'luau.diff', 'luau.pattern',
    'luau.flags', 'luau.ui_map', 'luau.migration',
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

// ── Tool definitions ──────────────────────────────────────────────────────────

const toolDefinitions = [
  // Meta
  {
    canonicalName: 'healthcheck',
    aliases: ['healthcheck', 'health_check', 'ping'],
    description: 'Return a compatibility and health summary for the MCP server.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  // Workspace
  {
    canonicalName: 'workspace.summary',
    aliases: ['workspace.summary', 'workspace_summary'],
    description: 'Summarize the current workspace and Luau coverage.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    canonicalName: 'workspace.risks',
    aliases: ['workspace.risks', 'workspace_risks'],
    description: 'Risk-focused report for all Luau files, sorted by risk count.',
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
    description: 'Combined health audit: pcall coverage, local pressure, legacy API, unbounded loops — prioritized action list.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  // Brain
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
    canonicalName: 'brain.teach',
    aliases: ['brain.teach', 'brain_teach'],
    description: 'Store a structured lesson in mistake→fix→rule format. Tagged as "learned" and immediately active.',
    inputSchema: {
      type: 'object',
      properties: {
        mistake: { type: 'string', description: 'What went wrong.' },
        fix: { type: 'string', description: 'What was done to fix it.' },
        rule: { type: 'string', description: 'The reusable rule to prevent recurrence (becomes the title).' },
        sourcePath: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
      },
      required: ['mistake', 'fix', 'rule'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.search',
    aliases: ['brain.search', 'brain_search'],
    description: 'Search brain notes and workspace files. Results ranked by relevance.',
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
      properties: { id: { type: 'string' }, status: { type: 'string' } },
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
    description: 'Edit title, summary, evidence, or scope of an existing note by its ID.',
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
      properties: { id: { type: 'string' } },
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
  // Luau
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
      properties: { filePath: { type: 'string' } },
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
      properties: { filePath: { type: 'string' }, baselinePath: { type: 'string' } },
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
      properties: { pathA: { type: 'string' }, pathB: { type: 'string' } },
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
        pattern: { type: 'string' },
        maxResults: { type: 'number' },
        context: { type: 'number' },
        fileFilter: { type: 'string' },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.flags',
    aliases: ['luau.flags', 'luau_flags'],
    description: 'Scan a Luau file for LibSixtyTen Flag definitions and reads. Detects duplicates and orphaned flags.',
    inputSchema: {
      type: 'object',
      properties: { filePath: { type: 'string' } },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.ui_map',
    aliases: ['luau.ui_map', 'luau_ui_map'],
    description: 'Extract the LibSixtyTen Page→Category→Section→Controls hierarchy from a Luau file.',
    inputSchema: {
      type: 'object',
      properties: { filePath: { type: 'string' } },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.migration',
    aliases: ['luau.migration', 'luau_migration'],
    description: 'Semantic migration checklist between two Luau files. Checks flag loss, autoload, remotes, pcall, dashboard init. Returns BLOCKED / REVIEW / READY verdict.',
    inputSchema: {
      type: 'object',
      properties: {
        oldPath: { type: 'string', description: 'Path to the old (before) file.' },
        newPath: { type: 'string', description: 'Path to the new (after) file.' },
      },
      required: ['oldPath', 'newPath'],
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

// ── Public API ────────────────────────────────────────────────────────────────

export function getToolDefinitions() { return toolDefinitions; }

export function getTools() {
  return toolDefinitions.map((definition) => {
    const displayName = definition.aliases.find((a) => !a.includes('.')) || definition.canonicalName;
    return {
      name: displayName,
      title: definition.canonicalName.replace(/\./g, ' '),
      description: definition.description,
      inputSchema: definition.inputSchema,
      annotations: toolAnnotations(definition.canonicalName),
    };
  });
}

export function getCanonicalToolNames() { return toolDefinitions.map((t) => t.canonicalName); }

export function getAliasesByTool() {
  return Object.fromEntries(toolDefinitions.map((t) => [t.canonicalName, t.aliases.slice()]));
}

export function getResources(workspaceRoot) {
  return [
    { uri: 'helper://workspace/summary', name: 'Workspace summary', description: 'Current workspace summary and Luau coverage.', mimeType: 'application/json' },
    { uri: 'helper://brain/snapshot', name: 'Brain snapshot', description: 'Current local brain snapshot.', mimeType: 'application/json' },
    { uri: 'helper://luau/scan', name: 'Luau scan', description: 'Current Luau workspace scan.', mimeType: 'application/json' },
  ];
}

export function readResource(workspaceRoot, uri) {
  switch (uri) {
    case 'helper://workspace/summary': return resourceResult(uri, jsonText(workspaceSummary(workspaceRoot)), 'application/json');
    case 'helper://brain/snapshot': return resourceResult(uri, jsonText(buildBrainSnapshot(workspaceRoot)), 'application/json');
    case 'helper://luau/scan': return resourceResult(uri, jsonText(scanLuauWorkspace(workspaceRoot)), 'application/json');
    default: throw new Error(`Unknown resource: ${uri}`);
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
  const canonicalName = toolDefinitions.find((t) => t.aliases.includes(requestedName))?.canonicalName || requestedName;

  switch (canonicalName) {
    case 'healthcheck': return textResult(jsonText(healthcheckPayload(workspaceRoot)));
    case 'workspace.summary': return textResult(jsonText(workspaceSummary(workspaceRoot)));
    case 'workspace.risks': return textResult(jsonText(workspaceRisks(workspaceRoot)));
    case 'workspace.coverage': return textResult(jsonText(workspaceCoverage(workspaceRoot)));
    case 'workspace.audit': return textResult(jsonText(workspaceAudit(workspaceRoot)));

    case 'brain.add': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title, summary: args.summary,
        scope: args.scope || 'workspace', status: args.status || 'candidate',
        tags: args.tags || [], sourcePath: args.sourcePath || '', evidence: args.evidence || '',
      });
      return textResult(jsonText({ ok: true, message: 'Brain note stored.', counts: snapshot.counts }));
    }

    case 'brain.teach': {
      const result = teachBrainLesson(workspaceRoot, {
        mistake: args.mistake, fix: args.fix, rule: args.rule,
        sourcePath: args.sourcePath, tags: args.tags,
      });
      return textResult(jsonText(result));
    }

    case 'brain.search': {
      const hits = searchBrainNotes(workspaceRoot, args.query, { limit: args.limit });
      return textResult(jsonText({ query: args.query, total: hits.length, hits }));
    }

    case 'brain.list': {
      const notes = listBrainNotes(workspaceRoot, { status: args.status, tag: args.tag, limit: args.limit });
      return textResult(jsonText({ total: notes.length, notes }));
    }

    case 'brain.snapshot': return textResult(jsonText(loadBrainSnapshot(workspaceRoot)));

    case 'brain.promote': return textResult(jsonText(promoteBrainNote(workspaceRoot, args.id, args.status)));

    case 'brain.tag': return textResult(jsonText(tagBrainNote(workspaceRoot, args.id, args.tags || [])));

    case 'brain.update': {
      return textResult(jsonText(updateBrainNote(workspaceRoot, args.id, {
        title: args.title, summary: args.summary, evidence: args.evidence, scope: args.scope,
      })));
    }

    case 'brain.delete': return textResult(jsonText(deleteBrainNote(workspaceRoot, args.id)));

    case 'brain.export': return textResult(exportBrainToMarkdown(workspaceRoot));

    case 'luau.scan': return textResult(jsonText(scanLuauWorkspace(workspaceRoot)));

    case 'luau.inspect': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      return textResult(formatLuauAnalysis(analyzeLuauText(readText(resolved), resolved)));
    }

    case 'luau.compare': return textResult(jsonText(compareLuauFiles(workspaceRoot, args.filePath, args.baselinePath)));

    case 'luau.diff': return textResult(jsonText(diffLuauFiles(workspaceRoot, args.pathA, args.pathB)));

    case 'luau.pattern': {
      return textResult(jsonText(patternSearchLuau(workspaceRoot, args.pattern, {
        maxResults: args.maxResults, context: args.context, fileFilter: args.fileFilter,
      })));
    }

    case 'luau.flags': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      return textResult(jsonText(extractFlagsFromText(readText(resolved), resolved)));
    }

    case 'luau.ui_map': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      return textResult(jsonText(extractUIMap(readText(resolved), resolved)));
    }

    case 'luau.migration': {
      return textResult(jsonText(migrationChecklist(workspaceRoot, args.oldPath, args.newPath)));
    }

    case 'luau.note': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title, summary: args.summary, scope: 'luau', status: 'active',
        tags: args.tags || ['luau'], sourcePath: args.sourcePath || '', evidence: args.evidence || '',
      });
      return textResult(jsonText({ ok: true, message: 'Luau lesson stored.', counts: snapshot.counts }));
    }

    default: throw new Error(`Unknown tool: ${requestedName}`);
  }
}
