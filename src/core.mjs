import path from 'node:path';
import {
  appendBrainNote,
  buildBrainSnapshot,
  brainHistory,
  deleteBrainNote,
  exportBrainToMarkdown,
  importBrainNotes,
  listBrainNotes,
  loadBrainSnapshot,
  mergeBrainNotes,
  promoteBrainNote,
  searchBrainNotes,
  tagBrainNote,
  teachBrainLesson,
  updateBrainNote,
} from './brain.mjs';
import {
  analyzeLuauText,
  buildLuauDependencyMap,
  buildLuauMigrationChangelog,
  buildLuauRemoteGraph,
  compareLuauFiles,
  diffLuauFiles,
  decompileLuauHeuristics,
  extractFlagsFromText,
  extractUIMap,
  formatLuauAnalysis,
  formatLuauHotfix,
  generateLuauTemplate,
  hotfixLuauText,
  migrationChecklist,
  patternSearchLuau,
  profileLuauPerformance,
  repairLuauRisk,
  scoreLuauComplexity,
  scanLuauSecurity,
  scanLuauWorkspace,
  writeLuauHotfixSnapshots,
} from './luau.mjs';
import { buildConfigValidationMarkdown, saveConfigValidation, validateConfigFile } from './config.mjs';
import { captureLuauMetrics } from './metrics.mjs';
import { captureWorkspaceBaseline, generateWorkspaceChangelog } from './workspace.mjs';
import { readText, toPosix, writeText } from './fs.mjs';

export const serverName = 'helper-mcp';
export const serverVersion = '0.6.0';

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
    'brain.search', 'brain.snapshot', 'brain.list', 'brain.export', 'brain.history',
    'luau.scan', 'luau.inspect', 'luau.compare', 'luau.diff', 'luau.pattern',
    'luau.flags', 'luau.ui_map', 'luau.migration',
    'luau.decompile', 'luau.security_scan', 'luau.performance_profile', 'luau.dependencies', 'luau.remotes', 'luau.complexity',
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

function toolDefinition(canonicalName, aliases, description, inputSchema) {
  return { canonicalName, aliases, description, inputSchema };
}

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
  {
    canonicalName: 'brain.history',
    aliases: ['brain.history', 'brain_history'],
    description: 'Show brain notes ordered by updatedAt with status changes.',
    inputSchema: {
      type: 'object',
      properties: {
        noteId: { type: 'string' },
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.merge',
    aliases: ['brain.merge', 'brain_merge'],
    description: 'Find or consolidate similar brain notes using the existing search scoring.',
    inputSchema: {
      type: 'object',
      properties: {
        noteId: { type: 'string' },
        mergeIds: { type: 'array', items: { type: 'string' } },
        limit: { type: 'number' },
        apply: { type: 'boolean' },
      },
      additionalProperties: false,
    },
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
    canonicalName: 'luau.repair',
    aliases: ['luau.repair', 'luau_repair'],
    description: 'Suggest a targeted fix snippet for a Luau risk label.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        riskLabel: { type: 'string' },
      },
      required: ['filePath', 'riskLabel'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.dependencies',
    aliases: ['luau.dependencies', 'luau_dependencies', 'luau.dependency_map', 'luau_dependency_map'],
    description: 'Build a dependency graph from require() calls and unused imports.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.remotes',
    aliases: ['luau.remotes', 'luau_remotes'],
    description: 'Map remote call sites, remote kinds, and corresponding handlers.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.complexity',
    aliases: ['luau.complexity', 'luau_complexity'],
    description: 'Score cyclomatic complexity for each function in a Luau file.',
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
    canonicalName: 'luau.changelog',
    aliases: ['luau.changelog', 'luau_changelog'],
    description: 'Generate a migration note and persist it to the brain.',
    inputSchema: {
      type: 'object',
      properties: {
        oldPath: { type: 'string' },
        newPath: { type: 'string' },
        title: { type: 'string' },
      },
      required: ['oldPath', 'newPath'],
      additionalProperties: false,
    },
  },
  toolDefinition('luau.security_scan', ['luau.security_scan', 'luau_security_scan'], 'Audit Luau scripts for webhook leaks, token exfiltration, and backdoor patterns.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
    },
    required: ['filePath'],
    additionalProperties: false,
  }),
  toolDefinition('luau.performance_profile', ['luau.performance_profile', 'luau_performance_profile'], 'Profile Luau scripts for loop pressure, register hotspots, and cleanup risks.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
    },
    required: ['filePath'],
    additionalProperties: false,
  }),
  toolDefinition('luau.template', ['luau.template', 'luau_template'], 'Generate a Luau scaffold with safety and cleanup patterns.', {
    type: 'object',
    properties: {
      templateType: { type: 'string' },
      name: { type: 'string' },
      outputPath: { type: 'string' },
    },
    additionalProperties: false,
  }),
  toolDefinition('workspace.baseline', ['workspace.baseline', 'workspace_baseline'], 'Capture a regression baseline for a workspace or script path.', {
    type: 'object',
    properties: {
      targetPath: { type: 'string' },
      outputPath: { type: 'string' },
      label: { type: 'string' },
    },
    additionalProperties: false,
  }),
  toolDefinition('workspace.changelog', ['workspace.changelog', 'workspace_changelog'], 'Generate a changelog from a baseline comparison.', {
    type: 'object',
    properties: {
      baselinePath: { type: 'string' },
      targetPath: { type: 'string' },
      title: { type: 'string' },
    },
    required: ['baselinePath'],
    additionalProperties: false,
  }),
  toolDefinition('config.validate', ['config.validate', 'config_validate'], 'Validate a LibSixtyTen config file against inferred or supplied schema rules.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
      schemaPath: { type: 'string' },
      record: { type: 'boolean' },
    },
    required: ['filePath'],
    additionalProperties: false,
  }),
  toolDefinition('brain.import', ['brain.import', 'brain_import'], 'Import notes from markdown, JSON, or text sources into the local helper brain.', {
    type: 'object',
    properties: {
      sources: { type: 'array', items: { type: 'string' } },
    },
    required: ['sources'],
    additionalProperties: false,
  }),
  toolDefinition('luau.hotfix', ['luau.hotfix', 'luau_hotfix'], 'Apply conservative Luau repair heuristics and store before/after snapshots.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
      apply: { type: 'boolean' },
    },
    required: ['filePath'],
    additionalProperties: false,
  }),
  toolDefinition('luau.decompile', ['luau.decompile', 'luau_decompile'], 'Heuristically analyze Luau bytecode-like or obfuscated source patterns.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
    },
    required: ['filePath'],
    additionalProperties: false,
  }),
  toolDefinition('luau.metrics', ['luau.metrics', 'luau_metrics'], 'Capture Luau quality metrics snapshots and compare trends over time.', {
    type: 'object',
    properties: {
      label: { type: 'string' },
      record: { type: 'boolean' },
    },
    additionalProperties: false,
  }),
];

// ── Public API ────────────────────────────────────────────────────────────────

export function getToolDefinitions() { return toolDefinitions; }

export function getTools() {
  return toolDefinitions.map((definition) => {
    const displayName = definition.aliases.find((a) => !a.includes('.')) || definition.canonicalName;
    return {
      name: displayName,
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

function resolveFilePath(workspaceRoot, filePath) {
  const trimmed = String(filePath || '').trim();
  return trimmed ? (path.isAbsolute(trimmed) ? trimmed : path.resolve(workspaceRoot, trimmed)) : '';
}

function resolveOptionalPath(workspaceRoot, filePath) {
  const trimmed = String(filePath || '').trim();
  return trimmed ? (path.isAbsolute(trimmed) ? trimmed : path.resolve(workspaceRoot, trimmed)) : '';
}

function storeMigrationBrainNote(workspaceRoot, result, oldPath, newPath, title = '') {
  const markdown = buildLuauMigrationChangelog(result, { title: title || `Migration ${result.verdict}` });
  const snapshot = appendBrainNote(workspaceRoot, {
    title: title || `Luau migration ${result.verdict}`,
    summary: markdown,
    scope: 'luau',
    status: result.verdict === 'READY' ? 'active' : 'candidate',
    tags: ['luau', 'migration', result.verdict.toLowerCase()],
    sourcePath: `${toPosix(oldPath)} -> ${toPosix(newPath)}`,
    evidence: result.checklist.map((item) => `${item.check}: ${item.detail}`).join('\n'),
  });
  return { markdown, snapshot };
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

    case 'brain.history': {
      return textResult(jsonText(brainHistory(workspaceRoot, { noteId: args.noteId, limit: args.limit })));
    }

    case 'brain.merge': {
      return textResult(jsonText(mergeBrainNotes(workspaceRoot, {
        noteId: args.noteId,
        mergeIds: args.mergeIds || [],
        apply: args.apply === true,
        limit: args.limit,
      })));
    }

    case 'brain.import': {
      const imported = importBrainNotes(workspaceRoot, args.sources || []);
      return textResult(jsonText({
        ok: true,
        message: 'Brain notes imported.',
        ...imported,
      }));
    }

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
      const result = migrationChecklist(workspaceRoot, args.oldPath, args.newPath);
      const note = storeMigrationBrainNote(workspaceRoot, result, args.oldPath, args.newPath);
      return textResult(jsonText({ ...result, brainNote: note }));
    }

    case 'luau.note': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title, summary: args.summary, scope: 'luau', status: 'active',
        tags: args.tags || ['luau'], sourcePath: args.sourcePath || '', evidence: args.evidence || '',
      });
      return textResult(jsonText({ ok: true, message: 'Luau lesson stored.', counts: snapshot.counts }));
    }

    case 'luau.hotfix': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const before = readText(resolved);
      const report = hotfixLuauText(before, resolved, { apply: args.apply !== false });
      if (args.apply !== false && report.summary.changed) {
        writeText(resolved, `${report.after.trimEnd()}\n`);
      }
      const snapshotPath = writeLuauHotfixSnapshots(workspaceRoot, resolved, report);
      return textResult(jsonText({
        ok: true,
        snapshotPath,
        report,
        markdown: formatLuauHotfix(report),
      }));
    }

    case 'luau.decompile': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = decompileLuauHeuristics(readText(resolved), resolved);
      return textResult(jsonText(report));
    }

    case 'luau.repair': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = repairLuauRisk(readText(resolved), resolved, args.riskLabel);
      return textResult(jsonText(report));
    }

    case 'luau.security_scan': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = scanLuauSecurity(readText(resolved), resolved);
      return textResult(jsonText(report));
    }

    case 'luau.performance_profile': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = profileLuauPerformance(readText(resolved), resolved);
      return textResult(jsonText(report));
    }

    case 'luau.dependencies': {
      const report = buildLuauDependencyMap(workspaceRoot, args.targetPath || '');
      return textResult(jsonText(report));
    }

    case 'luau.remotes': {
      const report = buildLuauRemoteGraph(workspaceRoot, args.targetPath || '');
      return textResult(jsonText(report));
    }

    case 'luau.complexity': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = scoreLuauComplexity(readText(resolved), resolved);
      return textResult(jsonText(report));
    }

    case 'luau.changelog': {
      const result = migrationChecklist(workspaceRoot, args.oldPath, args.newPath);
      const note = storeMigrationBrainNote(workspaceRoot, result, args.oldPath, args.newPath, args.title);
      return textResult(jsonText({ ...result, brainNote: note }));
    }

    case 'luau.template': {
      const report = generateLuauTemplate({
        templateType: args.templateType || 'utility',
        name: args.name || 'NewScript',
        outputPath: args.outputPath || '',
      });
      return textResult(jsonText(report));
    }

    case 'luau.metrics': {
      return textResult(jsonText(captureLuauMetrics(workspaceRoot, {
        label: args.label,
        record: args.record !== false,
      })));
    }

    default: throw new Error(`Unknown tool: ${requestedName}`);
  }
}
