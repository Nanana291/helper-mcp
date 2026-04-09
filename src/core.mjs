import path from 'node:path';
import {
  appendBrainNote,
  autoCaptureBrain,
  buildBrainSnapshot,
  buildBrainGraph,
  brainHistory,
  brainFindingHistory,
  compareBrainSnapshots,
  diffBrainSnapshot,
  archiveBrainNote,
  deleteBrainNote,
  exportBrainToMarkdown,
  importBrainNotes,
  listBrainNotes,
  loadBrainSnapshot,
  mergeBrainNotes,
  buildBrainFindingGraph,
  pruneBrainFindingNotes,
  queryBrainFindingNotes,
  pruneDuplicateBrainNotes,
  promoteBrainNote,
  queryBrainAdvanced,
  linkBrainNotes,
  restoreBrainDiff,
  searchBrainNotes,
  tagBrainNote,
  teachBrainLesson,
  updateBrainNote,
  addBrainFinding,
  listBrainFindings,
  updateBrainFinding,
  brainFindingStats,
} from './brain.mjs';
import {
  analyzeLuauText,
  analyzeLuauFlow,
  analyzeLuauTaint,
  buildLuauFindingsReport,
  buildLuauDependencyMap,
  buildLuauMigrationChangelog,
  buildLuauModuleGraph,
  buildLuauRemoteGraph,
  compareLuauFiles,
  diffLuauWithContext,
  diffLuauFiles,
  decompileLuauHeuristics,
  extractFlagsFromText,
  extractUIMap,
  explainLuauText,
  extractRemoteDetails,
  formatLuauAnalysis,
  formatLuauHotfix,
  generateLuauTemplate,
  hotfixLuauText,
  migrationChecklist,
  mapLuauHandlers,
  patternSearchLuau,
  profileLuauPerformance,
  repairLuauRisk,
  repairLuauRiskApply,
  scoreLuauRisk,
  scoreLuauComplexity,
  semanticLuauSearch,
  simulateRespawnLifecycle,
  summarizeLuauSurface,
  suggestLuauRefactor,
  scanLuauSecurity,
  scanLuauWorkspace,
  extractRemotePayloads,
  lintLuauText,
  scanRemotePayloads,
  scanLuauLint,
  extractGameApiMap,
  scanGameApi,
  analyzeFeatureParity,
  checkRespawnLifecycle,
  scanRespawnChecks,
  checkExecutorCompat,
  scanExecutorCompat,
  validateStatusParagraphs,
  scanStatusParagraphs,
  summarizeRisks,
  summarizeDiff,
  generateV2Scaffold,
  bridgeLuauCommandResult,
  writeLuauHotfixSnapshots,
} from './luau.mjs';
import { buildConfigValidationMarkdown, saveConfigValidation, validateConfigFile } from './config.mjs';
import { captureLuauMetrics } from './metrics.mjs';
import {
  captureWorkspaceBaseline,
  cloneWorkspace,
  diffWorkspaceState,
  gateWorkspace,
  generateWorkspaceChangelog,
  generateWorkspaceReleaseNotes,
  restoreWorkspaceSnapshot,
  rollbackWorkspaceSnapshot,
  validateWorkspaceRelease,
} from './workspace.mjs';
import { readText, toPosix, writeText } from './fs.mjs';

export const serverName = 'helper-mcp';
export const serverVersion = '0.6.2';

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function textResult(text) {
  return { content: [{ type: 'text', text }] };
}

function bridgeLuauTextResult(workspaceRoot, commandName, report, context = {}) {
  return textResult(jsonText(bridgeLuauCommandResult(workspaceRoot, commandName, report, context)));
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
  const coverage = workspaceCoverage(workspaceRoot);
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
      coveredFiles: coverage.coveredFiles,
      uncoveredFiles: coverage.uncoveredFiles,
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
    'workspace.summary', 'workspace.risks', 'workspace.coverage', 'workspace.audit', 'workspace.diff', 'workspace.validate', 'workspace.release_notes',
    'brain.search', 'brain.snapshot', 'brain.list', 'brain.export', 'brain.history', 'brain.graph', 'brain.query_advanced', 'brain.diff', 'brain.restore_diff',
    'brain.findings', 'brain.finding_history', 'brain.finding_graph',
    'brain.findings', 'brain.finding_history', 'brain.finding_graph', 'brain.finding_prune',
    'luau.scan', 'luau.inspect', 'luau.compare', 'luau.diff', 'luau.pattern', 'luau.findings',
    'luau.flags', 'luau.ui_map', 'luau.migration',
    'luau.decompile', 'luau.security_scan', 'luau.performance_profile', 'luau.dependencies', 'luau.remotes', 'luau.complexity',
    'luau.taint', 'luau.flow', 'luau.handlers', 'luau.surface', 'luau.refactor', 'luau.modulegraph', 'luau.risk_score', 'luau.diff_context',
    'luau.explain', 'luau.respawn_simulate', 'luau.grep', 'luau.extract_remote',
    'workspace.gate',
    'brain.compare',
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
    canonicalName: 'brain.graph',
    aliases: ['brain.graph', 'brain_graph'],
    description: 'Build a graph of brain notes linked by tags, similarity, source paths, and explicit links.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.query_advanced',
    aliases: ['brain.query_advanced', 'brain_query_advanced'],
    description: 'Rank notes with richer filters for status, scope, tags, and time windows.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        status: { type: 'string' },
        scope: { type: 'string' },
        tag: { type: 'string' },
        from: { type: 'string' },
        to: { type: 'string' },
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.findings',
    aliases: ['brain.findings', 'brain_findings'],
    description: 'Query brain notes derived from Luau findings.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        severity: { type: 'string' },
        status: { type: 'string' },
        command: { type: 'string' },
        filePath: { type: 'string' },
        label: { type: 'string' },
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.finding_history',
    aliases: ['brain.finding_history', 'brain_finding_history'],
    description: 'Show temporal history for finding-derived brain notes.',
    inputSchema: {
      type: 'object',
      properties: {
        noteId: { type: 'string' },
        filePath: { type: 'string' },
        command: { type: 'string' },
        severity: { type: 'string' },
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.finding_graph',
    aliases: ['brain.finding_graph', 'brain_finding_graph'],
    description: 'Graph finding-derived notes alongside related regular notes.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.finding_prune',
    aliases: ['brain.finding_prune', 'brain_finding_prune'],
    description: 'Conservatively find or consolidate duplicate finding-derived notes.',
    inputSchema: {
      type: 'object',
      properties: {
        apply: { type: 'boolean' },
        limit: { type: 'number' },
        threshold: { type: 'number' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.link',
    aliases: ['brain.link', 'brain_link'],
    description: 'Create explicit relationships between two brain notes.',
    inputSchema: {
      type: 'object',
      properties: {
        fromId: { type: 'string' },
        toId: { type: 'string' },
        relation: { type: 'string' },
      },
      required: ['fromId', 'toId'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.archive',
    aliases: ['brain.archive', 'brain_archive'],
    description: 'Archive a brain note without deleting its history.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        reason: { type: 'string' },
      },
      required: ['id'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.restore_diff',
    aliases: ['brain.restore_diff', 'brain_restore_diff'],
    description: 'Compare a previous brain snapshot to the current state and return the diff.',
    inputSchema: {
      type: 'object',
      properties: {
        snapshotPath: { type: 'string' },
      },
      required: ['snapshotPath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.diff',
    aliases: ['brain.diff', 'brain_diff'],
    description: 'Compare the current brain snapshot to a saved snapshot and summarize drift.',
    inputSchema: {
      type: 'object',
      properties: {
        snapshotPath: { type: 'string' },
      },
      required: ['snapshotPath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.prune_duplicates',
    aliases: ['brain.prune_duplicates', 'brain_prune_duplicates'],
    description: 'Find or consolidate duplicate brain notes using similarity scoring.',
    inputSchema: {
      type: 'object',
      properties: {
        apply: { type: 'boolean' },
        limit: { type: 'number' },
        threshold: { type: 'number' },
      },
      additionalProperties: false,
    },
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
    canonicalName: 'luau.findings',
    aliases: ['luau.findings', 'luau_findings'],
    description: 'Return normalized Luau findings that can be bridged into brain notes.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.brain_sync',
    aliases: ['luau.brain_sync', 'luau_brain_sync'],
    description: 'Force a bridge pass that writes Luau findings into brain notes.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.taint',
    aliases: ['luau.taint', 'luau_taint'],
    description: 'Trace risky values from source to sink across a Luau file or workspace slice.',
    inputSchema: {
      type: 'object',
      properties: { filePath: { type: 'string' } },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.flow',
    aliases: ['luau.flow', 'luau_flow'],
    description: 'Summarize simple data flow between locals, functions, and remote calls.',
    inputSchema: {
      type: 'object',
      properties: { filePath: { type: 'string' } },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.handlers',
    aliases: ['luau.handlers', 'luau_handlers'],
    description: 'Map remote events/functions to likely handlers and missing coverage.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.surface',
    aliases: ['luau.surface', 'luau_surface'],
    description: 'Summarize the external surface of a script or workspace slice.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.refactor',
    aliases: ['luau.refactor', 'luau_refactor'],
    description: 'Suggest conservative refactor steps for high-confidence Luau risks.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        riskLabel: { type: 'string' },
      },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.modulegraph',
    aliases: ['luau.modulegraph', 'luau_modulegraph'],
    description: 'Build a module dependency graph for a Luau workspace slice.',
    inputSchema: {
      type: 'object',
      properties: {
        targetPath: { type: 'string' },
      },
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.risk_score',
    aliases: ['luau.risk_score', 'luau_risk_score'],
    description: 'Produce a normalized Luau risk score from risks, remotes, cleanup gaps, and taint signals.',
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
    canonicalName: 'luau.diff_context',
    aliases: ['luau.diff_context', 'luau_diff_context'],
    description: 'Diff two Luau files with surrounding context and a concise structural summary.',
    inputSchema: {
      type: 'object',
      properties: {
        pathA: { type: 'string' },
        pathB: { type: 'string' },
        context: { type: 'number' },
      },
      required: ['pathA', 'pathB'],
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
  toolDefinition('workspace.diff', ['workspace.diff', 'workspace_diff'], 'Compare current workspace state to a baseline and summarize drift.', {
    type: 'object',
    properties: {
      baselinePath: { type: 'string' },
      targetPath: { type: 'string' },
    },
    required: ['baselinePath'],
    additionalProperties: false,
  }),
  toolDefinition('workspace.rollback', ['workspace.rollback', 'workspace_rollback'], 'Restore a file or workspace snapshot from a saved artifact.', {
    type: 'object',
    properties: {
      snapshotPath: { type: 'string' },
      targetPath: { type: 'string' },
      apply: { type: 'boolean' },
    },
    required: ['snapshotPath'],
    additionalProperties: false,
  }),
  toolDefinition('workspace.validate', ['workspace.validate', 'workspace_validate'], 'Validate that the current workspace still matches the expected release shape.', {
    type: 'object',
    properties: {
      baselinePath: { type: 'string' },
      targetPath: { type: 'string' },
    },
    required: ['baselinePath'],
    additionalProperties: false,
  }),
  toolDefinition('workspace.release_notes', ['workspace.release_notes', 'workspace_release_notes'], 'Generate human-readable release notes from diffs, brain links, and snapshots.', {
    type: 'object',
    properties: {
      baselinePath: { type: 'string' },
      targetPath: { type: 'string' },
      title: { type: 'string' },
    },
    required: ['baselinePath'],
    additionalProperties: false,
  }),
  toolDefinition('workspace.restore_snapshot', ['workspace.restore_snapshot', 'workspace_restore_snapshot'], 'Restore a named snapshot and verify the post-restore state.', {
    type: 'object',
    properties: {
      snapshotPath: { type: 'string' },
      targetPath: { type: 'string' },
      apply: { type: 'boolean' },
    },
    required: ['snapshotPath'],
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
  toolDefinition('luau.remotes', ['luau.remotes', 'luau_remotes'], 'Deep analysis of FireServer/InvokeServer calls: payload structure, table keys, literal values, variable refs. Groups by remote name.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Specific file to analyze. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.lint', ['luau.lint', 'luau_lint'], 'Style and best-practice linting: deprecated APIs (wait/spawn/delay), magic numbers, hardcoded coordinates, long functions, unwrapped remotes.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Specific file to lint. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.api_map', ['luau.api_map', 'luau_api_map'], 'Extract game API surface: remotes, attributes, workspace refs, services, config keys, constants.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Specific file to analyze. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.feature_parity', ['luau.feature_parity', 'luau_feature_parity'], 'Feature-by-feature V1→V2 comparison: preserved, modified, new, and missing features.', {
    type: 'object',
    properties: {
      oldPath: { type: 'string' },
      newPath: { type: 'string' },
    },
    required: ['oldPath', 'newPath'],
    additionalProperties: false,
  }),
  toolDefinition('luau.respawn_check', ['luau.respawn_check', 'luau_respawn_check'], 'Character lifecycle analysis: respawn handlers, callback reconnection, loop safety, orphaned connections.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Specific file to check. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.compat', ['luau.compat', 'luau_compat'], 'Executor compatibility checker: maps APIs to Delta/Wave/Solara/Codex support levels.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Specific file to check. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  // ── New: Luau explain ──────────────────────────────────────────────────────
  toolDefinition('luau.explain', ['luau.explain', 'luau_explain'], 'Natural-language explanation of what a Luau script does: features, structure, risks, character lifecycle.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'File to explain. If omitted, explains the largest Luau file.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.repair_apply', ['luau.repair_apply', 'luau_repair_apply'], 'Apply a targeted fix to a Luau file for a specific risk label. Writes the patched file to disk.', {
    type: 'object',
    properties: {
      filePath: { type: 'string' },
      riskLabel: { type: 'string', description: 'Risk to fix: missing-pcall, wait, spawn, unbounded-loop, connection-cleanup, remote-rate-limit' },
      apply: { type: 'boolean', description: 'If false, dry-run only. Default true.' },
    },
    required: ['filePath', 'riskLabel'],
    additionalProperties: false,
  }),
  toolDefinition('luau.respawn_simulate', ['luau.respawn_simulate', 'luau_respawn_simulate'], 'Simulate full character respawn lifecycle: death → rebind → loop recovery → remote recovery. State machine analysis.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'File to simulate. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('luau.grep', ['luau.grep', 'luau_grep'], 'Semantic search within Luau files: find functions, variables, remotes, UI sections by name with context and scoring.', {
    type: 'object',
    properties: {
      query: { type: 'string', description: 'Search query — function name, variable, feature, etc.' },
      filePath: { type: 'string', description: 'Specific file to search. If omitted, searches all Luau files.' },
      context: { type: 'number', description: 'Lines of context before/after. Default 2.' },
    },
    required: ['query'],
    additionalProperties: false,
  }),
  toolDefinition('luau.extract_remote', ['luau.extract_remote', 'luau_extract_remote'], 'Deep remote analysis: call sites, handlers, pcall coverage, orphaned remotes, payload styles.', {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'File to analyze. If omitted, scans all Luau files.' },
    },
    additionalProperties: false,
  }),
  // ── New: Brain tools ───────────────────────────────────────────────────────
  toolDefinition('brain.auto_capture', ['brain.auto_capture', 'brain_auto_capture'], 'Auto-generate brain notes from analysis results. Infers titles, tags, and severity from scan/audit/risk data.', {
    type: 'object',
    properties: {
      scope: { type: 'string', description: 'Scope of capture: workspace, file, or custom. Default: workspace.' },
      skipExisting: { type: 'boolean', description: 'Skip if similar note exists. Default true.' },
      minConfidence: { type: 'number', description: 'Minimum confidence threshold. Default 0.3.' },
      autoTags: { type: 'boolean', description: 'Auto-infer tags from analysis. Default true.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('brain.compare', ['brain.compare', 'brain_compare'], 'Compare two brain snapshots: added, removed, modified notes, status drift, tag trends.', {
    type: 'object',
    properties: {
      snapshotA: { type: 'string' },
      snapshotB: { type: 'string' },
    },
    required: ['snapshotA', 'snapshotB'],
    additionalProperties: false,
  }),
  // ── New: Workspace tools ───────────────────────────────────────────────────
  toolDefinition('workspace.gate', ['workspace.gate', 'workspace_gate'], 'Pre-delivery gate: 9 checks (baseline parity, risk threshold, pcall coverage, deprecated API, security, etc.). Verdict: PASS/REVIEW/BLOCKED.', {
    type: 'object',
    properties: {
      baselinePath: { type: 'string' },
      targetPath: { type: 'string' },
      maxRiskDelta: { type: 'number', description: 'Max allowed risk increase. Default 5.' },
      minPcallCoverage: { type: 'number', description: 'Min pcall coverage %. Default 80.' },
      maxNewRisks: { type: 'number', description: 'Max new risks allowed. Default 3.' },
      requireBaseline: { type: 'boolean', description: 'Fail without baseline. Default false.' },
    },
    additionalProperties: false,
  }),
  toolDefinition('workspace.clone', ['workspace.clone', 'workspace_clone'], 'Clone workspace files + brain state to a new directory. Preserves directory structure.', {
    type: 'object',
    properties: {
      targetDir: { type: 'string' },
      includeBrain: { type: 'boolean', description: 'Copy .helper-mcp/brain. Default true.' },
      includeBaselines: { type: 'boolean', description: 'Copy .helper-mcp/baselines. Default true.' },
      includeMetrics: { type: 'boolean', description: 'Copy .helper-mcp/metrics. Default true.' },
      luauOnly: { type: 'boolean', description: 'Only copy .lua/.luau files. Default false.' },
      fileFilter: { type: 'string', description: 'Only copy files matching this glob pattern.' },
    },
    required: ['targetDir'],
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

export async function handleTool(workspaceRoot, requestedName, args = {}) {
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

    case 'brain.graph': {
      return textResult(jsonText(buildBrainGraph(workspaceRoot, { limit: args.limit })));
    }

    case 'brain.query_advanced': {
      return textResult(jsonText(queryBrainAdvanced(workspaceRoot, args.query || '', {
        status: args.status,
        scope: args.scope,
        tag: args.tag,
        from: args.from,
        to: args.to,
        limit: args.limit,
      })));
    }

    case 'brain.findings': {
      return textResult(jsonText(queryBrainFindingNotes(workspaceRoot, {
        query: args.query || '',
        severity: args.severity,
        status: args.status,
        command: args.command,
        filePath: args.filePath,
        label: args.label,
        limit: args.limit,
      })));
    }

    case 'brain.finding_history': {
      return textResult(jsonText(brainFindingHistory(workspaceRoot, {
        noteId: args.noteId,
        filePath: args.filePath,
        command: args.command,
        severity: args.severity,
        limit: args.limit,
      })));
    }

    case 'brain.finding_graph': {
      return textResult(jsonText(buildBrainFindingGraph(workspaceRoot, { limit: args.limit })));
    }

    case 'brain.finding_prune': {
      return textResult(jsonText(pruneBrainFindingNotes(workspaceRoot, {
        apply: args.apply === true,
        limit: args.limit,
        threshold: args.threshold,
      })));
    }

    case 'brain.link': {
      return textResult(jsonText(linkBrainNotes(workspaceRoot, args.fromId, args.toId, args.relation)));
    }

    case 'brain.archive': {
      return textResult(jsonText(archiveBrainNote(workspaceRoot, args.id, { reason: args.reason })));
    }

    case 'brain.restore_diff': {
      return textResult(jsonText(restoreBrainDiff(workspaceRoot, args.snapshotPath)));
    }
    case 'brain.diff': {
      return textResult(jsonText(diffBrainSnapshot(workspaceRoot, args.snapshotPath)));
    }

    case 'brain.prune_duplicates': {
      return textResult(jsonText(pruneDuplicateBrainNotes(workspaceRoot, {
        apply: args.apply === true,
        limit: args.limit,
        threshold: args.threshold,
      })));
    }

    case 'luau.scan': return bridgeLuauTextResult(workspaceRoot, 'luau.scan', scanLuauWorkspace(workspaceRoot));

    case 'luau.inspect': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      const analysis = analyzeLuauText(readText(resolved), resolved);
      const bridged = bridgeLuauCommandResult(workspaceRoot, 'luau.inspect', analysis, { filePath: resolved });
      const bridgeLines = bridged.brainNoteIds.length > 0
        ? [`## Brain Bridge`, `- note ids: ${bridged.brainNoteIds.join(', ')}`]
        : ['## Brain Bridge', '- no bridgeable findings'];
      return textResult(`${formatLuauAnalysis(analysis)}\n${bridgeLines.join('\n')}\n`);
    }

    case 'luau.compare': return bridgeLuauTextResult(workspaceRoot, 'luau.compare', compareLuauFiles(workspaceRoot, args.filePath, args.baselinePath), {
      filePath: args.filePath || '',
    });

    case 'luau.diff': return bridgeLuauTextResult(workspaceRoot, 'luau.diff', diffLuauFiles(workspaceRoot, args.pathA, args.pathB), {
      filePath: args.pathA || '',
    });

    case 'luau.pattern': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.pattern', patternSearchLuau(workspaceRoot, args.pattern, {
        maxResults: args.maxResults, context: args.context, fileFilter: args.fileFilter,
      }), { bridgeInfo: true });
    }

    case 'luau.flags': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      return bridgeLuauTextResult(workspaceRoot, 'luau.flags', extractFlagsFromText(readText(resolved), resolved), { filePath: resolved });
    }

    case 'luau.ui_map': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      return bridgeLuauTextResult(workspaceRoot, 'luau.ui_map', extractUIMap(readText(resolved), resolved), { filePath: resolved });
    }

    case 'luau.migration': {
      const result = migrationChecklist(workspaceRoot, args.oldPath, args.newPath);
      const note = storeMigrationBrainNote(workspaceRoot, result, args.oldPath, args.newPath);
      return textResult(jsonText({ ...result, brainNote: note }));
    }

    case 'luau.findings': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.findings', buildLuauFindingsReport(workspaceRoot, {
        filePath: args.filePath || '',
        targetPath: args.targetPath || '',
      }), {
        filePath: args.filePath || args.targetPath || '',
        bridgeInfo: true,
      });
    }

    case 'luau.brain_sync': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.brain_sync', buildLuauFindingsReport(workspaceRoot, {
        filePath: args.filePath || '',
        targetPath: args.targetPath || '',
      }), {
        filePath: args.filePath || args.targetPath || '',
        bridgeInfo: true,
      });
    }

    case 'luau.taint': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      return bridgeLuauTextResult(workspaceRoot, 'luau.taint', analyzeLuauTaint(readText(resolved), resolved), { filePath: resolved });
    }

    case 'luau.flow': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      return bridgeLuauTextResult(workspaceRoot, 'luau.flow', analyzeLuauFlow(readText(resolved), resolved), { filePath: resolved, bridgeInfo: true });
    }

    case 'luau.handlers': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.handlers', mapLuauHandlers(workspaceRoot, args.targetPath || ''), {
        filePath: args.targetPath || '',
        bridgeInfo: true,
      });
    }

    case 'luau.surface': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.surface', summarizeLuauSurface(workspaceRoot, args.targetPath || ''), {
        filePath: args.targetPath || '',
        bridgeInfo: true,
      });
    }

    case 'luau.refactor': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      return bridgeLuauTextResult(workspaceRoot, 'luau.refactor', suggestLuauRefactor(readText(resolved), resolved, args.riskLabel), {
        filePath: resolved,
        bridgeInfo: true,
      });
    }

    case 'luau.modulegraph': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.modulegraph', buildLuauModuleGraph(workspaceRoot, args.targetPath || ''), {
        filePath: args.targetPath || '',
        bridgeInfo: true,
      });
    }

    case 'luau.risk_score': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      return bridgeLuauTextResult(workspaceRoot, 'luau.risk_score', scoreLuauRisk(readText(resolved), resolved), {
        filePath: resolved,
        bridgeInfo: true,
      });
    }

    case 'luau.diff_context': {
      return bridgeLuauTextResult(workspaceRoot, 'luau.diff_context', diffLuauWithContext(workspaceRoot, args.pathA, args.pathB, { context: args.context }), {
        filePath: args.pathA || '',
        bridgeInfo: true,
      });
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
      return bridgeLuauTextResult(workspaceRoot, 'luau.decompile', report, { filePath: resolved, bridgeInfo: true });
    }

    case 'luau.repair': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = repairLuauRisk(readText(resolved), resolved, args.riskLabel);
      return bridgeLuauTextResult(workspaceRoot, 'luau.repair', report, { filePath: resolved, bridgeInfo: true });
    }

    case 'luau.security_scan': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = scanLuauSecurity(readText(resolved), resolved);
      return bridgeLuauTextResult(workspaceRoot, 'luau.security_scan', report, { filePath: resolved });
    }

    case 'luau.performance_profile': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = profileLuauPerformance(readText(resolved), resolved);
      return bridgeLuauTextResult(workspaceRoot, 'luau.performance_profile', report, { filePath: resolved });
    }

    case 'luau.dependencies': {
      const report = buildLuauDependencyMap(workspaceRoot, args.targetPath || '');
      return bridgeLuauTextResult(workspaceRoot, 'luau.dependencies', report, { filePath: args.targetPath || '', bridgeInfo: true });
    }

    case 'luau.remotes': {
      const report = buildLuauRemoteGraph(workspaceRoot, args.targetPath || '');
      return bridgeLuauTextResult(workspaceRoot, 'luau.remotes', report, { filePath: args.targetPath || '', bridgeInfo: true });
    }

    case 'luau.complexity': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const report = scoreLuauComplexity(readText(resolved), resolved);
      return bridgeLuauTextResult(workspaceRoot, 'luau.complexity', report, { filePath: resolved });
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

    case 'luau.remotes': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(extractRemotePayloads(text, resolved)));
      }
      return textResult(jsonText(scanRemotePayloads(workspaceRoot)));
    }

    case 'luau.lint': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(lintLuauText(text, resolved)));
      }
      return textResult(jsonText(scanLuauLint(workspaceRoot)));
    }

    case 'luau.api_map': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(extractGameApiMap(text, resolved)));
      }
      return textResult(jsonText(scanGameApi(workspaceRoot)));
    }

    case 'luau.feature_parity': {
      const oldResolved = resolveFilePath(workspaceRoot, args.oldPath);
      const newResolved = resolveFilePath(workspaceRoot, args.newPath);
      const oldText = readText(oldResolved);
      const newText = readText(newResolved);
      return textResult(jsonText(analyzeFeatureParity(oldText, newText, oldResolved, newResolved)));
    }

    case 'luau.respawn_check': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(checkRespawnLifecycle(text, resolved)));
      }
      return textResult(jsonText(scanRespawnChecks(workspaceRoot)));
    }

    case 'luau.compat': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(checkExecutorCompat(text, resolved)));
      }
      return textResult(jsonText(scanExecutorCompat(workspaceRoot)));
    }

    case 'workspace.diff': {
      return textResult(jsonText(diffWorkspaceState(workspaceRoot, {
        baselinePath: args.baselinePath,
        targetPath: args.targetPath || '',
      })));
    }

    case 'workspace.rollback': {
      return textResult(jsonText(rollbackWorkspaceSnapshot(workspaceRoot, {
        snapshotPath: args.snapshotPath,
        targetPath: args.targetPath || '',
        apply: args.apply !== false,
      })));
    }

    case 'workspace.validate': {
      return textResult(jsonText(validateWorkspaceRelease(workspaceRoot, {
        baselinePath: args.baselinePath,
        targetPath: args.targetPath || '',
      })));
    }

    case 'workspace.release_notes': {
      return textResult(jsonText(generateWorkspaceReleaseNotes(workspaceRoot, {
        baselinePath: args.baselinePath,
        targetPath: args.targetPath || '',
        title: args.title || 'Workspace release notes',
      })));
    }

    case 'workspace.restore_snapshot': {
      return textResult(jsonText(restoreWorkspaceSnapshot(workspaceRoot, {
        snapshotPath: args.snapshotPath,
        targetPath: args.targetPath || '',
        apply: args.apply !== false,
      })));
    }

    case 'luau.explain': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(explainLuauText(text, resolved)));
      }
      // Auto-pick the largest Luau file
      const scan = scanLuauWorkspace(workspaceRoot);
      if (scan.totalFiles === 0) {
        return textResult(jsonText({ ok: false, error: 'No Luau files found in workspace.' }));
      }
      const largest = scan.files.sort((a, b) => b.summary.lineCount - a.summary.lineCount)[0];
      const text = readText(largest.filePath);
      return textResult(jsonText(explainLuauText(text, largest.filePath)));
    }

    case 'luau.repair_apply': {
      const resolved = resolveFilePath(workspaceRoot, args.filePath);
      const text = readText(resolved);
      const report = repairLuauRiskApply(text, resolved, args.riskLabel, { apply: args.apply !== false });
      if (args.apply !== false && report.applied) {
        writeText(resolved, `${report.newText.trimEnd()}\n`);
      }
      return textResult(jsonText({
        ok: true,
        applied: report.applied,
        filePath: resolved,
        riskLabel: args.riskLabel,
        line: report.line,
        before: report.before,
        after: report.after,
        explanation: report.explanation,
      }));
    }

    case 'luau.respawn_simulate': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(simulateRespawnLifecycle(text, resolved)));
      }
      // Scan all files
      const scan = scanLuauWorkspace(workspaceRoot);
      const results = scan.files.map((f) => {
        try {
          const text = readText(f.filePath);
          return simulateRespawnLifecycle(text, f.filePath);
        } catch { return null; }
      }).filter(Boolean);
      return textResult(jsonText({
        totalFiles: results.length,
        verdicts: {
          pass: results.filter((r) => r.verdict === 'PASS').length,
          warn: results.filter((r) => r.verdict === 'WARN').length,
          fail: results.filter((r) => r.verdict === 'FAIL').length,
        },
        files: results,
      }));
    }

    case 'luau.grep': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(semanticLuauSearch(text, resolved, args.query, { context: args.context || 2 })));
      }
      // Search all files
      const scan = scanLuauWorkspace(workspaceRoot);
      const allMatches = [];
      for (const f of scan.files) {
        try {
          const text = readText(f.filePath);
          const result = semanticLuauSearch(text, f.filePath, args.query, { context: args.context || 2 });
          if (result.totalMatches > 0) allMatches.push(result);
        } catch { /* skip unreadable */ }
      }
      return textResult(jsonText({
        query: args.query,
        fileCount: allMatches.length,
        totalMatches: allMatches.reduce((sum, m) => sum + m.totalMatches, 0),
        files: allMatches,
      }));
    }

    case 'luau.extract_remote': {
      if (args.filePath) {
        const resolved = resolveFilePath(workspaceRoot, args.filePath);
        const text = readText(resolved);
        return textResult(jsonText(extractRemoteDetails(text, resolved)));
      }
      // Scan all files
      const scan = scanLuauWorkspace(workspaceRoot);
      const allRemotes = [];
      for (const f of scan.files) {
        try {
          const text = readText(f.filePath);
          const result = extractRemoteDetails(text, f.filePath);
          if (result.summary.totalCalls > 0) allRemotes.push(result);
        } catch { /* skip unreadable */ }
      }
      return textResult(jsonText({
        totalFiles: allRemotes.length,
        summary: {
          totalCalls: allRemotes.reduce((sum, r) => sum + r.summary.totalCalls, 0),
          uniqueRemotes: allRemotes.reduce((sum, r) => sum + r.summary.uniqueRemotes, 0),
          withPcall: allRemotes.reduce((sum, r) => sum + r.summary.withPcall, 0),
          withoutPcall: allRemotes.reduce((sum, r) => sum + r.summary.withoutPcall, 0),
          orphaned: allRemotes.reduce((sum, r) => sum + r.summary.orphanedRemotes, 0),
        },
        files: allRemotes,
      }));
    }

    case 'brain.auto_capture': {
      const scan = scanLuauWorkspace(workspaceRoot);
      const analysisResults = scan.files
        .filter((f) => f.summary.riskCount > 0 || f.summary.remoteCount > 0)
        .map((f) => ({
          type: f.summary.riskCount > 5 ? 'audit' : 'scan',
          filePath: f.filePath,
          data: { summary: f.summary, risks: f.categories.risks },
        }));
      const result = autoCaptureBrain(workspaceRoot, analysisResults, {
        skipExisting: args.skipExisting !== false,
        minConfidence: args.minConfidence || 0.3,
        autoTags: args.autoTags !== false,
        status: args.status || 'candidate',
      });
      return textResult(jsonText(result));
    }

    case 'brain.compare': {
      const resolvedA = path.isAbsolute(args.snapshotA) ? args.snapshotA : path.resolve(workspaceRoot, args.snapshotA);
      const resolvedB = path.isAbsolute(args.snapshotB) ? args.snapshotB : path.resolve(workspaceRoot, args.snapshotB);
      return textResult(jsonText(compareBrainSnapshots(workspaceRoot, resolvedA, resolvedB)));
    }

    case 'workspace.gate': {
      return textResult(jsonText(await gateWorkspace(workspaceRoot, {
        baselinePath: args.baselinePath,
        targetPath: args.targetPath,
        maxRiskDelta: args.maxRiskDelta,
        minPcallCoverage: args.minPcallCoverage,
        maxNewRisks: args.maxNewRisks,
        requireBaseline: args.requireBaseline,
      })));
    }

    case 'workspace.clone': {
      const targetDir = path.isAbsolute(args.targetDir) ? args.targetDir : path.resolve(workspaceRoot, args.targetDir);
      return textResult(jsonText(cloneWorkspace(workspaceRoot, {
        targetDir,
        includeBrain: args.includeBrain !== false,
        includeBaselines: args.includeBaselines !== false,
        includeMetrics: args.includeMetrics !== false,
        luauOnly: args.luauOnly || false,
        fileFilter: args.fileFilter,
      })));
    }

    default: throw new Error(`Unknown tool: ${requestedName}`);
  }
}
