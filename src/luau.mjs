import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { readText, relative, toPosix, walkFiles, writeText } from './fs.mjs';
import { loadLuauPatterns, defaultLuauPatterns } from './patterns.mjs';
import { deriveFindingNoteId, upsertBrainFindingNote } from './brain.mjs';

const LUAU_EXTENSIONS = new Set(['.lua', '.luau']);

const callbackPatterns = [
  { label: 'signal-connect', re: /\bConnect\s*\(/ },
  { label: 'server-event', re: /\bOnServerEvent\b/ },
  { label: 'client-event', re: /\bOnClientEvent\b/ },
  { label: 'property-signal', re: /\bGetPropertyChangedSignal\s*\(/ },
  { label: 'task-spawn', re: /\btask\.spawn\s*\(/ },
  { label: 'render-stepped', re: /\bRenderStepped\b/ },
  { label: 'heartbeat', re: /\bHeartbeat\b/ },
];

const remotePatterns = [
  { label: 'fire-server', re: /\b:FireServer\s*\(/ },
  { label: 'invoke-server', re: /\b:InvokeServer\s*\(/ },
  { label: 'fire-client', re: /\b:FireClient\s*\(/ },
  { label: 'remote-event', re: /\bRemoteEvent\b/ },
  { label: 'remote-function', re: /\bRemoteFunction\b/ },
];

const statePatterns = [
  { label: 'settings', re: /\bSettings\b/ },
  { label: 'selected', re: /\bSelected\b/ },
  { label: 'runtime-info', re: /\bRuntimeInfo\b/ },
  { label: 'stats', re: /\bStats\b/ },
  { label: 'flags', re: /\bFlags\b/ },
];

const uiPatterns = [
  { label: 'window', re: /\bLibrary:Window\s*\(/ },
  { label: 'dashboard', re: /\bCreateDashboard\s*\(/ },
  { label: 'toggle', re: /\bToggle\s*\(/ },
  { label: 'slider', re: /\bSlider\s*\(/ },
  { label: 'dropdown', re: /\bDropdown\s*\(/ },
  { label: 'button', re: /\bButton\s*\(/ },
  { label: 'paragraph', re: /\bParagraph\s*\(/ },
  { label: 'label', re: /\bLabel\s*\(/ },
];

const riskPatterns = [
  { label: 'wait', re: /\bwait\s*\(/ },
  { label: 'spawn', re: /\bspawn\s*\(/ },
  { label: 'delay', re: /\bdelay\s*\(/ },
  { label: 'repeat-wait', re: /\brepeat\b[\s\S]{0,80}\bwait\s*\(/ },
  { label: 'unbounded-loop', re: /\bwhile\s+true\s+do\b/ },
];

// Patterns for extracting named functions (used by luau.diff)
const functionPatterns = [
  /\blocal\s+function\s+(\w+)/,
  /\bfunction\s+(\w[\w.:]*)\s*\(/,
  /\b(\w+)\s*=\s*function\s*\(/,
];

function getMatches(lines, pattern) {
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.re.test(lines[index])) {
      matches.push({ line: index + 1, text: lines[index].trim() });
    }
  }
  return matches;
}

function annotateFinding(category, label) {
  const base = { severity: 'info', confidence: 0.5 };
  if (category === 'risks') {
    if (label === 'missing-pcall') return { severity: 'high', confidence: 0.97 };
    if (label === 'unbounded-loop') return { severity: 'high', confidence: 0.93 };
    if (label === 'repeat-wait') return { severity: 'medium', confidence: 0.82 };
    if (label === 'wait' || label === 'spawn' || label === 'delay') return { severity: 'medium', confidence: 0.75 };
    return { severity: 'medium', confidence: 0.7 };
  }
  if (category === 'security') {
    if (label === 'webhook' || label === 'loadstring-remote' || label === 'backdoor-pattern') {
      return { severity: 'high', confidence: 0.96 };
    }
    if (label === 'token-exfil') return { severity: 'high', confidence: 0.91 };
    return { severity: 'medium', confidence: 0.8 };
  }
  if (category === 'performance') {
    if (label === 'hot-loop' || label === 'repeat-loop' || label === 'nested-wait') {
      return { severity: 'medium', confidence: 0.85 };
    }
    if (label === 'connect-without-cleanup') return { severity: 'medium', confidence: 0.82 };
    return { severity: 'low', confidence: 0.68 };
  }
  if (category === 'obfuscation') {
    return { severity: 'medium', confidence: 0.72 };
  }
  if (category === 'callbacks' || category === 'remotes') {
    return { severity: 'info', confidence: 0.76 };
  }
  if (category === 'state' || category === 'ui') {
    return { severity: 'info', confidence: 0.65 };
  }
  return base;
}

/**
 * Detect FireServer / InvokeServer calls that are NOT wrapped in pcall on the same line.
 */
function getMissingPcallMatches(lines) {
  const remoteCallRe = /:FireServer\s*\(|:InvokeServer\s*\(/;
  const matches = [];
  for (let i = 0; i < lines.length; i++) {
    if (remoteCallRe.test(lines[i]) && !/\bpcall\b/.test(lines[i])) {
      matches.push({ line: i + 1, text: lines[i].trim(), label: 'missing-pcall' });
    }
  }
  return matches;
}

function countIdentifiers(text, identifier) {
  if (!identifier) return 0;
  const escaped = String(identifier).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = String(text || '').match(new RegExp(`\\b${escaped}\\b`, 'g'));
  return matches ? matches.length : 0;
}

function textHash(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function averageConfidence(items) {
  const values = (items || []).map((item) => Number(item?.confidence ?? item?.confidenceAverage ?? 0)).filter((value) => Number.isFinite(value));
  if (values.length === 0) return 0;
  return Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(2));
}

function normalizeFindingSeverity(severity) {
  const value = String(severity || 'review').trim().toLowerCase();
  if (value === 'critical' || value === 'high') return 'high';
  if (value === 'warning' || value === 'medium' || value === 'review') return 'review';
  return 'info';
}

function isLuauBridgeableCommand(commandName) {
  return /luau\.(findings|flow|handlers|modulegraph|complexity|taint|security_scan|risk_score|repair|diff_context|dependencies|remotes|surface|decompile|metrics|changelog|migration|compare|inspect|scan)/.test(String(commandName || ''));
}

export function normalizeLuauFinding(commandName, finding = {}, context = {}) {
  const filePath = toPosix(finding.filePath || context.filePath || context.sourcePath || '');
  const line = Number(finding.line ?? context.line ?? 0) || 0;
  const label = String(finding.label || finding.kind || finding.type || 'finding').trim() || 'finding';
  const severity = normalizeFindingSeverity(finding.severity || context.severity || 'review');
  const confidence = Number((Number(finding.confidence ?? context.confidence ?? (severity === 'high' ? 0.96 : severity === 'review' ? 0.78 : 0.62)) || 0).toFixed(2));
  const evidence = String(finding.evidence || finding.text || finding.summary || '').trim();
  const suggestedFix = String(finding.suggestedFix || finding.after || finding.repair || '').trim();
  const bridgeable = finding.bridgeable !== false && (severity !== 'info' || context.bridgeInfo === true || isLuauBridgeableCommand(commandName));
  const brainNoteId = deriveFindingNoteId({
    command: commandName,
    filePath,
    line,
    label,
    evidence,
  });

  return {
    command: commandName,
    filePath,
    line,
    label,
    severity,
    confidence,
    evidence,
    suggestedFix,
    bridgeable,
    brainNoteId,
    title: String(finding.title || `${label} @ ${filePath || 'workspace'}:${line || 0}`).trim(),
    summary: String(finding.summary || evidence || suggestedFix || '').trim(),
    tags: Array.isArray(finding.tags) ? finding.tags.map((tag) => String(tag).trim()).filter(Boolean) : [],
    raw: finding,
  };
}

export function collectLuauFindings(commandName, report, context = {}) {
  const findings = [];
  const sourcePath = String(context.filePath || context.sourcePath || report?.summary?.filePath || '').trim();

  const pushMany = (items, base = {}) => {
    for (const item of items || []) {
      findings.push(normalizeLuauFinding(commandName, item, { ...context, ...base, filePath: item?.filePath || base.filePath || sourcePath }));
    }
  };

  if (Array.isArray(report?.findings)) {
    pushMany(report.findings, { filePath: sourcePath });
  }

  if (Array.isArray(report?.files) && !Array.isArray(report?.findings)) {
    for (const entry of report.files) {
      findings.push(...collectLuauFindings(commandName, entry, { ...context, filePath: entry.filePath || sourcePath, bridgeInfo: true }));
    }
  }

  if (report?.dependencies && typeof report.dependencies === 'object') {
    findings.push(...collectLuauFindings(commandName, report.dependencies, { ...context, filePath: sourcePath, bridgeInfo: true }));
  }

  if (report?.categories) {
    for (const [category, items] of Object.entries(report.categories)) {
      pushMany(items.map((item) => ({
        ...item,
        label: item.label || category,
        title: item.title || `${category} finding`,
        summary: item.text || item.summary || '',
        evidence: item.text || item.evidence || '',
      })), { filePath: sourcePath });
    }
  }

  if (Array.isArray(report?.sources)) {
    pushMany(report.sources.map((item) => ({
      ...item,
      label: item.label || 'taint-source',
      summary: item.text || 'taint source',
      evidence: item.text || '',
      severity: item.severity || 'high',
    })), { filePath: sourcePath, bridgeInfo: true });
  }

  if (Array.isArray(report?.sinks)) {
    pushMany(report.sinks.map((item) => ({
      ...item,
      label: item.label || 'taint-sink',
      summary: item.text || 'taint sink',
      evidence: item.text || '',
      severity: item.severity || 'high',
    })), { filePath: sourcePath, bridgeInfo: true });
  }

  if (Array.isArray(report?.flows)) {
    pushMany(report.flows.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: item.label || 'taint-flow',
      summary: `${item.variable || 'value'} flow from L${item.sourceLine || 0} to L${item.sinkLine || 0}`,
      evidence: `${item.variable || 'value'} flow from L${item.sourceLine || 0} to L${item.sinkLine || 0}`,
      severity: item.severity || 'review',
    })), { filePath: sourcePath, bridgeInfo: true });
  }

  if (Array.isArray(report?.functions)) {
    pushMany(report.functions.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: item.label || 'complexity',
      summary: `complexity ${item.complexity || 0} in ${item.name || 'function'}`,
      evidence: item.text || item.name || '',
      severity: (item.complexity || 0) >= 8 ? 'high' : 'review',
    })), { filePath: sourcePath, bridgeInfo: true });
  }

  if (Array.isArray(report?.scripts)) {
    pushMany(report.scripts.flatMap((script) => [
      ...(Array.isArray(script.unusedImports) ? script.unusedImports.map((alias) => ({
        filePath: script.path,
        line: 0,
        label: 'unused-import',
        title: `${alias} unused in ${script.path}`,
        summary: `${alias} is only referenced once in ${script.path}`,
        evidence: alias,
        severity: 'review',
      })) : []),
      ...(script.requires?.length === 0 ? [{
        filePath: script.path,
        line: 0,
        label: 'orphaned-script',
        title: `No require() calls in ${script.path}`,
        summary: `${script.path} does not require any modules`,
        evidence: script.path,
        severity: 'info',
      }] : []),
    ]), { bridgeInfo: true });
  }

  if (Array.isArray(report?.remotes)) {
    pushMany(report.remotes.flatMap((remote) => [
      ...(remote.orphaned ? [{
        filePath: (remote.files && remote.files[0]) || sourcePath,
        line: remote.uses?.[0]?.line || 0,
        label: 'orphaned-remote',
        title: `${remote.name} has no handlers`,
        summary: `${remote.name} is used but lacks a matching handler`,
        evidence: remote.name,
        severity: 'review',
      }] : []),
      ...((!remote.hasServerHandler || !remote.hasClientHandler) ? [{
        filePath: (remote.files && remote.files[0]) || sourcePath,
        line: remote.handlers?.[0]?.line || remote.uses?.[0]?.line || 0,
        label: 'remote-handler-gap',
        title: `${remote.name} missing handler coverage`,
        summary: `${remote.name} is missing ${remote.hasServerHandler ? 'client' : 'server'} coverage`,
        evidence: remote.name,
        severity: 'info',
      }] : []),
    ]), { bridgeInfo: true });
  }

  if (Array.isArray(report?.hunks)) {
    pushMany(report.hunks.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: item.type || 'diff-hunk',
      title: `${item.type} line ${item.line}`,
      summary: item.after || item.before || '',
      evidence: item.after || item.before || '',
      severity: item.type === 'added' ? 'info' : 'review',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.matches)) {
    pushMany(report.matches.map((item) => ({
      ...item,
      filePath: item.file || sourcePath,
      label: 'pattern-match',
      title: `Pattern match in ${item.file || sourcePath}`,
      summary: item.text || '',
      evidence: item.text || '',
      severity: 'info',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.added)) {
    pushMany(report.added.map((item) => ({
      filePath: sourcePath,
      line: item?.line || 0,
      label: 'added-finding',
      title: typeof item === 'string' ? item : `${item?.name || 'item'} added`,
      summary: typeof item === 'string' ? item : `${item?.name || 'item'} added`,
      evidence: typeof item === 'string' ? item : JSON.stringify(item),
      severity: 'info',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.missing)) {
    pushMany(report.missing.map((item) => ({
      filePath: sourcePath,
      line: item?.line || 0,
      label: 'missing-finding',
      title: typeof item === 'string' ? item : `${item?.name || 'item'} removed`,
      summary: typeof item === 'string' ? item : `${item?.name || 'item'} removed`,
      evidence: typeof item === 'string' ? item : JSON.stringify(item),
      severity: 'review',
    })), { bridgeInfo: true });
  }

  if (report?.structural && typeof report.structural === 'object') {
    const structural = report.structural;
    if (structural.functions && typeof structural.functions === 'object') {
      pushMany([
        ...(Array.isArray(structural.functions.added) ? structural.functions.added.map((item) => ({
          filePath: sourcePath,
          line: item.line || 0,
          label: 'function-added',
          title: `Function added: ${item.name || 'unknown'}`,
          summary: `Function added: ${item.name || 'unknown'}`,
          evidence: item.name || '',
          severity: 'info',
        })) : []),
        ...(Array.isArray(structural.functions.removed) ? structural.functions.removed.map((item) => ({
          filePath: sourcePath,
          line: item.line || 0,
          label: 'function-removed',
          title: `Function removed: ${item.name || 'unknown'}`,
          summary: `Function removed: ${item.name || 'unknown'}`,
          evidence: item.name || '',
          severity: 'review',
        })) : []),
      ], { bridgeInfo: true });
    }
  }

  if (Array.isArray(report?.duplicates)) {
    pushMany(report.duplicates.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: 'duplicate-flag',
      title: `${item.name || 'flag'} duplicated`,
      summary: `${item.name || 'flag'} appears ${item.count || 0} times`,
      evidence: `${item.name || 'flag'} appears ${item.count || 0} times`,
      severity: 'high',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.orphanedDefined)) {
    pushMany(report.orphanedDefined.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: 'orphaned-flag',
      title: `${item.name || 'flag'} defined but never read`,
      summary: `${item.name || 'flag'} is never read`,
      evidence: item.name || '',
      severity: 'review',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.edges)) {
    pushMany(report.edges.map((item) => ({
      ...item,
      filePath: sourcePath,
      label: item.kind || 'graph-edge',
      title: `${item.kind || 'edge'} ${item.from || '?'} -> ${item.to || '?'}`,
      summary: `${item.from || '?'} -> ${item.to || '?'}`,
      evidence: `${item.from || '?'} -> ${item.to || '?'}`,
      severity: item.kind === 'remote-call' ? 'review' : 'info',
    })), { bridgeInfo: true });
  }

  if (Array.isArray(report?.modules)) {
    pushMany(report.modules.flatMap((module) => [
      ...(Array.isArray(module.unusedImports) ? module.unusedImports.map((alias) => ({
        filePath: module.path,
        line: 0,
        label: 'unused-import',
        title: `${alias} unused in ${module.path}`,
        summary: `${alias} is only referenced once in ${module.path}`,
        evidence: alias,
        severity: 'review',
      })) : []),
      ...(Array.isArray(module.requires) ? module.requires.map((entry) => ({
        filePath: module.path,
        line: entry.line || 0,
        label: 'module-edge',
        title: `${module.path} requires ${entry.target}`,
        summary: `${module.path} requires ${entry.target}`,
        evidence: entry.text || `${module.path} requires ${entry.target}`,
        severity: 'info',
      })) : []),
    ]), { bridgeInfo: true });
  }

  return findings.map((finding) => ({
    ...finding,
    sourceCommand: commandName,
  }));
}

export function bridgeLuauCommandResult(root, commandName, report, context = {}) {
  const findings = collectLuauFindings(commandName, report, context);
  const brainNoteIds = [];
  for (const finding of findings) {
    if (!finding.bridgeable) continue;
    const note = upsertBrainFindingNote(root, finding);
    if (note?.note?.id) {
      brainNoteIds.push(note.note.id);
    }
  }
  const uniqueBrainNoteIds = [...new Set(brainNoteIds)];
  return {
    ...report,
    findings: Array.isArray(report?.findings) ? report.findings : findings,
    brainNoteIds: uniqueBrainNoteIds,
    bridge: {
      totalFindings: findings.length,
      bridgedFindings: uniqueBrainNoteIds.length,
    },
  };
}

export function summarizeLuauFindings(findings) {
  const total = (findings || []).length;
  return {
    totalFindings: total,
    bridgeableCount: (findings || []).filter((finding) => finding.bridgeable).length,
    highCount: (findings || []).filter((finding) => finding.severity === 'high').length,
    reviewCount: (findings || []).filter((finding) => finding.severity === 'review').length,
    infoCount: (findings || []).filter((finding) => finding.severity === 'info').length,
    confidenceAverage: averageConfidence(findings),
  };
}

export function buildLuauFindingsReport(root, { filePath = '', targetPath = '' } = {}) {
  const patterns = loadLuauPatterns(root);
  const findings = [];
  const files = [];
  const resolvedFile = filePath ? (path.isAbsolute(filePath) ? filePath : path.join(root, filePath)) : '';

  if (resolvedFile) {
    const analysis = analyzeLuauText(readText(resolvedFile), resolvedFile, patterns);
    const normalized = collectLuauFindings('luau.findings', analysis, { filePath: toPosix(relative(root, resolvedFile)), bridgeInfo: true });
    findings.push(...normalized);
    files.push({ filePath: toPosix(relative(root, resolvedFile)), findingCount: normalized.length });
  } else {
    const scan = scanLuauWorkspace(root);
    const selectedFiles = resolveLuauFiles(root, targetPath);
    const selectedPaths = new Set(selectedFiles.map((item) => toPosix(relative(root, item))));
    for (const entry of scan.files) {
      if (selectedPaths.size > 0 && !selectedPaths.has(entry.filePath)) continue;
      const normalized = collectLuauFindings('luau.findings', entry, { filePath: entry.filePath, bridgeInfo: true });
      findings.push(...normalized);
      files.push({ filePath: entry.filePath, findingCount: normalized.length });
    }
  }

  return {
    summary: {
      ...summarizeLuauFindings(findings),
      fileCount: files.length,
    },
    files,
    findings,
  };
}

function resolveLuauFiles(root, targetPath = '') {
  const normalizedTarget = targetPath
    ? (() => {
      const rawTarget = path.isAbsolute(targetPath) ? path.relative(root, targetPath) : targetPath;
      return rawTarget === '.' ? '' : toPosix(rawTarget);
    })()
    : '';
  return walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (!LUAU_EXTENSIONS.has(ext)) return false;
    if (!normalizedTarget) return true;
    const rel = toPosix(relative(root, filePath));
    return rel === normalizedTarget || rel.startsWith(`${normalizedTarget}/`);
  });
}

function buildContextSnippet(lines, lineNumber, context = 2) {
  const start = Math.max(0, lineNumber - 1 - context);
  const end = Math.min(lines.length, lineNumber + context);
  return lines.slice(start, end).map((text, index) => ({ line: start + index + 1, text }));
}

function getPatternSet(patterns = defaultLuauPatterns) {
  return {
    callbacks: patterns.callbacks || [],
    remotes: patterns.remotes || [],
    state: patterns.state || [],
    ui: patterns.ui || [],
    risks: patterns.risks || [],
    performance: patterns.performance || [],
    security: patterns.security || [],
    obfuscation: patterns.obfuscation || [],
  };
}

function analyzeWithPatterns(text, filePath, patterns) {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);

  // Count local declarations as a register-pressure heuristic
  const localCount = lines.filter((l) => /^\s*local\s+/.test(l)).length;
  const patternSet = getPatternSet(patterns);

  const categories = {
    callbacks: patternSet.callbacks.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label, ...annotateFinding('callbacks', pattern.label) }))),
    remotes: patternSet.remotes.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label, ...annotateFinding('remotes', pattern.label) }))),
    state: patternSet.state.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label, ...annotateFinding('state', pattern.label) }))),
    ui: patternSet.ui.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label, ...annotateFinding('ui', pattern.label) }))),
    risks: [
      ...patternSet.risks.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label, ...annotateFinding('risks', pattern.label) }))),
      ...getMissingPcallMatches(lines).map((match) => ({ ...match, ...annotateFinding('risks', match.label) })),
    ],
  };

  // Flag register pressure as a synthetic risk entry
  if (localCount > 150) {
    const severity = localCount > 180 ? 'critical' : 'warning';
    categories.risks.push({
      line: 0,
      text: `~${localCount} local declarations detected (limit: 200)`,
      label: `local-pressure-${severity}`,
    });
  }

  const summary = {
    filePath: toPosix(filePath),
    lineCount: lines.length,
    localCount,
    callbackCount: categories.callbacks.length,
    remoteCount: categories.remotes.length,
    stateCount: categories.state.length,
    uiCount: categories.ui.length,
    riskCount: categories.risks.length,
    pcallCount: countIdentifiers(source, 'pcall'),
    loadstringCount: countIdentifiers(source, 'loadstring'),
    connectCount: countIdentifiers(source, 'Connect'),
    hash: textHash(source),
  };

  return { summary, categories };
}

export function analyzeLuauText(text, filePath = '', patterns = defaultLuauPatterns) {
  return analyzeWithPatterns(text, filePath, patterns);
}

export function scanLuauWorkspace(root) {
  const patterns = loadLuauPatterns(root);
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUAU_EXTENSIONS.has(ext);
  });

  const analyzed = files.map((filePath) => ({
    filePath: toPosix(relative(root, filePath)),
    ...analyzeLuauText(readText(filePath), filePath, patterns),
  }));

  return {
    totalFiles: analyzed.length,
    totalCallbacks: analyzed.reduce((sum, entry) => sum + entry.summary.callbackCount, 0),
    totalRemotes: analyzed.reduce((sum, entry) => sum + entry.summary.remoteCount, 0),
    totalRisks: analyzed.reduce((sum, entry) => sum + entry.summary.riskCount, 0),
    files: analyzed,
  };
}

export function compareLuauFiles(root, currentPath, baselinePath) {
  const currentFile = path.isAbsolute(currentPath) ? currentPath : path.join(root, currentPath);
  const baselineFile = path.isAbsolute(baselinePath) ? baselinePath : path.join(root, baselinePath);
  const current = analyzeLuauText(readText(currentFile), currentFile);
  const baseline = analyzeLuauText(readText(baselineFile), baselineFile);

  const missing = [];
  const added = [];
  for (const key of ['callbacks', 'remotes', 'state', 'ui', 'risks']) {
    const currentCount = current.categories[key].length;
    const baselineCount = baseline.categories[key].length;
    if (currentCount > baselineCount) {
      added.push(`${key}: +${currentCount - baselineCount}`);
    } else if (baselineCount > currentCount) {
      missing.push(`${key}: -${baselineCount - currentCount}`);
    }
  }

  return {
    current: current.summary,
    baseline: baseline.summary,
    added,
    missing,
  };
}

/**
 * Structural diff between two Luau files.
 * Reports added/removed functions, and delta counts for remotes and callbacks.
 */
export function diffLuauFiles(root, pathA, pathB) {
  const fileA = path.isAbsolute(pathA) ? pathA : path.join(root, pathA);
  const fileB = path.isAbsolute(pathB) ? pathB : path.join(root, pathB);

  function extractStructure(filePath) {
    const text = readText(filePath);
    const lines = text.split(/\r?\n/);
    const functions = [];
    const remotes = [];
    const callbacks = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pat of functionPatterns) {
        const m = pat.exec(line);
        if (m) {
          functions.push({ name: m[1], line: i + 1 });
          break;
        }
      }
      for (const rp of remotePatterns) {
        if (rp.re.test(line)) remotes.push({ label: rp.label, line: i + 1, text: line.trim() });
      }
      for (const cp of callbackPatterns) {
        if (cp.re.test(line)) callbacks.push({ label: cp.label, line: i + 1, text: line.trim() });
      }
    }

    return { functions, remotes, callbacks, lineCount: lines.length };
  }

  const a = extractStructure(fileA);
  const b = extractStructure(fileB);

  const namesA = new Set(a.functions.map((f) => f.name));
  const namesB = new Set(b.functions.map((f) => f.name));

  return {
    paths: { a: toPosix(pathA), b: toPosix(pathB) },
    lines: { a: a.lineCount, b: b.lineCount, delta: b.lineCount - a.lineCount },
    functions: {
      added: b.functions.filter((f) => !namesA.has(f.name)),
      removed: a.functions.filter((f) => !namesB.has(f.name)),
      unchanged: a.functions.filter((f) => namesB.has(f.name)).length,
    },
    remotes: { a: a.remotes.length, b: b.remotes.length, delta: b.remotes.length - a.remotes.length },
    callbacks: { a: a.callbacks.length, b: b.callbacks.length, delta: b.callbacks.length - a.callbacks.length },
  };
}

export function formatLuauAnalysis(report) {
  const lines = [];
  lines.push(`# ${report.summary.filePath || 'Luau file'}`);
  lines.push('');
  lines.push(`Lines: ${report.summary.lineCount}`);
  lines.push(`Locals: ${report.summary.localCount} / 200`);
  lines.push(`Callbacks: ${report.summary.callbackCount}`);
  lines.push(`Remotes: ${report.summary.remoteCount}`);
  lines.push(`State refs: ${report.summary.stateCount}`);
  lines.push(`UI refs: ${report.summary.uiCount}`);
  lines.push(`Risk refs: ${report.summary.riskCount}`);
  lines.push('');

  for (const [name, items] of Object.entries(report.categories)) {
    lines.push(`## ${name}`);
    if (items.length === 0) {
      lines.push('- none');
    } else {
      for (const item of items) {
        lines.push(`- L${item.line}: ${item.label} | ${item.text}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n').trimEnd() + '\n';
}

/**
 * Search for a regex pattern across all Luau files in the workspace.
 * Returns matches with file, line number, matched text, and optional context lines.
 */
export function patternSearchLuau(root, rawPattern, { maxResults = 100, context = 0, fileFilter } = {}) {
  let regex;
  try {
    regex = new RegExp(rawPattern, 'i');
  } catch {
    // Treat as literal string if invalid regex
    regex = new RegExp(rawPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  }

  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (!LUau_EXTENSIONS.has(ext)) return false;
    if (fileFilter) {
      const name = path.basename(filePath);
      return name.toLowerCase().includes(String(fileFilter).toLowerCase());
    }
    return true;
  });

  const matches = [];

  for (const file of files) {
    if (matches.length >= maxResults) break;
    const text = readText(file);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    const relPath = toPosix(relative(root, file));

    for (let i = 0; i < lines.length; i++) {
      if (matches.length >= maxResults) break;
      if (!regex.test(lines[i])) continue;

      const before = context > 0 ? lines.slice(Math.max(0, i - context), i).map((l, o) => ({ line: i - context + o + 1, text: l })) : [];
      const after = context > 0 ? lines.slice(i + 1, Math.min(lines.length, i + 1 + context)).map((l, o) => ({ line: i + 2 + o, text: l })) : [];

      matches.push({
        file: relPath,
        line: i + 1,
        text: lines[i],
        before,
        after,
      });
    }
  }

  return {
    pattern: rawPattern,
    totalMatches: matches.length,
    capped: matches.length >= maxResults,
    matches,
  };
}

// ── Flag Analysis ─────────────────────────────────────────────────────────────

/**
 * Extract all LibSixtyTen Flag definitions and reads from Luau text.
 * Detects duplicates and orphaned flags.
 */
export function extractFlagsFromText(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const defined = [];
  const read = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Flag definition: Flag = "Name" or Flag = 'Name'
    const defMatch = /\bFlag\s*=\s*["']([^"']+)["']/.exec(line);
    if (defMatch) {
      defined.push({ name: defMatch[1], line: i + 1, text: line.trim() });
    }

    // Flag reads: Library.Flags["Name"], Flags["Name"], Library.Flags.Name, Flags.Name
    const readMatch = /(?:Library\.)?Flags\[["']([^"']+)["']\]|(?:Library\.)?Flags\.(\w+)/.exec(line);
    if (readMatch) {
      const name = readMatch[1] || readMatch[2];
      if (name) read.push({ name, line: i + 1, text: line.trim() });
    }
  }

  const nameCounts = {};
  for (const d of defined) {
    nameCounts[d.name] = (nameCounts[d.name] || 0) + 1;
  }

  const definedNames = new Set(defined.map((d) => d.name));
  const readNames = new Set(read.map((r) => r.name));

  const duplicates = Object.entries(nameCounts)
    .filter(([, count]) => count > 1)
    .map(([name, count]) => ({
      name,
      count,
      occurrences: defined.filter((d) => d.name === name),
    }));

  return {
    filePath: toPosix(filePath),
    totalDefined: defined.length,
    totalRead: read.length,
    duplicates,
    hasDuplicates: duplicates.length > 0,
    orphanedDefined: defined.filter((d) => !readNames.has(d.name)),
    orphanedRead: read.filter((r) => !definedNames.has(r.name)),
    allFlags: defined,
  };
}

// ── UI Map Extraction ─────────────────────────────────────────────────────────

const UI_CONTAINERS = ['Page', 'Category', 'Section'];
const UI_CONTROLS = ['Toggle', 'Button', 'Slider', 'Dropdown', 'DropdownAmount', 'Textbox', 'Paragraph', 'Label', 'Divider', 'Keybind', 'Colorpicker'];
const UI_ALL = [...UI_CONTAINERS, ...UI_CONTROLS];

/**
 * Extract the Page→Category→Section→Controls hierarchy from a LibSixtyTen script.
 * Uses heuristic regex: handles single-line definitions and multi-line with Name on first line.
 */
export function extractUIMap(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const nodes = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Look ahead for Name if not on same line (handles 2-line case)
    const context = line + (lines[i + 1] || '');

    for (const method of UI_ALL) {
      // With assignment: local VarName = ParentVar:Method({...
      const assignRe = new RegExp(`local\\s+(\\w+)\\s*=\\s*(\\w+):${method}\\s*\\(`);
      const assignMatch = assignRe.exec(line);
      if (assignMatch) {
        const nameMatch = /Name\s*=\s*["']([^"']+)["']/.exec(context);
        const flagMatch = /Flag\s*=\s*["']([^"']+)["']/.exec(context);
        nodes.push({
          varName: assignMatch[1],
          type: method,
          name: nameMatch ? nameMatch[1] : '?',
          parentVar: assignMatch[2],
          line: i + 1,
          flag: flagMatch ? flagMatch[1] : null,
        });
        break;
      }

      // Without assignment: ParentVar:Method({...
      const callRe = new RegExp(`(\\w+):${method}\\s*\\(`);
      const callMatch = callRe.exec(line);
      if (callMatch && !/^\s*(?:local\s+\w+\s*=\s*)?\w+:(?:Window|Library)/.test(line)) {
        if (line.includes(`local `) && assignRe.test(line)) break;
        const nameMatch = /Name\s*=\s*["']([^"']+)["']/.exec(context);
        const flagMatch = /Flag\s*=\s*["']([^"']+)["']/.exec(context);
        nodes.push({
          varName: null,
          type: method,
          name: nameMatch ? nameMatch[1] : '?',
          parentVar: callMatch[1],
          line: i + 1,
          flag: flagMatch ? flagMatch[1] : null,
        });
        break;
      }
    }
  }

  // Build tree
  const byVar = {};
  for (const node of nodes) {
    if (node.varName) byVar[node.varName] = node;
  }

  const childrenMap = {};
  const roots = [];

  for (const node of nodes) {
    if (byVar[node.parentVar]) {
      if (!childrenMap[node.parentVar]) childrenMap[node.parentVar] = [];
      childrenMap[node.parentVar].push(node);
    } else {
      roots.push(node);
    }
  }

  function buildNode(node) {
    const result = { type: node.type, name: node.name, line: node.line };
    if (node.flag) result.flag = node.flag;
    const kids = node.varName ? childrenMap[node.varName] : null;
    if (kids && kids.length > 0) result.children = kids.map(buildNode);
    return result;
  }

  return {
    filePath: toPosix(filePath),
    summary: {
      pages: nodes.filter((n) => n.type === 'Page').length,
      sections: nodes.filter((n) => n.type === 'Section').length,
      controls: nodes.filter((n) => UI_CONTROLS.includes(n.type)).length,
    },
    tree: roots.map(buildNode),
  };
}

// ── Migration Checklist ───────────────────────────────────────────────────────

/**
 * Semantic migration checklist between two Luau files.
 * Returns a verdict (BLOCKED / REVIEW / READY) and a prioritized checklist.
 */
export function migrationChecklist(root, oldPath, newPath) {
  const oldFile = path.isAbsolute(oldPath) ? oldPath : path.join(root, oldPath);
  const newFile = path.isAbsolute(newPath) ? newPath : path.join(root, newPath);
  const oldText = readText(oldFile);
  const newText = readText(newFile);

  const oldA = analyzeLuauText(oldText, oldPath);
  const newA = analyzeLuauText(newText, newPath);
  const oldF = extractFlagsFromText(oldText, oldPath);
  const newF = extractFlagsFromText(newText, newPath);

  const oldFlagNames = new Set(oldF.allFlags.map((f) => f.name));
  const newFlagNames = new Set(newF.allFlags.map((f) => f.name));

  const lostFlags = [...oldFlagNames].filter((n) => !newFlagNames.has(n));
  const addedFlags = [...newFlagNames].filter((n) => !oldFlagNames.has(n));

  const hasPattern = (t, re) => re.test(t);
  const checklist = [];

  // Saved config loss — HIGH
  if (lostFlags.length > 0) {
    checklist.push({
      severity: 'high',
      check: 'saved-config-loss',
      pass: false,
      detail: `${lostFlags.length} flag(s) in old missing from new: [${lostFlags.join(', ')}] — saved user config will be lost unless migrated.`,
    });
  }

  // Autoload — HIGH
  const oldAutoload = hasPattern(oldText, /LoadAutoloadConfig\s*\(/);
  const newAutoload = hasPattern(newText, /LoadAutoloadConfig\s*\(/);
  checklist.push({
    severity: 'high',
    check: 'autoload-present',
    pass: newAutoload || !oldAutoload,
    detail: oldAutoload && !newAutoload
      ? 'LoadAutoloadConfig present in old but MISSING in new — config will not restore on load.'
      : newAutoload ? 'LoadAutoloadConfig present in new version.' : 'LoadAutoloadConfig absent in both versions.',
  });

  // Dashboard init — HIGH
  const oldDash = hasPattern(oldText, /CreateDashboard\s*\(/);
  const newDash = hasPattern(newText, /CreateDashboard\s*\(/);
  checklist.push({
    severity: 'high',
    check: 'dashboard-init',
    pass: newDash || !oldDash,
    detail: oldDash && !newDash
      ? 'CreateDashboard present in old but MISSING in new — UI will not initialize.'
      : newDash ? 'CreateDashboard present in new version.' : 'CreateDashboard absent in both versions.',
  });

  // Remote loss — MEDIUM
  const remoteDelta = newA.summary.remoteCount - oldA.summary.remoteCount;
  if (remoteDelta < 0) {
    checklist.push({
      severity: 'medium',
      check: 'remote-loss',
      pass: false,
      detail: `${Math.abs(remoteDelta)} fewer remote call(s) in new — verify each removal is intentional.`,
    });
  }

  // Callback loss — MEDIUM
  const callbackDelta = newA.summary.callbackCount - oldA.summary.callbackCount;
  if (callbackDelta < 0) {
    checklist.push({
      severity: 'medium',
      check: 'callback-loss',
      pass: false,
      detail: `${Math.abs(callbackDelta)} fewer callback(s) in new — verify each removal is intentional.`,
    });
  }

  // New risks — MEDIUM
  const newRisks = newA.summary.riskCount - oldA.summary.riskCount;
  if (newRisks > 0) {
    checklist.push({
      severity: 'medium',
      check: 'new-risks',
      pass: false,
      detail: `${newRisks} new risk(s) introduced in new version.`,
    });
  }

  // pcall coverage in new — MEDIUM
  const missingPcall = newA.categories.risks.filter((r) => r.label === 'missing-pcall').length;
  checklist.push({
    severity: 'medium',
    check: 'pcall-coverage',
    pass: missingPcall === 0,
    detail: missingPcall > 0
      ? `${missingPcall} remote call(s) without pcall in new version.`
      : 'All remote calls have pcall coverage in new version.',
  });

  // New flags — ADVISORY
  if (addedFlags.length > 0) {
    checklist.push({
      severity: 'advisory',
      check: 'new-flags',
      pass: true,
      detail: `${addedFlags.length} new flag(s) in new version: [${addedFlags.join(', ')}] — verify they have sensible defaults.`,
    });
  }

  // Flag duplicates in new — HIGH
  if (newF.hasDuplicates) {
    checklist.push({
      severity: 'high',
      check: 'duplicate-flags',
      pass: false,
      detail: `${newF.duplicates.length} duplicate Flag value(s) in new version: [${newF.duplicates.map((d) => d.name).join(', ')}] — two controls will share state.`,
    });
  }

  const blockers = checklist.filter((c) => !c.pass && c.severity === 'high');
  const warnings = checklist.filter((c) => !c.pass && c.severity === 'medium');

  return {
    paths: { old: toPosix(oldPath), new: toPosix(newPath) },
    summary: {
      oldLines: oldA.summary.lineCount,
      newLines: newA.summary.lineCount,
      lineDelta: newA.summary.lineCount - oldA.summary.lineCount,
      oldFlags: oldFlagNames.size,
      newFlags: newFlagNames.size,
      lostFlags: lostFlags.length,
      addedFlags: addedFlags.length,
    },
    verdict: blockers.length > 0 ? 'BLOCKED' : warnings.length > 0 ? 'REVIEW' : 'READY',
    blockers: blockers.length,
    warnings: warnings.length,
    checklist,
  };
}

export function buildLuauMigrationChangelog(result, { title = 'Luau migration changelog' } = {}) {
  const lines = [];
  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`Verdict: ${result.verdict}`);
  lines.push(`Old: ${result.paths.old}`);
  lines.push(`New: ${result.paths.new}`);
  lines.push('');
  lines.push(`Blockers: ${result.blockers}`);
  lines.push(`Warnings: ${result.warnings}`);
  lines.push('');

  if (result.checklist.length > 0) {
    lines.push('## Checklist');
    for (const item of result.checklist) {
      const state = item.pass ? 'PASS' : 'FAIL';
      lines.push(`- [${state}] ${item.check}: ${item.detail}`);
    }
    lines.push('');
  }

  return `${lines.join('\n').trimEnd()}\n`;
}

function describeRepair(label, beforeLine, afterLine) {
  switch (label) {
    case 'missing-pcall':
      return {
        explanation: 'Wrap the remote call in pcall so failures do not crash the script.',
        before: beforeLine,
        after: `pcall(function()\n  ${beforeLine.trim()}\nend)`,
      };
    case 'wait':
      return {
        explanation: 'Replace legacy wait() with task.wait() to match modern Luau scheduling.',
        before: beforeLine,
        after: beforeLine.replace(/\bwait\s*\(/g, 'task.wait('),
      };
    case 'spawn':
      return {
        explanation: 'Replace spawn() with task.spawn() to avoid legacy scheduler behavior.',
        before: beforeLine,
        after: beforeLine.replace(/\bspawn\s*\(/g, 'task.spawn('),
      };
    case 'unbounded-loop':
      return {
        explanation: 'Add a bounded loop or explicit exit condition before shipping this code path.',
        before: beforeLine,
        after: afterLine || '-- add a termination condition or iteration limit here',
      };
    case 'connection-cleanup':
      return {
        explanation: 'Track connections and disconnect them during teardown to prevent leaks.',
        before: beforeLine,
        after: 'local connections = {}\nlocal function track(connection)\n  connections[#connections + 1] = connection\n  return connection\nend',
      };
    case 'remote-rate-limit':
      return {
        explanation: 'Throttle repeated remote calls so the script does not spam the server.',
        before: beforeLine,
        after: `task.wait(0.15)\n${beforeLine}`,
      };
    default:
      return {
        explanation: 'No specific repair rule matched; review the line manually.',
        before: beforeLine,
        after: beforeLine,
      };
  }
}

export function repairLuauRisk(text, filePath = '', riskLabel = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const label = String(riskLabel || '').trim().toLowerCase();
  let lineIndex = lines.findIndex((line) => {
    if (label === 'wait') return /\bwait\s*\(/i.test(line);
    if (label === 'spawn') return /\bspawn\s*\(/i.test(line);
    if (label === 'missing-pcall') return /:((FireServer)|(InvokeServer))\s*\(/i.test(line) && !/\bpcall\b/i.test(line);
    if (label === 'unbounded-loop') return /\bwhile\s+true\s+do\b/i.test(line);
    if (label === 'connection-cleanup') return /\bConnect\s*\(/i.test(line);
    if (label === 'remote-rate-limit') return /:((FireServer)|(InvokeServer))\s*\(/i.test(line);
    return false;
  });
  if (lineIndex === -1) {
    lineIndex = 0;
  }
  const beforeLine = lines[lineIndex] || '';
  const repair = describeRepair(label, beforeLine, lines[lineIndex + 1] || '');
  const snippetLines = [
    ...lines.slice(Math.max(0, lineIndex - 1), lineIndex),
    repair.after,
    ...lines.slice(lineIndex + 1, Math.min(lines.length, lineIndex + 2)),
  ].filter(Boolean);
  return {
    summary: {
      filePath: toPosix(filePath),
      riskLabel: label,
      line: lineIndex + 1,
      sourceHash: crypto.createHash('sha256').update(source, 'utf8').digest('hex'),
    },
    explanation: repair.explanation,
    before: beforeLine,
    after: repair.after,
    snippet: snippetLines.join('\n'),
  };
}

export function buildLuauRemoteGraph(root, targetPath = '') {
  const files = resolveLuauFiles(root, targetPath);

  const remotes = new Map();
  const register = (name, filePath, line, kind, text) => {
    if (!name) return;
    if (!remotes.has(name)) {
      remotes.set(name, { name, kinds: new Set(), uses: [], handlers: [], files: new Set() });
    }
    const remote = remotes.get(name);
    remote.kinds.add(kind);
    remote.files.add(toPosix(relative(root, filePath)));
    const entry = { filePath: toPosix(relative(root, filePath)), line, text };
    if (/onserverevent|onclientevent/i.test(kind)) remote.handlers.push(entry); else remote.uses.push(entry);
  };

  for (const filePath of files) {
    const text = readText(filePath);
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const assign = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.*\b(RemoteEvent|RemoteFunction)\b/i.exec(line);
      if (assign) {
        register(assign[1], filePath, i + 1, assign[2].toLowerCase(), line.trim());
      }
      const waitForChild = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*.*WaitForChild\s*\(\s*["']([^"']+)["']\s*\)/i.exec(line);
      if (waitForChild) {
        register(waitForChild[1], filePath, i + 1, 'waitforchild', line.trim());
      }
      const fireMatch = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(FireServer|InvokeServer|FireClient)\s*\(/.exec(line);
      if (fireMatch) {
        register(fireMatch[1], filePath, i + 1, fireMatch[2].toLowerCase(), line.trim());
      }
      const handlerMatch = /([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(OnServerEvent|OnClientEvent)\b/.exec(line);
      if (handlerMatch) {
        register(handlerMatch[1], filePath, i + 1, handlerMatch[2].toLowerCase(), line.trim());
      }
    }
  }

  const entries = [...remotes.values()].map((remote) => {
    const kinds = [...remote.kinds];
    const hasServerHandler = remote.handlers.some((entry) => /OnServerEvent/i.test(entry.text));
    const hasClientHandler = remote.handlers.some((entry) => /OnClientEvent/i.test(entry.text));
    const kind = kinds.includes('remotefunction') || kinds.includes('invokeserver') ? 'function' : 'event';
    return {
      name: remote.name,
      kind,
      kinds,
      files: [...remote.files],
      uses: remote.uses,
      handlers: remote.handlers,
      hasServerHandler,
      hasClientHandler,
      orphaned: remote.uses.length > 0 && remote.handlers.length === 0,
    };
  }).sort((a, b) => a.name.localeCompare(b.name));

  return {
    summary: {
      fileCount: files.length,
      remoteCount: entries.length,
      orphanedCount: entries.filter((entry) => entry.orphaned).length,
      handlerCount: entries.reduce((sum, entry) => sum + entry.handlers.length, 0),
    },
    remotes: entries,
  };
}

export function scoreLuauComplexity(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const functions = [];
  const starts = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/\b(function\s+[A-Za-z_][A-Za-z0-9_\.:\[\]]*|local\s+function\s+[A-Za-z_][A-Za-z0-9_]*|=\s*function\s*\()/i.test(line)) {
      starts.push(i);
    }
  }

  for (const start of starts) {
    let depth = 1;
    let end = lines.length - 1;
    for (let i = start + 1; i < lines.length; i += 1) {
      const line = lines[i];
      depth += (line.match(/\b(function|if|for|while|repeat|do|then)\b/gi) || []).length;
      depth -= (line.match(/\b(end|until)\b/gi) || []).length;
      if (depth <= 0) {
        end = i;
        break;
      }
    }
    const body = lines.slice(start, end + 1).join('\n');
    const branchCount = (body.match(/\b(if|elseif|for|while|repeat|and|or|case)\b/gi) || []).length;
    const name = (lines[start].match(/local\s+function\s+([A-Za-z_][A-Za-z0-9_]*)/i)?.[1])
      || (lines[start].match(/function\s+([A-Za-z_][A-Za-z0-9_\.:\[\]]*)/i)?.[1])
      || `line_${start + 1}`;
    functions.push({
      name,
      startLine: start + 1,
      endLine: end + 1,
      complexity: 1 + branchCount,
      branchCount,
      text: lines.slice(start, end + 1).join('\n').trim(),
    });
  }

  return {
    summary: {
      filePath: toPosix(filePath),
      functionCount: functions.length,
      maxComplexity: functions.reduce((max, entry) => Math.max(max, entry.complexity), 0),
      averageComplexity: functions.length > 0 ? Number((functions.reduce((sum, entry) => sum + entry.complexity, 0) / functions.length).toFixed(2)) : 0,
    },
    functions: functions.sort((a, b) => b.complexity - a.complexity || a.startLine - b.startLine),
  };
}

export function analyzeLuauTaint(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const taintedVariables = new Set();
  const sources = [];
  const sinks = [];
  const sourceRe = /\b(HttpGetAsync|HttpGet|GetAsync|RequestAsync|loadstring|string\.char|bit32\.bxor|syn\.request|http_request)\b|https?:\/\//i;
  const sinkRe = /:((FireServer)|(InvokeServer)|(FireClient))\s*\(|\bloadstring\s*\(|\brequire\s*\(/i;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const assign = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)/.exec(line);
    if (assign && sourceRe.test(assign[2])) {
      taintedVariables.add(assign[1]);
      sources.push({ line: i + 1, variable: assign[1], text: line.trim(), severity: 'high', confidence: 0.96 });
    }
    for (const variable of taintedVariables) {
      if (new RegExp(`\\b${variable}\\b`).test(line) && sinkRe.test(line)) {
        sinks.push({ line: i + 1, variable, text: line.trim(), severity: 'high', confidence: 0.94 });
      }
    }
  }

  return {
    summary: {
      filePath: toPosix(filePath),
      sourceCount: sources.length,
      sinkCount: sinks.length,
      taintedVariableCount: taintedVariables.size,
      confidenceAverage: averageConfidence([...sources, ...sinks]),
    },
    taintedVariables: [...taintedVariables],
    sources,
    sinks,
    flows: sources.flatMap((source) => sinks.filter((sink) => sink.variable === source.variable).map((sink) => ({
      variable: source.variable,
      sourceLine: source.line,
      sinkLine: sink.line,
      severity: 'high',
      confidence: Number(((source.confidence + sink.confidence) / 2).toFixed(2)),
    }))),
  };
}

export function analyzeLuauFlow(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const nodes = new Map();
  const edges = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const assign = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b/.exec(line);
    if (assign) {
      nodes.set(assign[1], { name: assign[1], kind: 'local', line: i + 1 });
      nodes.set(assign[2], nodes.get(assign[2]) || { name: assign[2], kind: 'reference' });
      edges.push({ from: assign[2], to: assign[1], line: i + 1, kind: 'assignment' });
    }

    const fn = /(?:local\s+function|function)\s+([A-Za-z_][A-Za-z0-9_\.:\[\]]*)/.exec(line);
    if (fn) {
      nodes.set(fn[1], { name: fn[1], kind: 'function', line: i + 1 });
    }

    const remote = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(FireServer|InvokeServer|FireClient)\s*\(/.exec(line);
    if (remote) {
      nodes.set(remote[1], nodes.get(remote[1]) || { name: remote[1], kind: 'remote' });
      edges.push({ from: remote[1], to: remote[2], line: i + 1, kind: 'remote-call' });
    }
  }

  return {
    summary: {
      filePath: toPosix(filePath),
      nodeCount: nodes.size,
      edgeCount: edges.length,
      localCount: lines.filter((line) => /^\s*local\s+/.test(line)).length,
    },
    nodes: [...nodes.values()],
    edges,
  };
}

export function mapLuauHandlers(root, targetPath = '') {
  const graph = buildLuauRemoteGraph(root, targetPath);
  return {
    summary: {
      fileCount: graph.summary.fileCount,
      remoteCount: graph.summary.remoteCount,
      handlerCount: graph.summary.handlerCount,
      orphanedCount: graph.summary.orphanedCount,
    },
    remotes: graph.remotes.map((remote) => ({
      name: remote.name,
      kind: remote.kind,
      files: remote.files,
      hasServerHandler: remote.hasServerHandler,
      hasClientHandler: remote.hasClientHandler,
      orphaned: remote.orphaned,
    })),
  };
}

export function summarizeLuauSurface(root, targetPath = '') {
  const scan = scanLuauWorkspace(root);
  const dependencyGraph = buildLuauDependencyMap(root, targetPath);
  const files = scan.files.map((entry) => {
    const findings = [...entry.categories.callbacks, ...entry.categories.remotes, ...entry.categories.state, ...entry.categories.ui, ...entry.categories.risks];
    return {
      file: entry.filePath,
      riskCount: entry.summary.riskCount,
      remoteCount: entry.summary.remoteCount,
      callbackCount: entry.summary.callbackCount,
      confidenceAverage: averageConfidence(findings),
    };
  });

  return {
    summary: {
      totalFiles: scan.totalFiles,
      totalCallbacks: scan.totalCallbacks,
      totalRemotes: scan.totalRemotes,
      totalRisks: scan.totalRisks,
      dependencyCount: dependencyGraph.summary.dependencyCount,
      orphanedScriptCount: dependencyGraph.summary.orphanedScriptCount,
      confidenceAverage: averageConfidence(files),
    },
    files,
    dependencies: dependencyGraph,
  };
}

export function suggestLuauRefactor(text, filePath = '', riskLabel = '') {
  const repair = repairLuauRisk(text, filePath, riskLabel);
  return {
    summary: {
      ...repair.summary,
      confidence: repair.summary.riskLabel ? 0.9 : 0.7,
    },
    explanation: repair.explanation,
    before: repair.before,
    after: repair.after,
    snippet: repair.snippet,
  };
}

export function buildLuauModuleGraph(root, targetPath = '') {
  const graph = buildLuauDependencyMap(root, targetPath);
  const modules = graph.scripts.map((script) => ({
    path: script.path,
    hash: script.hash,
    requires: script.requires,
    unusedImports: script.unusedImports,
  }));
  const edges = modules.flatMap((module) => module.requires.map((requireEntry) => ({
    from: module.path,
    to: requireEntry.target,
    alias: requireEntry.alias,
    line: requireEntry.line,
  })));
  return {
    summary: {
      scriptCount: graph.summary.scriptCount,
      nodeCount: modules.length,
      edgeCount: edges.length,
      orphanedScriptCount: graph.summary.orphanedScriptCount,
    },
    modules,
    edges,
  };
}

export function scoreLuauRisk(text, filePath = '') {
  const analysis = analyzeLuauText(text, filePath);
  const security = scanLuauSecurity(text, filePath);
  const performance = profileLuauPerformance(text, filePath);
  const taint = analyzeLuauTaint(text, filePath);
  const missingPcall = analysis.categories.risks.filter((risk) => risk.label === 'missing-pcall').length;
  const score = Math.min(100, Math.round(
    analysis.summary.riskCount * 10
    + security.summary.findingCount * 8
    + performance.summary.findingCount * 4
    + taint.summary.sinkCount * 12
    + missingPcall * 15
    + analysis.summary.localCount / 4,
  ));
  return {
    summary: {
      filePath: toPosix(filePath),
      score,
      confidenceAverage: averageConfidence([
        ...analysis.categories.risks,
        ...security.findings,
        ...performance.findings,
        ...taint.sources,
        ...taint.sinks,
      ]),
      riskCount: analysis.summary.riskCount,
      securityCount: security.summary.findingCount,
      performanceCount: performance.summary.findingCount,
      taintCount: taint.summary.sinkCount,
    },
    contributions: {
      risks: analysis.summary.riskCount * 10,
      security: security.summary.findingCount * 8,
      performance: performance.summary.findingCount * 4,
      taint: taint.summary.sinkCount * 12,
      missingPcall: missingPcall * 15,
    },
  };
}

export function diffLuauWithContext(root, pathA, pathB, { context = 2 } = {}) {
  const fileA = path.isAbsolute(pathA) ? pathA : path.join(root, pathA);
  const fileB = path.isAbsolute(pathB) ? pathB : path.join(root, pathB);
  const textA = readText(fileA);
  const textB = readText(fileB);
  const linesA = textA.split(/\r?\n/);
  const linesB = textB.split(/\r?\n/);
  const max = Math.max(linesA.length, linesB.length);
  const hunks = [];

  for (let i = 0; i < max; i += 1) {
    const left = linesA[i];
    const right = linesB[i];
    if (left === right) continue;
    if (left !== undefined) {
      hunks.push({
        type: right === undefined ? 'removed' : 'changed',
        line: i + 1,
        before: left,
        after: right ?? '',
        contextBefore: buildContextSnippet(linesA, i + 1, context),
        contextAfter: buildContextSnippet(linesB, i + 1, context),
      });
    } else if (right !== undefined) {
      hunks.push({
        type: 'added',
        line: i + 1,
        before: '',
        after: right,
        contextBefore: buildContextSnippet(linesA, i + 1, context),
        contextAfter: buildContextSnippet(linesB, i + 1, context),
      });
    }
  }

  return {
    summary: {
      fileA: toPosix(pathA),
      fileB: toPosix(pathB),
      hunkCount: hunks.length,
    },
    structural: diffLuauFiles(root, pathA, pathB),
    hunks,
  };
}

export function scanLuauSecurity(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const patterns = [
    { label: 'webhook', re: /https?:\/\/(?:canary\.|ptb\.)?(?:discord(?:app)?\.com|discord\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/i },
    { label: 'loadstring-remote', re: /\bloadstring\s*\(\s*(?:game\.)?(?:HttpGet|HttpGetAsync|RequestAsync)\s*\(/i },
    { label: 'token-exfil', re: /\b(api[_-]?key|token|secret|cookie|session)\b/i },
    { label: 'http-call', re: /\bHttp(Service|Get|Post|RequestAsync)\b/i },
    { label: 'backdoor-pattern', re: /\b(getfenv|getgenv|setclipboard|syn\.request|http_request)\b/i },
  ];
  const findings = [];
  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i += 1) {
      if (pattern.re.test(lines[i])) {
        findings.push({ line: i + 1, label: pattern.label, text: lines[i].trim() });
      }
    }
  }
  return {
    summary: {
      filePath: toPosix(filePath),
      findingCount: findings.length,
      highRiskCount: findings.filter((finding) => /webhook|loadstring-remote|backdoor-pattern|token-exfil/i.test(finding.label)).length,
    },
    findings: findings.map((finding) => ({
      ...finding,
      severity: /webhook|loadstring-remote|backdoor-pattern|token-exfil/i.test(finding.label) ? 'high' : 'medium',
      confidence: /webhook|loadstring-remote|backdoor-pattern/i.test(finding.label) ? 0.96 : 0.88,
    })),
  };
}

export function profileLuauPerformance(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const findings = [];
  const patterns = [
    { label: 'hot-loop', re: /\bwhile\s+true\s+do\b/ },
    { label: 'repeat-loop', re: /\brepeat\b[\s\S]{0,80}\buntil\b/i },
    { label: 'nested-wait', re: /\bwait\s*\(\s*\)\s*[\s\S]{0,40}\bwait\s*\(\s*\)/i },
    { label: 'task-spawn', re: /\btask\.spawn\s*\(/i },
    { label: 'spawn', re: /\bspawn\s*\(/i },
    { label: 'delay', re: /\bdelay\s*\(/i },
    { label: 'connect-without-cleanup', re: /\bConnect\s*\(/i },
  ];
  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i += 1) {
      if (pattern.re.test(lines[i])) {
        findings.push({ line: i + 1, label: pattern.label, text: lines[i].trim() });
      }
    }
  }
  return {
    summary: {
      filePath: toPosix(filePath),
      findingCount: findings.length,
      loopCount: findings.filter((finding) => /hot-loop|repeat-loop|nested-wait/.test(finding.label)).length,
      cleanupIssues: findings.filter((finding) => finding.label === 'connect-without-cleanup').length,
    },
    findings: findings.map((finding) => ({
      ...finding,
      severity: /hot-loop|repeat-loop|nested-wait/i.test(finding.label) ? 'medium' : 'low',
      confidence: /connect-without-cleanup/i.test(finding.label) ? 0.82 : 0.85,
    })),
  };
}

export function decompileLuauHeuristics(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const patterns = [
    { label: 'char-encoding', re: /\bstring\.char\s*\(/i },
    { label: 'byte-encoding', re: /\bstring\.byte\s*\(/i },
    { label: 'xor-math', re: /\bbit32\.bxor\s*\(/i },
    { label: 'gsub-obfuscation', re: /\bstring\.gsub\s*\(\s*[^,]+,\s*["'][^"']{0,4}["']/i },
    { label: 'hex-string', re: /0x[0-9a-f]{8,}/i },
    { label: 'long-concat', re: /\.\.\s*["'][^"']{0,2}["']\s*\.\./ },
    { label: 'loader', re: /\b(loadstring|load|require)\s*\(/i },
  ];
  const findings = [];
  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i += 1) {
      if (pattern.re.test(lines[i])) {
        findings.push({ line: i + 1, label: pattern.label, text: lines[i].trim() });
      }
    }
  }
  const strings = (source.match(/["'][^"']{3,}["']/g) || []).slice(0, 100);
  return {
    summary: {
      filePath: toPosix(filePath),
      findingCount: findings.length,
      sourceHash: crypto.createHash('sha256').update(source, 'utf8').digest('hex'),
    },
    findings: findings.map((finding) => ({
      ...finding,
      severity: 'medium',
      confidence: /loader/i.test(finding.label) ? 0.9 : 0.72,
    })),
    strings,
    remoteHints: lines
      .map((line, index) => ({ line: index + 1, text: line.trim() }))
      .filter((entry) => /\b(RemoteEvent|RemoteFunction|FireServer|InvokeServer|FireClient)\b/i.test(entry.text)),
  };
}

export function buildLuauDependencyMap(root, targetPath = '') {
  const files = resolveLuauFiles(root, targetPath);

  const scripts = files.map((filePath) => {
    const text = readText(filePath);
    const requires = [];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const match = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*require\s*\(\s*([^)]+)\s*\)/.exec(lines[i]) || /([A-Za-z_][A-Za-z0-9_]*)\s*=\s*require\s*\(\s*([^)]+)\s*\)/.exec(lines[i]);
      if (match) {
        requires.push({ line: i + 1, alias: match[1], target: match[2].trim(), text: lines[i].trim() });
      }
    }
    const unusedImports = requires.filter((entry) => (text.match(new RegExp(`\\b${entry.alias}\\b`, 'g')) || []).length <= 1).map((entry) => entry.alias);
    return {
      path: toPosix(relative(root, filePath)),
      requires,
      unusedImports,
      hash: crypto.createHash('sha256').update(text, 'utf8').digest('hex'),
    };
  });

  return {
    summary: {
      scriptCount: scripts.length,
      dependencyCount: scripts.reduce((sum, script) => sum + script.requires.length, 0),
      orphanedScriptCount: scripts.filter((script) => script.requires.length === 0).length,
    },
    scripts,
  };
}

export function generateLuauTemplate({ templateType = 'utility', name = 'NewScript', outputPath = '' } = {}) {
  const safeName = String(name || 'NewScript').replace(/[^A-Za-z0-9_]/g, '') || 'NewScript';
  const templates = {
    'auto-farm': [
      'local Players = game:GetService("Players")',
      'local RunService = game:GetService("RunService")',
      '',
      'local Connections = {}',
      '',
      'local function Track(connection)',
      '    Connections[#Connections + 1] = connection',
      '    return connection',
      'end',
      '',
      'RunService.Heartbeat:Connect(function()',
      '    pcall(function()',
      '        -- auto-farm logic',
      '    end)',
      'end)',
      '',
    ],
    esp: [
      'local RunService = game:GetService("RunService")',
      '',
      'RunService.RenderStepped:Connect(function()',
      '    pcall(function()',
      '        -- ESP render logic',
      '    end)',
      'end)',
      '',
    ],
    combat: [
      'local ReplicatedStorage = game:GetService("ReplicatedStorage")',
      'local Remote = ReplicatedStorage:WaitForChild("RemoteEvent")',
      '',
      'local function FireSafely(...)',
      '    return pcall(function(...)',
      '        Remote:FireServer(...)',
      '    end, ...)',
      'end',
      '',
    ],
    utility: [
      'local function Main()',
      '    pcall(function()',
      '        -- utility logic',
      '    end)',
      'end',
      '',
      'Main()',
      '',
    ],
  };
  const scaffold = [`-- helper-mcp template: ${templateType}`, `-- script: ${safeName}`, '', ...(templates[templateType] || templates.utility)].join('\n');
  if (outputPath) {
    writeText(outputPath, `${scaffold.trimEnd()}\n`);
  }
  return { templateType, name: safeName, outputPath: toPosix(outputPath), scaffold: `${scaffold.trimEnd()}\n` };
}

function wrapRemoteStatements(lines) {
  const output = [];
  const edits = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (/:((FireServer)|(InvokeServer))\s*\(/.test(trimmed) && !/\bpcall\s*\(/.test(trimmed) && !trimmed.startsWith('--')) {
      output.push(`${line.match(/^\s*/)?.[0] || ''}pcall(function() ${trimmed} end)`);
      edits.push({ line: index + 1, before: line, after: `pcall(function() ${trimmed} end)`, label: 'pcall-wrap' });
      continue;
    }
    output.push(line);
  }
  return { lines: output, edits };
}

function insertRateLimitGuards(lines) {
  const output = [];
  const edits = [];
  let previousRemote = '';
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    const currentRemote = trimmed.match(/([A-Za-z_][A-Za-z0-9_\.:\[\]]*):(FireServer|InvokeServer)\s*\(/)?.[1] || '';
    if (currentRemote && currentRemote === previousRemote) {
      const indent = line.match(/^\s*/)?.[0] || '';
      const guard = `${indent}task.wait(0.15) -- helper-mcp inserted rate limiter`;
      output.push(guard);
      edits.push({ line: index + 1, before: '', after: guard, label: 'remote-rate-limit' });
    }
    output.push(line);
    previousRemote = currentRemote || previousRemote;
  }
  return { lines: output, edits };
}

function prependConnectionCleanup(lines, originalText) {
  const hasConnect = /\bConnect\s*\(/.test(originalText);
  const hasDisconnect = /\bDisconnect\s*\(/.test(originalText) || /\bDestroy\s*\(/.test(originalText);
  if (!hasConnect || hasDisconnect) {
    return { lines, edits: [] };
  }
  const helperBlock = [
    '-- helper-mcp inserted connection cleanup helper',
    'local __helperConnections = {}',
    'local function __helperTrack(connection)',
    '    __helperConnections[#__helperConnections + 1] = connection',
    '    return connection',
    'end',
    '',
  ];
  return {
    lines: [...helperBlock, ...lines],
    edits: [{ line: 1, before: '', after: helperBlock.join('\n').trimEnd(), label: 'connection-cleanup-helper' }],
  };
}

export function hotfixLuauText(text, filePath = '', { apply = true } = {}) {
  const source = String(text || '');
  const originalLines = source.split(/\r?\n/);
  const pcallFix = wrapRemoteStatements(originalLines);
  const rateLimitFix = insertRateLimitGuards(pcallFix.lines);
  const cleanupFix = prependConnectionCleanup(rateLimitFix.lines, source);
  const finalText = cleanupFix.lines.join('\n');
  return {
    summary: {
      filePath: toPosix(filePath),
      appliedFixCount: pcallFix.edits.length + rateLimitFix.edits.length + cleanupFix.edits.length,
      beforeHash: crypto.createHash('sha256').update(source, 'utf8').digest('hex'),
      afterHash: crypto.createHash('sha256').update(finalText, 'utf8').digest('hex'),
      changed: finalText !== source,
    },
    fixes: [...pcallFix.edits, ...rateLimitFix.edits, ...cleanupFix.edits],
    before: source,
    after: finalText,
    applied: apply !== false,
  };
}

export function formatLuauHotfix(report) {
  const lines = [];
  lines.push(`# ${report.summary.filePath || 'Luau hotfix'}`);
  lines.push('');
  lines.push(`Applied fixes: ${report.summary.appliedFixCount}`);
  lines.push(`Changed: ${report.summary.changed ? 'yes' : 'no'}`);
  lines.push(`Before hash: ${report.summary.beforeHash}`);
  lines.push(`After hash: ${report.summary.afterHash}`);
  lines.push('');
  for (const fix of report.fixes) {
    lines.push(`- ${fix.label} @ L${fix.line}`);
  }
  lines.push('');
  return `${lines.join('\n').trimEnd()}\n`;
}

export function writeLuauHotfixSnapshots(root, filePath, report) {
  const dir = path.join(root, '.helper-mcp', 'hotfixes');
  fs.mkdirSync(dir, { recursive: true });
  const safeName = String(filePath || 'hotfix').replace(/[^\w.-]+/g, '_') || 'hotfix';
  const snapshotPath = path.join(dir, `${safeName}.json`);
  writeText(snapshotPath, `${JSON.stringify({
    kind: 'helper-mcp-hotfix',
    generatedAt: new Date().toISOString(),
    filePath: toPosix(filePath),
    report,
  }, null, 2)}\n`);
  return snapshotPath;
}

// ── Remote Payload Analysis ───────────────────────────────────────────────────

/**
 * Deep analysis of FireServer / InvokeServer calls.
 * Extracts payload structure: table keys, literal values, variable references.
 * Groups by remote object name and generates reference documentation.
 */
export function extractRemotePayloads(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const remotes = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineRe = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer)\s*\(([\s\S]*)/;
    const match = lineRe.exec(line);
    if (!match) continue;

    const remoteName = match[1];
    const method = match[2];
    const restOfLine = match[3];

    // Collect full payload string (may span multiple lines)
    let payloadStr = restOfLine;
    let scanLine = i;
    let parenDepth = 1;
    while (scanLine < lines.length && parenDepth > 0) {
      const scanText = scanLine === i ? restOfLine : lines[scanLine];
      for (const ch of scanText) {
        if (ch === '(') parenDepth++;
        else if (ch === ')') {
          parenDepth--;
          if (parenDepth === 0) break;
        }
      }
      if (parenDepth > 0) {
        scanLine++;
        if (scanLine < lines.length) {
          payloadStr += '\n' + lines[scanLine];
        }
      }
    }

    payloadStr = payloadStr.replace(/\)\s*$/, '').trim();
    const payload = analyzePayload(payloadStr);

    remotes.push({
      remote: remoteName,
      method,
      line: i + 1,
      payload,
      rawSnippet: payloadStr.slice(0, 200),
    });
  }

  const byRemote = {};
  for (const r of remotes) {
    if (!byRemote[r.remote]) byRemote[r.remote] = [];
    byRemote[r.remote].push({ method: r.method, line: r.line, payload: r.payload, rawSnippet: r.rawSnippet });
  }

  const summary = {
    totalCalls: remotes.length,
    uniqueRemotes: Object.keys(byRemote).length,
    remoteNames: Object.keys(byRemote).sort(),
    callSites: remotes.map((r) => ({ remote: r.remote, method: r.method, line: r.line })),
    byRemote,
  };

  return {
    filePath: toPosix(filePath),
    summary,
    remotes,
  };
}

function analyzePayload(payloadStr) {
  const payload = {
    style: 'unknown',
    tableKeys: [],
    literalValues: [],
    variableRefs: [],
    nestingDepth: 0,
    rawSnippet: payloadStr.slice(0, 300),
  };

  const trimmed = payloadStr.trim();
  if (!trimmed) {
    payload.style = 'empty';
    return payload;
  }

  if (trimmed.startsWith('{')) {
    payload.style = 'table';
    payload.tableKeys = extractTableKeys(trimmed);
    payload.literalValues = extractLiterals(trimmed);
    payload.variableRefs = extractVariableRefs(trimmed);
    payload.nestingDepth = maxNestingDepth(trimmed);
    return payload;
  }

  payload.style = 'positional';
  const args = splitTopLevelArgs(trimmed);
  for (const arg of args) {
    const a = arg.trim();
    if (/^["']/.test(a)) {
      payload.literalValues.push({ type: 'string', value: a.replace(/^["']|["']$/g, '').slice(0, 80) });
    } else if (/^\d+\.?\d*$/.test(a)) {
      payload.literalValues.push({ type: 'number', value: parseFloat(a) });
    } else if (/^Enum\./.test(a)) {
      payload.literalValues.push({ type: 'enum', value: a });
    } else if (a) {
      payload.variableRefs.push(a.slice(0, 80));
    }
  }
  return payload;
}

function extractTableKeys(text) {
  const keys = [];
  const keyRe = /(?:^|,)\s*(?:(\w+)\s*=|(\[\s*["']([^"']+)["']\s*\])\s*=)/gm;
  let m;
  while ((m = keyRe.exec(text)) !== null) {
    const keyName = m[1] || m[3];
    if (keyName) keys.push(keyName);
  }
  return keys;
}

function extractLiterals(text) {
  const literals = [];
  const strRe = /["']([^"']{1,80})["']/g;
  let ms;
  while ((ms = strRe.exec(text)) !== null) {
    literals.push({ type: 'string', value: ms[1] });
  }
  const numRe = /(?<![.\w])(\d+\.?\d*)(?![.\w])/g;
  while ((ms = numRe.exec(text)) !== null) {
    literals.push({ type: 'number', value: parseFloat(ms[1]) });
  }
  if (/\btrue\b/.test(text)) literals.push({ type: 'boolean', value: true });
  if (/\bfalse\b/.test(text)) literals.push({ type: 'boolean', value: false });
  return literals;
}

function extractVariableRefs(text) {
  const vars = new Set();
  const idRe = /\b([A-Z]\w*)\b/g;
  let m;
  const keywords = new Set(['true', 'false', 'nil', 'Enum', 'task', 'game', 'workspace', 'script', 'math', 'string', 'table', 'os', 'Vector3', 'CFrame', 'UDim2', 'Color3', 'BrickColor']);
  while ((m = idRe.exec(text)) !== null) {
    if (!keywords.has(m[1])) vars.add(m[1]);
  }
  return [...vars];
}

function maxNestingDepth(text) {
  let depth = 0, max = 0;
  for (const ch of text) {
    if (ch === '{') { depth++; if (depth > max) max = depth; }
    else if (ch === '}') depth--;
  }
  return Math.max(0, max - 1);
}

function splitTopLevelArgs(text) {
  const args = [];
  let depth = 0, current = '';
  for (const ch of text) {
    if (ch === '{' || ch === '(' || ch === '[') depth++;
    else if (ch === '}' || ch === ')' || ch === ']') depth--;
    else if (ch === ',' && depth === 0) {
      args.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) args.push(current);
  return args;
}

// ── Luau Linting ──────────────────────────────────────────────────────────────

export function lintLuauText(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const issues = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith('--')) continue;

    if (/\bwait\s*\(/.test(trimmed) && !/\btask\.wait\b/.test(trimmed)) {
      issues.push({ line: i + 1, severity: 'warning', rule: 'deprecated-wait', message: 'Use task.wait() instead of wait().' });
    }
    if (/\bspawn\s*\(/.test(trimmed) && !/\btask\.spawn\b/.test(trimmed)) {
      issues.push({ line: i + 1, severity: 'warning', rule: 'deprecated-spawn', message: 'Use task.spawn() instead of spawn().' });
    }
    if (/\bdelay\s*\(/.test(trimmed) && !/\btask\.delay\b/.test(trimmed)) {
      issues.push({ line: i + 1, severity: 'warning', rule: 'deprecated-delay', message: 'Use task.delay() instead of delay().' });
    }

    const coordMatch = trimmed.match(/CFrame\.new\s*\(\s*(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)\s*,\s*(-?\d+\.?\d*)\s*\)/);
    if (coordMatch) {
      issues.push({ line: i + 1, severity: 'info', rule: 'magic-coordinates', message: `Hardcoded CFrame: (${coordMatch[1]}, ${coordMatch[2]}, ${coordMatch[3]}) — consider named constants.` });
    }

    const magicNumRe = /=\s*(\d{4,})\b/;
    const magicNumMatch = trimmed.match(magicNumRe);
    if (magicNumMatch && !/^\s*--/.test(trimmed)) {
      issues.push({ line: i + 1, severity: 'info', rule: 'magic-number', message: `Large literal ${magicNumMatch[1]} — consider a named constant.` });
    }

    if (trimmed.length > 200) {
      issues.push({ line: i + 1, severity: 'info', rule: 'long-line', message: `Line is ${trimmed.length} chars (max recommended: 200).` });
    }

    const urlMatch = trimmed.match(/https?:\/\/[^\s"')]+/g);
    if (urlMatch) {
      for (const url of urlMatch) {
        if (!url.includes('github.com') && !url.includes('discord.gg') && !url.includes('dsc.gg')) {
          issues.push({ line: i + 1, severity: 'info', rule: 'external-url', message: `External URL: ${url.slice(0, 80)} — verify it is still accessible.` });
        }
      }
    }

    if (/:FireServer\s*\(|:InvokeServer\s*\(/.test(trimmed) && !/\bpcall\b/.test(trimmed)) {
      if (!isInsidePcall(lines, i)) {
        issues.push({ line: i + 1, severity: 'warning', rule: 'unwrapped-remote', message: 'Remote call not wrapped in pcall — may error on unexpected game state.' });
      }
    }

    if (/while\s+true\s+do/.test(trimmed)) {
      let hasWait = false;
      for (let j = i + 1; j < Math.min(i + 20, lines.length); j++) {
        if (/task\.wait/.test(lines[j])) { hasWait = true; break; }
        if (/end\s*$/.test(lines[j].trim())) break;
      }
      if (!hasWait) {
        issues.push({ line: i + 1, severity: 'error', rule: 'unbounded-loop', message: 'while true do without task.wait — may freeze the executor.' });
      }
    }

    if (/game:GetService/.test(trimmed) && i > 50) {
      issues.push({ line: i + 1, severity: 'info', rule: 'uncached-service', message: 'game:GetService called late in file — consider caching at top.' });
    }
  }

  const funcRanges = extractFunctionRanges(lines);
  for (const func of funcRanges) {
    const len = func.end - func.start;
    if (len > 80) {
      issues.push({ line: func.start, severity: 'info', rule: 'long-function', message: `Function "${func.name}" is ${len} lines — consider splitting.` });
    }
  }

  const bySeverity = { error: 0, warning: 0, info: 0 };
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  return {
    filePath: toPosix(filePath),
    totalLines: lines.length,
    totalIssues: issues.length,
    bySeverity,
    issues,
  };
}

function isInsidePcall(lines, index) {
  for (let i = Math.max(0, index - 10); i < index; i++) {
    if (/\bpcall\s*\(/.test(lines[i])) return true;
    if (/\bpcallRef\s*\(/.test(lines[i])) return true;
  }
  return false;
}

function extractFunctionRanges(lines) {
  const funcs = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m1 = /local\s+function\s+(\w+)/.exec(line);
    const m2 = /function\s+(\w[\w.:]*)\s*\(/.exec(line);
    const m3 = /(\w+)\s*=\s*function\s*\(/.exec(line);
    const name = (m1 && m1[1]) || (m2 && m2[1]) || (m3 && m3[1]);
    if (name) {
      funcs.push({ name, start: i + 1, end: findFunctionEnd(lines, i) });
    }
  }
  return funcs;
}

function findFunctionEnd(lines, startIndex) {
  let depth = 0;
  let started = false;
  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i].trim();
    for (const keyword of ['function', 'then', 'do']) {
      const re = new RegExp(`\\b${keyword}\\b`, 'g');
      while (re.exec(line)) depth++;
    }
    const endRe = /\bend\b/g;
    while (endRe.exec(line)) depth--;
    if (depth <= 0 && started) return i + 1;
    if (depth > 0) started = true;
  }
  return lines.length;
}

export function scanRemotePayloads(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const results = [];
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const analysis = extractRemotePayloads(text, relPath);
    if (analysis.summary.totalCalls > 0) {
      results.push(analysis);
    }
  }

  return {
    totalFiles: results.length,
    totalCalls: results.reduce((sum, r) => sum + r.summary.totalCalls, 0),
    files: results.map((r) => ({
      file: r.filePath,
      totalCalls: r.summary.totalCalls,
      uniqueRemotes: r.summary.uniqueRemotes,
      remoteNames: r.summary.remoteNames.slice(0, 20),
    })),
  };
}

export function scanLuauLint(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const results = [];
  let totalIssues = 0;
  const bySeverity = { error: 0, warning: 0, info: 0 };

  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const lint = lintLuauText(text, relPath);
    if (lint.totalIssues > 0) {
      results.push({
        file: lint.filePath,
        totalLines: lint.totalLines,
        totalIssues: lint.totalIssues,
        bySeverity: lint.bySeverity,
        topIssues: lint.issues.slice(0, 10),
      });
      totalIssues += lint.totalIssues;
      for (const [sev, count] of Object.entries(lint.bySeverity)) {
        bySeverity[sev] = (bySeverity[sev] || 0) + count;
      }
    }
  }

  results.sort((a, b) => b.totalIssues - a.totalIssues);

  return {
    totalFiles: results.length,
    totalIssues,
    bySeverity,
    files: results,
  };
}

// ── Game API Surface Map ─────────────────────────────────────────────────────

/**
 * Extracts the full communication surface of a game script:
 * remote names, payload keys, attribute reads/writes, workspace object references,
 * service usage, custom functions, and config structures.
 */
export function extractGameApiMap(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const api = {
    remotes: { fire: [], invoke: [], definitions: [] },
    attributes: { get: [], set: [], patterns: [] },
    workspace: { live: [], other: [], referenced: [] },
    services: new Set(),
    functions: [],
    configKeys: [],
    constants: [],
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // 1. Remote calls
    const fireMatch = trimmed.match(/(\w[\w.]*)\s*:\s*(FireServer|InvokeServer|FireClient|FireAllClients)\s*\(/);
    if (fireMatch) {
      const entry = { name: fireMatch[1], method: fireMatch[2], line: i + 1 };
      api.remotes.fire.push(entry);
      // Extract payload keys
      const payloadExtract = extractPayloadKeys(trimmed);
      if (payloadExtract.length > 0) entry.keys = payloadExtract;
    }
    const invokeMatch = trimmed.match(/(\w[\w.]*)\s*:\s*(InvokeServer|InvokeClient)\s*\(/);
    if (invokeMatch && !fireMatch) {
      api.remotes.invoke.push({ name: invokeMatch[1], method: invokeMatch[2], line: i + 1 });
    }
    // Remote definitions
    const remoteDefMatch = trimmed.match(/:\s*(RemoteEvent|RemoteFunction)\s*\(\s*["']([^"']+)["']/);
    if (remoteDefMatch) {
      api.remotes.definitions.push({ type: remoteDefMatch[1], name: remoteDefMatch[2], line: i + 1 });
    }

    // 2. Attribute access
    const attrGetMatch = trimmed.match(/(\w+)\s*:\s*GetAttribute\s*\(\s*["']([^"']+)["']\s*\)/);
    if (attrGetMatch) {
      api.attributes.get.push({ key: attrGetMatch[2], source: attrGetMatch[1], line: i + 1 });
    }
    const attrSetMatch = trimmed.match(/(\w+)\s*:\s*SetAttribute\s*\(\s*["']([^"']+)["']\s*,/);
    if (attrSetMatch) {
      api.attributes.set.push({ key: attrSetMatch[2], source: attrSetMatch[1], line: i + 1 });
    }

    // 3. Workspace references (Live folder, etc)
    const liveMatch = trimmed.match(/workspace\s*\.Live\s*:\s*GetChildren\s*\(\)/);
    if (liveMatch) {
      api.workspace.live.push({ line: i + 1 });
    }
    const workspaceRefMatch = trimmed.match(/workspace\s*\.(\w[\w.]*)/);
    if (workspaceRefMatch && !/workspace\s*\./.test(trimmed.substring(0, trimmed.indexOf(workspaceRefMatch[0]))).includes('workspace.')) {
      const ref = workspaceRefMatch[1];
      if (!['CurrentCamera'].includes(ref)) {
        api.workspace.referenced.push({ path: ref, line: i + 1 });
      }
    }

    // 4. Services
    const serviceMatch = trimmed.match(/game\s*:\s*GetService\s*\(\s*["']([^"']+)["']\s*\)/);
    if (serviceMatch) {
      api.services.add(serviceMatch[1]);
    }

    // 5. Function definitions
    const funcMatch = trimmed.match(/(?:local\s+)?function\s+(\w[\w.:]*)\s*\(/);
    if (funcMatch && !/function\s*\(/.test(trimmed)) {
      api.functions.push({ name: funcMatch[1], line: i + 1 });
    }

    // 6. Config/Option keys
    const configMatch = trimmed.match(/(?:Options|Toggles|Flags|Library\.Flags)\s*\[\s*["']([^"']+)["']\s*\]/);
    if (configMatch) {
      api.configKeys.push({ key: configMatch[1], line: i + 1 });
    }

    // 7. Constants
    const constMatch = trimmed.match(/local\s+([A-Z_][A-Z0-9_]*)\s*=\s*(.+)/);
    if (constMatch && constMatch[1] !== 'A' && constMatch[1].length > 2) {
      api.constants.push({ name: constMatch[1], value: constMatch[2].trim().slice(0, 80), line: i + 1 });
    }
  }

  // Deduplicate
  api.attributes.patterns = summarizeAttributePatterns(api.attributes.get, api.attributes.set);
  api.workspace.referenced = deduplicateByKey(api.workspace.referenced, 'path');
  api.configKeys = deduplicateByKey(api.configKeys, 'key');
  api.services = [...api.services].sort();
  api.functions = api.functions.slice(0, 50); // cap

  return {
    filePath: toPosix(filePath),
    summary: {
      remoteCallCount: api.remotes.fire.length + api.remotes.invoke.length,
      uniqueRemotes: new Set(api.remotes.fire.map(r => r.name).concat(api.remotes.invoke.map(r => r.name))).size,
      attributeCount: new Set(api.attributes.get.map(a => a.key).concat(api.attributes.set.map(a => a.key))).size,
      serviceCount: api.services.length,
      functionCount: api.functions.length,
      configKeyCount: api.configKeys.length,
      constantCount: api.constants.length,
    },
    api,
  };
}

function extractPayloadKeys(line) {
  const keys = [];
  const keyRe = /(\w+)\s*=/g;
  let m;
  while ((m = keyRe.exec(line)) !== null) {
    if (!['function', 'local', 'return', 'if', 'then', 'end', 'for', 'while', 'do'].includes(m[1])) {
      keys.push(m[1]);
    }
  }
  return [...new Set(keys)];
}

function summarizeAttributePatterns(gets, sets) {
  const allKeys = new Set();
  for (const a of gets) allKeys.add(a.key);
  for (const a of sets) allKeys.add(a.key);
  const patterns = [];
  for (const key of allKeys) {
    const getSources = gets.filter(a => a.key === key).map(a => a.source);
    const setSources = sets.filter(a => a.key === key).map(a => a.source);
    patterns.push({
      key,
      read: getSources.length > 0,
      write: setSources.length > 0,
      readBy: [...new Set(getSources)],
      writtenBy: [...new Set(setSources)],
    });
  }
  return patterns;
}

function deduplicateByKey(arr, keyField) {
  const seen = new Set();
  return arr.filter(item => {
    if (seen.has(item[keyField])) return false;
    seen.add(item[keyField]);
    return true;
  });
}

export function scanGameApi(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const results = [];
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const map = extractGameApiMap(text, relPath);
    if (map.summary.remoteCallCount > 0 || map.summary.attributeCount > 0) {
      results.push(map);
    }
  }

  return {
    totalFiles: results.length,
    files: results.map(r => ({
      file: r.filePath,
      summary: r.summary,
      topRemotes: r.api.remotes.fire.slice(0, 10),
      topAttributes: r.api.attributes.patterns.slice(0, 15),
      services: r.api.services,
    })),
  };
}

// ── Feature Parity (V1 → V2) ─────────────────────────────────────────────────

/**
 * Generates a feature-by-feature comparison between a V1 and V2 script.
 * Identifies preserved, modified, new, and missing features.
 */
export function analyzeFeatureParity(oldText, newText, oldPath = '', newPath = '') {
  const oldApi = extractGameApiMap(oldText, oldPath);
  const newApi = extractGameApiMap(newText, newPath);
  const oldAnalysis = analyzeLuauText(oldText, oldPath);
  const newAnalysis = analyzeLuauText(newText, newPath);

  // Feature detection based on semantic patterns
  const features = compareFeatureSets(oldText, newText);

  // Remote parity
  const oldRemotes = new Set(oldApi.api.remotes.fire.map(r => r.name));
  const newRemotes = new Set(newApi.api.remotes.fire.map(r => r.name));
  const lostRemotes = [...oldRemotes].filter(r => !newRemotes.has(r));
  const addedRemotes = [...newRemotes].filter(r => !oldRemotes.has(r));

  // Attribute parity
  const oldAttrs = new Set(oldApi.api.attributes.get.map(a => a.key).concat(oldApi.api.attributes.set.map(a => a.key)));
  const newAttrs = new Set(newApi.api.attributes.get.map(a => a.key).concat(newApi.api.attributes.set.map(a => a.key)));
  const lostAttrs = [...oldAttrs].filter(a => !newAttrs.has(a));
  const addedAttrs = [...newAttrs].filter(a => !oldAttrs.has(a));

  // Config key parity
  const oldConfigs = new Set(oldApi.api.configKeys.map(c => c.key));
  const newConfigs = new Set(newApi.api.configKeys.map(c => c.key));
  const lostConfigs = [...oldConfigs].filter(c => !newConfigs.has(c));
  const addedConfigs = [...newConfigs].filter(c => !oldConfigs.has(c));

  // Build parity table
  const parity = features.map(f => ({
    feature: f.name,
    status: f.status, // 'preserved', 'modified', 'new', 'missing'
    v1: f.v1 ? 'Yes' : 'No',
    v2: f.v2 ? 'Yes' : 'No',
    detail: f.detail || '',
  }));

  const preserved = parity.filter(f => f.status === 'preserved').length;
  const modified = parity.filter(f => f.status === 'modified').length;
  const newOnes = parity.filter(f => f.status === 'new').length;
  const missing = parity.filter(f => f.status === 'missing').length;

  return {
    paths: { old: toPosix(oldPath), new: toPosix(newPath) },
    summary: {
      oldLines: oldAnalysis.summary.lineCount,
      newLines: newAnalysis.summary.lineCount,
      lineDelta: newAnalysis.summary.lineCount - oldAnalysis.summary.lineCount,
      features: { total: parity.length, preserved, modified, new: newOnes, missing },
      remotes: { lost: lostRemotes.length, added: addedRemotes.length },
      attributes: { lost: lostAttrs.length, added: addedAttrs.length },
      configKeys: { lost: lostConfigs.length, added: addedConfigs.length },
    },
    parity,
    lostRemotes,
    addedRemotes,
    lostAttrs,
    addedAttrs,
    lostConfigs,
    addedConfigs,
  };
}

function compareFeatureSets(oldText, newText) {
  const features = [];
  const oldLower = oldText.toLowerCase();
  const newLower = newText.toLowerCase();

  // Combat features
  addFeature(features, 'Auto Block', oldLower, newLower, ['autoblock', 'auto.block', 'block.range'], ['autoblock', 'auto.block', 'block.range']);
  addFeature(features, 'Auto Counter', oldLower, newLower, ['counter', 'countermode', 'auto.counter'], ['counter', 'countermode', 'auto.counter']);
  addFeature(features, 'Auto Ultimate', oldLower, newLower, ['autoult', 'auto.ult', 'auto.ultimate'], ['autoult', 'auto.ult', 'auto.ultimate']);
  addFeature(features, 'Auto Evasive', oldLower, newLower, ['autoevasive', 'auto.evasive', 'ragdoll'], ['autoevasive', 'auto.evasive', 'ragdoll']);
  addFeature(features, 'Auto Farm Players', oldLower, newLower, ['farm', 'farmp', 'auto.farm'], ['farm', 'farmp', 'auto.farm']);
  addFeature(features, 'Orbit Mode', oldLower, newLower, ['orbit', 'orbitspeed', 'orbitdist'], ['orbit', 'orbitspeed', 'orbitdist']);
  addFeature(features, 'Saved Positions', oldLower, newLower, ['savepos', 'savedposition', 'save.position'], ['savepos', 'savedposition', 'save.position']);
  addFeature(features, 'Escape / Low HP TP', oldLower, newLower, ['escape', 'escapehp', 'escape.on'], ['escape', 'escapehp', 'escape.on']);
  addFeature(features, 'Auto Skills', oldLower, newLower, ['autoskill', 'auto.skill', 'skilltouse'], ['autoskill', 'auto.skill', 'skilltouse']);
  addFeature(features, 'Character Select', oldLower, newLower, ['characterselect', 'autochangechar', 'change.character'], ['characterselect', 'autochangechar', 'change.character']);
  addFeature(features, 'WalkSpeed', oldLower, newLower, ['walkspeed', 'setws', 'set.walk'], ['walkspeed', 'setws', 'set.walk']);
  addFeature(features, 'JumpPower', oldLower, newLower, ['jumppower', 'setjp', 'set.jump'], ['jumppower', 'setjp', 'set.jump']);
  addFeature(features, 'Teleport Tween', oldLower, newLower, ['tween', 'tweenspeed', 'teleportmode'], ['tween', 'tweenspeed', 'teleportmode']);
  addFeature(features, 'Return to Spawn', oldLower, newLower, ['return', 'returntospawn', 'return.to'], ['return', 'returntospawn', 'return.to']);
  addFeature(features, 'Stop on Damage', oldLower, newLower, ['stopon', 'stop.damage', 'stoponhit'], ['stopon', 'stop.damage', 'stoponhit']);
  addFeature(features, 'Target Priority', oldLower, newLower, ['targetpriority', 'target.priority', 'priority'], ['targetpriority', 'target.priority', 'priority']);
  addFeature(features, 'Face Target', oldLower, newLower, ['facetarget', 'face.target', 'faceto'], ['facetarget', 'face.target', 'faceto']);
  addFeature(features, 'Status Paragraphs', oldLower, newLower, ['paragraph', 'settext', 'buildstatus', 'imp-hub-status'], ['paragraph', 'settext', 'buildstatus', 'imp-hub-status']);

  return features;
}

function addFeature(list, name, oldText, newText, oldPatterns, newPatterns) {
  const v1 = oldPatterns.some(p => oldText.includes(p));
  const v2 = newPatterns.some(p => newText.includes(p));
  let status = 'missing';
  let detail = '';
  if (v1 && v2) { status = 'preserved'; detail = 'Present in both versions.'; }
  else if (!v1 && v2) { status = 'new'; detail = 'Added in V2.'; }
  else if (v1 && !v2) { status = 'missing'; detail = 'Present in V1 but NOT in V2.'; }
  list.push({ name, v1, v2, status, detail });
}

// ── Character Lifecycle / Respawn Check ──────────────────────────────────────

/**
 * Analyzes how a Luau script handles character death, respawn, and callback reconnection.
 */
export function checkRespawnLifecycle(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const issues = [];
  const findings = {
    characterAddedHandler: false,
    characterVariableUpdate: false,
    rootNullChecks: 0,
    humanoidNullChecks: 0,
    orphanedConnections: false,
    connectionOwnership: [],
    respawnSafeLoops: 0,
    unsafeLoops: 0,
    reconnectionPatterns: [],
  };

  let hasCharAdded = false;
  let hasCharUpdate = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // CharacterAdded connection
    if (/CharacterAdded\s*:\s*Connect\s*\(/.test(trimmed)) {
      hasCharAdded = true;
      findings.characterAddedHandler = true;
      // Check if the callback updates the Character variable
      const callbackLines = lines.slice(i, Math.min(i + 8, lines.length)).join('\n');
      if (/Character\s*=\s*c\b/.test(callbackLines) || /Character\s*=\s*newChar/.test(callbackLines)) {
        hasCharUpdate = true;
        findings.characterVariableUpdate = true;
        findings.reconnectionPatterns.push({ type: 'full-rebind', line: i + 1, detail: 'Character variable updated on CharacterAdded' });
      } else {
        findings.reconnectionPatterns.push({ type: 'event-only', line: i + 1, detail: 'CharacterAdded fires but Character variable may not be updated' });
      }
    }

    // Null checks for HumanoidRootPart
    if (/FindFirstChild\s*\(\s*["']HumanoidRootPart["']\s*\)/.test(trimmed)) {
      findings.rootNullChecks++;
    }
    // Null checks for Humanoid
    if (/FindFirstChild\s*\(\s*["']Humanoid["']\s*\)/.test(trimmed)) {
      findings.humanoidNullChecks++;
    }
    if (/FindFirstChildOfClass\s*\(\s*["']Humanoid["']\s*\)/.test(trimmed)) {
      findings.humanoidNullChecks++;
    }

    // Loops without respawn safety
    if (/while\s+/.test(trimmed) && /task\s*\.\s*wait/.test(trimmed)) {
      // Check if loop body has Character/HumanoidRootPart validation
      const loopBody = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
      if (/FindFirstChild.*HumanoidRootPart/.test(loopBody) || /Character\s*&&/.test(loopBody)) {
        findings.respawnSafeLoops++;
      } else {
        findings.unsafeLoops++;
        issues.push({ line: i + 1, severity: 'warning', rule: 'respawn-unsafe-loop', message: 'Loop may not revalidate Character after respawn.' });
      }
    }

    // Connection ownership tracking
    if (/:\s*Connect\s*\(/.test(trimmed)) {
      findings.connectionOwnership.push({ line: i + 1, text: trimmed.slice(0, 100) });
    }
  }

  // Check for orphaned connections (no Disconnect or cleanup)
  if (findings.connectionOwnership.length > 3 && !/:Disconnect/.test(text) && !/task\.cancel/.test(text)) {
    findings.orphanedConnections = true;
    issues.push({ line: 0, severity: 'info', rule: 'orphaned-connections', message: `${findings.connectionOwnership.length} connections created but no Disconnect/cleanup found.` });
  }

  // Initial Character acquisition
  const hasInitialChar = /Character\s*=\s*Plr\.Character/.test(text) || /Character\s*=\s*LocalPlayer\.Character/.test(text);
  const hasWaitForChar = /CharacterAdded\s*:\s*Wait\s*\(\)/.test(text);

  if (!hasCharAdded && !hasWaitForChar) {
    issues.push({ line: 0, severity: 'warning', rule: 'no-respawn-handler', message: 'No CharacterAdded handler — script will break after first respawn.' });
  }

  if (hasCharAdded && !hasCharUpdate) {
    issues.push({ line: 0, severity: 'warning', rule: 'partial-rebind', message: 'CharacterAdded handler exists but Character variable may not be updated.' });
  }

  const bySeverity = { error: 0, warning: 0, info: 0 };
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  const verdict = bySeverity.error > 0 ? 'FAIL' : bySeverity.warning > 0 ? 'WARN' : 'PASS';

  return {
    filePath: toPosix(filePath),
    verdict,
    findings: {
      ...findings,
      hasInitialChar,
      hasWaitForChar,
      hasCharAdded,
      hasCharUpdate,
      totalConnections: findings.connectionOwnership.length,
    },
    issues,
    bySeverity,
  };
}

export function scanRespawnChecks(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const results = [];
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const check = checkRespawnLifecycle(text, relPath);
    if (check.verdict !== 'PASS' || check.issues.length > 0) {
      results.push(check);
    }
  }

  results.sort((a, b) => {
    const order = { FAIL: 0, WARN: 1, PASS: 2 };
    return (order[a.verdict] || 2) - (order[b.verdict] || 2);
  });

  return {
    totalFiles: results.length,
    files: results,
  };
}

// ── Executor Compatibility ───────────────────────────────────────────────────

/**
 * Checks a Luau script for executor-specific APIs and compatibility.
 * Maps detected APIs to known executor support levels.
 */
export function checkExecutorCompat(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const source = text;

  // API -> executor support matrix
  const apiMatrix = {
    // Universal
    'loadstring': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex', 'Oxygen'], severity: 'info', category: 'core' },
    'getgenv': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex', 'Oxygen'], severity: 'info', category: 'core' },
    'cloneref': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex', 'Oxygen'], severity: 'info', category: 'core' },
    'setclipboard': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex'], severity: 'info', category: 'utility' },
    'toclipboard': { support: ['Solara', 'MacSploit', 'Oxygen'], severity: 'info', category: 'utility' },
    'identifyexecutor': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex', 'Oxygen'], severity: 'info', category: 'detection' },
    'getexecutorname': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'detection' },
    // HTTP
    'http_request': { support: ['Delta', 'Wave', 'Solara'], severity: 'warning', category: 'http' },
    'syn.request': { support: ['Delta'], severity: 'warning', category: 'http-syn' },
    'fluxus.request': { support: ['Fluxus'], severity: 'warning', category: 'http-executor' },
    'request': { support: ['Delta', 'Wave', 'Solara', 'Codex'], severity: 'info', category: 'http' },
    // File
    'readfile': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'writefile': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'isfile': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'makefolder': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'isfolder': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'delfolder': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'delfile': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'listfiles': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    'appendfile': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'file' },
    // Drawing
    'Drawing.new': { support: ['Delta', 'Wave', 'Solara', 'MacSploit', 'Codex'], severity: 'info', category: 'drawing' },
    'drawing': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'drawing' },
    // Window
    'setfpscap': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'performance' },
    'fpscap': { support: ['Delta', 'Wave'], severity: 'info', category: 'performance' },
    // Debug
    'hookfunction': { support: ['Delta'], severity: 'warning', category: 'debug' },
    'getgc': { support: ['Delta'], severity: 'warning', category: 'debug' },
    'getinstances': { support: ['Delta', 'Wave'], severity: 'info', category: 'debug' },
    'getnilinstances': { support: ['Delta', 'Wave'], severity: 'info', category: 'debug' },
    // Environment
    'getrenv': { support: ['Delta'], severity: 'warning', category: 'env' },
    'getrunningscripts': { support: ['Delta'], severity: 'warning', category: 'env' },
    'checkcaller': { support: ['Delta'], severity: 'warning', category: 'env' },
    // Mobile
    'mouse1click': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'input' },
    'mouse2click': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'input' },
    'keypress': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'input' },
    'keyrelease': { support: ['Delta', 'Wave', 'Solara'], severity: 'info', category: 'input' },
  };

  const detections = [];
  const executors = {};
  const blocked = [];

  for (const [api, info] of Object.entries(apiMatrix)) {
    const escapedApi = api.replace(/\./g, '\\.');
    const re = new RegExp(`\\b${escapedApi}\\b`);
    if (re.test(source)) {
      detections.push({ api, ...info });
      for (const exec of info.support) {
        if (!executors[exec]) executors[exec] = { total: 0, warnings: 0, blocked: 0 };
        executors[exec].total++;
        if (info.severity === 'warning') executors[exec].warnings++;
      }
    }
  }

  // Additional checks
  // game:HttpGet — universal
  if (/game\s*:\s*HttpGet\b/.test(source)) {
    detections.push({ api: 'game:HttpGet', support: ['all'], severity: 'info', category: 'core' });
  }

  // queue_on_teleport — Delta/Wave only
  if (/queue_on_teleport/.test(source)) {
    detections.push({ api: 'queue_on_teleport', support: ['Delta', 'Wave'], severity: 'warning', category: 'teleport' });
    for (const exec of ['Delta', 'Wave']) {
      if (executors[exec]) executors[exec].total++;
    }
  }

  // Calculate compatibility scores
  const compatReport = Object.entries(executors).map(([name, stats]) => {
    const supported = detections.filter(d => d.support.includes('all') || d.support.includes(name));
    const unsupported = detections.filter(d => !d.support.includes('all') && !d.support.includes(name));
    const score = stats.total > 0 ? Math.round(((stats.total - stats.warnings) / stats.total) * 100) : 100;
    return {
      name,
      score,
      apiCount: stats.total,
      warnings: stats.warnings,
      missingApis: unsupported.map(d => d.api),
      status: score >= 90 ? 'Full' : score >= 70 ? 'Partial' : 'Limited',
    };
  });

  compatReport.sort((a, b) => b.score - a.score);

  // Identify blocking APIs (used but not supported by common executors)
  for (const det of detections) {
    if (det.severity === 'warning') {
      const unsupported = ['all', 'Delta', 'Wave', 'Solara', 'Codex'].filter(e => !det.support.includes(e));
      if (unsupported.length > 0) {
        blocked.push({ api: det.api, support: det.support, category: det.category });
      }
    }
  }

  return {
    filePath: toPosix(filePath),
    summary: {
      totalDetections: detections.length,
      executorCount: compatReport.length,
      blockedApis: blocked.length,
      universal: detections.filter(d => d.support.includes('all')).length,
      delta: compatReport.find(e => e.name === 'Delta'),
      wave: compatReport.find(e => e.name === 'Wave'),
      solara: compatReport.find(e => e.name === 'Solara'),
    },
    detections: detections.map(d => ({ api: d.api, category: d.category, severity: d.severity })),
    compat: compatReport,
    blocked,
  };
}

export function scanExecutorCompat(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const results = [];
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const check = checkExecutorCompat(text, relPath);
    if (check.summary.totalDetections > 0) {
      results.push(check);
    }
  }

  return {
    totalFiles: results.length,
    files: results.map(r => ({
      file: r.filePath,
      summary: r.summary,
      topCompat: r.compat.slice(0, 6),
    })),
  };
}

// ── Status Paragraph Validator ────────────────────────────────────────────────

/**
 * Validates that every feature in a LibSixtyTen script has an imp-hub-status paragraph.
 * Checks: paragraph existence, format, status colors, toggle-paragraph consistency.
 */
export function validateStatusParagraphs(text, filePath = '') {
  const lines = text.split(/\r?\n/);
  const source = text;
  const issues = [];

  // 1. Find all Paragraph() declarations
  const paragraphs = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const pMatch = line.match(/:\s*Paragraph\s*\(\s*["']([^"']+)["']\s*,/);
    if (pMatch) {
      paragraphs.push({ name: pMatch[1], line: i + 1 });
    }
    const pMatch2 = line.match(/:\s*Paragraph\s*\(\s*\{[^}]*Name\s*=\s*["']([^"']+)["']/);
    if (pMatch2) {
      paragraphs.push({ name: pMatch2[1], line: i + 1 });
    }
  }

  // 2. Find all Toggles (features that should have status)
  const toggles = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const tMatch = line.match(/:\s*Toggle\s*\(\s*\{[^}]*Name\s*=\s*["']([^"']+)["']/);
    if (tMatch) {
      toggles.push({ name: tMatch[1], line: i + 1 });
    }
  }

  // 3. Check SetText calls (paragraphs being updated)
  const setTextCalls = [];
  const statusColors = ['ACTIVE', 'DISABLED', 'WAITING', 'SCANNING', 'TARGETING', 'MOVING', 'FIGHTING', 'COLLECTING', 'RESTING', 'TIMING', 'DONE', 'ERROR'];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/SetText\s*\(/.test(line)) {
      // Check if it uses status colors
      let foundColor = null;
      for (const color of statusColors) {
        if (line.includes(color)) { foundColor = color; break; }
      }
      // Check if it uses BuildBasicStatus / BuildDetailedStatus / BuildMacroStatus
      const builderMatch = line.match(/(BuildBasicStatus|BuildDetailedStatus|BuildMacroStatus)\s*\(/);
      setTextCalls.push({
        line: i + 1,
        statusColor: foundColor,
        builder: builderMatch ? builderMatch[1] : null,
        text: line.trim().slice(0, 120),
      });
    }
  }

  // 4. Validate: every toggle should have a corresponding paragraph
  const paraNames = new Set(paragraphs.map(p => p.name.toLowerCase()));
  for (const toggle of toggles) {
    const toggleKey = toggle.name.toLowerCase();
    // Check if there's a paragraph with similar name
    const hasPara = paragraphs.some(p =>
      p.name.toLowerCase().includes(toggleKey) ||
      toggleKey.includes(p.name.toLowerCase())
    );
    if (!hasPara) {
      issues.push({
        line: toggle.line,
        severity: 'warning',
        rule: 'missing-paragraph',
        message: `Toggle "${toggle.name}" has no corresponding status paragraph.`,
      });
    }
  }

  // 5. Validate: every paragraph should have SetText call
  for (const para of paragraphs) {
    const hasSetText = setTextCalls.some(c => c.line > para.line);
    if (!hasSetText) {
      issues.push({
        line: para.line,
        severity: 'info',
        rule: 'no-settext',
        message: `Paragraph "${para.name}" declared but no SetText call found after it.`,
      });
    }
  }

  // 6. Validate: status colors used in SetText
  const missingColor = setTextCalls.filter(c => !c.statusColor && !c.builder);
  for (const mc of missingColor) {
    issues.push({
      line: mc.line,
      severity: 'info',
      rule: 'no-status-color',
      message: `SetText call does not use a recognized status color or builder.`,
    });
  }

  // 7. Check for STATUS_COLORS definition
  const hasStatusColors = /STATUS_COLORS/.test(source);
  if (!hasStatusColors && setTextCalls.length > 0) {
    issues.push({
      line: 0,
      severity: 'warning',
      rule: 'no-status-colors-const',
      message: 'No STATUS_COLORS constant found but SetText calls exist — colors may be inconsistent.',
    });
  }

  // 8. Check for status builder functions
  const builders = {
    basic: /BuildBasicStatus/.test(source),
    detailed: /BuildDetailedStatus/.test(source),
    macro: /BuildMacroStatus/.test(source),
  };
  const builderCount = (builders.basic ? 1 : 0) + (builders.detailed ? 1 : 0) + (builders.macro ? 1 : 0);

  const bySeverity = { error: 0, warning: 0, info: 0 };
  for (const issue of issues) {
    bySeverity[issue.severity] = (bySeverity[issue.severity] || 0) + 1;
  }

  const verdict = bySeverity.error > 0 ? 'FAIL' : bySeverity.warning > 0 ? 'WARN' : 'PASS';

  return {
    filePath: toPosix(filePath),
    verdict,
    summary: {
      totalParagraphs: paragraphs.length,
      totalToggles: toggles.length,
      setTextCalls: setTextCalls.length,
      hasStatusColors,
      builders,
      builderCount,
    },
    issues,
    bySeverity,
  };
}

export function scanStatusParagraphs(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });
  const results = [];
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const relPath = toPosix(relative(root, file));
    const check = validateStatusParagraphs(text, relPath);
    if (check.summary.totalParagraphs > 0 || check.issues.length > 0) {
      results.push(check);
    }
  }
  return { totalFiles: results.length, files: results };
}

// ── Risk Summary (Executive) ─────────────────────────────────────────────────

/**
 * Executive risk summary grouped by severity with effort estimates.
 */
export function summarizeRisks(root) {
  const scan = scanLuauWorkspace(root);
  const findings = [];

  for (const f of scan.files) {
    const filePath = path.isAbsolute(f.filePath) ? f.filePath : path.join(root, f.filePath);
    const text = readText(filePath);
    if (!text) continue;

    // Analyze each risk category
    const risks = f.categories.risks;
    for (const risk of risks) {
      let severity = 'info';
      let effort = 'quick';
      if (risk.label === 'unbounded-loop' || risk.label === 'local-pressure-critical') { severity = 'error'; effort = 'medium'; }
      else if (risk.label === 'missing-pcall' || risk.label === 'local-pressure-warning') { severity = 'warning'; effort = 'quick'; }
      else if (risk.label === 'wait' || risk.label === 'spawn' || risk.label === 'delay') { severity = 'warning'; effort = 'quick'; }
      else if (risk.label === 'repeat-wait') { severity = 'warning'; effort = 'medium'; }

      findings.push({
        file: f.filePath,
        line: risk.line,
        severity,
        rule: risk.label,
        text: risk.text,
        effort,
        fixable: ['wait', 'spawn', 'delay', 'missing-pcall'].includes(risk.label),
      });
    }
  }

  // Group by severity
  const bySeverity = { error: [], warning: [], info: [] };
  for (const finding of findings) {
    bySeverity[finding.severity].push(finding);
  }

  // By effort
  const byEffort = { quick: 0, medium: 0, hard: 0 };
  for (const finding of findings) {
    if (finding.effort === 'quick') byEffort.quick++;
    else if (finding.effort === 'medium') byEffort.medium++;
    else byEffort.hard++;
  }

  // Top risky files
  const fileRiskCount = {};
  for (const finding of findings) {
    fileRiskCount[finding.file] = (fileRiskCount[finding.file] || 0) + 1;
  }
  const topFiles = Object.entries(fileRiskCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([file, count]) => ({ file, count }));

  // Auto-fixable
  const fixable = findings.filter(f => f.fixable);

  return {
    totalFindings: findings.length,
    bySeverity: {
      error: bySeverity.error.length,
      warning: bySeverity.warning.length,
      info: bySeverity.info.length,
    },
    byEffort,
    fixableCount: fixable.length,
    topFiles,
    details: bySeverity,
  };
}

// ── Diff Summary (Human-Readable) ────────────────────────────────────────────

/**
 * Human-readable summary of changes between V1 and V2.
 */
export function summarizeDiff(oldText, newText, oldPath = '', newPath = '') {
  const oldLines = oldText.split(/\r?\n/).length;
  const newLines = newText.split(/\r?\n/).length;
  const oldLower = oldText.toLowerCase();
  const newLower = newText.toLowerCase();

  // Feature changes
  const featureChanges = [];
  const features = [
    { name: 'Auto Block', patterns: ['autoblock', 'auto.block', 'block.range'] },
    { name: 'Auto Counter', patterns: ['counter', 'countermode', 'auto.counter'] },
    { name: 'Auto Ultimate', patterns: ['autoult', 'auto.ult', 'auto.ultimate'] },
    { name: 'Auto Evasive', patterns: ['autoevasive', 'auto.evasive', 'ragdoll'] },
    { name: 'Auto Farm', patterns: ['farm', 'farmp', 'auto.farm'] },
    { name: 'Orbit Mode', patterns: ['orbit', 'orbitspeed', 'orbitdist'] },
    { name: 'Saved Positions', patterns: ['savepos', 'savedposition', 'save.position'] },
    { name: 'Escape', patterns: ['escape', 'escapehp', 'escape.on'] },
    { name: 'Auto Skills', patterns: ['autoskill', 'auto.skill', 'skilltouse'] },
    { name: 'Character Select', patterns: ['characterselect', 'autochangechar', 'change.character'] },
    { name: 'WalkSpeed', patterns: ['walkspeed', 'setws', 'set.walk'] },
    { name: 'JumpPower', patterns: ['jumppower', 'setjp', 'set.jump'] },
    { name: 'Teleport Tween', patterns: ['tween', 'tweenspeed', 'teleportmode'] },
    { name: 'Return to Spawn', patterns: ['return', 'returntospawn', 'return.to'] },
    { name: 'Stop on Damage', patterns: ['stopon', 'stop.damage', 'stoponhit'] },
    { name: 'Target Priority', patterns: ['targetpriority', 'target.priority', 'priority'] },
    { name: 'Status Paragraphs', patterns: ['paragraph', 'settext', 'buildstatus'] },
    { name: 'ThemeManager', patterns: ['thememanager', 'theme_manager'] },
    { name: 'SaveManager', patterns: ['savemanager', 'save_manager'] },
    { name: 'FPS Boost', patterns: ['setfpscap', 'fpscap'] },
  ];

  for (const feat of features) {
    const inOld = feat.patterns.some(p => oldLower.includes(p));
    const inNew = feat.patterns.some(p => newLower.includes(p));
    if (inOld && inNew) featureChanges.push({ feature: feat.name, change: 'preserved' });
    else if (!inOld && inNew) featureChanges.push({ feature: feat.name, change: 'added' });
    else if (inOld && !inNew) featureChanges.push({ feature: feat.name, change: 'removed' });
  }

  // Remote changes
  const oldRemoteNames = new Set();
  const newRemoteNames = new Set();
  const oldRemoteRe = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer)\s*\(/g;
  let rm;
  const oldRemoteText = oldText;
  while ((rm = oldRemoteRe.exec(oldRemoteText)) !== null) oldRemoteNames.add(rm[1]);
  const newRemoteRe2 = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer)\s*\(/g;
  while ((rm = newRemoteRe2.exec(newText)) !== null) newRemoteNames.add(rm[1]);
  const lostRemotes = [...oldRemoteNames].filter(r => !newRemoteNames.has(r));
  const addedRemotes = [...newRemoteNames].filter(r => !oldRemoteNames.has(r));

  // UI library change
  const oldLib = /Library:Window/.test(oldText) ? 'LibSixtyTen' : /Library:CreateWindow/.test(oldText) ? 'Obsidian' : 'Unknown';
  const newLib = /Library:Window/.test(newText) ? 'LibSixtyTen' : /Library:CreateWindow/.test(newText) ? 'Obsidian' : 'Unknown';

  // pcall coverage
  const oldRemoteCount = [...oldRemoteNames].length;
  const newRemoteCount = [...newRemoteNames].length;
  const oldPcall = (oldText.match(/\bpcall\b/g) || []).length;
  const newPcall = (newText.match(/\bpcall\b/g) || []).length;

  return {
    paths: { old: toPosix(oldPath), new: toPosix(newPath) },
    size: { old: oldLines, new: newLines, delta: newLines - oldLines },
    uiLibrary: { old: oldLib, new: newLib, changed: oldLib !== newLib },
    features: featureChanges,
    featureSummary: {
      preserved: featureChanges.filter(f => f.change === 'preserved').length,
      added: featureChanges.filter(f => f.change === 'added').length,
      removed: featureChanges.filter(f => f.change === 'removed').length,
    },
    remotes: { lost: lostRemotes, added: addedRemotes },
    pcall: { old: oldPcall, new: newPcall, delta: newPcall - oldPcall },
  };
}

// ── V2 Scaffold Generator ───────────────────────────────────────────────────

/**
 * Generates a V2 scaffold from a V1 file.
 * Produces: imports, service caching, LibSixtyTen load, window/dashboard,
 * section adapters, loop placeholders, paragraph refs, ThemeManager/SaveManager.
 */
export function generateV2Scaffold(v1Text, gameName = '') {
  const safeName = gameName || 'UnknownGame';
  const lines = v1Text.split(/\r?\n/);

  // Detect V1 features
  const features = [];
  const featurePatterns = [
    { name: 'AutoBlock', patterns: ['autoblock', 'auto.block'] },
    { name: 'AutoCounter', patterns: ['counter', 'countermode'] },
    { name: 'AutoUltimate', patterns: ['autoult', 'auto.ult'] },
    { name: 'AutoEvasive', patterns: ['autoevasive', 'ragdoll'] },
    { name: 'AutoFarm', patterns: ['farm', 'autofarm'] },
    { name: 'Escape', patterns: ['escape', 'escapehp'] },
    { name: 'AutoSkills', patterns: ['autoskill', 'skilltouse'] },
    { name: 'CharacterSelect', patterns: ['characterselect', 'autochangechar'] },
    { name: 'WalkSpeed', patterns: ['walkspeed', 'setws'] },
    { name: 'JumpPower', patterns: ['jumppower', 'setjp'] },
  ];
  const lowerText = v1Text.toLowerCase();
  for (const fp of featurePatterns) {
    if (fp.patterns.some(p => lowerText.includes(p))) features.push(fp.name);
  }

  // Detect UI library
  const v1Lib = /Library:CreateWindow/.test(v1Text) ? 'Obsidian' : /Library:Window/.test(v1Text) ? 'LibSixtyTen' : 'Unknown';

  // Detect remotes
  const remoteNames = new Set();
  const remoteRe = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer)\s*\(/g;
  let rm;
  while ((rm = remoteRe.exec(v1Text)) !== null) remoteNames.add(rm[1]);

  const scaffold = `--[[
    Imp Hub X — ${safeName} V2
    Auto-generated scaffold from V1 (${v1Lib} → LibSixtyTen)
    Features detected: ${features.length > 0 ? features.join(', ') : 'none'}
]]

-- ============================================================
-- 1. CACHED SERVICES
-- ============================================================
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local TweenService = game:GetService("TweenService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Workspace = game:GetService("Workspace")

-- ============================================================
-- 2. LOCAL VARIABLE CACHING
-- ============================================================
local t_insert, t_find, t_remove, t_sort = table.insert, table.find, table.remove, table.sort
local m_huge, m_clamp = math.huge, math.clamp
local str_fmt = string.format
local pcallRef, taskWait, taskSpawn = pcall, task.wait, task.spawn

local Plr = Players.LocalPlayer
local Character = Plr.Character or Plr.CharacterAdded:Wait()
Plr.CharacterAdded:Connect(function(c) Character = c end)

-- ============================================================
-- 3. LIBSIXTYTEN LOAD
-- ============================================================
local function LoadLibSixtyTen()
    local urls = {
        "https://raw.githubusercontent.com/Nanana291/Kong/refs/heads/main/LibSixtyTen.lua",
    }
    for _, url in ipairs(urls) do
        local ok, result = pcallRef(function()
            local source = game:HttpGet(url)
            if source and #source > 0 then
                local chunk = loadstring(source)
                return chunk and chunk() or nil
            end
            return nil
        end)
        if ok and result and type(result) == "table" then return result end
    end
    warn("${safeName}: LibSixtyTen load failed")
    return nil
end

local Library = LoadLibSixtyTen()
if not Library then return end

local Options = {}
local Toggles = {}

-- ============================================================
-- 4. STATUS SYSTEM
-- ============================================================
local STATUS_COLORS = {
    DISABLED = "#ef4444", ACTIVE = "#22c55e", WAITING = "#f59e0b",
    SCANNING = "#06b6d4", TARGETING = "#3b82f6", MOVING = "#0ea5e9",
    FIGHTING = "#f97316", DONE = "#84cc16", ERROR = "#dc2626",
}

local function BuildBasicStatus(state, subtext)
    local s = STATUS_COLORS[state] and state or "DISABLED"
    return str_fmt(
        "<font size='14' color='%s'><b>● %s</b></font>\\n<font size='12' color='%s'>%s</font>",
        STATUS_COLORS[s], s, "#9ca3af", subtext or "Ready..."
    )
end

local function BuildDetailedStatus(state, headline, meta)
    local s = STATUS_COLORS[state] and state or "DISABLED"
    local m = meta and str_fmt("\\n<font size='11' color='%s'>%s</font>", "#6b7280", meta) or ""
    return str_fmt(
        "<font size='14' color='%s'><b>● %s</b></font>\\n<font size='13' color='%s'>%s</font>%s",
        STATUS_COLORS[s], s, "#f3f4f6", headline or "Ready...", m
    )
end

-- ============================================================
-- 5. SECTION ADAPTER
-- ============================================================
local function CreateSectionAdapter(section)
    local adapter = { Section = section }
    function adapter:AddToggle(flag, config)
        Toggles[flag] = { Element = nil, Value = config.Default or false }
        local toggle = section:Toggle({
            Name = config.Text or flag, Flag = flag, Default = config.Default or false,
            ToolTip = config.Tooltip or "",
            Callback = function(value)
                if Toggles[flag] then Toggles[flag].Value = value end
                if config.Callback then config.Callback(value) end
            end,
        })
        Toggles[flag].Element = toggle
        return Toggles[flag]
    end
    function adapter:AddSlider(flag, config)
        Options[flag] = { Element = nil, Value = config.Default }
        local slider = section:Slider({
            Name = config.Text or flag, Flag = flag, Default = config.Default,
            Min = config.Min, Max = config.Max,
            Callback = function(value)
                if Options[flag] then Options[flag].Value = value end
                if config.Callback then config.Callback(value) end
            end,
        })
        Options[flag].Element = slider
        return Options[flag]
    end
    function adapter:AddDropdown(flag, config)
        Options[flag] = { Element = nil, Value = config.Default }
        local dd = section:Dropdown({
            Name = config.Text or flag, Flag = flag,
            Items = config.Values or {}, Multi = config.Multi or false,
            Callback = function(value)
                if Options[flag] then Options[flag].Value = value end
                if config.Callback then config.Callback(value) end
            end,
        })
        Options[flag].Element = dd
        return Options[flag]
    end
    function adapter:AddButton(config)
        return section:Button({
            Name = config.Text, ToolTip = config.Tooltip or "",
            Callback = config.Func or function() end,
        })
    end
    function adapter:AddParagraph(name, text)
        return section:Paragraph({ Name = name, Text = text or BuildBasicStatus("DISABLED", "No status set") })
    end
    return adapter
end

-- ============================================================
-- 6. WINDOW + DASHBOARD
-- ============================================================
local Window = Library:Window({
    Name = "Imp Hub X",
    SubName = "${safeName}",
    Logo = "79000737943964",
    SelectedTab = 1,
    Compact = false,
})

Library:CreateDashboard(Window)

-- ============================================================
-- 7. PAGES + TABS
-- ============================================================
local Pages = {
    Main      = Window:Page({ Name = "Main",      Icon = "home",        Columns = 2 }),
    Combat    = Window:Page({ Name = "Combat",    Icon = "swords",      Columns = 2 }),
    Farming   = Window:Page({ Name = "Farming",   Icon = "crosshair",   Columns = 2 }),
    Players   = Window:Page({ Name = "Players",   Icon = "user",        Columns = 2 }),
    Teleports = Window:Page({ Name = "Teleports", Icon = "map-pin",     Columns = 2 }),
    Misc      = Window:Page({ Name = "Misc",      Icon = "more-horizontal", Columns = 2 }),
    Settings  = Window:Page({ Name = "Settings",  Icon = "settings",    Columns = 1 }),
}

local Tabs = {
    Main      = CreateSectionAdapter(Pages.Main),
    Combat    = CreateSectionAdapter(Pages.Combat),
    Farming   = CreateSectionAdapter(Pages.Farming),
    Players   = CreateSectionAdapter(Pages.Players),
    Teleports = CreateSectionAdapter(Pages.Teleports),
    Misc      = CreateSectionAdapter(Pages.Misc),
    Settings  = CreateSectionAdapter(Pages.Settings),
}

-- ============================================================
-- 8. FEATURE PLACEHOLDERS
-- ============================================================
${features.map(f => `// TODO: Implement ${f} — see V1 logic
`).join('')}
-- Paragraph refs — assign after UI creation
${features.map(f => {
  const name = f.replace(/([A-Z])/g, ' $1').trim();
  return `local ${f}Status = Tabs.${f.includes('Block') ? 'Combat' : f.includes('Farm') ? 'Farming' : f.includes('Skill') ? 'Farming' : f.includes('Escape') ? 'Teleports' : 'Main'}:AddParagraph("${name} Status", BuildBasicStatus("DISABLED", "Off"))`;
}).join('\n')}

-- ============================================================
-- 9. REMOTE CACHE
-- ============================================================
-- Detected remotes from V1: ${[...remoteNames].join(', ') || 'none detected'}
-- TODO: Verify and map each remote

-- ============================================================
-- 10. RUNTIME LOOPS (one per feature, pcallRef wrapped)
-- ============================================================
${features.map(f => `taskSpawn(function()
    while taskWait(0.1) do
        if not (Toggles["${f}"] and Toggles["${f}"].Value) then continue end
        pcallRef(function()
            -- TODO: Implement ${f} logic from V1
        end)
    end
end)`).join('\n\n')}

-- ============================================================
-- 11. SETTINGS + SAVE/THEME
-- ============================================================
local repo = "https://raw.githubusercontent.com/Nanana291/Kong/refs/heads/main/"
pcallRef(function()
    local ThemeManager = loadstring(game:HttpGet(repo .. "addons/ThemeManager.lua"))()
    local SaveManager = loadstring(game:HttpGet(repo .. "addons/SaveManager.lua"))()
    if ThemeManager and SaveManager then
        ThemeManager:SetLibrary(Library)
        SaveManager:SetLibrary(Library)
        ThemeManager:SetFolder("ImpHub")
        SaveManager:SetFolder("ImpHub/${safeName}")
        SaveManager:BuildConfigSection(Tabs.Settings)
        ThemeManager:ApplyToTab(Tabs.Settings)
        SaveManager:LoadAutoloadConfig()
    end
end)

-- ============================================================
-- 12. LOAD NOTIFICATION
-- ============================================================
Library:Notify({
    Title = "Imp Hub X",
    Description = "${safeName} V2 loaded",
    SubText = "Scaffold — implement features from V1",
    Type = "info",
    Time = 6,
})
`;

  return {
    gameName: safeName,
    v1Library: v1Lib,
    featuresDetected: features,
    remoteCount: remoteNames.size,
    scaffold,
    lineCount: scaffold.split(/\r?\n/).length,
  };
}

// ── Explain Luau Text (Natural-Language) ─────────────────────────────────────

/**
 * Composes a natural-language explanation of what a Luau script does.
 * Uses analyzeLuauText, extractRemotePayloads, extractFlagsFromText,
 * and checkRespawnLifecycle as composition sources.
 *
 * Enhanced v2: confidence-scored features, ASCII data-flow diagram, severity-grouped risks.
 */
export function explainLuauText(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);

  // Compose from existing analysis
  const analysis = analyzeLuauText(text, filePath);
  const remoteData = extractRemotePayloads(text, filePath);
  const flags = extractFlagsFromText(text, filePath);
  const respawn = checkRespawnLifecycle(text, filePath);

  // ── Detect UI library ────────────────────────────────────────────────────
  let uiLibrary = 'Unknown';
  if (/Library:Window\s*\(/.test(source) && /CreateDashboard\s*\(/.test(source)) {
    uiLibrary = 'LibSixtyTen';
  } else if (/Library:CreateWindow\s*\(/.test(source) || /Library:Window\s*\(/.test(source)) {
    if (/CreateDashboard/.test(source)) {
      uiLibrary = 'LibSixtyTen';
    } else if (/Library:CreateWindow/.test(source)) {
      uiLibrary = 'Obsidian';
    }
  }
  if (uiLibrary === 'Unknown' && /loadstring.*LibSixtyTen/.test(source)) {
    uiLibrary = 'LibSixtyTen';
  } else if (uiLibrary === 'Unknown' && /loadstring.*Obsidian/.test(source)) {
    uiLibrary = 'Obsidian';
  }

  // ── Feature confidence scoring ───────────────────────────────────────────
  const allText_lower = source.toLowerCase();

  // Build lookup sets from flags, function names, and UI sections
  const flagNameSet = new Set((flags.allFlags || []).map(f => f.name.toLowerCase()));

  const funcNames = [];
  const funcNameSet = new Set();
  for (const line of lines) {
    let m;
    if ((m = /\blocal\s+function\s+(\w+)/.exec(line))) { funcNames.push(m[1]); funcNameSet.add(m[1].toLowerCase()); }
    else if ((m = /\bfunction\s+(\w[\w.:]*)\s*\(/.exec(line))) { funcNames.push(m[1]); funcNameSet.add(m[1].toLowerCase()); }
    else if ((m = /\b(\w+)\s*=\s*function\s*\(/.exec(line))) { funcNames.push(m[1]); funcNameSet.add(m[1].toLowerCase()); }
  }

  const uiSectionNames = [];
  const uiSectionSet = new Set();
  const sectionRe = /(?:Page|Section|Category)\s*\(\s*\{[^}]*Name\s*=\s*["']([^"']+)["']/g;
  const simpleSectionRe = /:\s*(Page|Section|Category)\s*\(\s*["']([^"']+)["']/g;
  let scm;
  while ((scm = sectionRe.exec(source)) !== null) { uiSectionNames.push(scm[1]); uiSectionSet.add(scm[1].toLowerCase()); }
  while ((scm = simpleSectionRe.exec(source)) !== null) { uiSectionNames.push(scm[2]); uiSectionSet.add(scm[2].toLowerCase()); }

  // Feature keyword definitions with multiple evidence types
  const featureKeywords = [
    {
      name: 'Auto Farm',
      flagPatterns: ['auto.farm', 'autofarm', 'auto farm'],
      funcPatterns: ['autofarm', 'farm', 'farmp'],
      uiPatterns: ['auto farm', 'autofarm', 'farm'],
      textPatterns: ['auto.farm', 'autofarm', 'auto farm', 'farmp'],
    },
    {
      name: 'Auto Block',
      flagPatterns: ['auto.block', 'autoblock', 'auto block'],
      funcPatterns: ['autoblock', 'block'],
      uiPatterns: ['auto block', 'autoblock'],
      textPatterns: ['auto.block', 'autoblock', 'auto block'],
    },
    {
      name: 'Auto Counter',
      flagPatterns: ['auto.counter', 'autocounter', 'auto counter'],
      funcPatterns: ['autocounter', 'counter'],
      uiPatterns: ['auto counter', 'autocounter'],
      textPatterns: ['auto.counter', 'autocounter', 'auto counter', 'countermode'],
    },
    {
      name: 'Auto Ultimate',
      flagPatterns: ['auto.ultimate', 'autoult', 'auto ultimate'],
      funcPatterns: ['autoult', 'ultimate'],
      uiPatterns: ['auto ultimate', 'autoult'],
      textPatterns: ['auto.ultimate', 'autoult', 'auto ultimate'],
    },
    {
      name: 'Auto Evasive',
      flagPatterns: ['auto.evasive', 'autoevasive', 'auto evasive'],
      funcPatterns: ['autoevasive', 'evasive'],
      uiPatterns: ['auto evasive', 'autoevasive'],
      textPatterns: ['auto.evasive', 'autoevasive', 'auto evasive'],
    },
    {
      name: 'Auto Skills',
      flagPatterns: ['auto.skill', 'autoskill', 'auto skill'],
      funcPatterns: ['autoskill', 'skill'],
      uiPatterns: ['auto skill', 'autoskill'],
      textPatterns: ['auto.skill', 'autoskill', 'auto skill', 'skilltouse'],
    },
    {
      name: 'ESP',
      flagPatterns: ['esp'],
      funcPatterns: ['esp', 'highlight', 'chams', 'esp render'],
      uiPatterns: ['esp'],
      textPatterns: ['esp', 'highlight', 'chams', 'esp render'],
    },
    {
      name: 'Teleport',
      flagPatterns: ['teleport', 'teleportmode', 'tp'],
      funcPatterns: ['teleport', 'tpto', 'tween'],
      uiPatterns: ['teleport', 'teleports'],
      textPatterns: ['teleport', 'tp to', 'tween to', 'teleportmode'],
    },
    {
      name: 'Orbit',
      flagPatterns: ['orbit'],
      funcPatterns: ['orbit'],
      uiPatterns: ['orbit'],
      textPatterns: ['orbit', 'orbitspeed', 'orbitdist', 'orbit mode'],
    },
    {
      name: 'Combat',
      flagPatterns: ['combat', 'auto.attack', 'autoattack'],
      funcPatterns: ['combat', 'attack'],
      uiPatterns: ['combat', 'attack'],
      textPatterns: ['combat', 'auto.attack', 'autoattack', 'attack mode'],
    },
    {
      name: 'WalkSpeed',
      flagPatterns: ['walkspeed', 'ws'],
      funcPatterns: ['walkspeed', 'setws'],
      uiPatterns: ['walkspeed', 'ws'],
      textPatterns: ['walkspeed', 'setws', 'set.walk'],
    },
    {
      name: 'JumpPower',
      flagPatterns: ['jumppower', 'jp'],
      funcPatterns: ['jumppower', 'setjp'],
      uiPatterns: ['jumppower', 'jp'],
      textPatterns: ['jumppower', 'setjp', 'set.jump'],
    },
    {
      name: 'Settings',
      flagPatterns: ['settings', 'theme', 'config'],
      funcPatterns: ['thememanager', 'savemanager', 'settings'],
      uiPatterns: ['settings', 'config'],
      textPatterns: ['thememanager', 'savemanager', 'config', 'settings tab'],
    },
    {
      name: 'Character Select',
      flagPatterns: ['characterselect', 'change.character', 'autochangechar'],
      funcPatterns: ['characterselect', 'changecharacter'],
      uiPatterns: ['character select', 'characterselect'],
      textPatterns: ['characterselect', 'change.character', 'autochangechar'],
    },
    {
      name: 'Return to Spawn',
      flagPatterns: ['returntospawn', 'return.to', 'returntosspawn'],
      funcPatterns: ['returntospawn', 'return'],
      uiPatterns: ['return to spawn', 'returntospawn'],
      textPatterns: ['returntospawn', 'return.to', 'return to spawn'],
    },
  ];

  /**
   * Score a single feature:
   *  100 = explicit flag name + UI section + function name all match
   *   80 = flag name + function name match  OR  flag name + UI section match
   *   60 = only flag name match (cross-referenced from flags list)
   *   40 = only function/comment mention (function name or text pattern, no flag)
   *   20 = weak keyword match only (text pattern, no flag, no function, no UI)
   */
  function scoreFeature(feat) {
    const inFlag = feat.flagPatterns.some(p => [...flagNameSet].some(fn => fn.includes(p.replace('.', ''))));
    const inFunc = feat.funcPatterns.some(p => [...funcNameSet].some(fn => fn.includes(p)));
    const inUI = feat.uiPatterns.some(p => [...uiSectionSet].some(s => s.includes(p)));
    const inText = feat.textPatterns.some(p => allText_lower.includes(p));

    const evidenceParts = [];
    if (inFlag) {
      const matchedFlag = (flags.allFlags || []).find(f => feat.flagPatterns.some(p => f.name.toLowerCase().includes(p.replace('.', ''))));
      if (matchedFlag) evidenceParts.push(`flag "${matchedFlag.name}" (L${matchedFlag.line})`);
      else evidenceParts.push('flag name match');
    }
    if (inFunc) {
      const matchedFunc = funcNames.find(fn => feat.funcPatterns.some(p => fn.toLowerCase().includes(p)));
      if (matchedFunc) evidenceParts.push(`function "${matchedFunc}"`);
      else evidenceParts.push('function name match');
    }
    if (inUI) {
      const matchedSection = uiSectionNames.find(s => feat.uiPatterns.some(p => s.toLowerCase().includes(p)));
      if (matchedSection) evidenceParts.push(`UI section "${matchedSection}"`);
      else evidenceParts.push('UI section match');
    }
    if (inText && !inFlag && !inFunc && !inUI) {
      evidenceParts.push('text/keyword mention');
    }

    const evidence = evidenceParts.length > 0 ? evidenceParts.join(', ') : 'weak keyword match';

    if (inFlag && inFunc && inUI) return { confidence: 100, evidence };
    if ((inFlag && inFunc) || (inFlag && inUI)) return { confidence: 80, evidence };
    if (inFlag) return { confidence: 60, evidence };
    if (inFunc || inText) return { confidence: inFunc ? 40 : 20, evidence };
    return null; // not detected at all
  }

  const detectedFeatures = [];
  for (const feat of featureKeywords) {
    const score = scoreFeature(feat);
    if (score) {
      detectedFeatures.push({ name: feat.name, confidence: score.confidence, evidence: score.evidence });
    }
  }

  // Sort features by confidence descending, then alphabetically
  detectedFeatures.sort((a, b) => b.confidence - a.confidence || a.name.localeCompare(b.name));

  // ── Services ─────────────────────────────────────────────────────────────
  const serviceRe = /game\s*:\s*GetService\s*\(\s*["']([^"']+)["']\s*\)/g;
  const services = new Set();
  let sm;
  while ((sm = serviceRe.exec(source)) !== null) services.add(sm[1]);

  // ── Modules ──────────────────────────────────────────────────────────────
  const requireRe = /require\s*\(\s*([^)]+)\s*\)/g;
  const modules = new Set();
  let rm;
  while ((rm = requireRe.exec(source)) !== null) modules.add(rm[1].trim().slice(0, 80));

  // ── UI sections ──────────────────────────────────────────────────────────
  const sections = [...uiSectionNames];

  // ── Loops ────────────────────────────────────────────────────────────────
  const whileLoops = (source.match(/\bwhile\s+/g) || []).length;
  const forLoops = (source.match(/\bfor\s+/g) || []).length;
  const totalLoops = whileLoops + forLoops;

  let pcallInLoops = 0;
  let charCheckInLoops = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\bwhile\s+/.test(line) || /\bfor\s+/.test(line)) {
      const loopBody = lines.slice(i, Math.min(i + 12, lines.length)).join('\n');
      if (/\bpcall\b/.test(loopBody)) pcallInLoops++;
      if (/HumanoidRootPart|Character\s*=|Character\s*&&/.test(loopBody)) charCheckInLoops++;
    }
  }

  // ── Data flow diagram (ASCII) ────────────────────────────────────────────
  // Build edges: service→function, function→remote, remote→ui
  const edges = [];
  const serviceList = [...services].sort();

  // Infer service→function edges from common patterns
  const funcServiceMap = {}; // funcName → serviceName
  for (const svc of serviceList) {
    const svcLower = svc.toLowerCase();
    for (const fn of funcNames) {
      const fnLower = fn.toLowerCase();
      // Heuristic: function name contains service-related keywords
      if (svcLower === 'players' && (fnLower.includes('player') || fnLower.includes('char') || fnLower.includes('join'))) {
        funcServiceMap[fn] = svc;
      } else if (svcLower === 'workspace' && (fnLower.includes('npc') || fnLower.includes('move') || fnLower.includes('teleport') || fnLower.includes('part'))) {
        funcServiceMap[fn] = svc;
      } else if (svcLower === 'replicatedstorage' && (fnLower.includes('remote') || fnLower.includes('fire') || fnLower.includes('invoke'))) {
        funcServiceMap[fn] = svc;
      } else if (svcLower === 'userinputservice' && (fnLower.includes('input') || fnLower.includes('key') || fnLower.includes('mouse'))) {
        funcServiceMap[fn] = svc;
      } else if (svcLower === 'runservice' && (fnLower.includes('render') || fnLower.includes('heartbeat') || fnLower.includes('loop') || fnLower.includes('frame'))) {
        funcServiceMap[fn] = svc;
      }
    }
  }

  // Build function→remote edges from actual FireServer/InvokeServer calls
  const remoteCallSites = remoteData.remotes || [];
  // Map remote calls to the nearest enclosing function
  const funcRemoteMap = {}; // remoteName → functionName (or 'global')
  for (const rc of remoteCallSites) {
    // Find the closest function definition above this line
    let enclosingFunc = null;
    for (let i = rc.line - 1; i >= 0; i--) {
      const m = /\b(?:local\s+)?function\s+(\w[\w.:]*)\s*\(/.exec(lines[i]) || /\b(\w+)\s*=\s*function\s*\(/.exec(lines[i]);
      if (m) { enclosingFunc = m[1]; break; }
    }
    funcRemoteMap[rc.remote] = enclosingFunc || 'global scope';
  }

  // Build remote→UI section edges
  const remoteUiMap = {}; // remoteName → sectionName
  // Heuristic: match remote name keywords to section names
  for (const rc of remoteCallSites) {
    const rcLower = rc.remote.toLowerCase();
    for (const sec of sections) {
      const secLower = sec.toLowerCase();
      if (rcLower.includes('farm') && secLower.includes('farm')) remoteUiMap[rc.remote] = sec;
      else if (rcLower.includes('teleport') && secLower.includes('teleport')) remoteUiMap[rc.remote] = sec;
      else if (rcLower.includes('combat') && secLower.includes('combat')) remoteUiMap[rc.remote] = sec;
      else if (rcLower.includes('block') && secLower.includes('block')) remoteUiMap[rc.remote] = sec;
      else if (rcLower.includes('skill') && secLower.includes('skill')) remoteUiMap[rc.remote] = sec;
      else if (rcLower.includes('esp') && secLower.includes('esp')) remoteUiMap[rc.remote] = sec;
    }
  }

  // Assemble edges
  for (const [fn, svc] of Object.entries(funcServiceMap)) {
    edges.push({ from: `game.${svc}`, to: `${fn}()`, type: 'service→function' });
  }
  for (const [remote, fn] of Object.entries(funcRemoteMap)) {
    edges.push({ from: `${fn}()`, to: `${remote}:FireServer/InvokeServer`, type: 'function→remote' });
  }
  for (const [remote, sec] of Object.entries(remoteUiMap)) {
    edges.push({ from: `${remote}`, to: `${sec} Section`, type: 'remote→ui' });
  }

  // If no edges could be inferred, create minimal ones from raw services
  if (edges.length === 0 && serviceList.length > 0) {
    for (const svc of serviceList) {
      edges.push({ from: `game.${svc}`, to: '[script logic]', type: 'service→function' });
    }
  }

  // Build ASCII diagram
  const separator = '─'.repeat(60);
  const header = 'Services → [Functions] → Remotes → UI';
  const diagramLines = [header, separator];
  for (const edge of edges) {
    diagramLines.push(`${edge.from.padEnd(30)} → ${edge.to}`);
  }
  if (edges.length === 0) {
    diagramLines.push('(no inferable data flow edges)');
  }
  const diagram = diagramLines.join('\n');

  // ── Risk severity breakdown ──────────────────────────────────────────────
  const riskItems = analysis.categories.risks || [];
  const bySeverity = { high: [], medium: [], low: [] };
  for (const risk of riskItems) {
    const sev = risk.severity || 'medium';
    const label = risk.label || 'unknown';
    const lineInfo = risk.line ? ` (L${risk.line})` : '';
    const entry = `${label}${lineInfo}`;
    if (sev === 'high' || sev === 'critical') bySeverity.high.push(entry);
    else if (sev === 'medium' || sev === 'warning' || sev === 'review') bySeverity.medium.push(entry);
    else bySeverity.low.push(entry);
  }

  // Remote summary
  const remoteNames = remoteData.summary.remoteNames || [];
  const remoteCallCount = remoteData.summary.totalCalls || 0;

  // ── Build natural language explanation ───────────────────────────────────
  const highConfFeatures = detectedFeatures.filter(f => f.confidence >= 80);
  const featureList = highConfFeatures.length > 0
    ? highConfFeatures.map(f => f.name).join(', ')
    : detectedFeatures.length > 0
      ? detectedFeatures.map(f => f.name).join(', ')
      : 'various game features';

  const featureListSentence = featureList.toLowerCase();

  const remoteSummary = remoteCallCount > 0
    ? `${remoteCallCount} remote call(s) to ${remoteNames.slice(0, 5).join(', ')}${remoteNames.length > 5 ? ' and others' : ''}`
    : 'no direct remote calls detected';

  const respawnStatus = respawn.verdict === 'PASS'
    ? 'has proper respawn handler with character lifecycle support'
    : respawn.verdict === 'WARN'
      ? 'has partial respawn handling but some gaps exist'
      : 'lacks proper respawn handling — will break after character death';

  const riskSentence = analysis.summary.riskCount > 0
    ? `${analysis.summary.riskCount} risk(s) detected: ${bySeverity.high.length} high, ${bySeverity.medium.length} medium, ${bySeverity.low.length} low`
    : 'no significant risks detected';

  const explanation = `This is a ${analysis.summary.lineCount}-line ${uiLibrary} script providing ${featureListSentence}. `
    + `Remote calls: ${remoteSummary}. `
    + `Character lifecycle: ${respawnStatus}. `
    + `Risks: ${riskSentence}.`;

  return {
    filePath: toPosix(filePath),
    summary: {
      lineCount: analysis.summary.lineCount,
      localCount: analysis.summary.localCount,
      callbackCount: analysis.summary.callbackCount,
      remoteCount: analysis.summary.remoteCount,
      riskCount: analysis.summary.riskCount,
      flagCount: flags.totalDefined,
      uiLibrary,
      features: detectedFeatures,
      hasRespawnHandler: respawn.verdict !== 'FAIL',
    },
    explanation,
    structure: {
      services: [...services].sort(),
      modules: [...modules].sort(),
      sections,
      loops: {
        count: totalLoops,
        withPcall: pcallInLoops,
        withCharCheck: charCheckInLoops,
      },
    },
    dataFlow: {
      diagram,
      edges,
    },
    risks: {
      total: analysis.summary.riskCount,
      unprotectedRemotes: analysis.categories.risks.filter(r => r.label === 'missing-pcall').length,
      orphanedConnections: respawn.findings.orphanedConnections || false,
      deprecatedApi: analysis.categories.risks.filter(r => ['wait', 'spawn', 'delay'].includes(r.label)).length,
      bySeverity,
    },
  };
}

// ── Repair Luau Risk (Apply Fix) ─────────────────────────────────────────────

/**
 * Applies a risk fix to the Luau text. Uses repairLuauRisk to get the
 * before/after snippet, then applies the fix at the correct line.
 */
export function repairLuauRiskApply(text, filePath, riskLabel, options = {}) {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const label = String(riskLabel || '').trim().toLowerCase();
  const apply = options.apply !== false;

  // Get the proposed fix from repairLuauRisk
  const repair = repairLuauRisk(text, filePath, riskLabel);
  const lineIndex = (repair.summary.line || 1) - 1;
  const beforeLine = repair.before;

  // Determine the actual replacement
  let afterLine = repair.after;
  let explanation = repair.explanation;

  // For multi-line replacements (like pcall wrapping), handle properly
  if (label === 'missing-pcall') {
    const originalLine = lines[lineIndex] || '';
    const indent = originalLine.match(/^\s*/)?.[0] || '';
    const trimmed = originalLine.trim();
    afterLine = `${indent}pcall(function()\n${indent}    ${trimmed}\n${indent}end)`;
    explanation = 'Wrap the remote call in pcall so failures do not crash the script.';
  } else if (label === 'wait') {
    const originalLine = lines[lineIndex] || '';
    afterLine = originalLine.replace(/\bwait\s*\(/g, 'task.wait(');
    explanation = 'Replace legacy wait() with task.wait() to match modern Luau scheduling.';
  } else if (label === 'spawn') {
    const originalLine = lines[lineIndex] || '';
    afterLine = originalLine.replace(/\bspawn\s*\(/g, 'task.spawn(');
    explanation = 'Replace spawn() with task.spawn() to avoid legacy scheduler behavior.';
  } else if (label === 'unbounded-loop') {
    const originalLine = lines[lineIndex] || '';
    afterLine = originalLine + '\n-- TODO: add a termination condition or iteration limit';
    explanation = 'Add a bounded loop or explicit exit condition before shipping this code path.';
  } else if (label === 'connection-cleanup') {
    const helperBlock = [
      'local __helperConnections = {}',
      'local function __helperTrack(connection)',
      '    __helperConnections[#__helperConnections + 1] = connection',
      '    return connection',
      'end',
      '',
    ];
    afterLine = helperBlock.join('\n');
    explanation = 'Track connections and disconnect them during teardown to prevent leaks.';
  } else if (label === 'remote-rate-limit') {
    const originalLine = lines[lineIndex] || '';
    const indent = originalLine.match(/^\s*/)?.[0] || '';
    afterLine = `${indent}task.wait(0.15)\n${originalLine}`;
    explanation = 'Throttle repeated remote calls so the script does not spam the server.';
  }

  // Build new text
  let newText = source;
  if (apply && lineIndex >= 0 && lineIndex < lines.length) {
    const newLines = [...lines];
    if (afterLine.includes('\n')) {
      // Multi-line replacement
      const afterLines = afterLine.split('\n');
      newLines.splice(lineIndex, 1, ...afterLines);
    } else {
      newLines[lineIndex] = afterLine;
    }
    newText = newLines.join('\n');
  }

  return {
    filePath: toPosix(filePath),
    riskLabel: label,
    applied: apply && lineIndex >= 0,
    line: (repair.summary.line || 1),
    before: beforeLine,
    after: afterLine,
    newText,
    explanation,
  };
}

// ── Simulate Respawn Lifecycle ───────────────────────────────────────────────

/**
 * Extended version of checkRespawnLifecycle that simulates the full respawn flow.
 */
export function simulateRespawnLifecycle(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);

  // Use checkRespawnLifecycle as the base
  const base = checkRespawnLifecycle(text, filePath);

  // Analyze loops for respawn safety
  const loopAnalysis = {
    total: 0,
    withCharGuard: 0,
    withoutGuard: 0,
    wouldSurviveRespawn: 0,
    wouldFailOnRespawn: 0,
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\bwhile\s+/.test(line) || /\bfor\s+/.test(line)) {
      loopAnalysis.total++;
      // Check next 15 lines for character guards
      const loopBody = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
      const hasCharGuard = /HumanoidRootPart|Character\s*==\s*nil|not\s+Character|FindFirstChild.*HumanoidRootPart|Character\s*&&/.test(loopBody);
      const hasContinue = /\bcontinue\b/.test(loopBody);

      if (hasCharGuard) {
        loopAnalysis.withCharGuard++;
        loopAnalysis.wouldSurviveRespawn++;
      } else {
        loopAnalysis.withoutGuard++;
        loopAnalysis.wouldFailOnRespawn++;
      }
    }
  }

  // Analyze remotes for character dependency
  const remoteAnalysis = {
    total: 0,
    charDependent: 0,
    wouldFailWithoutChar: 0,
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/:FireServer\s*\(|:InvokeServer\s*\(/.test(line)) {
      remoteAnalysis.total++;
      // Check if this remote call sends Character data
      const callLine = line;
      if (/Character|HumanoidRootPart|\.Character/.test(callLine)) {
        remoteAnalysis.charDependent++;
        // Check if wrapped in pcall
        if (!/\bpcall\b/.test(callLine)) {
          // Check surrounding context
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 2)).join('\n');
          if (!/\bpcall\b/.test(context)) {
            remoteAnalysis.wouldFailWithoutChar++;
          }
        }
      }
    }
  }

  // Build lifecycle phases
  const phases = [];

  // Phase 1: Initial
  const initialChecks = [];
  if (/Plr\.Character|LocalPlayer\.Character/.test(source)) {
    initialChecks.push('Initial Character acquired via Plr.Character');
  }
  if (/CharacterAdded\s*:\s*Wait\s*\(\)/.test(source)) {
    initialChecks.push('CharacterAdded:Wait() used for initial character');
  }
  const initialGaps = [];
  if (!/Plr\.Character|LocalPlayer\.Character/.test(source) && !/CharacterAdded\s*:\s*Wait/.test(source)) {
    initialGaps.push('No explicit initial character acquisition found');
  }
  phases.push({
    phase: 'initial',
    checks: initialChecks,
    connections: base.findings.characterAddedHandler ? ['CharacterAdded handler registered'] : [],
    gaps: initialGaps,
  });

  // Phase 2: Alive
  const aliveChecks = [];
  if (base.findings.rootNullChecks > 0) {
    aliveChecks.push(`${base.findings.rootNullChecks} HumanoidRootPart null check(s)`);
  }
  if (base.findings.humanoidNullChecks > 0) {
    aliveChecks.push(`${base.findings.humanoidNullChecks} Humanoid null check(s)`);
  }
  phases.push({
    phase: 'alive',
    checks: aliveChecks,
    connections: base.findings.connectionOwnership.map((c, idx) => `Connection #${idx + 1} @ L${c.line}`),
    gaps: [],
  });

  // Phase 3: Dead
  const deadChecks = [];
  const deadGaps = [];
  if (!/Died\s*:\s*Connect/.test(source) && !/Humanoid\s*.*Died/.test(source)) {
    deadGaps.push('No explicit Humanoid.Died handler — death detection relies on CharacterAdded firing');
  }
  phases.push({
    phase: 'dead',
    checks: deadChecks,
    connections: [],
    gaps: deadGaps,
  });

  // Phase 4: Respawning
  phases.push({
    phase: 'respawning',
    checks: ['CharacterAdded event will fire when new character spawns'],
    connections: base.findings.characterAddedHandler ? ['CharacterAdded:Connect callback ready'] : [],
    gaps: base.findings.characterAddedHandler ? [] : ['No CharacterAdded handler registered — will not auto-rebind'],
  });

  // Phase 5: Rebinding
  const rebindingChecks = [];
  if (base.findings.characterVariableUpdate) {
    rebindingChecks.push('Character variable updated in CharacterAdded callback');
  }
  const rebindingGaps = [];
  if (!base.findings.characterVariableUpdate && base.findings.characterAddedHandler) {
    rebindingGaps.push('CharacterAdded handler exists but Character variable may not be updated');
  }
  phases.push({
    phase: 'rebinding',
    checks: rebindingChecks,
    connections: base.findings.reconnectionPatterns.map(r => `${r.type} @ L${r.line}`),
    gaps: rebindingGaps,
  });

  // Phase 6: Active
  const activeChecks = [];
  if (loopAnalysis.withCharGuard > 0) {
    activeChecks.push(`${loopAnalysis.withCharGuard} loop(s) with character guard`);
  }
  const activeGaps = [];
  if (loopAnalysis.withoutGuard > 0) {
    activeGaps.push(`${loopAnalysis.withoutGuard} loop(s) without character guard — will error on nil HumanoidRootPart`);
  }
  phases.push({
    phase: 'active',
    checks: activeChecks,
    connections: [],
    gaps: activeGaps,
  });

  // Build state diagram
  const stateDiagram = [
    '┌─────────┐     Character.Died      ┌──────┐     CharacterAdded      ┌───────────┐',
    '│ INITIAL ├─────────────────────────►│ DEAD ├───────────────────────►│ RESPAWNING │',
    '└────┬────┘                         └──┬───┘                         └─────┬─────┘',
    '     │                                 │                                   │',
    '     │  Plr.Character                  │  (no action)                      │  CharacterAdded:Connect',
    '     ▼                                 ▼                                   ▼',
    '┌─────────┐     nil HRP check         ┌───────────┐     rebind            ┌──────────┐',
    '│  ALIVE  ├───────────────────────────►│  ACTIVE   │◄─────────────────────┤ REBIND   │',
    '└─────────┘                           └───────────┘                       └──────────┘',
  ].join('\n');

  // Calculate transition coverage
  const transitions = [
    { from: 'initial', to: 'alive', hasCheck: initialChecks.length > 0 },
    { from: 'alive', to: 'dead', hasCheck: true }, // death is automatic
    { from: 'dead', to: 'respawning', hasCheck: true }, // CharacterAdded is automatic
    { from: 'respawning', to: 'rebinding', hasCheck: base.findings.characterAddedHandler },
    { from: 'rebinding', to: 'active', hasCheck: base.findings.characterVariableUpdate },
    { from: 'alive', to: 'active', hasCheck: loopAnalysis.withCharGuard > 0 },
  ];
  const coveredTransitions = transitions.filter(t => t.hasCheck).length;
  const transitionCoverage = Math.round((coveredTransitions / transitions.length) * 100);

  // Build simulation: character dies
  const simulation = {
    scenario: 'character_dies',
    steps: [],
    finalState: 'partial',
  };

  // Step 1: Character dies
  simulation.steps.push({
    step: 1,
    event: 'Character.Died fires',
    outcome: 'ok',
    detail: 'Character reference becomes invalid (nil or destroyed).',
  });

  // Step 2: Character becomes nil
  simulation.steps.push({
    step: 2,
    event: 'Character variable is now nil/stale',
    outcome: loopAnalysis.withoutGuard > 0 ? 'fail' : 'ok',
    detail: loopAnalysis.withoutGuard > 0
      ? `${loopAnalysis.withoutGuard} loop(s) will attempt to access nil HumanoidRootPart — will error.`
      : 'All loops have character guards — they will skip or wait.',
  });

  // Step 3: CharacterAdded fires
  simulation.steps.push({
    step: 3,
    event: 'CharacterAdded:Connect callback fires',
    outcome: base.findings.characterAddedHandler ? 'ok' : 'fail',
    detail: base.findings.characterAddedHandler
      ? 'CharacterAdded handler exists and will receive new character.'
      : 'No CharacterAdded handler — script will not automatically rebind.',
  });

  // Step 4: Rebind callbacks
  simulation.steps.push({
    step: 4,
    event: 'Rebind callbacks to new Character',
    outcome: base.findings.characterVariableUpdate ? 'ok' : 'warn',
    detail: base.findings.characterVariableUpdate
      ? 'Character variable updated in callback — loops will use new Character reference.'
      : 'CharacterAdded handler exists but Character variable may not be updated — loops may still reference stale Character.',
  });

  // Step 5: Restore loops
  simulation.steps.push({
    step: 5,
    event: 'Loops resume with new Character',
    outcome: loopAnalysis.wouldFailOnRespawn > 0 ? 'warn' : 'ok',
    detail: loopAnalysis.wouldFailOnRespawn > 0
      ? `${loopAnalysis.wouldFailOnRespawn} loop(s) lack character guard and may fail before revalidation.`
      : `All ${loopAnalysis.wouldSurviveRespawn} loop(s) have character guards and will resume safely.`,
  });

  // Step 6: Remote calls
  simulation.steps.push({
    step: 6,
    event: 'Remote calls resume',
    outcome: remoteAnalysis.wouldFailWithoutChar > 0 ? 'warn' : 'ok',
    detail: remoteAnalysis.wouldFailWithoutChar > 0
      ? `${remoteAnalysis.wouldFailWithoutChar} character-dependent remote call(s) without pcall may error.`
      : remoteAnalysis.charDependent > 0
        ? `${remoteAnalysis.charDependent} character-dependent remote(s) — ensure pcall wraps are in place.`
        : 'No character-dependent remote calls detected.',
  });

  // Determine final state
  const failSteps = simulation.steps.filter(s => s.outcome === 'fail');
  const warnSteps = simulation.steps.filter(s => s.outcome === 'warn');
  if (failSteps.length > 0) {
    simulation.finalState = 'broken';
  } else if (warnSteps.length > 0) {
    simulation.finalState = 'partial';
  } else {
    simulation.finalState = 'recovered';
  }

  // Build recommendations
  const recommendations = [];
  if (!base.findings.characterAddedHandler) {
    recommendations.push('Add a CharacterAdded:Connect handler to auto-rebind after respawn.');
  }
  if (!base.findings.characterVariableUpdate && base.findings.characterAddedHandler) {
    recommendations.push('Update the Character variable inside the CharacterAdded callback.');
  }
  if (loopAnalysis.withoutGuard > 0) {
    recommendations.push(`Add Character/HumanoidRootPart null checks to ${loopAnalysis.withoutGuard} loop(s) without guards.`);
  }
  if (remoteAnalysis.wouldFailWithoutChar > 0) {
    recommendations.push(`Wrap ${remoteAnalysis.wouldFailWithoutChar} character-dependent remote call(s) in pcall.`);
  }
  if (base.findings.orphanedConnections) {
    recommendations.push('Track and disconnect connections during character death to prevent memory leaks.');
  }
  if (base.findings.rootNullChecks === 0) {
    recommendations.push('Add HumanoidRootPart wait before accessing it in loops.');
  }
  if (recommendations.length === 0) {
    recommendations.push('Respawn lifecycle handling looks solid — no critical gaps detected.');
  }

  // Build auto-fix snippets
  const autoFixSnippets = [];

  // Phase 'alive': no CharacterAdded handler
  if (phases.find(p => p.phase === 'alive')?.gaps?.includes('No CharacterAdded handler registered — will not auto-rebind')) {
    autoFixSnippets.push({
      phase: 'alive',
      issue: 'No CharacterAdded handler',
      fix: [
        'local function onCharacterAdded(char)',
        '    -- Rebind callbacks to new character here',
        '    print("Character added, rebinding...")',
        'end',
        '',
        'localPlr.CharacterAdded:Connect(onCharacterAdded)',
      ].join('\n'),
      description: 'Add a CharacterAdded:Connect handler to auto-rebind after respawn.',
    });
  }

  // Phase 'rebinding': Character variable not updated
  if (phases.find(p => p.phase === 'rebinding')?.gaps?.includes('CharacterAdded handler exists but Character variable may not be updated')) {
    autoFixSnippets.push({
      phase: 'rebinding',
      issue: 'Character variable not updated',
      fix: [
        'local function onCharacterAdded(char)',
        '    Character = char  -- Update the Character variable',
        '    -- Rebind other callbacks here',
        'end',
        '',
        'localPlr.CharacterAdded:Connect(onCharacterAdded)',
      ].join('\n'),
      description: 'Update Character = char inside the CharacterAdded handler to rebind the variable.',
    });
  }

  // Phase 'active': loops without guard
  if (loopAnalysis.withoutGuard > 0) {
    autoFixSnippets.push({
      phase: 'active',
      issue: `${loopAnalysis.withoutGuard} loop(s) without character guard`,
      fix: [
        'while taskRunning do',
        '    if not Character or not Character:FindFirstChild("HumanoidRootPart") then',
        '        task.wait(0.1)',
        '        continue',
        '    end',
        '    local hrp = Character.HumanoidRootPart',
        '    -- loop body continues here',
        '    task.wait(0.1)',
        'end',
      ].join('\n'),
      description: 'Add character guard at the start of each loop to skip iteration when Character is nil.',
    });
  }

  // Phase 'active': remote calls without char check
  if (remoteAnalysis.wouldFailWithoutChar > 0) {
    autoFixSnippets.push({
      phase: 'active',
      issue: `${remoteAnalysis.wouldFailWithoutChar} remote call(s) without character guard`,
      fix: [
        'if Character and Character:FindFirstChild("HumanoidRootPart") then',
        '    local hrp = Character.HumanoidRootPart',
        '    pcall(function()',
        '        Remote:FireServer(hrp.CFrame)',
        '    end)',
        'end',
      ].join('\n'),
      description: 'Wrap character-dependent remote calls in a character existence check.',
    });
  }

  // Orphaned connections
  if (base.findings.orphanedConnections) {
    autoFixSnippets.push({
      phase: 'connections',
      issue: 'Orphaned connections without cleanup',
      fix: [
        'local connections = {}',
        '',
        '-- Instead of: signal:Connect(fn)',
        '-- Use:',
        'table.insert(connections, signal:Connect(function()',
        '    -- handler body',
        'end))',
        '',
        '-- Cleanup on respawn or script end:',
        'for _, conn in ipairs(connections) do',
        '    if typeof(conn) == "RBXScriptConnection" then',
        '        conn:Disconnect()',
        '    end',
        'end',
        'table.clear(connections)',
      ].join('\n'),
      description: 'Track all connections in a table and disconnect them during cleanup.',
    });
  }

  // No root null checks
  if (base.findings.rootNullChecks === 0 && /Character/.test(source)) {
    autoFixSnippets.push({
      phase: 'active',
      issue: 'No HumanoidRootPart wait pattern',
      fix: 'local hrp = Character:WaitForChild("HumanoidRootPart", 10)',
      description: 'Use WaitForChild to safely acquire HumanoidRootPart before use.',
    });
  }

  const autoFix = {
    available: autoFixSnippets.length,
    snippets: autoFixSnippets,
  };

  // Determine overall verdict
  let verdict = base.verdict;
  if (simulation.finalState === 'broken') verdict = 'FAIL';
  else if (simulation.finalState === 'partial' && verdict === 'PASS') verdict = 'WARN';

  return {
    filePath: toPosix(filePath),
    verdict,
    lifecycle: {
      phases,
      stateDiagram,
      transitionCoverage,
    },
    loopAnalysis,
    remoteAnalysis,
    simulation,
    recommendations,
    autoFix,
  };
}

// ── Semantic Luau Search ─────────────────────────────────────────────────────

/**
 * Semantic search within a Luau file. Unlike regex, understands code structure.
 * Parses function definitions, variable assignments, remote calls, UI sections.
 */
// ── Fuzzy Matching ───────────────────────────────────────────────────────────

/**
 * Compute a fuzzy match score between a query string and a code identifier.
 * Returns 0-100, where 0 means no meaningful match.
 */
function fuzzyMatchScore(query, name) {
  if (!query || !name) return 0;
  const q = query.toLowerCase();
  const n = name.toLowerCase();

  // Exact match = 100
  if (n === q) return 100;

  // Substring match (either direction) = 60
  if (n.includes(q) || q.includes(n)) return 60;

  // CamelCase word partial: split name on camel boundaries, check if any word contains query
  const camelWords = name.split(/(?=[A-Z])/).map(w => w.toLowerCase());
  let bestCamel = 0;
  for (const cw of camelWords) {
    if (cw === q) { bestCamel = 100; break; }
    if (cw.includes(q) || q.includes(cw)) { bestCamel = Math.max(bestCamel, 80); }
  }
  if (bestCamel > 0) return bestCamel;

  // Prefix match (3+ chars) = 30
  const prefixLen = Math.min(Math.max(q.length, n.length), 4);
  if (prefixLen >= 3 && n.substring(0, prefixLen) === q.substring(0, prefixLen)) {
    return Math.max(30, prefixLen * 7); // scale 3→21, 4→28 → use flat 30 for consistency
  }

  // Fuzzy char sequence: all query chars appear in order in the name
  if (fuzzySubsequence(q, n)) {
    // Score higher if chars are contiguous
    const density = q.length / n.length;
    return Math.max(40, Math.round(40 + density * 20));
  }

  // Levenshtein distance <= 2 for short names (<= 12 chars) = 50
  if (n.length <= 12) {
    const dist = levenshteinDistance(q, n);
    if (dist <= 2) return 50;
  }

  return 0;
}

/**
 * Check if all characters of `sub` appear in order within `str`.
 */
function fuzzySubsequence(sub, str) {
  let si = 0;
  for (let i = 0; i < str.length && si < sub.length; i++) {
    if (str[i] === sub[si]) si++;
  }
  return si === sub.length;
}

/**
 * Compute Levenshtein edit distance between two strings.
 */
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  // For very short strings, use the simple matrix approach
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// ── Remote Reference Tracking ────────────────────────────────────────────────

/**
 * Given an index of remote calls, find all lines referencing the SAME remote
 * name and check pcall protection.
 */
function buildRemoteRefMap(lines, remoteName) {
  if (!remoteName) return null;
  const escaped = remoteName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Match lines that reference this remote name and a FireServer/InvokeServer/etc call
  const refRe = new RegExp(`${escaped}\\s*:\\s*(FireServer|InvokeServer|FireClient|InvokeClient)\\s*\\(`);
  const pcallContextRe = /(?:local\s+\w+\s*=\s*)?pcall\s*\(/;

  const refLines = [];
  let withPcall = 0;
  let withoutPcall = 0;

  for (let i = 0; i < lines.length; i++) {
    if (refRe.test(lines[i])) {
      const lineNum = i + 1;
      let hasPcall = false;

      // Check same line
      if (pcallContextRe.test(lines[i])) {
        hasPcall = true;
      } else {
        // Check up to 3 lines before for pcall wrapping
        for (let j = Math.max(0, i - 3); j < i; j++) {
          if (pcallContextRe.test(lines[j])) {
            hasPcall = true;
            break;
          }
        }
      }

      if (hasPcall) withPcall++;
      else withoutPcall++;
      refLines.push(lineNum);
    }
  }

  if (refLines.length === 0) return null;

  return {
    remoteName,
    totalRefs: refLines.length,
    withPcall,
    withoutPcall,
    lines: refLines,
  };
}

// ── Cross-File Index Builder ─────────────────────────────────────────────────

/**
 * Build a keyword set from the query to quickly skip files that have zero
 * chance of matching.  We extract all alpha tokens >= 3 chars.
 */
function buildQueryKeywords(queryStr) {
  const tokens = new Set();
  const raw = queryStr.replace(/[^a-zA-Z0-9_]+/g, ' ');
  for (const part of raw.split(/\s+/)) {
    if (part.length >= 3) tokens.add(part.toLowerCase());
    // Also split camelCase
    const camelParts = part.split(/(?=[A-Z])/);
    if (camelParts.length > 1) {
      for (const cp of camelParts) {
        if (cp.length >= 3) tokens.add(cp.toLowerCase());
      }
    }
  }
  return tokens;
}

/**
 * Check if a file's text contains at least one query keyword.
 */
function fileHasKeyword(text, keywords) {
  if (keywords.size === 0) return true;
  const lower = text.toLowerCase();
  for (const kw of keywords) {
    if (lower.includes(kw)) return true;
  }
  return false;
}

/**
 * Analyze a single file's text and return scored matches (same logic as the
 * single-file path, but reused for cross-file search).
 */
function analyzeFileMatches(text, filePath, queryStr, queryTokens, options) {
  const lines = text.split(/\r?\n/);
  const contextLines = options.context || 2;

  // Build mini-index
  const index = { functions: [], variables: [], remotes: [], uiSections: [], comments: [], keywords: [] };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    const fnMatch = /(?:local\s+function|function)\s+([\w.:]+)\s*\(/.exec(line) || /(\w+)\s*=\s*function\s*\(/.exec(line);
    if (fnMatch) index.functions.push({ name: fnMatch[1], line: lineNum });

    const localMatch = /local\s+(\w+)\s*=/.exec(line);
    if (localMatch) index.variables.push({ name: localMatch[1], line: lineNum });

    const remoteMatch = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer|FireClient|InvokeClient)\s*\(/.exec(line);
    if (remoteMatch) index.remotes.push({ name: remoteMatch[1], line: lineNum, method: remoteMatch[2] });

    const uiMatch = /:\s*(Page|Section|Category|Toggle|Button|Slider|Dropdown|Paragraph|Label)\s*\(/.exec(line);
    if (uiMatch) {
      const nameMatch = /Name\s*=\s*["']([^"']+)["']/.exec(line);
      index.uiSections.push({ name: nameMatch ? nameMatch[1] : '?', line: lineNum, type: uiMatch[1] });
    }

    const commentMatch = /^\s*--\s*(.+)$/.exec(line);
    if (commentMatch) index.comments.push({ text: commentMatch[1].trim(), line: lineNum });

    const svcMatch = /game\s*:\s*GetService\s*\(\s*["']([^"']+)["']/.exec(line);
    if (svcMatch) index.keywords.push({ type: 'service', text: svcMatch[0], line: lineNum });
    if (/require\s*\(/.test(line)) index.keywords.push({ type: 'require', text: line.trim().slice(0, 80), line: lineNum });
    if (/\b(while|for|repeat)\s+\w+/.test(line)) index.keywords.push({ type: 'loop', text: line.trim().slice(0, 80), line: lineNum });
  }

  const matches = [];
  const maxResults = options.maxResults || 50;
  const fuzzy = options.fuzzy !== false; // default true

  function scoreElement(elementName) {
    if (!elementName || !queryStr) return 0;
    const fuzzyScore = fuzzyMatchScore(queryStr, elementName);

    // Legacy scoring for compatibility
    const nameLower = elementName.toLowerCase();
    const queryLower = queryStr.toLowerCase();
    let legacyScore = 0;
    if (nameLower === queryLower) legacyScore = 100;
    else if (nameLower.includes(queryLower) || queryLower.includes(nameLower)) legacyScore = 50;
    else {
      for (const token of queryTokens) {
        if (nameLower === token) { legacyScore = Math.max(legacyScore, 100); continue; }
        if (nameLower.includes(token)) { legacyScore = Math.max(legacyScore, 50); continue; }
        if (token.includes(nameLower)) { legacyScore = Math.max(legacyScore, 50); }
      }
    }

    // Use the higher of fuzzy and legacy
    return Math.max(fuzzyScore, legacyScore);
  }

  function getContext(lineNum) {
    const idx = lineNum - 1;
    const before = [];
    for (let i = Math.max(0, idx - contextLines); i < idx; i++) before.push(lines[i]);
    const after = [];
    for (let i = idx + 1; i < Math.min(lines.length, idx + 1 + contextLines); i++) after.push(lines[i]);
    return { before, line: lines[idx] || '', after };
  }

  function addMatches(items, type) {
    for (const item of items) {
      const score = scoreElement(item.name);
      if (score > 0) {
        const entry = { type, name: item.name, line: item.line, score, context: getContext(item.line) };
        if (fuzzy) {
          entry.fuzzyScore = fuzzyMatchScore(queryStr, item.name);
        }
        matches.push(entry);
      }
    }
  }

  addMatches(index.functions, 'function');
  addMatches(index.variables, 'variable');
  addMatches(index.remotes, 'remote');
  addMatches(index.uiSections, 'ui_section');

  for (const c of index.comments) {
    const score = scoreElement(c.text);
    if (score > 0) {
      const entry = { type: 'comment', name: c.text.slice(0, 60), line: c.line, score, context: getContext(c.line) };
      if (fuzzy) entry.fuzzyScore = fuzzyMatchScore(queryStr, c.text);
      matches.push(entry);
    }
  }

  for (const k of index.keywords) {
    const score = scoreElement(k.text);
    if (score > 0) {
      const entry = { type: 'keyword', name: k.text.slice(0, 60), line: k.line, score, context: getContext(k.line) };
      if (fuzzy) entry.fuzzyScore = fuzzyMatchScore(queryStr, k.text);
      matches.push(entry);
    }
  }

  matches.sort((a, b) => b.score - a.score || a.line - b.line);

  return {
    matches: matches.slice(0, maxResults),
    index,
    lines,
  };
}

// ── Main Export: semanticLuauSearch ──────────────────────────────────────────

export function semanticLuauSearch(text, filePath, query, options = {}) {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const queryStr = String(query || '').trim();
  const contextLines = options.context || 2;

  // Build mini index by iterating lines (O(n) instead of O(n²) substring/split)
  const index = {
    functions: [],
    variables: [],
    remotes: [],
    uiSections: [],
    comments: [],
    keywords: [],
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Function definitions
    const fnMatch = /(?:local\s+function|function)\s+([\w.:]+)\s*\(/.exec(line) || /(\w+)\s*=\s*function\s*\(/.exec(line);
    if (fnMatch) index.functions.push({ name: fnMatch[1], line: lineNum });

    // Local variable declarations
    const localMatch = /local\s+(\w+)\s*=/.exec(line);
    if (localMatch) index.variables.push({ name: localMatch[1], line: lineNum });

    // Remote calls
    const remoteMatch = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer|FireClient|InvokeClient)\s*\(/.exec(line);
    if (remoteMatch) index.remotes.push({ name: remoteMatch[1], line: lineNum, method: remoteMatch[2] });

    // UI sections
    const uiMatch = /:\s*(Page|Section|Category|Toggle|Button|Slider|Dropdown|Paragraph|Label)\s*\(/.exec(line);
    if (uiMatch) {
      const nameMatch = /Name\s*=\s*["']([^"']+)["']/.exec(line);
      index.uiSections.push({ name: nameMatch ? nameMatch[1] : '?', line: lineNum, type: uiMatch[1] });
    }

    // Comments
    const commentMatch = /^\s*--\s*(.+)$/.exec(line);
    if (commentMatch) index.comments.push({ text: commentMatch[1].trim(), line: lineNum });

    // Keywords
    const svcMatch = /game\s*:\s*GetService\s*\(\s*["']([^"']+)["']/.exec(line);
    if (svcMatch) index.keywords.push({ type: 'service', text: svcMatch[0], line: lineNum });
    if (/require\s*\(/.test(line)) index.keywords.push({ type: 'require', text: line.trim().slice(0, 80), line: lineNum });
    if (/\b(while|for|repeat)\s+\w+/.test(line)) index.keywords.push({ type: 'loop', text: line.trim().slice(0, 80), line: lineNum });
  }

  // Score matches against query
  const queryTokens = queryStr
    .split(/[\s_-]+/)
    .flatMap(token => {
      const camelSplit = token.split(/(?=[A-Z])/);
      return camelSplit.length > 1 ? camelSplit.map(t => t.toLowerCase()) : [token.toLowerCase()];
    })
    .filter(t => t.length > 0);

  const matches = [];
  const fuzzy = options.fuzzy !== false; // default true

  function scoreElement(elementName) {
    if (!elementName || !queryStr) return 0;

    if (fuzzy) {
      return fuzzyMatchScore(queryStr, elementName);
    }

    // Legacy non-fuzzy scoring
    const nameLower = elementName.toLowerCase();
    const queryLower = queryStr.toLowerCase();
    if (nameLower === queryLower) return 100;
    if (nameLower.includes(queryLower) || queryLower.includes(nameLower)) return 50;

    let maxTokenScore = 0;
    for (const token of queryTokens) {
      if (nameLower === token) { maxTokenScore = Math.max(maxTokenScore, 100); continue; }
      if (nameLower.includes(token)) { maxTokenScore = Math.max(maxTokenScore, 50); continue; }
      if (token.includes(nameLower)) { maxTokenScore = Math.max(maxTokenScore, 50); continue; }
      const camelWords = nameLower.split(/(?=[A-Z])/);
      for (const cw of camelWords) {
        if (cw.includes(token) || token.includes(cw)) maxTokenScore = Math.max(maxTokenScore, 75);
      }
    }

    if (maxTokenScore === 0) {
      for (const token of queryTokens) {
        const prefixLen = Math.min(4, token.length, nameLower.length);
        if (prefixLen >= 3 && nameLower.substring(0, prefixLen) === token.substring(0, prefixLen)) {
          maxTokenScore = 25;
          break;
        }
      }
    }

    return maxTokenScore;
  }

  function getContext(lineNum) {
    const idx = lineNum - 1;
    const before = [];
    for (let i = Math.max(0, idx - contextLines); i < idx; i++) before.push(lines[i]);
    const after = [];
    for (let i = idx + 1; i < Math.min(lines.length, idx + 1 + contextLines); i++) after.push(lines[i]);
    return { before, line: lines[idx] || '', after };
  }

  function addMatches(items, type) {
    for (const item of items) {
      const score = scoreElement(item.name);
      if (score > 0) {
        const entry = { type, name: item.name, line: item.line, score, context: getContext(item.line) };
        if (fuzzy) {
          entry.fuzzyScore = fuzzyMatchScore(queryStr, item.name);
        }
        matches.push(entry);
      }
    }
  }

  addMatches(index.functions, 'function');
  addMatches(index.variables, 'variable');
  addMatches(index.remotes, 'remote');
  addMatches(index.uiSections, 'ui_section');

  for (const c of index.comments) {
    const score = scoreElement(c.text);
    if (score > 0) {
      const entry = { type: 'comment', name: c.text.slice(0, 60), line: c.line, score, context: getContext(c.line) };
      if (fuzzy) entry.fuzzyScore = fuzzyMatchScore(queryStr, c.text);
      matches.push(entry);
    }
  }

  for (const k of index.keywords) {
    const score = scoreElement(k.text);
    if (score > 0) {
      const entry = { type: 'keyword', name: k.text.slice(0, 60), line: k.line, score, context: getContext(k.line) };
      if (fuzzy) entry.fuzzyScore = fuzzyMatchScore(queryStr, k.text);
      matches.push(entry);
    }
  }

  // Sort by score descending
  matches.sort((a, b) => b.score - a.score || a.line - b.line);

  const maxResults = options.maxResults || 50;

  // Build result
  const result = {
    filePath: toPosix(filePath),
    query: queryStr,
    totalMatches: matches.length,
    matches: matches.slice(0, maxResults),
    index: {
      functionCount: index.functions.length,
      variableCount: index.variables.length,
      remoteCount: index.remotes.length,
      uiSectionCount: index.uiSections.length,
    },
  };

  // Remote reference tracking: if a remote name was matched, track all refs
  const matchedRemoteNames = new Set();
  for (const m of matches) {
    if (m.type === 'remote') {
      matchedRemoteNames.add(m.name);
    }
  }

  if (matchedRemoteNames.size > 0) {
    // Use the highest-scoring remote for tracking
    const bestRemoteMatch = matches.find(m => m.type === 'remote');
    if (bestRemoteMatch) {
      const refs = buildRemoteRefMap(lines, bestRemoteMatch.name);
      if (refs) result.remoteRefs = refs;
    }
  }

  // Cross-file search
  if (options.crossFile && options.root) {
    const root = options.root;
    const keywords = buildQueryKeywords(queryStr);
    const crossFileResults = [];
    let totalCrossMatches = 0;

    try {
      const luauFiles = walkFiles(root, (fp) => {
        const ext = path.extname(fp).toLowerCase();
        return ext === '.lua' || ext === '.luau';
      });

      for (const fp of luauFiles) {
        // Skip the original file
        const resolvedFp = path.isAbsolute(fp) ? fp : path.join(root, fp);
        if (resolvedFp === path.resolve(filePath) || toPosix(relative(root, resolvedFp)) === toPosix(relative(root, path.resolve(filePath)))) {
          continue;
        }

        const fileText = readText(resolvedFp);
        if (!fileHasKeyword(fileText, keywords)) continue;

        const fileResult = analyzeFileMatches(fileText, resolvedFp, queryStr, queryTokens, options);
        if (fileResult.matches.length === 0) continue;

        const bestScore = fileResult.matches.length > 0 ? fileResult.matches[0].score : 0;
        crossFileResults.push({
          filePath: toPosix(relative(root, resolvedFp)),
          matchCount: fileResult.matches.length,
          bestScore,
          matches: fileResult.matches,
        });
        totalCrossMatches += fileResult.matches.length;
      }
    } catch {
      // If cross-file search fails (permissions, etc.), silently skip
    }

    // Sort files by best score
    crossFileResults.sort((a, b) => b.bestScore - a.bestScore);

    result.crossFile = {
      fileCount: crossFileResults.length > 0
        ? (() => {
            // Count total .lua/.luau files scanned
            try {
              return walkFiles(root, (fp) => {
                const ext = path.extname(fp).toLowerCase();
                return ext === '.lua' || ext === '.luau';
              }).length;
            } catch {
              return 0;
            }
          })()
        : 0,
      filesWithMatches: crossFileResults.length,
      totalMatches: totalCrossMatches,
      files: crossFileResults,
    };
  }

  return result;
}

// ── Extract Remote Details (Calls + Handlers) ────────────────────────────────

/**
 * Enhanced version of extractRemotePayloads that adds handler-side information.
 * Maps remote calls to their potential handlers, detects pcall usage.
 */
export function extractRemoteDetails(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);

  // Use extractRemotePayloads for the call-side
  const base = extractRemotePayloads(text, filePath);

  // Build a map of remote variable names to their definitions
  const remoteDefs = new Map(); // name -> { type, line, varName }
  const remoteCalls = new Map(); // varName -> [call info]
  const remoteHandlers = new Map(); // varName -> [handler info]

  // 1. Find remote definitions (RemoteEvent, RemoteFunction)
  const defPatterns = [
    { re: /local\s+(\w[\w.]*)\s*=\s*(?:.*?):(?:RemoteEvent|RemoteFunction)\s*\(\s*["']([^"']+)["']/, type: 'named' },
    { re: /local\s+(\w[\w.]*)\s*=\s*(?:ReplicatedStorage|game)\s*:\s*(?:WaitForChild|FindFirstChild)\s*\(\s*["']([^"']+)["']\s*\)/, type: 'waitforchild' },
    { re: /local\s+(\w[\w.]*)\s*=\s*["']([^"']+)["']\s*:\s*(?:RemoteEvent|RemoteFunction)/, type: 'reverse' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const dp of defPatterns) {
      const m = dp.re.exec(line);
      if (m) {
        const varName = m[1];
        const remoteName = m[2];
        const kind = /RemoteFunction/.test(line) ? 'RemoteFunction' : 'RemoteEvent';
        remoteDefs.set(varName, { name: remoteName, kind, line: i + 1, varName });
        break;
      }
    }
  }

  // 2. Find all remote calls with pcall detection
  const callRe = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer|FireClient|InvokeClient)\s*\(/g;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let callMatch;
    // Reset lastIndex since we reuse the regex
    const lineCallRe = /(\w[\w.]*)\s*:\s*(FireServer|InvokeServer|FireClient|InvokeClient)\s*\(/;
    callMatch = lineCallRe.exec(line);
    if (callMatch) {
      const varName = callMatch[1];
      const method = callMatch[2];

      // Check for pcall on this line or in surrounding context
      let hasPcall = false;
      if (/\bpcall\b/.test(line)) {
        hasPcall = true;
      } else {
        // Check up to 3 lines before
        for (let j = Math.max(0, i - 3); j < i; j++) {
          if (/\bpcall\s*\(/.test(lines[j])) {
            hasPcall = true;
            break;
          }
        }
      }

      // Determine payload style
      const payloadStr = line.substring(callMatch.index + callMatch[0].length).trim();
      let payloadStyle = 'empty';
      if (payloadStr.startsWith('{')) {
        payloadStyle = 'table';
      } else if (payloadStr && payloadStr !== ')') {
        payloadStyle = 'positional';
      }

      const callInfo = {
        line: i + 1,
        method,
        hasPcall,
        payloadStyle,
        snippet: line.trim().slice(0, 120),
      };

      if (!remoteCalls.has(varName)) remoteCalls.set(varName, []);
      remoteCalls.get(varName).push(callInfo);
    }
  }

  // 3. Find handlers (OnServerEvent, OnClientEvent, OnServerInvoke, OnClientInvoke)
  const handlerPatterns = [
    { re: /(\w[\w.]*)\s*\.\s*(OnServerEvent)\s*:\s*Connect\s*\(/, type: 'OnServerEvent' },
    { re: /(\w[\w.]*)\s*\.\s*(OnClientEvent)\s*:\s*Connect\s*\(/, type: 'OnClientEvent' },
    { re: /(\w[\w.]*)\s*\.\s*(OnServerInvoke)\s*\s*=\s*/, type: 'OnServerInvoke' },
    { re: /(\w[\w.]*)\s*\.\s*(OnClientInvoke)\s*\s*=\s*/, type: 'OnClientInvoke' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const hp of handlerPatterns) {
      const m = hp.re.exec(line);
      if (m) {
        const varName = m[1];
        const handlerType = hp.type;
        const handlerInfo = {
          line: i + 1,
          type: handlerType,
          snippet: line.trim().slice(0, 120),
        };
        if (!remoteHandlers.has(varName)) remoteHandlers.set(varName, []);
        remoteHandlers.get(varName).push(handlerInfo);
      }
    }
  }

  // 4. Build unified remote list
  const allVarNames = new Set([
    ...remoteDefs.keys(),
    ...remoteCalls.keys(),
    ...remoteHandlers.keys(),
  ]);

  const remotes = [];
  const orphans = [];

  for (const varName of allVarNames) {
    const def = remoteDefs.get(varName);
    const calls = remoteCalls.get(varName) || [];
    const handlers = remoteHandlers.get(varName) || [];
    const isOrphaned = calls.length > 0 && handlers.length === 0;

    // Determine kind
    let kind = 'unknown';
    if (def) {
      kind = def.kind;
    } else if (calls.some(c => c.method === 'InvokeServer' || c.method === 'InvokeClient')) {
      kind = 'RemoteFunction';
    } else if (calls.length > 0) {
      kind = 'RemoteEvent';
    }

    // Calculate pcall coverage
    const totalCalls = calls.length;
    const pcallCalls = calls.filter(c => c.hasPcall).length;
    const pcallCoverage = totalCalls > 0 ? Math.round((pcallCalls / totalCalls) * 100) : 100;

    const remoteName = def ? def.name : varName;

    remotes.push({
      name: remoteName,
      kind,
      calls,
      handlers,
      isOrphaned,
      pcallCoverage,
    });

    if (isOrphaned) {
      orphans.push(remoteName);
    }
  }

  // Sort by name
  remotes.sort((a, b) => a.name.localeCompare(b.name));

  // Summary
  const allCalls = remotes.flatMap(r => r.calls);
  const totalCalls = allCalls.length;
  const withPcall = allCalls.filter(c => c.hasPcall).length;
  const uniqueRemotes = remotes.length;
  const withHandlers = remotes.filter(r => r.handlers.length > 0).length;

  return {
    filePath: toPosix(filePath),
    summary: {
      totalCalls,
      uniqueRemotes,
      withPcall,
      withoutPcall: totalCalls - withPcall,
      withHandlers,
      orphanedRemotes: orphans.length,
    },
    remotes,
    orphans,
  };
}

// ── Batch Fix Luau File ──────────────────────────────────────────────────────

/**
 * Scans a file and applies ALL fixable risks in a single pass.
 * Uses existing hotfixLuauText internals (wrapRemoteStatements, insertRateLimitGuards,
 * prependConnectionCleanup) and adds more fix stages.
 */
export function batchFixLuauFile(text, filePath, options = {}) {
  const source = String(text || '');
  const { apply = true, stages = [], skipStages = [] } = options;

  const allStages = ['pcall-wrap', 'deprecated-wait', 'deprecated-spawn', 'deprecated-delay', 'rate-limit', 'connection-cleanup', 'loop-guard', 'magic-number'];
  const activeStages = stages.length > 0
    ? allStages.filter(s => stages.includes(s))
    : allStages.filter(s => !skipStages.includes(s));

  const beforeHash = textHash(source);
  let currentLines = source.split(/\r?\n/);
  const stageResults = [];

  function runStage(name, fn) {
    if (!activeStages.includes(name)) return;
    const result = fn(currentLines);
    const changed = result.edits.length > 0;
    stageResults.push({ name, fixes: result.edits.length, edits: result.edits, changed });
    if (changed) currentLines = result.lines || currentLines;
  }

  // Stage 1: pcall-wrap (reuse existing internal function)
  runStage('pcall-wrap', (lines) => wrapRemoteStatements(lines));

  // Stage 2: deprecated-wait
  runStage('deprecated-wait', (lines) => {
    const edits = [];
    const out = lines.map((line, idx) => {
      if (/\bwait\s*\(/.test(line) && !/\btask\.wait\s*\(/.test(line) && !/^\s*--/.test(line)) {
        const after = line.replace(/\bwait\s*\(/g, 'task.wait(');
        edits.push({ line: idx + 1, before: line, after, label: 'deprecated-wait' });
        return after;
      }
      return line;
    });
    return { lines: out, edits };
  });

  // Stage 3: deprecated-spawn
  runStage('deprecated-spawn', (lines) => {
    const edits = [];
    const out = lines.map((line, idx) => {
      if (/\bspawn\s*\(/.test(line) && !/\btask\.spawn\s*\(/.test(line) && !/^\s*--/.test(line)) {
        const after = line.replace(/\bspawn\s*\(/g, 'task.spawn(');
        edits.push({ line: idx + 1, before: line, after, label: 'deprecated-spawn' });
        return after;
      }
      return line;
    });
    return { lines: out, edits };
  });

  // Stage 4: deprecated-delay
  runStage('deprecated-delay', (lines) => {
    const edits = [];
    const out = lines.map((line, idx) => {
      if (/\bdelay\s*\(/.test(line) && !/\btask\.delay\s*\(/.test(line) && !/^\s*--/.test(line)) {
        const after = line.replace(/\bdelay\s*\(/g, 'task.delay(');
        edits.push({ line: idx + 1, before: line, after, label: 'deprecated-delay' });
        return after;
      }
      return line;
    });
    return { lines: out, edits };
  });

  // Stage 5: rate-limit (reuse existing internal function)
  runStage('rate-limit', (lines) => insertRateLimitGuards(lines));

  // Stage 6: connection-cleanup (reuse existing internal function on joined text)
  runStage('connection-cleanup', (lines) => {
    const currentText = lines.join('\n');
    const result = prependConnectionCleanup(lines, currentText);
    // Re-label edits for clarity
    for (const edit of result.edits) {
      edit.label = 'connection-cleanup';
    }
    return result;
  });

  // Stage 7: loop-guard — add character guard after `while true do`
  runStage('loop-guard', (lines) => {
    const edits = [];
    const guardRe = /while\s+true\s+do\b/;
    const charGuardRe = /FindFirstChild\s*\(\s*["']HumanoidRootPart["']\s*\)/;
    const out = [];
    for (let i = 0; i < lines.length; i++) {
      out.push(lines[i]);
      if (guardRe.test(lines[i]) && !/^\s*--/.test(lines[i])) {
        // Check next 20 lines for character guard
        let hasGuard = false;
        for (let j = i + 1; j < Math.min(i + 21, lines.length); j++) {
          if (charGuardRe.test(lines[j])) { hasGuard = true; break; }
          if (/^\s*end\s*$/.test(lines[j])) break;
        }
        if (!hasGuard) {
          const indent = lines[i].match(/^\s*/)?.[0] || '';
          const guard = `${indent}if not Character or not Character:FindFirstChild("HumanoidRootPart") then task.wait(0.1) continue end`;
          out.push(guard);
          edits.push({ line: i + 1, before: lines[i], after: guard, label: 'loop-guard' });
        }
      }
    }
    return { lines: out, edits };
  });

  // Stage 8: magic-number — flag but don't fix
  runStage('magic-number', (lines) => {
    const edits = [];
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (/^\s*--/.test(trimmed)) continue;
      const numRe = /\b(\d{5,})\b/g;
      let m;
      while ((m = numRe.exec(trimmed)) !== null) {
        const num = parseInt(m[1], 10);
        if (num > 99999) {
          edits.push({
            line: i + 1,
            before: trimmed,
            after: `-- MAGIC-NUMBER: ${m[1]} — consider using a named constant`,
            label: 'magic-number',
          });
        }
      }
    }
    return { lines, edits };
  });

  const afterText = currentLines.join('\n');
  const afterHash = textHash(afterText);
  const totalFixes = stageResults.reduce((sum, s) => sum + s.fixes, 0);
  const stagesApplied = stageResults.filter(s => s.fixes > 0).length;

  let recommendation;
  if (totalFixes === 0) {
    recommendation = 'No fixes needed across all stages.';
  } else {
    recommendation = `${totalFixes} fix(es) applied across ${stagesApplied} stage(s).`;
  }

  const finalAfter = apply ? afterText : source;

  return {
    filePath: toPosix(filePath),
    summary: {
      stages: allStages.length,
      stagesApplied,
      totalFixes,
      beforeHash,
      afterHash,
      changed: afterText !== source,
    },
    stages: stageResults,
    after: finalAfter,
    applied: apply,
    recommendation,
  };
}

// ── UI Audit Luau ────────────────────────────────────────────────────────────

/**
 * Validates LibSixtyTen/Obsidian UI scripts for common issues.
 */
export function uiAuditLuau(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const checks = [];
  const recommendations = [];
  const flags = extractFlagsFromText(source, filePath);
  const uiMap = extractUIMap(source, filePath);

  // Detect UI library
  let uiLibrary = 'Unknown';
  if (/LibSixtyTen/.test(source) || /Library:Window\s*\(/.test(source)) {
    uiLibrary = 'LibSixtyTen';
  }
  if (/Obsidian/.test(source) || /Library:CreateWindow\s*\(/.test(source)) {
    uiLibrary = 'Obsidian';
  }
  if (/loadstring.*LibSixtyTen/.test(source)) uiLibrary = 'LibSixtyTen';
  if (/loadstring.*Obsidian/.test(source)) uiLibrary = 'Obsidian';

  // Count UI sections
  const sectionNames = [];
  const sectionRe = /:\s*(Page|Category|Section)\s*\(\s*(?:\{[^}]*Name\s*=\s*["']([^"']+)["']|["']([^"']+)["'])/g;
  let sm;
  while ((sm = sectionRe.exec(source)) !== null) {
    sectionNames.push(sm[2] || sm[3] || '?');
  }
  const totalSections = sectionNames.length;

  // ── Check 1: status-paragraphs ─────────────────────────────────────────
  const hasBuildBasic = /BuildBasicStatus\s*\(/.test(source);
  const hasBuildDetailed = /BuildDetailedStatus\s*\(/.test(source);
  const hasStatusColors = /STATUS_COLORS/.test(source);
  const hasSetText = /SetText\s*\(/.test(source);
  const hasParagraph = /:\s*Paragraph\s*\(/.test(source);

  if (hasBuildBasic || hasBuildDetailed) {
    if (!hasSetText) {
      checks.push({
        check: 'status-paragraphs',
        pass: false,
        severity: 'warning',
        detail: 'Status builder functions found but no SetText calls — status paragraphs are not being updated.',
      });
      recommendations.push('Add SetText calls to update status paragraphs with real-time state.');
    } else {
      checks.push({ check: 'status-paragraphs', pass: true, severity: 'info', detail: 'Status builders and SetText calls present.' });
    }
    if (!hasStatusColors) {
      checks.push({
        check: 'status-colors',
        pass: false,
        severity: 'error',
        detail: 'STATUS_COLORS constant missing — status colors may be inconsistent.',
      });
      recommendations.push('Define a STATUS_COLORS table for consistent status color theming.');
    } else {
      checks.push({ check: 'status-colors', pass: true, severity: 'info', detail: 'STATUS_COLORS constant present.' });
    }
  } else if (hasParagraph) {
    checks.push({
      check: 'status-paragraphs',
      pass: false,
      severity: 'warning',
      detail: 'Paragraph declarations found but no BuildBasicStatus or BuildDetailedStatus builders.',
    });
    recommendations.push('Use BuildBasicStatus or BuildDetailedStatus for consistent status formatting.');
  } else {
    checks.push({ check: 'status-paragraphs', pass: false, severity: 'info', detail: 'No status paragraph patterns detected.' });
  }

  // ── Check 2: flag-naming ───────────────────────────────────────────────
  const flagNames = flags.allFlags.map(f => f.name);
  const duplicateFlags = flagNames.filter((name, idx) => flagNames.indexOf(name) !== idx);
  const uniqueDuplicates = [...new Set(duplicateFlags)];

  const namingIssues = [];
  const knownPrefixes = ['Farm_', 'Esp_', 'Teleport_', 'Combat_', 'Auto_', 'Misc_', 'Settings_', 'Player_', 'UI_', 'Orbit_', 'Block_', 'Skill_', 'Return_', 'Target_', 'Walk_', 'Jump_'];

  for (const fname of flagNames) {
    // Check for snake_case vs camelCase inconsistency
    if (fname.includes('_') && !knownPrefixes.some(p => fname.startsWith(p))) {
      namingIssues.push(`Flag "${fname}" uses underscore — prefer PascalCase with prefix.`);
    }
    // Check for missing system prefix
    if (!knownPrefixes.some(p => fname.startsWith(p))) {
      // Only flag if it looks like a feature flag (not a generic name)
      if (fname.length > 3 && !/^[A-Z]/.test(fname)) {
        namingIssues.push(`Flag "${fname}" missing system prefix (e.g., Farm_, Esp_, Teleport_).`);
      }
    }
  }

  if (uniqueDuplicates.length > 0) {
    checks.push({
      check: 'flag-naming',
      pass: false,
      severity: 'error',
      detail: `${uniqueDuplicates.length} duplicate Flag value(s): [${uniqueDuplicates.join(', ')}] — controls will share state.`,
    });
    recommendations.push(`Remove duplicate Flag values: ${uniqueDuplicates.join(', ')}.`);
  } else if (namingIssues.length > 0) {
    checks.push({
      check: 'flag-naming',
      pass: false,
      severity: 'warning',
      detail: `${namingIssues.length} flag naming issue(s): ${namingIssues.slice(0, 3).join('; ')}${namingIssues.length > 3 ? '...' : ''}`,
    });
    recommendations.push('Standardize flag names to PascalCase with consistent prefixes.');
  } else {
    checks.push({ check: 'flag-naming', pass: true, severity: 'info', detail: 'Flag names look consistent.' });
  }

  // ── Check 3: ui-duplicates ─────────────────────────────────────────────
  const duplicateSections = sectionNames.filter((name, idx) => sectionNames.indexOf(name) !== idx);
  const uniqueDuplicateSections = [...new Set(duplicateSections)];

  if (uniqueDuplicateSections.length > 0) {
    checks.push({
      check: 'ui-duplicates',
      pass: false,
      severity: 'error',
      detail: `Duplicate UI section(s): [${uniqueDuplicateSections.join(', ')}].`,
    });
    recommendations.push(`Rename or merge duplicate UI sections: ${uniqueDuplicateSections.join(', ')}.`);
  } else {
    checks.push({ check: 'ui-duplicates', pass: true, severity: 'info', detail: 'No duplicate UI sections found.' });
  }

  // ── Check 4: mobile-first ──────────────────────────────────────────────
  const mobileIssues = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\.hover\b/.test(line) && !/^\s*--/.test(line)) {
      mobileIssues.push(`L${i + 1}: hover dependency — does not work on mobile: ${line.trim().slice(0, 80)}`);
    }
    if (/MouseButton1Click/.test(line) && !/TouchTap/.test(line)) {
      // Check nearby lines for TouchTap fallback
      const nearby = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join('\n');
      if (!/TouchTap|TouchEnded/.test(nearby)) {
        mobileIssues.push(`L${i + 1}: MouseButton1Click without TouchTap fallback — limited mobile support.`);
      }
    }
  }

  if (mobileIssues.length > 0) {
    checks.push({
      check: 'mobile-first',
      pass: false,
      severity: 'warning',
      detail: `${mobileIssues.length} mobile compatibility issue(s).`,
      line: parseInt(mobileIssues[0].match(/L(\d+)/)?.[1] || '0', 10),
    });
    recommendations.push('Replace hover patterns with touch-compatible alternatives for mobile support.');
  } else {
    checks.push({ check: 'mobile-first', pass: true, severity: 'info', detail: 'No mobile compatibility issues found.' });
  }

  // ── Check 5: section-adapter ───────────────────────────────────────────
  const hasSectionAdapter = /SectionAdapter/.test(source);
  if (!hasSectionAdapter && (uiLibrary === 'LibSixtyTen' || /loadstring.*LibSixtyTen/.test(source))) {
    checks.push({
      check: 'section-adapter',
      pass: false,
      severity: 'warning',
      detail: 'LibSixtyTen detected but no SectionAdapter pattern — sections may lack unified control interface.',
    });
    recommendations.push('Add SectionAdapter pattern for consistent section control management.');
  } else {
    checks.push({ check: 'section-adapter', pass: true, severity: 'info', detail: hasSectionAdapter ? 'SectionAdapter pattern present.' : 'SectionAdapter not required for this UI library.' });
  }

  // ── Check 6: theme-save ────────────────────────────────────────────────
  const hasThemeManager = /ThemeManager/.test(source);
  const hasSaveManager = /SaveManager/.test(source);
  if (!hasThemeManager || !hasSaveManager) {
    const missing = [];
    if (!hasThemeManager) missing.push('ThemeManager');
    if (!hasSaveManager) missing.push('SaveManager');
    checks.push({
      check: 'theme-save',
      pass: false,
      severity: 'info',
      detail: `${missing.join(' and ')} not found — no theme persistence or config saving.`,
    });
    recommendations.push('Integrate ThemeManager and SaveManager for config persistence and theming.');
  } else {
    checks.push({ check: 'theme-save', pass: true, severity: 'info', detail: 'ThemeManager and SaveManager integrated.' });
  }

  // ── Check 7: loadstring-safe ───────────────────────────────────────────
  const loadstringCalls = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/loadstring\s*\(\s*(?:game\s*:\s*HttpGet|game\.HttpGet)/.test(line)) {
      // Check if wrapped in pcall
      let inPcall = false;
      for (let j = Math.max(0, i - 3); j <= i; j++) {
        if (/\bpcall\b/.test(lines[j]) || /\bpcallRef\b/.test(lines[j])) {
          inPcall = true;
          break;
        }
      }
      loadstringCalls.push({ line: i + 1, inPcall });
    }
  }

  const unsafeLoadstrings = loadstringCalls.filter(c => !c.inPcall);
  if (unsafeLoadstrings.length > 0) {
    checks.push({
      check: 'loadstring-safe',
      pass: false,
      severity: 'error',
      detail: `${unsafeLoadstrings.length} loadstring(game:HttpGet...) call(s) without pcall wrapper.`,
      line: unsafeLoadstrings[0].line,
    });
    recommendations.push('Wrap loadstring(game:HttpGet...) calls in pcall for safe loading.');
  } else if (loadstringCalls.length > 0) {
    checks.push({ check: 'loadstring-safe', pass: true, severity: 'info', detail: 'All loadstring(game:HttpGet...) calls are pcall-wrapped.' });
  } else {
    checks.push({ check: 'loadstring-safe', pass: true, severity: 'info', detail: 'No loadstring(game:HttpGet...) calls detected.' });
  }

  // ── Compute verdict ────────────────────────────────────────────────────
  const errors = checks.filter(c => !c.pass && c.severity === 'error');
  const warnings = checks.filter(c => !c.pass && c.severity === 'warning');
  const passed = checks.filter(c => c.pass);

  let verdict = 'PASS';
  if (errors.length > 0) verdict = 'FAIL';
  else if (warnings.length > 0) verdict = 'WARN';

  return {
    filePath: toPosix(filePath),
    verdict,
    summary: {
      totalChecks: checks.length,
      passed: passed.length,
      warnings: warnings.length,
      failures: errors.length,
      uiLibrary,
      totalSections,
      totalFlags: flagNames.length,
    },
    checks,
    flags: {
      total: flagNames.length,
      duplicates: uniqueDuplicates,
      namingIssues,
    },
    uiSections: {
      total: totalSections,
      duplicates: uniqueDuplicateSections,
      mobileIssues,
    },
    recommendations,
  };
}

// ── Performance Budget Luau ──────────────────────────────────────────────────

/**
 * Defines performance budgets and scans all Luau files to find violations.
 */
export function performanceBudgetLuau(root, options = {}) {
  const { budgets: customBudgets = {}, targetPath = '' } = options;

  const defaultBudgets = {
    maxLocals: 180,
    maxCallbacks: 20,
    maxRemotes: 50,
    maxLoops: 5,
    maxConnections: 10,
    maxLines: 1500,
    maxRisks: 10,
    maxOrphanedConnections: 0,
  };

  const limits = { ...defaultBudgets, ...customBudgets };

  // Scan workspace
  const scan = scanLuauWorkspace(root);
  const files = scan.files || [];

  // Filter by targetPath if specified
  const filteredFiles = targetPath
    ? files.filter(f => {
        const rel = f.filePath;
        return rel === targetPath || rel.startsWith(`${targetPath}/`);
      })
    : files;

  const fileResults = [];
  const budgetUsage = {};

  // Initialize budget tracking
  for (const key of Object.keys(limits)) {
    budgetUsage[key] = { limit: limits[key], used: 0, worstFile: '', worstValue: 0 };
  }

  let filesWithinBudget = 0;
  let filesOverBudget = 0;

  for (const entry of filteredFiles) {
    const violations = [];
    const resolvedPath = entry.filePath;

    // Parse the actual file text for more detailed counts
    const fullFilePath = path.isAbsolute(resolvedPath) ? resolvedPath : path.join(root, resolvedPath);
    const fileText = readText(fullFilePath);
    const fileLines = fileText ? fileText.split(/\r?\n/) : [];
    const lineCount = fileLines.length;

    // maxLines
    if (lineCount > limits.maxLines) {
      const pct = Math.round((lineCount / limits.maxLines) * 100);
      violations.push({
        budget: 'maxLines',
        limit: limits.maxLines,
        actual: lineCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (lineCount > budgetUsage.maxLines.worstValue) {
      budgetUsage.maxLines.used = lineCount;
      budgetUsage.maxLines.worstFile = resolvedPath;
      budgetUsage.maxLines.worstValue = lineCount;
    }

    // maxLocals
    const localCount = entry.summary.localCount || 0;
    if (localCount > limits.maxLocals) {
      const pct = Math.round((localCount / limits.maxLocals) * 100);
      violations.push({
        budget: 'maxLocals',
        limit: limits.maxLocals,
        actual: localCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (localCount > budgetUsage.maxLocals.worstValue) {
      budgetUsage.maxLocals.used = localCount;
      budgetUsage.maxLocals.worstFile = resolvedPath;
      budgetUsage.maxLocals.worstValue = localCount;
    }

    // maxCallbacks
    const callbackCount = entry.summary.callbackCount || 0;
    if (callbackCount > limits.maxCallbacks) {
      const pct = Math.round((callbackCount / limits.maxCallbacks) * 100);
      violations.push({
        budget: 'maxCallbacks',
        limit: limits.maxCallbacks,
        actual: callbackCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (callbackCount > budgetUsage.maxCallbacks.worstValue) {
      budgetUsage.maxCallbacks.used = callbackCount;
      budgetUsage.maxCallbacks.worstFile = resolvedPath;
      budgetUsage.maxCallbacks.worstValue = callbackCount;
    }

    // maxRemotes
    const remoteCount = entry.summary.remoteCount || 0;
    if (remoteCount > limits.maxRemotes) {
      const pct = Math.round((remoteCount / limits.maxRemotes) * 100);
      violations.push({
        budget: 'maxRemotes',
        limit: limits.maxRemotes,
        actual: remoteCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (remoteCount > budgetUsage.maxRemotes.worstValue) {
      budgetUsage.maxRemotes.used = remoteCount;
      budgetUsage.maxRemotes.worstFile = resolvedPath;
      budgetUsage.maxRemotes.worstValue = remoteCount;
    }

    // maxLoops — count while/for/repeat
    const loopCount = (fileText.match(/\bwhile\s+/g) || []).length + (fileText.match(/\bfor\s+/g) || []).length + (fileText.match(/\brepeat\s+/g) || []).length;
    if (loopCount > limits.maxLoops) {
      const pct = Math.round((loopCount / limits.maxLoops) * 100);
      violations.push({
        budget: 'maxLoops',
        limit: limits.maxLoops,
        actual: loopCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (loopCount > budgetUsage.maxLoops.worstValue) {
      budgetUsage.maxLoops.used = loopCount;
      budgetUsage.maxLoops.worstFile = resolvedPath;
      budgetUsage.maxLoops.worstValue = loopCount;
    }

    // maxConnections — count Connect calls
    const connectionCount = entry.summary.connectCount || (fileText.match(/\bConnect\s*\(/g) || []).length;
    if (connectionCount > limits.maxConnections) {
      const pct = Math.round((connectionCount / limits.maxConnections) * 100);
      violations.push({
        budget: 'maxConnections',
        limit: limits.maxConnections,
        actual: connectionCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (connectionCount > budgetUsage.maxConnections.worstValue) {
      budgetUsage.maxConnections.used = connectionCount;
      budgetUsage.maxConnections.worstFile = resolvedPath;
      budgetUsage.maxConnections.worstValue = connectionCount;
    }

    // maxRisks
    const riskCount = entry.summary.riskCount || 0;
    if (riskCount > limits.maxRisks) {
      const pct = Math.round((riskCount / limits.maxRisks) * 100);
      violations.push({
        budget: 'maxRisks',
        limit: limits.maxRisks,
        actual: riskCount,
        severity: pct > 150 ? 'critical' : 'warning',
      });
    }
    if (riskCount > budgetUsage.maxRisks.worstValue) {
      budgetUsage.maxRisks.used = riskCount;
      budgetUsage.maxRisks.worstFile = resolvedPath;
      budgetUsage.maxRisks.worstValue = riskCount;
    }

    // maxOrphanedConnections — check for Connect without Disconnect
    const disconnectCount = (fileText.match(/\bDisconnect\s*\(/g) || []).length;
    const taskCancelCount = (fileText.match(/\btask\.cancel\b/g) || []).length;
    const orphanedConnections = connectionCount > 0 && (disconnectCount + taskCancelCount) === 0 ? connectionCount : 0;
    if (orphanedConnections > limits.maxOrphanedConnections) {
      violations.push({
        budget: 'maxOrphanedConnections',
        limit: limits.maxOrphanedConnections,
        actual: orphanedConnections,
        severity: orphanedConnections > 3 ? 'critical' : 'warning',
      });
    }
    if (orphanedConnections > budgetUsage.maxOrphanedConnections.worstValue) {
      budgetUsage.maxOrphanedConnections.used = orphanedConnections;
      budgetUsage.maxOrphanedConnections.worstFile = resolvedPath;
      budgetUsage.maxOrphanedConnections.worstValue = orphanedConnections;
    }

    const withinBudget = violations.length === 0;
    if (withinBudget) filesWithinBudget++;
    else filesOverBudget++;

    fileResults.push({
      filePath: resolvedPath,
      lineCount,
      withinBudget,
      violations,
    });
  }

  // Build worst offenders list
  const worstOffenders = fileResults
    .filter(f => f.violations.length > 0)
    .sort((a, b) => b.violations.length - a.violations.length)
    .slice(0, 5)
    .map(f => ({
      filePath: f.filePath,
      violationCount: f.violations.length,
      worstViolations: f.violations.slice(0, 5),
    }));

  // Calculate budget health
  const totalFiles = fileResults.length;
  const budgetHealth = totalFiles > 0 ? Math.round((filesWithinBudget / totalFiles) * 100) : 100;

  // Build recommendation
  let recommendation;
  if (filesOverBudget === 0) {
    recommendation = `All ${totalFiles} file(s) are within performance budgets.`;
  } else {
    const topOffender = worstOffenders[0];
    recommendation = `${filesOverBudget}/${totalFiles} file(s) exceed budgets. Worst offender: ${topOffender?.filePath || 'N/A'} with ${topOffender?.violationCount || 0} violation(s).`;
  }

  return {
    summary: {
      totalFiles,
      filesWithinBudget,
      filesOverBudget,
      budgetHealth,
      budgets: budgetUsage,
    },
    files: fileResults,
    worstOffenders,
    recommendation,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// luau.callback_trace — Trace execution paths from a toggle/control to remotes
// ═══════════════════════════════════════════════════════════════════════

/**
 * Given a control name (toggle, button, slider, dropdown) or function name,
 * trace ALL execution paths from that entry point to every FireServer/InvokeServer
 * call, remote reference, and side effect. Reports pcall wrapping, loop spawning,
 * and character guards at each path segment.
 */
export function traceCallback(text, query, filePath = '') {
  const lines = text.split('\n');
  const totalLines = lines.length;

  // ── Step 1: Find the anchor (control or function) ───────────────────────
  // Match patterns like: Toggle("Auto Farm" ...), Button("Teleport" ...),
  // local function autoFarm(), AutoFarm = function(), ["Auto Farm"] = ...
  const anchorPatterns = [
    { re: new RegExp(`(?:Toggle|Button|Slider|Dropdown)\\s*\\([^)]*${escapeRegex(query)}`, 'i'), label: 'ui-control' },
    { re: new RegExp(`local\\s+function\\s+${escapeRegex(query)}\\s*\\(`, 'i'), label: 'local-function' },
    { re: new RegExp(`${escapeRegex(query)}\\s*=\\s*function\\s*\\(`, 'i'), label: 'function-assign' },
    { re: new RegExp(`\\[\\s*["']${escapeRegex(query)}["']\\s*\\]\\s*=`), label: 'table-key' },
    { re: new RegExp(`\\b(function|local\\s+function)\\s+\\w*[${escapeRegex(query.toLowerCase())}]\\w*`, 'i'), label: 'fuzzy-function' },
  ];

  const anchors = [];
  for (const pat of anchorPatterns) {
    for (let i = 0; i < totalLines; i++) {
      if (pat.re.test(lines[i])) {
        anchors.push({ line: i + 1, label: pat.label, text: lines[i].trim() });
      }
    }
  }

  if (anchors.length === 0) {
    // Try case-insensitive substring match as fallback
    const lowerQuery = query.toLowerCase();
    for (let i = 0; i < totalLines; i++) {
      const lower = lines[i].toLowerCase();
      if (lower.includes(lowerQuery) && (lower.includes('function') || lower.includes('toggle') || lower.includes('button') || lower.includes('slider') || lower.includes('dropdown'))) {
        anchors.push({ line: i + 1, label: 'fuzzy-match', text: lines[i].trim() });
      }
    }
  }

  if (anchors.length === 0) {
    return {
      query,
      filePath,
      totalLines,
      anchorsFound: 0,
      paths: [],
      remotes: [],
      loops: [],
      pcallCoverage: null,
      recommendation: `"${query}" not found in script. Try a different name or check spelling.`,
    };
  }

  // ── Step 2: For each anchor, trace forward to find all downstream effects ─
  const paths = [];
  const allRemotes = new Set();
  const allLoops = [];
  let pcallCount = 0;
  let unpcallCount = 0;

  for (const anchor of anchors) {
    const path = {
      anchor,
      functionsCalled: [],
      remotes: [],
      loops: [],
      variablesMutated: [],
      taskSpawnLoops: [],
      pcallWrapped: 0,
      unpcallRemotes: 0,
      characterGuards: 0,
      depth: 0,
    };

    // Walk forward from anchor line to find the callback body
    // Heuristic: find the next block (between braces or do...end or function body)
    const bodyStart = anchor.line; // 1-based
    const bodyEnd = findBlockEnd(lines, bodyStart - 1); // convert to 0-based

    if (bodyEnd <= bodyStart) {
      // Callback body extends to end of file or until next top-level statement
      const scanEnd = Math.min(bodyStart + 200, totalLines);
      scanBlock(lines, bodyStart - 1, scanEnd, path, allRemotes, allLoops);
    } else {
      scanBlock(lines, bodyStart - 1, bodyEnd, path, allRemotes, allLoops);
    }

    pcallCount += path.pcallWrapped;
    unpcallCount += path.unpcallRemotes;
    path.remotes = [...new Set(path.remotes)];
    path.loops = [...new Set(path.loops)];
    paths.push(path);
  }

  // ── Step 3: Build summary ───────────────────────────────────────────────
  const remotesFound = [...allRemotes].map(r => {
    const isPcallWrapped = paths.some(p => p.remotes.includes(r) && p.pcallWrapped > 0);
    return { name: r, pcallWrapped: isPcallWrapped };
  });

  const pcallCoverage = {
    totalRemotes: pcallCount + unpcallCount,
    wrapped: pcallCount,
    unwrapped: unpcallCount,
    ratio: pcallCount + unpcallCount > 0 ? (pcallCount / (pcallCount + unpcallCount) * 100).toFixed(0) + '%' : 'N/A',
  };

  let recommendation;
  if (unpcallCount > 0 && pcallCount === 0) {
    recommendation = `ALL ${unpcallCount} remote call(s) are unprotected. Wrap in pcall or pcallRef.`;
  } else if (unpcallCount > 0) {
    recommendation = `${unpcallCount} remote call(s) lack pcall protection. Prioritize wrapping these.`;
  } else if (pcallCount > 0) {
    recommendation = `All remote calls are pcall-wrapped. Callback trace looks clean.`;
  } else {
    recommendation = `No remote calls found in "${query}" execution paths.`;
  }

  return {
    query,
    filePath,
    totalLines,
    anchorsFound: anchors.length,
    anchors,
    paths,
    remotes: remotesFound,
    loops: [...allLoops],
    pcallCoverage,
    recommendation,
  };
}

/**
 * Scan a line range for remotes, loops, pcall wrapping, character guards, and function calls.
 */
function scanBlock(lines, start, end, path, allRemotes, allLoops) {
  const fireRe = /:(FireServer|InvokeServer)\s*\(/g;
  const pcallRe = /\bpcall\s*\(/;
  const pcallRefRe = /\bpcallRef\s*\(/;
  const charGuardRe = /\bCharacter\b.*HumanoidRootPart|HumanoidRootPart.*\bCharacter\b|\bCharacter\s+and\b/;
  const loopRe = /\b(while|for|repeat)\b/;
  const taskSpawnRe = /\btask\.spawn\s*\(/;
  const funcCallRe = /\b([a-zA-Z_]\w*)\s*\(/;

  let inPcall = false;
  let pcallDepth = 0;

  for (let i = start; i < end && i < lines.length; i++) {
    const line = lines[i];

    // Track pcall scope
    if (pcallRe.test(line) || pcallRefRe.test(line)) {
      inPcall = true;
      pcallDepth++;
    }
    if (inPcall) {
      const open = (line.match(/\(/g) || []).length;
      const close = (line.match(/\)/g) || []).length;
      pcallDepth += open - close;
      if (pcallDepth <= 0) {
        inPcall = false;
        pcallDepth = 0;
      }
    }

    // Remote calls
    let m;
    while ((m = fireRe.exec(line)) !== null) {
      // Extract remote name by looking back from the FireServer/InvokeServer
      const prefix = line.substring(0, m.index);
      const nameMatch = prefix.match(/(\w+)\s*:/);
      const remoteName = nameMatch ? nameMatch[1] : 'unknown';
      path.remotes.push(remoteName);
      allRemotes.add(remoteName);
      if (inPcall) {
        path.pcallWrapped++;
      } else {
        path.unpcallRemotes++;
      }
    }

    // Character guards
    if (charGuardRe.test(line)) {
      path.characterGuards++;
    }

    // Loops
    if (loopRe.test(line)) {
      const loopLabel = line.trim().substring(0, 60);
      path.loops.push(loopLabel);
      allLoops.add(loopLabel);
    }

    // task.spawn loops
    if (taskSpawnRe.test(line)) {
      const spawnLabel = line.trim().substring(0, 80);
      path.taskSpawnLoops.push(spawnLabel);
    }

    // Function calls (exclude common builtins)
    const builtin = /^(if|then|else|elseif|end|for|while|do|repeat|until|return|local|function|and|or|not|in|true|false|nil|break|continue|task\.wait|task\.delay|task\.defer|print|warn|error|type|typeof|tostring|tonumber|pcall|xpcall|require|game|workspace|script|Enum|Vector3|CFrame|Ray|UDim2|UDim|Color3|BrickColor|TweenInfo|Instance|math|table|string|coroutine|setmetatable|getmetatable|ipairs|pairs|next|select|unpack|loadstring|gcinfo|newproxy)\s*\(/;
    while ((m = funcCallRe.exec(line)) !== null) {
      const name = m[1];
      if (!builtin.test(name + '(') && name !== line.substring(m.index).split('.')[0]) {
        // Only add if it looks like a user function call (lowercase or CamelCase, not ALLCAPS)
        if (/^[a-zA-Z_]\w*$/.test(name) && name.length > 1 && name.length < 40) {
          path.functionsCalled.push({ name, line: i + 1 });
        }
      }
    }
  }
}

/**
 * Heuristic: find the end of a block starting at the given line.
 * Returns the 0-based line index of the block end, or -1 if not found within range.
 */
function findBlockEnd(lines, startLine) {
  let depth = 0;
  let started = false;
  const maxScan = Math.min(startLine + 300, lines.length);

  for (let i = startLine; i < maxScan; i++) {
    const line = lines[i].replace(/--.*$/, '').trim(); // strip comments
    if (!line) continue;

    // Count block openers
    const openers = line.match(/\b(if|for|while|repeat|do|function|then)\b/g) || [];
    const closers = line.match(/\bend\b/g) || [];

    for (const kw of openers) {
      depth++;
      started = true;
    }
    for (const _kw of closers) {
      depth--;
    }

    if (started && depth <= 0) {
      return i;
    }
  }
  return -1;
}

// ═══════════════════════════════════════════════════════════════════════
// luau.dependency_graph — Build call graph + variable dependency map
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a dependency graph of a Luau script: which functions call which,
 * which functions use which variables, which remotes are shared,
 * and what happens if you remove or modify a function.
 */
export function buildDependencyGraph(text, filePath = '') {
  const lines = text.split('\n');
  const totalLines = lines.length;

  // ── Step 1: Extract all named functions ─────────────────────────────────
  const functions = {};
  const funcDefRe = /(?:local\s+)?function\s+([\w:]+)\s*\(/g;
  const funcAssignRe = /(\w+)\s*=\s*function\s*\(/g;

  for (let i = 0; i < totalLines; i++) {
    const line = lines[i];
    let m;
    while ((m = funcDefRe.exec(line)) !== null) {
      functions[m[1]] = { line: i + 1, calls: [], uses: [], remotes: [], loops: 0, complexity: 0, callers: [] };
    }
    funcAssignRe.lastIndex = 0;
    while ((m = funcAssignRe.exec(line)) !== null) {
      functions[m[1]] = { line: i + 1, calls: [], uses: [], remotes: [], loops: 0, complexity: 0, callers: [] };
    }
  }

  // ── Step 2: For each function, find its body and analyze ────────────────
  const funcNames = Object.keys(functions);
  const callRe = /(\w+)\s*\(/g;
  const remoteRe = /(\w+)\s*:(FireServer|InvokeServer)\s*\(/;
  const loopRe = /\b(while|for)\b/g;
  const builtinSet = new Set(['if','then','else','elseif','end','for','while','do','repeat','until','return','local','function','and','or','not','in','true','false','nil','break','continue','print','warn','error','type','typeof','tostring','tonumber','pcall','xpcall','require','game','workspace','script','Enum','Vector3','CFrame','Ray','UDim2','UDim','Color3','BrickColor','TweenInfo','Instance','math','table','string','coroutine','setmetatable','getmetatable','ipairs','pairs','next','select','unpack','loadstring','gcinfo','newproxy','task','tick','wait']);

  for (const name of funcNames) {
    const fn = functions[name];
    const bodyStart = fn.line; // 1-based
    const bodyEnd = findBlockEnd(lines, bodyStart - 1);
    const scanEnd = bodyEnd > 0 ? bodyEnd : Math.min(bodyStart + 200, totalLines);

    for (let i = bodyStart - 1; i < scanEnd && i < totalLines; i++) {
      const line = lines[i].replace(/--.*$/, '');

      // Function calls
      callRe.lastIndex = 0;
      let m;
      while ((m = callRe.exec(line)) !== null) {
        const called = m[1];
        if (funcNames.includes(called) && called !== name && !builtinSet.has(called)) {
          if (!fn.calls.includes(called)) {
            fn.calls.push(called);
          }
        }
      }

      // Remote usage
      if ((m = line.match(remoteRe)) !== null) {
        const remoteName = m[1];
        if (!fn.remotes.includes(remoteName)) {
          fn.remotes.push(remoteName);
        }
      }

      // Loop count
      loopRe.lastIndex = 0;
      while (loopRe.exec(line) !== null) {
        fn.loops++;
      }

      // Complexity (rough: each branch/loop adds 1)
      const branchRe = /\b(if|elseif|else|for|while|and|or)\b/g;
      while (branchRe.exec(line) !== null) {
        fn.complexity++;
      }
    }
  }

  // ── Step 3: Build reverse call graph (callers) ──────────────────────────
  for (const name of funcNames) {
    for (const called of functions[name].calls) {
      if (functions[called]) {
        if (!functions[called].callers.includes(name)) {
          functions[called].callers.push(name);
        }
      }
    }
  }

  // ── Step 4: Variable dependency analysis ────────────────────────────────
  const variables = {};
  const localVarRe = /local\s+(\w+)\s*=/g;
  const tableVarRe = /local\s+(\w+)\s*=\s*\{/g;
  const varUseRe = /\b(\w+)\b/g;

  for (const name of funcNames) {
    const fn = functions[name];
    const bodyStart = fn.line;
    const bodyEnd = findBlockEnd(lines, bodyStart - 1);
    const scanEnd = bodyEnd > 0 ? bodyEnd : Math.min(bodyStart + 200, totalLines);

    for (let i = bodyStart - 1; i < scanEnd && i < totalLines; i++) {
      const line = lines[i].replace(/--.*$/, '');

      // Local var definitions
      let m;
      while ((m = localVarRe.exec(line)) !== null) {
        const varName = m[1];
        if (!builtinSet.has(varName)) {
          variables[varName] = variables[varName] || { definedAt: i + 1, usedBy: [], writtenBy: [] };
          if (!variables[varName].usedBy.includes(name)) {
            variables[varName].usedBy.push(name);
          }
          if (!variables[varName].writtenBy.includes(name)) {
            variables[varName].writtenBy.push(name);
          }
        }
      }

      // Variable usage (skip the function's own name and builtins)
      varUseRe.lastIndex = 0;
      while ((m = varUseRe.exec(line)) !== null) {
        const varName = m[1];
        if (variables[varName] && !builtinSet.has(varName) && varName !== name) {
          if (!variables[varName].usedBy.includes(name)) {
            variables[varName].usedBy.push(name);
          }
        }
      }
    }
  }

  // ── Step 5: Shared remote analysis ──────────────────────────────────────
  const remoteSharing = {};
  for (const name of funcNames) {
    for (const remote of functions[name].remotes) {
      if (!remoteSharing[remote]) remoteSharing[remote] = [];
      remoteSharing[remote].push(name);
    }
  }

  // ── Step 6: Impact analysis — what breaks if you modify a function ──────
  const impactAnalysis = {};
  for (const name of funcNames) {
    const fn = functions[name];
    const transitiveCallers = new Set(fn.callers);

    // BFS up the caller tree
    const queue = [...fn.callers];
    while (queue.length > 0) {
      const current = queue.shift();
      for (const caller of (functions[current]?.callers || [])) {
        if (!transitiveCallers.has(caller)) {
          transitiveCallers.add(caller);
          queue.push(caller);
        }
      }
    }

    impactAnalysis[name] = {
      directCallers: fn.callers,
      transitiveCallers: [...transitiveCallers],
      sharedRemotes: fn.remotes.filter(r => (remoteSharing[r] || []).length > 1),
      riskLevel: transitiveCallers.size > 3 ? 'high' : transitiveCallers.size > 1 ? 'medium' : 'low',
    };
  }

  // ── Build report ────────────────────────────────────────────────────────
  const functionList = funcNames.map(name => ({
    name,
    line: functions[name].line,
    calls: functions[name].calls,
    callers: functions[name].callers,
    remotes: functions[name].remotes,
    loops: functions[name].loops,
    complexity: functions[name].complexity,
  }));

  const variableList = Object.keys(variables).map(name => ({
    name,
    definedAt: variables[name].definedAt,
    usedBy: variables[name].usedBy,
    writtenBy: variables[name].writtenBy,
    sharedAcross: variables[name].usedBy.length > 1 ? variables[name].usedBy : null,
  }));

  const sharedRemoteList = Object.keys(remoteSharing).map(remote => ({
    remote,
    functions: remoteSharing[remote],
  }));

  const highRiskFunctions = funcNames.filter(n => impactAnalysis[n].riskLevel === 'high');

  return {
    filePath,
    totalLines,
    totalFunctions: funcNames.length,
    totalVariables: Object.keys(variables).length,
    functions: functionList,
    variables: variableList,
    sharedRemotes: sharedRemoteList,
    impactAnalysis,
    highRiskFunctions,
    summary: {
      mostCalledFunction: funcNames.reduce((best, n) =>
        (!best || functions[n].callers.length > functions[best].callers.length) ? n : best, null),
      mostCallingFunction: funcNames.reduce((best, n) =>
        (!best || functions[n].calls.length > functions[best].calls.length) ? n : best, null),
      mostSharedRemote: Object.keys(remoteSharing).reduce((best, r) =>
        (!best || remoteSharing[r].length > remoteSharing[best].length) ? r : best, null),
      highRiskCount: highRiskFunctions.length,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// luau.event_map — Map all event connections with lifecycle analysis
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract ALL event connections in a Luau script: which object, which event,
 * which callback, whether it uses :Connect() or :Once(), whether it gets
 * disconnected, and identify orphaned connections (memory leak risk).
 */
export function buildEventMap(text, filePath = '') {
  const lines = text.split('\n');
  const totalLines = lines.length;

  // ── Step 1: Find all :Connect() and :Once() calls ──────────────────────
  const connectRe = /(\w+)\s*:\s*(Connect|Once)\s*\(\s*([\w.]+)/g;
  const connectInlineRe = /(\w+)\s*:\s*(Connect|Once)\s*\(\s*function\s*\(/g;
  const disconnectRe = /(\w+)\s*:\s*Disconnect\s*\(\s*\)/g;
  const taskSpawnConnectRe = /task\.spawn\s*\(\s*(\w+)/g;

  const connections = [];
  const disconnects = [];
  const connectionVariables = {}; // tracks which var holds the connection

  for (let i = 0; i < totalLines; i++) {
    const line = lines[i];

    // Named callback connections: Player.CharacterAdded:Connect(onCharacterAdded)
    let m;
    while ((m = connectRe.exec(line)) !== null) {
      const [, source, method, callback] = m;
      connections.push({
        line: i + 1,
        source,
        event: callback.includes('.') ? callback.split('.')[1] : 'Unknown',
        sourceObject: source,
        callback,
        method,
        isNamed: true,
        isInline: false,
      });
    }

    // Inline function connections: Player.CharacterAdded:Connect(function()
    connectInlineRe.lastIndex = 0;
    while ((m = connectInlineRe.exec(line)) !== null) {
      const [, source, method] = m;
      connections.push({
        line: i + 1,
        source,
        event: 'Unknown',
        sourceObject: source,
        callback: '(inline function)',
        method,
        isNamed: false,
        isInline: true,
      });
    }

    // Disconnections: connection:Disconnect()
    disconnectRe.lastIndex = 0;
    while ((m = disconnectRe.exec(line)) !== null) {
      disconnects.push({ line: i + 1, name: m[1] });
    }

    // task.spawn wrapping: task.spawn(someFunction)
    taskSpawnConnectRe.lastIndex = 0;
    while ((m = taskSpawnConnectRe.exec(line)) !== null) {
      // This is a taskSpawn call, not a disconnect — skip for now
    }
  }

  // ── Step 2: Track connection variables ──────────────────────────────────
  // Look for patterns like: local conn = Something:Connect(...)
  const connAssignRe = /local\s+(\w+)\s*=\s*(\w+)\s*:\s*(Connect|Once)\s*\(/g;
  const connAssignRe2 = /(\w+)\s*=\s*(\w+)\s*:\s*(Connect|Once)\s*\(/g;

  for (let i = 0; i < totalLines; i++) {
    const line = lines[i];
    let m;
    connAssignRe.lastIndex = 0;
    while ((m = connAssignRe.exec(line)) !== null) {
      const [, varName, source, method] = m;
      connectionVariables[varName] = { assignedAt: i + 1, source, method };
    }
    // Also catch non-local assignments
    connAssignRe2.lastIndex = 0;
    while ((m = connAssignRe2.exec(line)) !== null) {
      const [, varName, source, method] = m;
      if (!connectionVariables[varName]) {
        connectionVariables[varName] = { assignedAt: i + 1, source, method };
      }
    }
  }

  // ── Step 3: Classify events by type ─────────────────────────────────────
  const eventTypes = {
    character: ['CharacterAdded', 'CharacterRemoving', 'CharacterAppearanceLoaded'],
    input: ['InputBegan', 'InputEnded', 'InputChanged', 'MouseButton1Click', 'MouseButton1Down'],
    remote: ['OnServerEvent', 'OnClientEvent', 'OnServerInvoke', 'OnClientInvoke'],
    loop: ['Heartbeat', 'RenderStepped', 'Stepped'],
    property: ['GetPropertyChangedSignal', 'Changed'],
    workspace: ['ChildAdded', 'ChildRemoved', 'DescendantAdded', 'DescendantRemoving'],
    player: ['PlayerAdded', 'PlayerRemoving', 'OnPlayerEvent'],
  };

  for (const conn of connections) {
    conn.classifiedAs = 'unknown';
    for (const [category, events] of Object.entries(eventTypes)) {
      if (events.some(e => conn.event.includes(e) || conn.callback.includes(e))) {
        conn.classifiedAs = category;
        break;
      }
    }
    // Also check source object name for hints
    if (conn.classifiedAs === 'unknown') {
      const src = conn.sourceObject.toLowerCase();
      if (src.includes('player')) conn.classifiedAs = 'player';
      else if (src.includes('character')) conn.classifiedAs = 'character';
      else if (src.includes('remote') || src.includes('event') || src.includes('function')) conn.classifiedAs = 'remote';
      else if (src.includes('heartbeat') || src.includes('render') || src.includes('stepped')) conn.classifiedAs = 'loop';
      else if (src.includes('button') || src.includes('input') || src.includes('mouse')) conn.classifiedAs = 'input';
      else if (src.includes('changed') || src.includes('property')) conn.classifiedAs = 'property';
    }
  }

  // ── Step 4: Detect orphaned connections (no Disconnect) ────────────────
  const disconnectNames = new Set(disconnects.map(d => d.name));
  const orphanedConnections = [];

  // Check assigned variables that are never disconnected
  for (const [varName, info] of Object.entries(connectionVariables)) {
    if (!disconnectNames.has(varName)) {
      orphanedConnections.push({
        variable: varName,
        assignedAt: info.assignedAt,
        source: info.source,
        method: info.method,
        risk: 'high',
      });
    }
  }

  // Also flag named callbacks that appear to be connection targets but have no cleanup
  const callbackNames = connections.filter(c => c.isNamed).map(c => c.callback);
  const callbackCleanupRe = new RegExp(`(${callbackNames.map(escapeRegex).join('|')})\\s*:\\s*Disconnect`, 'g');

  for (const conn of connections.filter(c => c.isNamed)) {
    const fullText = text;
    const hasDisconnect = fullText.includes(`${conn.callback}:Disconnect`) ||
                          fullText.includes(`${conn.callback} :Disconnect`) ||
                          disconnects.some(d => d.name === conn.callback);
    if (!hasDisconnect && conn.classifiedAs !== 'character') {
      // Character callbacks are expected to persist, but loop/input/property should clean up
      if (['loop', 'input', 'property', 'remote'].includes(conn.classifiedAs)) {
        orphanedConnections.push({
          callback: conn.callback,
          connectedAt: conn.line,
          source: conn.sourceObject,
          event: conn.event,
          classifiedAs: conn.classifiedAs,
          risk: conn.classifiedAs === 'loop' ? 'high' : 'medium',
        });
      }
    }
  }

  // ── Step 5: Build summary ──────────────────────────────────────────────
  const byCategory = {};
  for (const conn of connections) {
    const cat = conn.classifiedAs;
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push({
      line: conn.line,
      source: conn.sourceObject,
      event: conn.event,
      callback: conn.callback,
      method: conn.method,
    });
  }

  const orphanedByRisk = { high: 0, medium: 0, low: 0 };
  for (const o of orphanedConnections) {
    orphanedByRisk[o.risk] = (orphanedByRisk[o.risk] || 0) + 1;
  }

  let recommendation;
  if (orphanedConnections.length === 0) {
    recommendation = `All ${connections.length} connection(s) have proper cleanup. No orphaned connections detected.`;
  } else {
    const highRisk = orphanedConnections.filter(o => o.risk === 'high');
    const mediumRisk = orphanedConnections.filter(o => o.risk === 'medium');
    recommendation = `${orphanedConnections.length} connection(s) lack Disconnect cleanup: ${highRisk.length} high-risk (loop/remote), ${mediumRisk.length} medium-risk. Memory leak risk.`;
  }

  return {
    filePath,
    totalLines,
    totalConnections: connections.length,
    totalDisconnections: disconnects.length,
    totalOrphaned: orphanedConnections.length,
    connections: connections.map(c => ({
      line: c.line,
      source: c.sourceObject,
      event: c.event,
      callback: c.callback,
      method: c.method,
      isNamed: c.isNamed,
      isInline: c.isInline,
      classifiedAs: c.classifiedAs,
    })),
    disconnections: disconnects,
    orphanedConnections,
    byCategory,
    orphanedByRisk,
    recommendation,
  };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
