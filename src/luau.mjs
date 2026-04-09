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
