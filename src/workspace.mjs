import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { analyzeLuauText, hotfixLuauText, scanLuauWorkspace, scanLuauSecurity } from './luau.mjs';
import { readText, relative, toPosix, walkFiles, writeText } from './fs.mjs';

const LUAU_EXTENSIONS = new Set(['.lua', '.luau']);

function hashText(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function safeFileStem(filePath) {
  return toPosix(String(filePath || 'workspace')).replace(/[^\w.-]+/g, '_') || 'workspace';
}

function targetLabel(root, targetPath) {
  if (!targetPath) {
    return 'workspace';
  }
  return toPosix(path.relative(root, targetPath) || targetPath).replace(/\/+/g, '/');
}

function listScriptFiles(root, targetPath = '') {
  const resolvedTarget = targetPath ? (path.isAbsolute(targetPath) ? targetPath : path.resolve(root, targetPath)) : root;
  if (fs.existsSync(resolvedTarget) && fs.statSync(resolvedTarget).isFile()) {
    return [resolvedTarget];
  }

  const base = fs.existsSync(resolvedTarget) ? resolvedTarget : root;
  return walkFiles(base, (filePath) => LUAU_EXTENSIONS.has(path.extname(filePath).toLowerCase()));
}

function snapshotEntry(root, filePath) {
  const text = readText(filePath);
  const analysis = analyzeLuauText(text, filePath);
  return {
    path: toPosix(relative(root, filePath)),
    hash: hashText(text),
    byteCount: Buffer.byteLength(text, 'utf8'),
    lineCount: analysis.summary.lineCount,
    callbacks: analysis.summary.callbackCount,
    remotes: analysis.summary.remoteCount,
    risks: analysis.summary.riskCount,
  };
}

function readBaselineFile(baselinePath) {
  if (!baselinePath || !fs.existsSync(baselinePath)) {
    return null;
  }
  try {
    return JSON.parse(readText(baselinePath));
  } catch {
    return null;
  }
}

function compareEntries(currentEntries, baselineEntries) {
  const baselineByPath = new Map((baselineEntries || []).map((entry) => [entry.path, entry]));
  const currentByPath = new Map(currentEntries.map((entry) => [entry.path, entry]));
  const added = [];
  const removed = [];
  const modified = [];

  for (const entry of currentEntries) {
    const baseline = baselineByPath.get(entry.path);
    if (!baseline) {
      added.push(entry);
      continue;
    }
    if (baseline.hash !== entry.hash) {
      modified.push({
        path: entry.path,
        beforeHash: baseline.hash,
        afterHash: entry.hash,
        lineDelta: entry.lineCount - baseline.lineCount,
        riskDelta: entry.risks - baseline.risks,
      });
    }
  }

  for (const entry of baselineEntries || []) {
    if (!currentByPath.has(entry.path)) {
      removed.push(entry);
    }
  }

  return { added, removed, modified };
}

function readWorkspaceSnapshot(snapshotPath) {
  if (!snapshotPath || !fs.existsSync(snapshotPath)) {
    return null;
  }
  try {
    return JSON.parse(readText(snapshotPath));
  } catch {
    return null;
  }
}

function restoreSingleFileFromSnapshot(root, snapshot, targetPath) {
  const resolvedTarget = targetPath ? (path.isAbsolute(targetPath) ? targetPath : path.resolve(root, targetPath)) : '';
  const filePath = resolvedTarget || (snapshot?.filePath ? (path.isAbsolute(snapshot.filePath) ? snapshot.filePath : path.resolve(root, snapshot.filePath)) : '');
  const content = snapshot?.content || snapshot?.before || snapshot?.report?.before || '';
  if (!filePath || !content) {
    return { ok: false, error: 'Snapshot does not contain restorable file content.' };
  }
  writeText(filePath, `${String(content).trimEnd()}\n`);
  return {
    ok: true,
    filePath: toPosix(path.relative(root, filePath) || filePath),
  };
}

export function captureWorkspaceBaseline(root, { targetPath = '', outputPath = '', label = '' } = {}) {
  const scripts = listScriptFiles(root, targetPath);
  const entries = scripts.map((filePath) => snapshotEntry(root, filePath));
  const baseline = {
    kind: 'helper-mcp-workspace-baseline',
    generatedAt: new Date().toISOString(),
    workspaceRoot: root,
    target: targetLabel(root, targetPath),
    label: String(label || '').trim(),
    entryCount: entries.length,
    entries,
  };

  const baselineDir = path.join(root, '.helper-mcp', 'baselines');
  fs.mkdirSync(baselineDir, { recursive: true });
  const resolvedOutput = outputPath
    ? (path.isAbsolute(outputPath) ? outputPath : path.join(root, outputPath))
    : path.join(baselineDir, `${safeFileStem(targetPath || 'workspace')}.json`);
  writeText(resolvedOutput, `${JSON.stringify(baseline, null, 2)}\n`);
  return {
    path: toPosix(path.relative(root, resolvedOutput) || resolvedOutput),
    baseline,
  };
}

export function compareWorkspaceBaseline(root, baselinePath, { targetPath = '' } = {}) {
  const baseline = readBaselineFile(path.isAbsolute(baselinePath) ? baselinePath : path.join(root, baselinePath));
  const scripts = listScriptFiles(root, targetPath);
  const currentEntries = scripts.map((filePath) => snapshotEntry(root, filePath));
  const baselineEntries = baseline?.entries || [];
  const diff = compareEntries(currentEntries, baselineEntries);
  return {
    baselinePath: baseline ? (baselinePath.startsWith(root) ? toPosix(path.relative(root, baselinePath) || baselinePath) : toPosix(baselinePath)) : toPosix(baselinePath),
    target: baseline?.target || targetLabel(root, targetPath),
    currentCount: currentEntries.length,
    baselineCount: baselineEntries.length,
    currentEntries,
    baselineEntries,
    diff,
    baseline,
  };
}

export function generateWorkspaceChangelog(root, baselinePath, { targetPath = '', title = 'Workspace changelog' } = {}) {
  const comparison = compareWorkspaceBaseline(root, baselinePath, { targetPath });
  const lines = [];
  lines.push(`# ${title}`);
  lines.push('');
  lines.push(`Workspace: ${toPosix(root)}`);
  lines.push(`Target: ${comparison.target}`);
  lines.push(`Baseline: ${comparison.baselinePath}`);
  lines.push('');
  lines.push(`Added: ${comparison.diff.added.length}`);
  lines.push(`Removed: ${comparison.diff.removed.length}`);
  lines.push(`Modified: ${comparison.diff.modified.length}`);
  lines.push('');

  if (comparison.diff.added.length > 0) {
    lines.push('## Added');
    for (const entry of comparison.diff.added) {
      lines.push(`- ${entry.path} (${entry.lineCount} lines, ${entry.risks} risk refs)`);
    }
    lines.push('');
  }

  if (comparison.diff.modified.length > 0) {
    lines.push('## Modified');
    for (const entry of comparison.diff.modified) {
      lines.push(`- ${entry.path} (lines ${entry.lineDelta >= 0 ? '+' : ''}${entry.lineDelta}, risks ${entry.riskDelta >= 0 ? '+' : ''}${entry.riskDelta})`);
    }
    lines.push('');
  }

  if (comparison.diff.removed.length > 0) {
    lines.push('## Removed');
    for (const entry of comparison.diff.removed) {
      lines.push(`- ${entry.path}`);
    }
    lines.push('');
  }

  const changelogDir = path.join(root, '.helper-mcp', 'changelog');
  fs.mkdirSync(changelogDir, { recursive: true });
  const changelogPath = path.join(changelogDir, `${safeFileStem(targetPath || baselinePath)}.md`);
  const markdown = `${lines.join('\n').trimEnd()}\n`;
  writeText(changelogPath, markdown);

  return {
    path: toPosix(path.relative(root, changelogPath) || changelogPath),
    markdown,
    comparison,
  };
}

export function writeWorkspaceArtifact(root, subdir, filename, payload) {
  const dir = path.join(root, '.helper-mcp', subdir);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, filename);
  writeText(filePath, `${JSON.stringify(payload, null, 2)}\n`);
  return toPosix(path.relative(root, filePath) || filePath);
}

export function hotfixWorkspaceFile(root, filePath, options = {}) {
  const resolved = path.isAbsolute(filePath) ? filePath : path.resolve(root, filePath);
  const before = readText(resolved);
  const report = hotfixLuauText(before, resolved, options);
  if (options.apply !== false && report.summary.changed) {
    writeText(resolved, `${report.after.trimEnd()}\n`);
  }
  const snapshotPath = writeWorkspaceArtifact(root, 'hotfixes', `${safeFileStem(filePath)}.json`, {
    kind: 'helper-mcp-hotfix',
    generatedAt: new Date().toISOString(),
    filePath: toPosix(path.relative(root, resolved) || resolved),
    report,
  });
  return {
    snapshotPath,
    report,
  };
}

export function diffWorkspaceState(root, { baselinePath = '', targetPath = '' } = {}) {
  if (!baselinePath) {
    return { ok: false, error: 'baselinePath is required.' };
  }
  const comparison = compareWorkspaceBaseline(root, baselinePath, { targetPath });
  return {
    ok: true,
    comparison,
    markdown: generateWorkspaceChangelog(root, baselinePath, { targetPath, title: 'Workspace diff' }).markdown,
  };
}

export function rollbackWorkspaceSnapshot(root, { snapshotPath = '', targetPath = '', apply = true } = {}) {
  const snapshot = readWorkspaceSnapshot(path.isAbsolute(snapshotPath) ? snapshotPath : path.resolve(root, snapshotPath));
  if (!snapshot) {
    return { ok: false, error: `Snapshot not found or invalid: ${snapshotPath}` };
  }
  if (!apply) {
    return { ok: true, mode: 'dry-run', snapshotPath: toPosix(snapshotPath), snapshot };
  }
  if (snapshot.filePath || snapshot.content || snapshot.before || snapshot.report?.before) {
    return restoreSingleFileFromSnapshot(root, snapshot, targetPath);
  }
  return { ok: false, error: 'Snapshot does not include file content to restore.' };
}

export function validateWorkspaceRelease(root, { baselinePath = '', targetPath = '' } = {}) {
  if (!baselinePath) {
    return { ok: false, error: 'baselinePath is required.' };
  }
  const comparison = compareWorkspaceBaseline(root, baselinePath, { targetPath });
  const currentRisks = comparison.currentEntries.reduce((sum, entry) => sum + entry.risks, 0);
  const baselineRisks = comparison.baselineEntries.reduce((sum, entry) => sum + entry.risks, 0);
  const valid = comparison.diff.removed.length === 0 && comparison.diff.modified.length === 0 && comparison.diff.added.length === 0;
  return {
    ok: true,
    valid,
    summary: {
      currentCount: comparison.currentCount,
      baselineCount: comparison.baselineCount,
      currentRisks,
      baselineRisks,
      riskDelta: currentRisks - baselineRisks,
      added: comparison.diff.added.length,
      removed: comparison.diff.removed.length,
      modified: comparison.diff.modified.length,
    },
    comparison,
  };
}

export function generateWorkspaceReleaseNotes(root, { baselinePath = '', targetPath = '', title = 'Workspace release notes' } = {}) {
  if (!baselinePath) {
    return { ok: false, error: 'baselinePath is required.' };
  }
  const changelog = generateWorkspaceChangelog(root, baselinePath, { targetPath, title });
  const notes = [
    changelog.markdown.trimEnd(),
    '',
    `Release target: ${targetLabel(root, targetPath)}`,
    `Artifact: ${changelog.path}`,
    '',
  ].join('\n');
  return {
    ok: true,
    path: changelog.path,
    markdown: `${notes.trimEnd()}\n`,
    comparison: changelog.comparison,
  };
}

export function restoreWorkspaceSnapshot(root, { snapshotPath = '', targetPath = '', apply = true } = {}) {
  return rollbackWorkspaceSnapshot(root, { snapshotPath, targetPath, apply });
}

// ── Delivery Gate ───────────────────────────────────────────────────────────

function checkBaselineParity(root, options) {
  const { baselinePath, requireBaseline } = options;
  if (!baselinePath) {
    const detail = requireBaseline
      ? 'requireBaseline is true but no baselinePath was provided.'
      : 'No baseline provided; parity check skipped.';
    return {
      check: 'baseline-parity',
      pass: !requireBaseline,
      severity: requireBaseline ? 'blocker' : 'warning',
      detail,
    };
  }
  const resolvedBaseline = path.isAbsolute(baselinePath) ? baselinePath : path.join(root, baselinePath);
  if (!fs.existsSync(resolvedBaseline)) {
    return {
      check: 'baseline-parity',
      pass: !requireBaseline,
      severity: requireBaseline ? 'blocker' : 'warning',
      detail: `Baseline file not found: ${toPosix(baselinePath)}`,
    };
  }
  const comparison = compareWorkspaceBaseline(root, baselinePath, options);
  const { added, removed, modified } = comparison.diff;
  const hasChanges = added.length > 0 || removed.length > 0 || modified.length > 0;
  const detailParts = [`added: ${added.length}`, `removed: ${removed.length}`, `modified: ${modified.length}`];
  if (hasChanges) {
    detailParts.push('baseline parity changed');
  } else {
    detailParts.push('no parity changes');
  }
  return {
    check: 'baseline-parity',
    pass: !hasChanges,
    severity: requireBaseline ? 'blocker' : 'warning',
    detail: detailParts.join('; '),
  };
}

function checkRiskThreshold(scan, options) {
  const { maxNewRisks = 3 } = options;
  const totalRisks = scan.totalRisks || 0;
  const pass = totalRisks <= maxNewRisks;
  return {
    check: 'risk-threshold',
    pass,
    severity: 'blocker',
    detail: `Total risks: ${totalRisks} (max allowed: ${maxNewRisks})`,
  };
}

function checkRiskDelta(root, options) {
  const { baselinePath, maxRiskDelta = 5 } = options;
  if (!baselinePath) {
    return {
      check: 'risk-delta',
      pass: true,
      severity: 'warning',
      detail: 'No baseline provided; risk delta check skipped.',
    };
  }
  const resolvedBaseline = path.isAbsolute(baselinePath) ? baselinePath : path.join(root, baselinePath);
  if (!fs.existsSync(resolvedBaseline)) {
    return {
      check: 'risk-delta',
      pass: true,
      severity: 'warning',
      detail: `Baseline file not found: ${toPosix(baselinePath)}`,
    };
  }
  const comparison = compareWorkspaceBaseline(root, baselinePath, options);
  const currentRisks = comparison.currentEntries.reduce((sum, e) => sum + e.risks, 0);
  const baselineRisks = comparison.baselineEntries.reduce((sum, e) => sum + e.risks, 0);
  const delta = currentRisks - baselineRisks;
  const pass = delta <= maxRiskDelta;
  return {
    check: 'risk-delta',
    pass,
    severity: 'warning',
    detail: `Risk delta: ${delta} (current: ${currentRisks}, baseline: ${baselineRisks}, max allowed: ${maxRiskDelta})`,
  };
}

function checkPcallCoverage(scan, options) {
  const { minPcallCoverage = 80 } = options;
  let totalCalls = 0;
  let pcallCalls = 0;
  for (const file of scan.files || []) {
    const risks = file.summary?.risks || file.risks || 0;
    const callbacks = file.summary?.callbackCount || file.callbacks || 0;
    totalCalls += callbacks;
    // Count pcall-wrapped callbacks from risk analysis
    const pcallRefs = (file.summary?.pcallCount ?? 0) + (file.summary?.xpcallCount ?? 0);
    pcallCalls += pcallRefs;
  }
  // If we can't determine pcall count precisely, use risk analysis as proxy
  let coverage;
  if (totalCalls === 0) {
    coverage = 100;
  } else {
    // Estimate: risks that are NOT pcall-wrapped
    const unprotectedRisks = scan.totalRisks || 0;
    const protectedCalls = Math.max(0, totalCalls - unprotectedRisks);
    coverage = Math.round((protectedCalls / totalCalls) * 100);
    coverage = Math.min(100, Math.max(0, coverage));
  }
  const pass = coverage >= minPcallCoverage;
  return {
    check: 'pcall-coverage',
    pass,
    severity: 'blocker',
    detail: `Pcall coverage: ${coverage}% (minimum: ${minPcallCoverage}%)`,
  };
}

function checkLocalPressure(scan) {
  const warnings = [];
  for (const file of scan.files || []) {
    const localCount = file.summary?.localCount ?? file.locals ?? 0;
    if (localCount > 180) {
      warnings.push(`${file.filePath}: ${localCount} locals`);
    }
  }
  const pass = warnings.length === 0;
  return {
    check: 'local-pressure',
    pass,
    severity: 'warning',
    detail: pass
      ? 'All files within local variable pressure limits (<=180).'
      : `High local pressure in ${warnings.length} file(s): ${warnings.join('; ')}`,
  };
}

function checkOrphanedConnections(scan) {
  const orphaned = [];
  for (const file of scan.files || []) {
    const filePath = file.filePath;
    const text = readText(path.isAbsolute(filePath) ? filePath : path.join(scan.root || '', filePath));
    const connectCount = (text.match(/\bConnect\s*\(/g) || []).length;
    const disconnectCount = (text.match(/\bDisconnect\s*\(/g) || []).length;
    const destroyCount = (text.match(/\bDestroy\s*\(/g) || []).length;
    const cleanupCount = disconnectCount + destroyCount;
    if (connectCount > 0 && cleanupCount === 0) {
      orphaned.push(`${file.filePath}: ${connectCount} Connect() without Disconnect()/Destroy()`);
    }
  }
  const pass = orphaned.length === 0;
  return {
    check: 'orphaned-connections',
    pass,
    severity: 'warning',
    detail: pass
      ? 'All connections have cleanup patterns.'
      : `Potential orphaned connections in ${orphaned.length} file(s): ${orphaned.join('; ')}`,
  };
}

async function checkBrainCoverage(root, options) {
  const { targetPath } = options;
  let brainNotes;
  try {
    const { listBrainNotes } = await import('./brain.mjs');
    brainNotes = listBrainNotes(root, { limit: 500 });
  } catch {
    brainNotes = [];
  }
  const luauScan = scanLuauWorkspace(targetPath || root);
  const scannedPaths = new Set((luauScan.files || []).map((f) => f.filePath));
  const brainPaths = new Set(
    (brainNotes || [])
      .filter((n) => n.filePath)
      .map((n) => n.filePath)
  );
  let covered = 0;
  for (const p of scannedPaths) {
    for (const bp of brainPaths) {
      if (p.includes(bp) || bp.includes(p)) {
        covered++;
        break;
      }
    }
  }
  const total = scannedPaths.size || 1;
  const coverage = Math.round((covered / total) * 100);
  return {
    check: 'brain-coverage',
    pass: true,
    severity: 'info',
    detail: `Brain coverage: ${coverage}% (${covered}/${total} scanned files have brain notes)`,
    brainCoverage: coverage,
  };
}

function checkDeprecatedApi(scan) {
  const deprecated = [];
  const deprecatedPatterns = [
    { label: 'wait()', re: /(?<!task\.)\bwait\s*\(/ },
    { label: 'spawn()', re: /(?<!task\.)\bspawn\s*\(/ },
    { label: 'delay()', re: /(?<!task\.)\bdelay\s*\(/ },
  ];
  for (const file of scan.files || []) {
    const filePath = file.filePath;
    const text = readText(path.isAbsolute(filePath) ? filePath : path.join(scan.root || '', filePath));
    const lines = text.split(/\r?\n/);
    for (const pattern of deprecatedPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.re.test(lines[i])) {
          deprecated.push(`${file.filePath}:${i + 1} uses deprecated ${pattern.label}`);
        }
      }
    }
  }
  const pass = deprecated.length === 0;
  return {
    check: 'deprecated-api',
    pass,
    severity: 'blocker',
    detail: pass
      ? 'No deprecated API usage found.'
      : `Deprecated API usage in ${deprecated.length} location(s): ${deprecated.slice(0, 5).join('; ')}${deprecated.length > 5 ? '...' : ''}`,
  };
}

function checkSecurityFindings(scan) {
  const highFindings = [];
  for (const file of scan.files || []) {
    const filePath = file.filePath;
    const text = readText(path.isAbsolute(filePath) ? filePath : path.join(scan.root || '', filePath));
    const security = scanLuauSecurity(text, filePath);
    for (const finding of security.findings || []) {
      if (finding.severity === 'high') {
        highFindings.push(`${file.filePath}:${finding.line} [${finding.label}] ${finding.text}`);
      }
    }
  }
  const pass = highFindings.length === 0;
  return {
    check: 'security-findings',
    pass,
    severity: 'blocker',
    detail: pass
      ? 'No high-severity security findings.'
      : `High-severity findings: ${highFindings.length} — ${highFindings.slice(0, 3).join('; ')}${highFindings.length > 3 ? '...' : ''}`,
  };
}

export async function gateWorkspace(root, options = {}) {
  const {
    baselinePath,
    targetPath,
    maxRiskDelta = 5,
    minPcallCoverage = 80,
    maxNewRisks = 3,
    requireBaseline = false,
    checks,
  } = options;

  const resolvedTarget = targetPath
    ? (path.isAbsolute(targetPath) ? targetPath : path.resolve(root, targetPath))
    : root;

  const scan = scanLuauWorkspace(resolvedTarget);
  scan.root = resolvedTarget;

  const checkFns = {
    'baseline-parity': () => checkBaselineParity(root, { baselinePath, requireBaseline, targetPath }),
    'risk-threshold': () => checkRiskThreshold(scan, { maxNewRisks }),
    'risk-delta': () => checkRiskDelta(root, { baselinePath, maxRiskDelta, targetPath }),
    'pcall-coverage': () => checkPcallCoverage(scan, { minPcallCoverage }),
    'local-pressure': () => checkLocalPressure(scan),
    'orphaned-connections': () => checkOrphanedConnections(scan),
    'brain-coverage': () => checkBrainCoverage(root, { targetPath }),
    'deprecated-api': () => checkDeprecatedApi(scan),
    'security-findings': () => checkSecurityFindings(scan),
  };

  const activeChecks = checks && checks.length > 0 ? checks : Object.keys(checkFns);
  const results = [];

  for (const checkName of activeChecks) {
    const fn = checkFns[checkName];
    if (!fn) {
      results.push({
        check: checkName,
        pass: false,
        severity: 'warning',
        detail: `Unknown check: ${checkName}`,
      });
      continue;
    }
    const result = await fn();
    results.push(result);
  }

  const blockers = results.filter((r) => r.severity === 'blocker' && !r.pass).map((r) => r.check);
  const warnings = results.filter((r) => r.severity === 'warning' && !r.pass).map((r) => r.check);
  const passed = results.filter((r) => r.pass).length;
  const infoOnly = results.filter((r) => r.severity === 'info').length;

  let verdict;
  let recommendation;
  if (blockers.length > 0) {
    verdict = 'BLOCKED';
    recommendation = 'Fix blockers before delivery';
  } else if (warnings.length > 0) {
    verdict = 'REVIEW';
    recommendation = 'Review warnings';
  } else {
    verdict = 'PASS';
    recommendation = 'Ready for delivery';
  }

  // Gather brain coverage from results
  const brainResult = results.find((r) => r.check === 'brain-coverage');
  const brainCoverage = brainResult?.brainCoverage ?? 0;

  return {
    verdict,
    summary: {
      totalChecks: results.length,
      passed,
      warnings: warnings.length,
      blockers: blockers.length,
      infoOnly,
    },
    checks: results,
    blockers,
    warnings,
    workspace: {
      totalFiles: scan.totalFiles,
      totalRisks: scan.totalRisks,
      totalCallbacks: scan.totalCallbacks,
      totalRemotes: scan.totalRemotes,
      brainCoverage,
    },
    recommendation,
  };
}

// ── Workspace Clone ─────────────────────────────────────────────────────────

export function cloneWorkspace(root, options = {}) {
  const {
    targetDir,
    includeBrain = true,
    includeBaselines = true,
    includeMetrics = true,
    fileFilter,
    luauOnly = false,
  } = options;

  if (!targetDir) {
    return { ok: false, error: 'targetDir is required.' };
  }

  const resolvedRoot = path.isAbsolute(root) ? root : path.resolve(root);
  const resolvedTarget = path.isAbsolute(targetDir) ? targetDir : path.resolve(targetDir);

  const filesCopied = [];
  const dirsCreated = new Set();
  let totalBytes = 0;

  function copyFile(src, dst) {
    const dstDir = path.dirname(dst);
    if (!dirsCreated.has(dstDir)) {
      fs.mkdirSync(dstDir, { recursive: true });
      dirsCreated.add(dstDir);
    }
    const content = fs.readFileSync(src);
    fs.writeFileSync(dst, content);
    totalBytes += content.length;
    filesCopied.push(toPosix(relative(resolvedRoot, src) || src));
  }

  try {
    // Step 1: Create target directory
    if (!dirsCreated.has(resolvedTarget)) {
      fs.mkdirSync(resolvedTarget, { recursive: true });
      dirsCreated.add(resolvedTarget);
    }

    // Step 2-4: Copy workspace files
    if (luauOnly) {
      const luauFiles = walkFiles(resolvedRoot, (filePath) => {
        const ext = path.extname(filePath).toLowerCase();
        return ext === '.lua' || ext === '.luau';
      });
      for (const file of luauFiles) {
        const rel = toPosix(relative(resolvedRoot, file));
        copyFile(file, path.join(resolvedTarget, rel));
      }
    } else if (fileFilter) {
      // Use walkFiles with a custom filter that matches the glob-like pattern
      const allFiles = walkFiles(resolvedRoot);
      const filterRe = globToRegex(fileFilter);
      const matched = allFiles.filter((f) => {
        const rel = toPosix(relative(resolvedRoot, f));
        return filterRe.test(rel);
      });
      for (const file of matched) {
        const rel = toPosix(relative(resolvedRoot, file));
        copyFile(file, path.join(resolvedTarget, rel));
      }
    } else {
      const allFiles = walkFiles(resolvedRoot);
      for (const file of allFiles) {
        const rel = toPosix(relative(resolvedRoot, file));
        copyFile(file, path.join(resolvedTarget, rel));
      }
    }

    // Step 5: Copy brain data
    let brainIncluded = false;
    if (includeBrain) {
      const brainDir = path.join(resolvedRoot, '.helper-mcp', 'brain');
      if (fs.existsSync(brainDir)) {
        const brainTarget = path.join(resolvedTarget, '.helper-mcp', 'brain');
        const brainFiles = walkFiles(brainDir);
        for (const file of brainFiles) {
          const rel = toPosix(relative(resolvedRoot, file));
          copyFile(file, path.join(resolvedTarget, rel));
        }
        brainIncluded = brainFiles.length > 0;
      }
    }

    // Step 6: Copy baselines
    let baselinesIncluded = false;
    if (includeBaselines) {
      const baselinesDir = path.join(resolvedRoot, '.helper-mcp', 'baselines');
      if (fs.existsSync(baselinesDir)) {
        const baselinesTarget = path.join(resolvedTarget, '.helper-mcp', 'baselines');
        const baselineFiles = walkFiles(baselinesDir);
        for (const file of baselineFiles) {
          const rel = toPosix(relative(resolvedRoot, file));
          copyFile(file, path.join(resolvedTarget, rel));
        }
        baselinesIncluded = baselineFiles.length > 0;
      }
    }

    // Step 7: Copy metrics
    let metricsIncluded = false;
    if (includeMetrics) {
      const metricsFile = path.join(resolvedRoot, '.helper-mcp', 'metrics.jsonl');
      if (fs.existsSync(metricsFile)) {
        const metricsTarget = path.join(resolvedTarget, '.helper-mcp', 'metrics.jsonl');
        copyFile(metricsFile, metricsTarget);
        metricsIncluded = true;
      }
    }

    return {
      ok: true,
      source: toPosix(resolvedRoot),
      target: toPosix(resolvedTarget),
      summary: {
        filesCopied: filesCopied.length,
        dirsCreated: dirsCreated.size,
        brainIncluded,
        baselinesIncluded,
        metricsIncluded,
        totalBytes,
      },
      files: filesCopied.sort(),
    };
  } catch (err) {
    return {
      ok: false,
      error: `Clone failed: ${err.message}`,
      source: toPosix(resolvedRoot),
      target: toPosix(resolvedTarget),
      partial: {
        filesCopied: filesCopied.length,
        dirsCreated: dirsCreated.size,
        totalBytes,
      },
    };
  }
}

function globToRegex(pattern) {
  // Convert a simple glob pattern to a regex
  // Supports *, **, ?, [abc]
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${escaped}$`);
}
