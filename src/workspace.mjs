import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { analyzeLuauText, hotfixLuauText } from './luau.mjs';
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
