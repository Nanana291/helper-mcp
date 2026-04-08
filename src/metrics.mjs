import fs from 'node:fs';
import path from 'node:path';
import { scanLuauWorkspace } from './luau.mjs';
import { toPosix, readText } from './fs.mjs';

function metricsPath(root) {
  return path.join(root, '.helper-mcp', 'metrics.jsonl');
}

function loadMetrics(root) {
  const filePath = metricsPath(root);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return readText(filePath)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function summarizeWorkspace(scan) {
  const totalRemotes = scan.totalRemotes || 0;
  const missingPcall = scan.files.reduce((sum, file) => sum + file.categories.risks.filter((risk) => risk.label === 'missing-pcall').length, 0);
  const pcallCoverage = totalRemotes > 0 ? Number((((totalRemotes - missingPcall) / totalRemotes) * 100).toFixed(2)) : 100;
  const localPressure = scan.totalFiles > 0
    ? Number(((scan.files.reduce((sum, file) => sum + file.summary.localCount, 0) / (scan.totalFiles * 200)) * 100).toFixed(2))
    : 0;

  return {
    totalFiles: scan.totalFiles,
    totalRisks: scan.totalRisks,
    totalCallbacks: scan.totalCallbacks,
    totalRemotes,
    pcallCoverage,
    localPressure,
  };
}

export function captureLuauMetrics(root, { label = '', record = true } = {}) {
  const scan = scanLuauWorkspace(root);
  const summary = summarizeWorkspace(scan);
  const snapshot = {
    kind: 'helper-mcp-luau-metrics',
    generatedAt: new Date().toISOString(),
    workspaceRoot: toPosix(root),
    label: String(label || '').trim(),
    summary,
  };

  if (record !== false) {
    const filePath = metricsPath(root);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, `${JSON.stringify(snapshot)}\n`, 'utf8');
  }

  const history = loadMetrics(root);
  const previous = history.length > 1 ? history[history.length - 2] : null;
  const trend = previous ? {
    totalRisksDelta: summary.totalRisks - previous.summary.totalRisks,
    pcallCoverageDelta: Number((summary.pcallCoverage - previous.summary.pcallCoverage).toFixed(2)),
    localPressureDelta: Number((summary.localPressure - previous.summary.localPressure).toFixed(2)),
  } : {
    totalRisksDelta: 0,
    pcallCoverageDelta: 0,
    localPressureDelta: 0,
  };

  return {
    snapshot,
    previous,
    trend,
    historyCount: history.length,
  };
}

export function loadLuauMetrics(root) {
  return loadMetrics(root);
}
