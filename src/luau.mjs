import fs from 'node:fs';
import path from 'node:path';
import { readText, relative, toPosix, walkFiles } from './fs.mjs';

const LUau_EXTENSIONS = new Set(['.lua', '.luau']);

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

function getMatches(lines, pattern) {
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.re.test(lines[index])) {
      matches.push({ line: index + 1, text: lines[index].trim() });
    }
  }
  return matches;
}

export function analyzeLuauText(text, filePath = '') {
  const source = String(text || '');
  const lines = source.split(/\r?\n/);
  const categories = {
    callbacks: callbackPatterns.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label }))),
    remotes: remotePatterns.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label }))),
    state: statePatterns.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label }))),
    ui: uiPatterns.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label }))),
    risks: riskPatterns.flatMap((pattern) => getMatches(lines, pattern).map((match) => ({ ...match, label: pattern.label }))),
  };

  const summary = {
    filePath: toPosix(filePath),
    lineCount: lines.length,
    callbackCount: categories.callbacks.length,
    remoteCount: categories.remotes.length,
    stateCount: categories.state.length,
    uiCount: categories.ui.length,
    riskCount: categories.risks.length,
  };

  return { summary, categories };
}

export function scanLuauWorkspace(root) {
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return LUau_EXTENSIONS.has(ext);
  });

  const analyzed = files.map((filePath) => ({
    filePath: toPosix(relative(root, filePath)),
    ...analyzeLuauText(readText(filePath), filePath),
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

export function formatLuauAnalysis(report) {
  const lines = [];
  lines.push(`# ${report.summary.filePath || 'Luau file'}`);
  lines.push('');
  lines.push(`Lines: ${report.summary.lineCount}`);
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

