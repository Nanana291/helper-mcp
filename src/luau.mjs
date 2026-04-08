import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { readText, relative, toPosix, walkFiles, writeText } from './fs.mjs';
import { loadLuauPatterns, defaultLuauPatterns } from './patterns.mjs';

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
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (!LUAU_EXTENSIONS.has(ext)) return false;
    if (!targetPath) return true;
    const rel = toPosix(relative(root, filePath));
    const target = toPosix(targetPath);
    return rel === target || rel.startsWith(`${target}/`);
  });

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
  const files = walkFiles(root, (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (!LUAU_EXTENSIONS.has(ext)) return false;
    if (!targetPath) return true;
    const rel = toPosix(relative(root, filePath));
    const target = toPosix(targetPath);
    return rel === target || rel.startsWith(`${target}/`);
  });

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
