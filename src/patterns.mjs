import fs from 'node:fs';
import path from 'node:path';
import { readText } from './fs.mjs';

function pattern(label, source, flags = '') {
  return { label, re: source instanceof RegExp ? source : new RegExp(source, flags) };
}

export const defaultLuauPatterns = {
  callbacks: [
    pattern('signal-connect', /\bConnect\s*\(/),
    pattern('server-event', /\bOnServerEvent\b/),
    pattern('client-event', /\bOnClientEvent\b/),
    pattern('property-signal', /\bGetPropertyChangedSignal\s*\(/),
    pattern('task-spawn', /\btask\.spawn\s*\(/),
    pattern('render-stepped', /\bRenderStepped\b/),
    pattern('heartbeat', /\bHeartbeat\b/),
  ],
  remotes: [
    pattern('fire-server', /\b:FireServer\s*\(/),
    pattern('invoke-server', /\b:InvokeServer\s*\(/),
    pattern('fire-client', /\b:FireClient\s*\(/),
    pattern('remote-event', /\bRemoteEvent\b/),
    pattern('remote-function', /\bRemoteFunction\b/),
  ],
  state: [
    pattern('settings', /\bSettings\b/),
    pattern('selected', /\bSelected\b/),
    pattern('runtime-info', /\bRuntimeInfo\b/),
    pattern('stats', /\bStats\b/),
    pattern('flags', /\bFlags\b/),
  ],
  ui: [
    pattern('window', /\bLibrary:Window\s*\(/),
    pattern('dashboard', /\bCreateDashboard\s*\(/),
    pattern('toggle', /\bToggle\s*\(/),
    pattern('slider', /\bSlider\s*\(/),
    pattern('dropdown', /\bDropdown\s*\(/),
    pattern('button', /\bButton\s*\(/),
    pattern('paragraph', /\bParagraph\s*\(/),
    pattern('label', /\bLabel\s*\(/),
  ],
  risks: [
    pattern('wait', /\bwait\s*\(/),
    pattern('spawn', /\bspawn\s*\(/),
    pattern('delay', /\bdelay\s*\(/),
    pattern('repeat-wait', /\brepeat\b[\s\S]{0,80}\bwait\s*\(/),
    pattern('unbounded-loop', /\bwhile\s+true\s+do\b/),
  ],
  performance: [
    pattern('hot-loop', /\bwhile\s+true\s+do\b/),
    pattern('repeat-loop', /\brepeat\b[\s\S]{0,80}\buntil\b/i),
    pattern('nested-wait', /\bwait\s*\(\s*\)\s*[\s\S]{0,40}\bwait\s*\(\s*\)/i),
    pattern('task-spawn', /\btask\.spawn\s*\(/i),
    pattern('spawn', /\bspawn\s*\(/i),
    pattern('delay', /\bdelay\s*\(/i),
    pattern('connect-without-cleanup', /\bConnect\s*\(/i),
  ],
  security: [
    pattern('webhook', /https?:\/\/(?:canary\.|ptb\.)?(?:discord(?:app)?\.com|discord\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/i),
    pattern('loadstring-remote', /\bloadstring\s*\(\s*(?:game\.)?(?:HttpGet|HttpGetAsync|RequestAsync)\s*\(/i),
    pattern('token-exfil', /\b(api[_-]?key|token|secret|cookie|session)\b/i),
    pattern('http-call', /\bHttp(Service|Get|Post|RequestAsync)\b/i),
    pattern('backdoor-pattern', /\b(getfenv|getgenv|setclipboard|syn\.request|http_request)\b/i),
  ],
  obfuscation: [
    pattern('char-encoding', /\bstring\.char\s*\(/i),
    pattern('byte-encoding', /\bstring\.byte\s*\(/i),
    pattern('xor-math', /\bbit32\.bxor\s*\(/i),
    pattern('gsub-obfuscation', /\bstring\.gsub\s*\(\s*[^,]+,\s*["'][^"']{0,4}["']/i),
    pattern('hex-string', /0x[0-9a-f]{8,}/i),
    pattern('long-concat', /\.\.\s*["'][^"']{0,2}["']\s*\.\./),
    pattern('loader', /\b(loadstring|load|require)\s*\(/i),
  ],
};

function compileEntry(entry) {
  if (entry instanceof RegExp) {
    return { label: 'custom', re: entry };
  }
  if (typeof entry === 'string') {
    return pattern(entry, entry);
  }
  if (entry && typeof entry === 'object') {
    const label = String(entry.label || entry.name || entry.pattern || 'custom').trim() || 'custom';
    if (entry.pattern instanceof RegExp) {
      return { label, re: entry.pattern };
    }
    const flags = String(entry.flags || '').trim();
    return { label, re: new RegExp(String(entry.pattern || ''), flags) };
  }
  return null;
}

function loadOverrideFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    return JSON.parse(readText(filePath));
  } catch {
    return null;
  }
}

function mergeCategory(defaults, override) {
  if (override == null) {
    return defaults.slice();
  }
  const compiled = Array.isArray(override) ? override.map(compileEntry).filter(Boolean) : [];
  return compiled.length > 0 ? compiled : defaults.slice();
}

export function loadLuauPatterns(root) {
  const patterns = structuredClone(defaultLuauPatterns);
  const overridePath = path.join(root, '.helper-mcp', 'patterns.json');
  const override = loadOverrideFile(overridePath);
  if (!override || typeof override !== 'object' || Array.isArray(override)) {
    return patterns;
  }

  for (const key of Object.keys(patterns)) {
    if (Object.prototype.hasOwnProperty.call(override, key)) {
      patterns[key] = mergeCategory(patterns[key], override[key]);
    }
  }

  return patterns;
}

export function normalizePatternCategories(patterns) {
  return Object.fromEntries(Object.entries(patterns).map(([key, entries]) => [
    key,
    (entries || []).map(compileEntry).filter(Boolean),
  ]));
}

