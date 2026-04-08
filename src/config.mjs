import fs from 'node:fs';
import path from 'node:path';
import { readText, writeText, toPosix } from './fs.mjs';

function tryParseJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (error) {
    return { ok: false, error };
  }
}

function loadSchema(schemaPath) {
  if (!schemaPath) {
    return null;
  }
  const resolved = path.isAbsolute(schemaPath) ? schemaPath : path.resolve(schemaPath);
  if (!fs.existsSync(resolved)) {
    return null;
  }
  const parsed = tryParseJson(readText(resolved));
  return parsed.ok ? parsed.value : null;
}

function validateValueShape(value) {
  const issues = [];
  const suggestions = [];

  if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return { issues, suggestions, kind: typeof value };
  }

  if (Array.isArray(value)) {
    issues.push('arrays are not valid config flag values');
    suggestions.push('flatten the array into a scalar flag or convert it into a structured schema entry');
    return { issues, suggestions, kind: 'array' };
  }

  if (value && typeof value === 'object') {
    if ('Key' in value || 'Mode' in value) {
      if (typeof value.Key !== 'string') {
        issues.push('keybind entry is missing a string Key');
        suggestions.push('set Key to a Roblox key name string');
      }
      if (value.Mode !== undefined && typeof value.Mode !== 'string' && typeof value.Mode !== 'number') {
        issues.push('keybind Mode must be a string or number');
        suggestions.push('set Mode to the expected keybind mode');
      }
      return { issues, suggestions, kind: 'keybind' };
    }

    if ('Color' in value || 'Alpha' in value) {
      if (typeof value.Color !== 'string' || !/^#[0-9a-f]{6,8}$/i.test(value.Color)) {
        issues.push('color entry must use a hex string like #RRGGBB or #RRGGBBAA');
        suggestions.push('set Color to a hex string');
      }
      if (value.Alpha !== undefined && (typeof value.Alpha !== 'number' || value.Alpha < 0 || value.Alpha > 1)) {
        issues.push('color Alpha must be a number between 0 and 1');
        suggestions.push('set Alpha to a normalized opacity value');
      }
      return { issues, suggestions, kind: 'color' };
    }

    issues.push('object value does not match the expected LibSixtyTen config shapes');
    suggestions.push('use a scalar, keybind object, or color object');
    return { issues, suggestions, kind: 'object' };
  }

  issues.push(`unsupported config value type: ${typeof value}`);
  suggestions.push('convert the value to a supported scalar, keybind, or color object');
  return { issues, suggestions, kind: typeof value };
}

export function validateConfigObject(config, { schema = null } = {}) {
  const issues = [];
  const suggestions = [];
  const keys = Object.keys(config || {});
  const expectedKeys = schema && typeof schema === 'object' ? Object.keys(schema) : null;

  for (const [key, value] of Object.entries(config || {})) {
    if (key === '__ThemePreset') {
      if (typeof value !== 'string' || !value.trim()) {
        issues.push('__ThemePreset must be a non-empty string');
        suggestions.push('set __ThemePreset to a valid theme preset name');
      }
      continue;
    }

    const shape = validateValueShape(value);
    issues.push(...shape.issues.map((issue) => `${key}: ${issue}`));
    suggestions.push(...shape.suggestions.map((suggestion) => `${key}: ${suggestion}`));

    if (schema && Object.prototype.hasOwnProperty.call(schema, key)) {
      const expectedType = schema[key];
      const actualType = Array.isArray(value) ? 'array' : typeof value;
      if (expectedType && expectedType !== actualType && expectedType !== shape.kind) {
        issues.push(`${key}: expected ${expectedType}, received ${actualType}`);
        suggestions.push(`${key}: update the value to match the schema type`);
      }
    }
  }

  if (expectedKeys) {
    for (const key of expectedKeys) {
      if (!Object.prototype.hasOwnProperty.call(config || {}, key)) {
        issues.push(`missing expected key: ${key}`);
        suggestions.push(`add ${key} to the config`);
      }
    }

    for (const key of keys) {
      if (!Object.prototype.hasOwnProperty.call(schema || {}, key)) {
        issues.push(`extra key not in schema: ${key}`);
        suggestions.push(`remove ${key} or add it to the schema if it is intentional`);
      }
    }
  }

  return {
    valid: issues.length === 0,
    issues,
    suggestions: [...new Set(suggestions)],
    keyCount: keys.length,
  };
}

export function validateConfigText(text, { schemaPath = '', sourcePath = '' } = {}) {
  const parsed = tryParseJson(text);
  if (!parsed.ok || !parsed.value || typeof parsed.value !== 'object' || Array.isArray(parsed.value)) {
    return {
      valid: false,
      sourcePath: toPosix(sourcePath),
      issues: ['config file is not valid JSON object'],
      suggestions: ['export the config using the built-in JSON format or provide a schema file'],
      parsed: null,
    };
  }

  const schema = loadSchema(schemaPath);
  const validation = validateConfigObject(parsed.value, { schema });
  return {
    ...validation,
    sourcePath: toPosix(sourcePath),
    schemaPath: toPosix(schemaPath),
    parsed: parsed.value,
  };
}

export function validateConfigFile(root, filePath, options = {}) {
  const resolved = path.isAbsolute(filePath) ? filePath : path.resolve(root, filePath);
  return validateConfigText(readText(resolved), {
    ...options,
    sourcePath: resolved,
  });
}

export function buildConfigValidationMarkdown(report) {
  const lines = [];
  lines.push(`# ${report.sourcePath || 'Config validation'}`);
  lines.push('');
  lines.push(`Valid: ${report.valid ? 'yes' : 'no'}`);
  lines.push(`Keys: ${report.keyCount || 0}`);
  if (report.schemaPath) {
    lines.push(`Schema: ${report.schemaPath}`);
  }
  lines.push('');
  if ((report.issues || []).length > 0) {
    lines.push('## Issues');
    for (const issue of report.issues) {
      lines.push(`- ${issue}`);
    }
    lines.push('');
  }
  if ((report.suggestions || []).length > 0) {
    lines.push('## Suggestions');
    for (const suggestion of report.suggestions) {
      lines.push(`- ${suggestion}`);
    }
    lines.push('');
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

export function saveConfigValidation(root, filePath, report) {
  const dir = path.join(root, '.helper-mcp', 'config-validations');
  fs.mkdirSync(dir, { recursive: true });
  const output = path.join(dir, `${String(filePath || 'config').replace(/[^\w.-]+/g, '_')}.json`);
  writeText(output, `${JSON.stringify({
    kind: 'helper-mcp-config-validation',
    generatedAt: new Date().toISOString(),
    filePath: toPosix(filePath),
    report,
  }, null, 2)}\n`);
  return toPosix(path.relative(root, output) || output);
}
