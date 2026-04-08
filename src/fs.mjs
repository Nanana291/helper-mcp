import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ignoredDirNames = new Set(['.git', 'node_modules', '.helper-mcp']);

export function resolveWorkspaceRoot() {
  const envRoot = String(process.env.HELPER_MCP_ROOT || '').trim();
  return envRoot ? path.resolve(envRoot) : process.cwd();
}

export function readText(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

export function writeText(filePath, text) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, text, 'utf8');
}

export function walkFiles(root, predicate = () => true) {
  const results = [];
  if (!fs.existsSync(root)) {
    return results;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirNames.has(entry.name)) {
          stack.push(fullPath);
        }
        continue;
      }
      if (entry.isFile() && predicate(fullPath)) {
        results.push(fullPath);
      }
    }
  }

  return results.sort((left, right) => left.localeCompare(right));
}

export function relative(root, filePath) {
  return path.relative(root, filePath) || '.';
}

export function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

export function toPosix(filePath) {
  return String(filePath || '').split(path.sep).join('/');
}

