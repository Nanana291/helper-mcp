import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('helper-mcp exposes an OpenCode local MCP config', () => {
  const configPath = path.join(repoRoot, 'opencode.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));

  assert.equal(config.$schema, 'https://opencode.ai/config.json');
  assert.equal(config.mcp?.['helper-mcp']?.type, 'local');
  assert.deepEqual(config.mcp?.['helper-mcp']?.command, ['node', './src/index.mjs']);
  assert.equal(config.mcp?.['helper-mcp']?.enabled, true);
});
