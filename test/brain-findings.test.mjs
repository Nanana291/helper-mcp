import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { handleTool } from '../src/core.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('brain finding commands expose history, graph, and pruning behavior', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-brain-findings-'));
  try {
    const filePath = path.join(root, 'script.luau');
    writeFileSync(filePath, [
      'local token = game:HttpGet("https://example.com")',
      'Remote:FireServer(token)',
    ].join('\n'), 'utf8');

    callJson(root, 'luau.security_scan', { filePath });
    callJson(root, 'luau.security_scan', { filePath });

    const findings = callJson(root, 'brain.findings', { filePath, severity: 'high', limit: 20 });
    assert.ok(findings.total >= 1);
    assert.equal(findings.notes[0].sourceCommand, 'luau.security_scan');

    const history = callJson(root, 'brain.finding_history', { filePath, limit: 20 });
    assert.ok(history.total >= 1);

    const graph = callJson(root, 'brain.finding_graph', { limit: 20 });
    assert.ok(graph.summary.totalNodes >= 1);

    const prune = callJson(root, 'brain.finding_prune', { apply: false, limit: 20 });
    assert.equal(typeof prune.total, 'number');
    assert.ok(Array.isArray(prune.suggestions));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
