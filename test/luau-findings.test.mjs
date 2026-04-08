import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { handleTool } from '../src/core.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('luau.findings returns normalized bridgeable findings', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-luau-findings-'));
  try {
    const filePath = path.join(root, 'script.luau');
    writeFileSync(filePath, [
      'local token = game:HttpGet("https://example.com")',
      'Remote:FireServer(token)',
      'while true do',
      '  task.wait()',
      'end',
    ].join('\n'), 'utf8');

    const report = callJson(root, 'luau.findings', { filePath });
    assert.ok(Array.isArray(report.findings));
    assert.ok(report.findings.length >= 2);
    assert.equal(typeof report.findings[0].brainNoteId, 'string');
    assert.equal(typeof report.findings[0].bridgeable, 'boolean');
    assert.ok(report.summary.totalFindings >= report.findings.length);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
