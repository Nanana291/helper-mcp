import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { handleTool } from '../src/core.mjs';
import { loadBrainSnapshot } from '../src/brain.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('luau analyzers auto-write brain notes for findings', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-luau-bridge-'));
  try {
    const filePath = path.join(root, 'scan.luau');
    writeFileSync(filePath, [
      'local token = game:HttpGet("https://example.com")',
      'Remote:FireServer(token)',
    ].join('\n'), 'utf8');

    const security = callJson(root, 'luau.security_scan', { filePath });
    assert.ok(Array.isArray(security.brainNoteIds));
    assert.ok(security.brainNoteIds.length >= 1);

    const snapshot = loadBrainSnapshot(root);
    assert.ok(snapshot.counts.total >= 1);
    assert.equal(snapshot.counts.byStatus.active >= 1 || snapshot.counts.byStatus.candidate >= 1, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
