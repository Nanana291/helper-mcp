import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { importBrainNotes, loadBrainSnapshot } from '../src/brain.mjs';

test('brain import ingests markdown and json sources', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-brain-import-'));
  try {
    const docs = path.join(root, 'docs');
    const note = path.join(docs, 'note.md');
    const json = path.join(docs, 'note.json');
    mkdirSync(docs, { recursive: true });
    writeFileSync(note, '# Luau security scan\nDetect webhook leaks and loadstring usage.\n', 'utf8');
    writeFileSync(json, JSON.stringify({ title: 'Baseline drift', summary: 'Track workspace baselines and regression risk.' }), 'utf8');

    const report = importBrainNotes(root, [docs]);
    assert.equal(report.importedCount, 2);

    const snapshot = loadBrainSnapshot(root);
    assert.equal(snapshot.counts.total, 2);
    assert.ok(snapshot.counts.byTag.security >= 1);
    assert.ok(snapshot.counts.byTag.baseline >= 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
