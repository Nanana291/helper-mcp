import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { appendBrainNote, searchBrainNotes, loadBrainSnapshot } from '../src/brain.mjs';

test('brain notes are stored and searchable', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-brain-'));
  try {
    const snapshot = appendBrainNote(root, {
      title: 'Keep remotes wrapped in pcall',
      summary: 'Use pcall around FireServer and InvokeServer calls.',
      scope: 'luau',
      tags: ['luau', 'remotes'],
      sourcePath: 'scripts/main.luau',
      evidence: 'remote calls in hot paths',
    });

    assert.equal(snapshot.counts.total, 1);

    const results = searchBrainNotes(root, 'FireServer');
    assert.equal(results.length >= 1, true);
    assert.match(readFileSync(path.join(root, '.helper-mcp', 'brain', 'notes.jsonl'), 'utf8'), /Keep remotes wrapped in pcall/);

    const current = loadBrainSnapshot(root);
    assert.equal(current.counts.total, 1);
    assert.equal(current.notes[0].title, 'Keep remotes wrapped in pcall');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

