import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { appendBrainNote, buildBrainSnapshot } from '../src/brain.mjs';
import { handleTool } from '../src/core.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('brain platform commands expose graph, archive, restore, and pruning behavior', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-brain-platform-'));
  try {
    appendBrainNote(root, {
      title: 'Keep remotes wrapped in pcall',
      summary: 'Use pcall around FireServer and InvokeServer calls.',
      scope: 'luau',
      status: 'active',
      tags: ['luau', 'remotes'],
      sourcePath: 'scripts/main.luau',
    });
    appendBrainNote(root, {
      title: 'Keep FireServer safe',
      summary: 'Use pcall around FireServer and InvokeServer calls.',
      scope: 'luau',
      status: 'candidate',
      tags: ['luau', 'remotes'],
      sourcePath: 'scripts/main.luau',
    });

    const notes = callJson(root, 'brain.query_advanced', { query: 'FireServer', tag: 'remotes', limit: 10 });
    assert.ok(notes.total >= 1);
    assert.ok(notes.notes[0].score >= 0);

    const graph = callJson(root, 'brain.graph', { limit: 20 });
    assert.ok(graph.summary.totalNodes >= 2);

    const allNotes = callJson(root, 'brain.query_advanced', { query: '', limit: 10 });
    const source = allNotes.notes.find((note) => note.title === 'Keep remotes wrapped in pcall');
    const duplicate = allNotes.notes.find((note) => note.title === 'Keep FireServer safe');
    assert.ok(source);
    assert.ok(duplicate);

    const snapshotPath = path.join(root, 'brain-snapshot.json');
    writeFileSync(snapshotPath, `${JSON.stringify(buildBrainSnapshot(root), null, 2)}\n`, 'utf8');

    const linkResult = callJson(root, 'brain.link', { fromId: source.id, toId: duplicate.id, relation: 'duplicate' });
    assert.ok(linkResult.ok);
    assert.ok(Array.isArray(linkResult.from.links));

    const archived = callJson(root, 'brain.archive', { id: source.id, reason: 'superseded' });
    assert.ok(archived.ok);
    assert.equal(archived.note.status, 'archived');

    const restoredDiff = callJson(root, 'brain.restore_diff', { snapshotPath });
    assert.ok(restoredDiff.ok);
    assert.ok(restoredDiff.summary.changed >= 1);

    const diff = callJson(root, 'brain.diff', { snapshotPath });
    assert.ok(diff.ok);
    assert.ok(diff.summary.changed >= 1);

    const pruneSuggest = callJson(root, 'brain.prune_duplicates', { apply: false, limit: 10 });
    assert.ok(pruneSuggest.total >= 1);

    const pruneApply = callJson(root, 'brain.prune_duplicates', { apply: true, limit: 10 });
    assert.ok(pruneApply.ok);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
