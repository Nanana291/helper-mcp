import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import {
  appendBrainNote,
  brainHistory,
  listBrainNotes,
  loadBrainSnapshot,
  mergeBrainNotes,
  promoteBrainNote,
  updateBrainNote,
} from '../src/brain.mjs';

test('brain history tracks status changes and merge deduplicates similar notes', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-brain-advanced-'));
  try {
    appendBrainNote(root, {
      title: 'Wrap remotes in pcall',
      summary: 'Use pcall around remote calls before shipping.',
      scope: 'luau',
      tags: ['luau', 'remotes'],
    });
    appendBrainNote(root, {
      title: 'Wrap FireServer in pcall',
      summary: 'Use pcall around remote calls before shipping.',
      scope: 'luau',
      tags: ['luau', 'remotes'],
    });

    const notes = listBrainNotes(root, { limit: 10 });
    const primary = notes.find((note) => note.title === 'Wrap remotes in pcall');
    const duplicate = notes.find((note) => note.title === 'Wrap FireServer in pcall');

    assert.ok(primary);
    assert.ok(duplicate);

    promoteBrainNote(root, primary.id, 'active');
    updateBrainNote(root, primary.id, { summary: 'Use pcall around remote calls and keep the fix documented.' });

    const history = brainHistory(root, { noteId: primary.id });
    assert.ok(history.total >= 2);
    assert.ok(history.events.some((event) => event.action === 'promote'));
    assert.ok(history.events.some((event) => event.action === 'update'));

    const suggestions = mergeBrainNotes(root, { noteId: primary.id });
    assert.ok(suggestions.ok);
    assert.ok(suggestions.candidates.some((candidate) => candidate.id === duplicate.id));

    const merged = mergeBrainNotes(root, { noteId: primary.id, mergeIds: [duplicate.id], apply: true });
    assert.ok(merged.ok);
    assert.equal(loadBrainSnapshot(root).counts.total, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
