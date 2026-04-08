import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { captureWorkspaceBaseline } from '../src/workspace.mjs';
import { handleTool } from '../src/core.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('workspace automation commands produce diffs, notes, validation, and restores', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-workspace-auto-'));
  try {
    const filePath = path.join(root, 'script.luau');
    writeFileSync(filePath, 'local value = 1\n', 'utf8');

    const baseline = captureWorkspaceBaseline(root, { targetPath: filePath });
    writeFileSync(filePath, 'local value = 2\nRemoteEvent:FireServer()\n', 'utf8');

    const diff = callJson(root, 'workspace.diff', { baselinePath: baseline.path, targetPath: filePath });
    assert.ok(diff.ok);
    assert.ok(diff.comparison.diff.modified.length >= 1);

    const validate = callJson(root, 'workspace.validate', { baselinePath: baseline.path, targetPath: filePath });
    assert.ok(validate.ok);
    assert.equal(validate.valid, false);

    const notes = callJson(root, 'workspace.release_notes', { baselinePath: baseline.path, targetPath: filePath, title: 'Release notes' });
    assert.ok(notes.ok);
    assert.match(notes.markdown, /Workspace release notes|Release notes/);

    const snapshotPath = path.join(root, 'snapshot.json');
    writeFileSync(snapshotPath, JSON.stringify({
      kind: 'helper-mcp-snapshot',
      filePath: 'script.luau',
      content: 'local value = 1\n',
    }), 'utf8');
    const rollback = callJson(root, 'workspace.rollback', { snapshotPath, targetPath: filePath, apply: true });
    assert.ok(rollback.ok);
    assert.match(rollback.filePath, /script\.luau$/);
    assert.match(readFileSync(filePath, 'utf8'), /local value = 1/);

    const validateAfterRollback = callJson(root, 'workspace.validate', { baselinePath: baseline.path, targetPath: filePath });
    assert.ok(validateAfterRollback.valid);

    writeFileSync(filePath, 'local value = 3\n', 'utf8');
    const restore = callJson(root, 'workspace.restore_snapshot', { snapshotPath, targetPath: filePath, apply: true });
    assert.ok(restore.ok);
    assert.match(restore.filePath, /script\.luau$/);
    assert.match(readFileSync(filePath, 'utf8'), /local value = 1/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
