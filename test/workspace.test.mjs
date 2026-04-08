import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { captureWorkspaceBaseline, generateWorkspaceChangelog, hotfixWorkspaceFile } from '../src/workspace.mjs';

test('workspace baselines and changelogs capture drift', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-workspace-'));
  try {
    const script = path.join(root, 'script.luau');
    writeFileSync(script, 'RemoteEvent:FireServer()\n', 'utf8');

    const baseline = captureWorkspaceBaseline(root, { targetPath: script });
    assert.equal(baseline.baseline.entryCount, 1);

    writeFileSync(script, 'RemoteEvent:FireServer()\nlocal x = 1\n', 'utf8');
    const changelog = generateWorkspaceChangelog(root, path.join(root, '.helper-mcp', 'baselines', 'script.luau.json'), {
      targetPath: script,
    });

    assert.match(changelog.markdown, /Modified/);

    const hotfix = hotfixWorkspaceFile(root, script, { apply: true });
    assert.ok(hotfix.snapshotPath.endsWith('.json'));
    assert.match(readFileSync(script, 'utf8'), /pcall/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
