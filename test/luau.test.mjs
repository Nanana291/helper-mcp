import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { analyzeLuauText, compareLuauFiles, scanLuauWorkspace } from '../src/luau.mjs';

test('luau analysis finds callbacks, remotes, ui, state, and risks', () => {
  const report = analyzeLuauText(`
    local Settings = {}
    local Remote = game.ReplicatedStorage.RemoteEvent
    Remote:FireServer("hello")
    RunService.Heartbeat:Connect(function()
      print("tick")
    end)
    local Window = Library:Window("Main")
    while true do
      wait()
      break
    end
  `, 'scripts/main.luau');

  assert.equal(report.summary.callbackCount > 0, true);
  assert.equal(report.summary.remoteCount > 0, true);
  assert.equal(report.summary.uiCount > 0, true);
  assert.equal(report.summary.stateCount > 0, true);
  assert.equal(report.summary.riskCount > 0, true);
});

test('luau scan and compare work on a workspace', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-luau-'));
  try {
    const current = path.join(root, 'current.luau');
    const baseline = path.join(root, 'baseline.luau');
    writeFileSync(current, 'local Settings = {}\nRemoteEvent:FireServer()\n', 'utf8');
    writeFileSync(baseline, 'local Settings = {}\n', 'utf8');

    const scan = scanLuauWorkspace(root);
    assert.equal(scan.totalFiles, 2);

    const compare = compareLuauFiles(root, current, baseline);
    assert.equal(compare.added.length > 0, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

