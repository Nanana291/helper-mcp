import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { handleTool } from '../src/core.mjs';
import { captureLuauMetrics } from '../src/metrics.mjs';
import {
  buildLuauDependencyMap,
  buildLuauRemoteGraph,
  repairLuauRisk,
  scoreLuauComplexity,
} from '../src/luau.mjs';
import { loadBrainSnapshot } from '../src/brain.mjs';

test('luau repair, dependency graph, remote graph, complexity, metrics, and changelog work', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-luau-advanced-'));
  try {
    const clientPath = path.join(root, 'client.luau');
    const serverPath = path.join(root, 'server.luau');
    const modulePath = path.join(root, 'module.luau');
    const helperPath = path.join(root, 'helper.luau');
    const complexPath = path.join(root, 'complex.luau');
    const oldPath = path.join(root, 'old.luau');
    const newPath = path.join(root, 'new.luau');

    writeFileSync(clientPath, 'local Remote = game.ReplicatedStorage.RemoteEvent\nRemote:FireServer("hello")\n', 'utf8');
    writeFileSync(serverPath, 'local Remote = game.ReplicatedStorage.RemoteEvent\nRemote.OnServerEvent:Connect(function()\n  print("ok")\nend)\n', 'utf8');
    writeFileSync(modulePath, 'return function() return true end\n', 'utf8');
    writeFileSync(helperPath, 'local helper = require(script.Parent.Module)\nreturn true\n', 'utf8');
    writeFileSync(complexPath, [
      'local function compute(value)',
      '  if value > 1 and value < 3 then',
      '    return 1',
      '  elseif value > 10 then',
      '    for i = 1, 3 do',
      '      print(i)',
      '    end',
      '  end',
      '  return 0',
      'end',
    ].join('\n'), 'utf8');
    writeFileSync(oldPath, 'LoadAutoloadConfig()\nCreateDashboard()\nlocal Remote = game.ReplicatedStorage.RemoteEvent\nRemote:FireServer()\n', 'utf8');
    writeFileSync(newPath, 'CreateDashboard()\nlocal Remote = game.ReplicatedStorage.RemoteEvent\npcall(function() Remote:FireServer() end)\n', 'utf8');

    const repair = repairLuauRisk('Remote:FireServer("hello")\n', clientPath, 'missing-pcall');
    assert.match(repair.after, /pcall/);
    assert.match(repair.explanation, /remote call/i);

    const dependencies = buildLuauDependencyMap(root);
    assert.ok(dependencies.summary.scriptCount >= 4);
    assert.ok(dependencies.scripts.some((script) => script.unusedImports.includes('helper')));

    const remotes = buildLuauRemoteGraph(root);
    assert.ok(remotes.summary.remoteCount >= 1);
    assert.ok(remotes.remotes.some((remote) => remote.hasServerHandler));

    const complexity = scoreLuauComplexity(readFileSync(complexPath, 'utf8'), complexPath);
    assert.ok(complexity.summary.functionCount >= 1);
    assert.ok(complexity.summary.maxComplexity > 1);

    const firstMetrics = captureLuauMetrics(root, { label: 'baseline' });
    assert.ok(firstMetrics.snapshot.summary.totalFiles >= 6);

    writeFileSync(clientPath, 'pcall(function() Remote:FireServer("hello") end)\ntask.wait(0.1)\n', 'utf8');
    const secondMetrics = captureLuauMetrics(root, { label: 'after-fix' });
    assert.ok(secondMetrics.trend.totalRisksDelta <= 0);

    const changelog = JSON.parse(handleTool(root, 'luau.changelog', {
      oldPath,
      newPath,
      title: 'Migration note',
    }).content[0].text);

    assert.equal(changelog.verdict, 'BLOCKED');
    assert.ok(changelog.brainNote.markdown.includes('Verdict: BLOCKED'));
    assert.ok(loadBrainSnapshot(root).counts.total >= 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
