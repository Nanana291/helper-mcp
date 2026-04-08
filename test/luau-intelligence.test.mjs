import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { handleTool } from '../src/core.mjs';

function callJson(root, name, args) {
  return JSON.parse(handleTool(root, name, args).content[0].text);
}

test('luau intelligence commands return structured graphs and scores', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-luau-intel-'));
  try {
    const clientPath = path.join(root, 'client.luau');
    const serverPath = path.join(root, 'server.luau');
    const modulePath = path.join(root, 'module.luau');
    const consumerPath = path.join(root, 'consumer.luau');
    const beforePath = path.join(root, 'before.luau');
    const afterPath = path.join(root, 'after.luau');

    writeFileSync(clientPath, [
      'local Remote = game.ReplicatedStorage.RemoteEvent',
      'local token = game:HttpGet("https://example.com")',
      'Remote:FireServer(token)',
      'local function run(value)',
      '  if value > 1 then',
      '    return value',
      '  end',
      'end',
    ].join('\n'), 'utf8');
    writeFileSync(serverPath, [
      'local Remote = game.ReplicatedStorage.RemoteEvent',
      'Remote.OnServerEvent:Connect(function(player, value)',
      '  print(player, value)',
      'end)',
    ].join('\n'), 'utf8');
    writeFileSync(modulePath, 'return function() return true end\n', 'utf8');
    writeFileSync(consumerPath, 'local module = require(script.Parent.module)\nreturn module()\n', 'utf8');
    writeFileSync(beforePath, 'local value = 1\nreturn value\n', 'utf8');
    writeFileSync(afterPath, 'local value = 2\nreturn value + 1\n', 'utf8');

    const surface = callJson(root, 'luau.surface', { targetPath: clientPath });
    assert.ok(surface.summary.totalFiles >= 5);
    assert.ok(surface.summary.confidenceAverage >= 0);

    const taint = callJson(root, 'luau.taint', { filePath: clientPath });
    assert.ok(taint.summary.sourceCount >= 1);
    assert.ok(taint.summary.sinkCount >= 1);

    const flow = callJson(root, 'luau.flow', { filePath: clientPath });
    assert.ok(flow.summary.nodeCount >= 1);
    assert.ok(flow.summary.edgeCount >= 1);

    const handlers = callJson(root, 'luau.handlers', { targetPath: root });
    assert.ok(handlers.summary.remoteCount >= 1);
    assert.ok(handlers.remotes.some((remote) => remote.hasServerHandler));

    const refactor = callJson(root, 'luau.refactor', { filePath: clientPath, riskLabel: 'missing-pcall' });
    assert.match(refactor.after, /pcall/);

    const modulegraph = callJson(root, 'luau.modulegraph', { targetPath: root });
    assert.ok(modulegraph.summary.nodeCount >= 1);
    assert.ok(modulegraph.summary.edgeCount >= 1);

    const score = callJson(root, 'luau.risk_score', { filePath: clientPath });
    assert.ok(score.summary.score > 0);
    assert.ok(score.summary.confidenceAverage > 0);

    const diffContext = callJson(root, 'luau.diff_context', { pathA: beforePath, pathB: afterPath, context: 1 });
    assert.ok(diffContext.summary.hunkCount >= 1);
    assert.ok(diffContext.hunks[0].contextBefore.length >= 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
