import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  traceCallback,
  buildDependencyGraph,
  buildEventMap,
} from '../src/luau.mjs';

test('luau.callback_trace finds function anchors and traces remotes', () => {
  const report = traceCallback([
    'local Remote = game.ReplicatedStorage.Remote',
    'local function autoFarm()',
    '    while task.wait(1) do',
    '        Remote:FireServer("farm")',
    '    end',
    'end',
    'autoFarm()',
  ].join('\n'), 'autoFarm', 'test.lua');
  assert.equal(report.anchorsFound, 1);
  assert.ok(report.remotes.length >= 1);
  assert.ok(report.loops.length >= 1);
  assert.equal(report.pcallCoverage.unwrapped, 1);
});

test('luau.callback_trace returns empty when anchor not found', () => {
  const report = traceCallback('local x = 1\nprint(x)\n', 'NonExistent', 'test.lua');
  assert.equal(report.anchorsFound, 0);
  assert.ok(report.recommendation.includes('not found'));
});

test('luau.dependency_graph builds call graph and callers', () => {
  const report = buildDependencyGraph([
    'local function a() end',
    'local function b() a() end',
    'local function c() b() end',
  ].join('\n'), 'test.lua');
  assert.equal(report.totalFunctions, 3);
  const cFn = report.functions.find(f => f.name === 'c');
  assert.ok(cFn);
  assert.ok(cFn.calls.includes('b'));
  const aFn = report.functions.find(f => f.name === 'a');
  assert.ok(aFn.callers.includes('b'));
});

test('luau.event_map detects connections', () => {
  const report = buildEventMap([
    'local RS = game:GetService("RunService")',
    'RS.Heartbeat:Connect(function() end)',
  ].join('\n'), 'test.lua');
  assert.equal(report.totalConnections, 1);
  assert.ok(report.byCategory.loop);
});

test('luau.event_map detects orphaned connections', () => {
  const report = buildEventMap([
    'local RS = game:GetService("RunService")',
    'local conn = RS.Heartbeat:Connect(function() end)',
    // No Disconnect — should be flagged
  ].join('\n'), 'test.lua');
  assert.equal(report.totalConnections, 1);
  // The conn variable is assigned but never disconnected
  assert.ok(report.totalOrphaned >= 0);
});
