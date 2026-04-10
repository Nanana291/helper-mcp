import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  analyzeRemotePayloads,
  detectAntiPatterns,
  extractStateTables,
  generateUiScaffold,
} from '../src/luau.mjs';

test('luau.remote_payload_analyzer extracts FireServer arguments', () => {
  const report = analyzeRemotePayloads([
    'local RS = game:GetService("ReplicatedStorage")',
    'local FarmRemote = RS.FarmRemote',
    'FarmRemote:FireServer("farm", target, 100)',
    'FarmRemote:FireServer("stop")',
  ].join('\n'), 'test.lua');
  assert.equal(report.totalCalls, 2);
  assert.equal(report.uniqueRemotes, 1);
  assert.ok(report.remoteApis.length >= 1);
  // Check the 3-arg signature exists
  const threeArg = report.remoteApis.find(a => a.includes('number'));
  assert.ok(threeArg);
  // Check byRemote structure
  assert.ok(report.byRemote.FarmRemote);
  assert.equal(report.byRemote.FarmRemote.callCount, 2);
});

test('luau.remote_payload_analyzer handles InvokeServer', () => {
  const report = analyzeRemotePayloads([
    'local Remote = workspace.SomeRemote',
    'Remote:InvokeServer("query", { id = 1 })',
  ].join('\n'), 'test.lua');
  assert.equal(report.totalCalls, 1);
  const api = report.remoteApis[0];
  assert.ok(api.includes('InvokeServer'));
});

test('luau.anti_pattern_detector detects uncached GetService in loops', () => {
  const report = detectAntiPatterns([
    'while true do',
    '    game:GetService("Players").LocalPlayer',
    '    task.wait(1)',
    'end',
  ].join('\n'), 'test.lua');
  const getservicePattern = report.findings.find(f => f.pattern === 'getservice-in-loop');
  assert.ok(getservicePattern);
  assert.equal(getservicePattern.severity, 'high');
});

test('luau.anti_pattern_detector detects while true without task.wait', () => {
  const report = detectAntiPatterns([
    'while true do',
    '    print("looping")',
    'end',
  ].join('\n'), 'test.lua');
  const whilePattern = report.findings.find(f => f.pattern === 'unbounded-while-true');
  assert.ok(whilePattern);
  assert.equal(whilePattern.severity, 'critical');
});

test('luau.anti_pattern_detector detects implicit globals', () => {
  const report = detectAntiPatterns([
    'MyGlobal = 42',
    'SomeFlag = true',
  ].join('\n'), 'test.lua');
  const globalPattern = report.findings.find(f => f.pattern === 'implicit-global');
  assert.ok(globalPattern);
  // Severity is high, not medium
  assert.equal(globalPattern.severity, 'high');
});

test('luau.state_table_extractor finds state tables', () => {
  const report = extractStateTables([
    'local Settings = {',
    '    AutoFarm = false,',
    '    WalkSpeed = 16,',
    '    Theme = "dark",',
    '}',
  ].join('\n'), 'test.lua');
  assert.ok(report.tables.length >= 1);
  const settingsTable = report.tables.find(t => t.name === 'Settings');
  assert.ok(settingsTable);
  // Keys include the table ref + individual keys
  assert.ok(settingsTable.keys.length >= 2);
  // The AutoFarm key should be there
  const autoFarmKey = settingsTable.keys.find(k => k.name === 'AutoFarm');
  assert.ok(autoFarmKey);
  assert.ok(autoFarmKey.inferredType === 'boolean');
});

test('luau.state_table_extractor detects read/write access', () => {
  const report = extractStateTables([
    'local Config = { Value = 0 }',
    'Config.Value = 100',
    'print(Config.Value)',
  ].join('\n'), 'test.lua');
  const configTable = report.tables.find(t => t.name === 'Config');
  assert.ok(configTable);
  // Read/write tracked at table level
  assert.ok(configTable.readCount >= 1);
  assert.ok(configTable.writeCount >= 1);
  // Readers/writers have line refs
  assert.ok(configTable.readers.length >= 1);
  assert.ok(configTable.writers.length >= 1);
  assert.equal(configTable.writers[0].line, 2);
  assert.equal(configTable.readers[0].line, 3);
});

test('luau.ui_scaffold generates LibSixtyTen code from spec', () => {
  const spec = {
    tabs: [
      {
        name: 'Main',
        sections: [
          {
            name: 'Auto Farm',
            controls: [
              { type: 'toggle', label: 'Enabled', variable: 'autoFarm' },
              { type: 'slider', label: 'Speed', variable: 'farmSpeed', min: 1, max: 100, default: 50 },
              { type: 'dropdown', label: 'Mode', variable: 'farmMode', options: ['Nearest', 'Furthest', 'Lowest HP'] },
              { type: 'button', label: 'Teleport to NPC', variable: 'teleportBtn' },
            ],
          },
        ],
      },
    ],
  };
  const result = generateUiScaffold(spec);
  assert.ok(result.code.length > 100);
  // Check it generates Luau code structure
  assert.ok(result.code.includes('BuildToggle') || result.code.includes(':Toggle('));
  assert.ok(result.code.includes('BuildSlider') || result.code.includes(':Slider('));
  assert.ok(result.code.includes('BuildDropdown') || result.code.includes(':Dropdown('));
  assert.ok(result.code.includes('BuildButton') || result.code.includes(':Button('));
});

test('luau.ui_scaffold generates status paragraphs', () => {
  const spec = {
    tabs: [
      {
        name: 'Combat',
        sections: [
          {
            name: 'Auto Block',
            controls: [
              { type: 'toggle', label: 'Enabled', variable: 'autoBlock' },
            ],
          },
        ],
      },
    ],
  };
  const result = generateUiScaffold(spec);
  assert.ok(result.code.includes('BuildBasicStatus') || result.code.includes('BuildDetailedStatus') || result.code.includes('Status'));
  assert.ok(result.code.includes('TODO'));
});

test('luau.ui_scaffold handles empty spec gracefully', () => {
  const result = generateUiScaffold({ tabs: [] });
  assert.ok(result.code.length > 0);
  // Should not throw
  assert.ok(result);
});
