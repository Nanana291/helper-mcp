import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { analyzeLuauText, scanLuauWorkspace } from '../src/luau.mjs';

test('default Luau regex patterns stay quiet on benign snippets', () => {
  const benignSnippets = [
    'local value = 1\nreturn value\n',
    'local function greet(name)\n  return "hello " .. name\nend\n',
    'local data = { waitForIt = true, spawnPoint = 3 }\nreturn data\n',
    'print("FireServer is mentioned in text, not code")\n',
  ];

  for (const [index, snippet] of benignSnippets.entries()) {
    const report = analyzeLuauText(snippet, `benign-${index}.luau`);
    assert.equal(report.summary.riskCount, 0, `snippet ${index} should be clean`);
  }
});

test('workspace pattern overrides replace default risk detection', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-patterns-'));
  try {
    const helperDir = path.join(root, '.helper-mcp');
    const scriptPath = path.join(root, 'script.luau');
    mkdirSync(helperDir, { recursive: true });
    writeFileSync(scriptPath, 'legacyWait(0.2)\n', 'utf8');
    writeFileSync(path.join(helperDir, 'patterns.json'), JSON.stringify({
      risks: [
        { label: 'legacy-wait', pattern: '\\blegacyWait\\s*\\(' },
      ],
    }), 'utf8');

    const scan = scanLuauWorkspace(root);
    assert.equal(scan.totalFiles, 1);
    assert.equal(scan.files[0].categories.risks[0].label, 'legacy-wait');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
