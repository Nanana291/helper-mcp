import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { buildConfigValidationMarkdown, validateConfigFile } from '../src/config.mjs';

test('config validation reports schema and value issues', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'helper-mcp-config-'));
  try {
    const config = path.join(root, 'config.json');
    writeFileSync(config, JSON.stringify({
      __ThemePreset: 'Default',
      Jump: true,
      Keybind: { Key: 'F', Mode: 'Toggle' },
      Tint: { Color: '#ffffff', Alpha: 0.5 },
      Invalid: { nope: true },
    }), 'utf8');

    const report = validateConfigFile(root, config);
    assert.equal(report.valid, false);
    assert.ok(report.issues.length > 0);
    assert.match(buildConfigValidationMarkdown(report), /Issues/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
