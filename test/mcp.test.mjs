import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serverPath = path.join(repoRoot, 'src/index.mjs');

test('helper-mcp exposes compatibility aliases and resources', async () => {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [serverPath],
    cwd: repoRoot,
    env: {
      HELPER_MCP_ROOT: repoRoot,
    },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'helper-mcp-test', version: '1.0.0' });

  await client.connect(transport);
  try {
    const tools = await client.listTools();
    const toolNames = tools.tools.map((tool) => tool.name);

    assert.ok(toolNames.includes('healthcheck'));
    assert.ok(toolNames.includes('workspace_summary'));
    assert.ok(toolNames.includes('brain_snapshot'));
    assert.ok(toolNames.includes('brain_import'));
    assert.ok(toolNames.includes('brain_history'));
    assert.ok(toolNames.includes('brain_merge'));
    assert.ok(toolNames.includes('brain_graph'));
    assert.ok(toolNames.includes('brain_query_advanced'));
    assert.ok(toolNames.includes('brain_diff'));
    assert.ok(toolNames.includes('brain_findings'));
    assert.ok(toolNames.includes('brain_finding_history'));
    assert.ok(toolNames.includes('brain_finding_graph'));
    assert.ok(toolNames.includes('brain_finding_prune'));
    assert.ok(toolNames.includes('brain_link'));
    assert.ok(toolNames.includes('brain_archive'));
    assert.ok(toolNames.includes('brain_restore_diff'));
    assert.ok(toolNames.includes('brain_prune_duplicates'));
    assert.ok(toolNames.includes('luau_hotfix'));
    assert.ok(toolNames.includes('luau_decompile'));
    assert.ok(toolNames.includes('luau_repair'));
    assert.ok(toolNames.includes('luau_security_scan'));
    assert.ok(toolNames.includes('luau_performance_profile'));
    assert.ok(toolNames.includes('luau_dependencies'));
    assert.ok(toolNames.includes('luau_remotes'));
    assert.ok(toolNames.includes('luau_complexity'));
    assert.ok(toolNames.includes('luau_taint'));
    assert.ok(toolNames.includes('luau_flow'));
    assert.ok(toolNames.includes('luau_handlers'));
    assert.ok(toolNames.includes('luau_surface'));
    assert.ok(toolNames.includes('luau_refactor'));
    assert.ok(toolNames.includes('luau_findings'));
    assert.ok(toolNames.includes('luau_brain_sync'));
    assert.ok(toolNames.includes('luau_modulegraph'));
    assert.ok(toolNames.includes('luau_risk_score'));
    assert.ok(toolNames.includes('luau_diff_context'));
    assert.ok(toolNames.includes('luau_changelog'));
    assert.ok(toolNames.includes('luau_metrics'));
    assert.ok(toolNames.includes('luau_template'));
    assert.ok(toolNames.includes('workspace_diff'));
    assert.ok(toolNames.includes('workspace_rollback'));
    assert.ok(toolNames.includes('workspace_validate'));
    assert.ok(toolNames.includes('workspace_release_notes'));
    assert.ok(toolNames.includes('workspace_restore_snapshot'));
    assert.ok(toolNames.includes('workspace_baseline'));
    assert.ok(toolNames.includes('config_validate'));

    const resources = await client.listResources();
    const resourceUris = resources.resources.map((resource) => resource.uri);

    assert.ok(resourceUris.includes('helper://workspace/summary'));
    assert.ok(resourceUris.includes('helper://brain/snapshot'));
    assert.ok(resourceUris.includes('helper://luau/scan'));

    const brainResource = await client.readResource({ uri: 'helper://brain/snapshot' });
    const brainText = brainResource.contents.map((block) => block.text || '').join('\n');

    assert.match(brainText, /"kind": "helper-mcp-brain"/);

    const result = await client.callTool({ name: 'health_check', arguments: {} });
    const text = result.content.map((block) => block.text || '').join('\n');

    assert.match(text, /"ok": true/);
    assert.match(text, /"version": "0.6.2"/);
    assert.match(text, /"canonicalToolCount": 92/);
  } finally {
    await client.close?.();
    await transport.close();
  }
});
