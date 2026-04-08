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
    assert.match(text, /"canonicalToolCount": 16/);
  } finally {
    await client.close?.();
    await transport.close();
  }
});
