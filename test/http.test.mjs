import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

test('helper-mcp http transport starts and exposes tools', async () => {
  const port = 3334;
  const child = spawn('node', ['src/http.mjs'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      HELPER_MCP_PORT: String(port),
      HELPER_MCP_ROOT: process.cwd(),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const started = Promise.race([
    once(child.stdout, 'data'),
    once(child.stderr, 'data').then(([chunk]) => {
      throw new Error(String(chunk));
    }),
  ]);

  await started;

  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
  const client = new Client({ name: 'helper-mcp-http-test', version: '1.0.0' });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    assert.ok(tools.tools.length >= 9);
    assert.ok(tools.tools.some((tool) => tool.name === 'healthcheck'));
    assert.ok(tools.tools.some((tool) => tool.name === 'workspace_summary'));
  } finally {
    await client.close?.();
    await transport.close();
    child.kill('SIGTERM');
    await once(child, 'exit');
  }
});
