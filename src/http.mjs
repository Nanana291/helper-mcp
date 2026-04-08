#!/usr/bin/env node
import { createServer } from 'node:http';
import process from 'node:process';
import { randomUUID } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListResourcesRequestSchema, ListToolsRequestSchema, ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getResources, getTools, handleTool, readResource, serverName, serverVersion } from './core.mjs';
import { resolveWorkspaceRoot } from './fs.mjs';

const workspaceRoot = resolveWorkspaceRoot();
const port = Number(process.env.HELPER_MCP_PORT || process.argv[2] || 3333);
const host = process.env.HELPER_MCP_HOST || '127.0.0.1';

const server = new Server(
  { name: serverName, version: serverVersion },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: getTools(),
}));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: getResources(workspaceRoot),
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  return readResource(workspaceRoot, request.params.uri);
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name: toolName, arguments: args = {} } = request.params;
  return handleTool(workspaceRoot, toolName, args);
});

const transports = new Map();

const httpServer = createServer(async (req, res) => {
  if (!req.url || !req.url.startsWith('/mcp')) {
    res.statusCode = 404;
    res.end('Not found');
    return;
  }

  const sessionId = req.headers['mcp-session-id'];
  let transport = sessionId ? transports.get(String(sessionId)) : undefined;

  try {
    if (!transport && req.method === 'POST') {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          transports.set(newSessionId, transport);
        },
      });
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) {
          transports.delete(sid);
        }
      };
      await server.connect(transport);
    }

    if (!transport) {
      res.statusCode = 400;
      res.end('Invalid or missing session ID');
      return;
    }

    await transport.handleRequest(req, res);
  } catch (error) {
    res.statusCode = 500;
    res.end(error instanceof Error ? error.message : 'Internal server error');
  }
});

httpServer.listen(port, host, () => {
  process.stdout.write(`helper-mcp HTTP listening on http://${host}:${port}/mcp\n`);
});

process.on('SIGINT', async () => {
  for (const transport of transports.values()) {
    await transport.close();
  }
  httpServer.close(() => process.exit(0));
});
