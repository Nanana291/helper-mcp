#!/usr/bin/env node
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { randomUUID } from 'node:crypto';
import process from 'node:process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListResourcesRequestSchema, ListToolsRequestSchema, ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getResources, getTools, handleTool, readResource, serverName, serverVersion } from './core.mjs';
import { resolveWorkspaceRoot } from './fs.mjs';

export function createHttpServer({ port, host }) {
  const workspaceRoot = resolveWorkspaceRoot();
  return startHttpServer({ port, host, workspaceRoot });
}

export function createMcpServer(workspaceRoot) {
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

  return server;
}

function startHttpServer({ port, host, workspaceRoot }) {
  const createSessionServer = () => createMcpServer(workspaceRoot);

  const transports = new Map();
  const app = createMcpExpressApp({ host });

  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    let session = sessionId ? transports.get(String(sessionId)) : undefined;

    try {
      if (session) {
        await session.transport.handleRequest(req, res, req.body);
        return;
      }

      if (!sessionId && isInitializeRequest(req.body)) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            transports.set(newSessionId, session);
          },
        });

        session = {
          server: createSessionServer(),
          transport,
        };

        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid) {
            transports.delete(sid);
          }
        };

        await session.server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }

      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Bad Request: No valid session ID provided',
        },
        id: null,
      });
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: error instanceof Error ? error.message : 'Internal server error',
          },
          id: null,
        });
      }
    }
  });

  app.get('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    if (!sessionId || !transports.get(String(sessionId))) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports.get(String(sessionId)).transport.handleRequest(req, res);
  });

  app.delete('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    if (!sessionId || !transports.get(String(sessionId))) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await transports.get(String(sessionId)).transport.handleRequest(req, res);
  });

  const httpServer = app.listen(port, host, () => {
    process.stdout.write(`helper-mcp HTTP listening on http://${host}:${port}/mcp\n`);
  });

  async function close() {
    for (const session of transports.values()) {
      await session.transport.close();
    }
    await new Promise((resolve) => httpServer.close(resolve));
  }

  return {
    httpServer,
    close,
    port,
    host,
  };
}
