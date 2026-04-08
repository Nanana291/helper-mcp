#!/usr/bin/env node
import { createServer } from 'node:http';
import net from 'node:net';
import process from 'node:process';
import localtunnel from 'localtunnel';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { randomUUID } from 'node:crypto';
import { createMcpServer } from './http-server.mjs';
import { resolveWorkspaceRoot } from './fs.mjs';

const startPort = Number(process.env.HELPER_MCP_PORT || 3333);
const host = process.env.HELPER_MCP_HOST || '0.0.0.0';
const workspaceRoot = resolveWorkspaceRoot();

const sessions = new Map();

async function findFreePort(startPort) {
  for (let candidate = startPort; candidate < startPort + 20; candidate += 1) {
    const available = await new Promise((resolve) => {
      const probe = net.createServer();
      probe.unref();
      probe.once('error', () => resolve(false));
      probe.listen(candidate, host, () => {
        probe.close(() => resolve(true));
      });
    });
    if (available) {
      return candidate;
    }
  }
  throw new Error(`No free port found starting at ${startPort}`);
}

const actualPort = await findFreePort(startPort);

const httpServer = createServer(async (req, res) => {
  if (!req.url || !req.url.startsWith('/mcp')) {
    res.statusCode = 404;
    res.end('Not found');
    return;
  }

  const sessionId = req.headers['mcp-session-id'];
  let session = sessionId ? sessions.get(String(sessionId)) : undefined;

  try {
    if (session) {
      await session.transport.handleRequest(req, res);
      return;
    }

    if (req.method === 'POST') {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          sessions.set(newSessionId, session);
        },
      });

      session = {
        server: createMcpServer(workspaceRoot),
        transport,
      };

      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) {
          sessions.delete(sid);
        }
      };

      await session.server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    res.statusCode = 400;
    res.end('Invalid or missing session ID');
  } catch (error) {
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Internal server error',
        },
        id: null,
      }));
    }
  }
});

httpServer.listen(actualPort, host, async () => {
  process.stdout.write(`helper-mcp HTTP listening on http://${host}:${actualPort}/mcp\n`);
  try {
    const tunnel = await localtunnel({ port: actualPort });
    process.stdout.write(`helper-mcp tunnel URL: ${tunnel.url}\n`);
    process.stdout.write(`Codex add command: codex mcp add helper-mcp --url ${tunnel.url}/mcp\n`);

    const shutdown = async () => {
      try {
        await tunnel.close();
      } catch {
        // ignore
      }
      try {
        await new Promise((resolve) => httpServer.close(resolve));
      } catch {
        // ignore
      }
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  } catch (error) {
    process.stderr.write(`Failed to open tunnel: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
});
