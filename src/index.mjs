#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListResourcesRequestSchema, ListToolsRequestSchema, ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getResources, getTools, handleTool, readResource, serverName, serverVersion } from './core.mjs';
import { resolveWorkspaceRoot } from './fs.mjs';

const workspaceRoot = resolveWorkspaceRoot();
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

const transport = new StdioServerTransport();
await server.connect(transport);
