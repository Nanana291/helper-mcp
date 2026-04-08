#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { appendBrainNote, buildBrainSnapshot, loadBrainSnapshot, searchBrainNotes } from './brain.mjs';
import { analyzeLuauText, compareLuauFiles, formatLuauAnalysis, scanLuauWorkspace } from './luau.mjs';
import { readText, resolveWorkspaceRoot } from './fs.mjs';

const name = 'helper-mcp';
const version = '0.2.0';
const workspaceRoot = resolveWorkspaceRoot();

const server = new Server(
  { name, version },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  },
);

const toolDefinitions = [
  {
    canonicalName: 'healthcheck',
    aliases: ['healthcheck', 'health_check', 'ping'],
    description: 'Return a compatibility and health summary for the MCP server.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'workspace.summary',
    aliases: ['workspace.summary', 'workspace_summary'],
    description: 'Summarize the current workspace and Luau coverage.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.add',
    aliases: ['brain.add', 'brain_add'],
    description: 'Store a reusable lesson in the local helper brain.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        summary: { type: 'string' },
        scope: { type: 'string' },
        status: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        sourcePath: { type: 'string' },
        evidence: { type: 'string' },
      },
      required: ['title', 'summary'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.search',
    aliases: ['brain.search', 'brain_search'],
    description: 'Search local helper brain notes and workspace files.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'brain.snapshot',
    aliases: ['brain.snapshot', 'brain_snapshot'],
    description: 'Return the current local brain snapshot summary.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.scan',
    aliases: ['luau.scan', 'luau_scan'],
    description: 'Scan the workspace for Luau files and summarize their patterns.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.inspect',
    aliases: ['luau.inspect', 'luau_inspect'],
    description: 'Inspect a single Luau file for callbacks, remotes, state, UI, and risks.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
      },
      required: ['filePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.compare',
    aliases: ['luau.compare', 'luau_compare'],
    description: 'Compare a Luau file against a baseline file.',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string' },
        baselinePath: { type: 'string' },
      },
      required: ['filePath', 'baselinePath'],
      additionalProperties: false,
    },
  },
  {
    canonicalName: 'luau.note',
    aliases: ['luau.note', 'luau_note'],
    description: 'Store a Luau-specific lesson in the local helper brain.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        summary: { type: 'string' },
        sourcePath: { type: 'string' },
        tags: { type: 'array', items: { type: 'string' } },
        evidence: { type: 'string' },
      },
      required: ['title', 'summary'],
      additionalProperties: false,
    },
  },
];

const tools = [];
const canonicalToAliases = new Map();
const aliasToCanonical = new Map();

for (const definition of toolDefinitions) {
  canonicalToAliases.set(definition.canonicalName, definition.aliases.slice());
  for (const alias of definition.aliases) {
    aliasToCanonical.set(alias, definition.canonicalName);
    tools.push({
      name: alias,
      description: definition.description,
      inputSchema: definition.inputSchema,
    });
  }
}

const resourceDefinitions = [
  {
    uri: 'helper://workspace/summary',
    name: 'Workspace summary',
    description: 'Current workspace summary and Luau coverage.',
    mimeType: 'application/json',
    read: () => jsonText(workspaceSummary()),
  },
  {
    uri: 'helper://brain/snapshot',
    name: 'Brain snapshot',
    description: 'Current local brain snapshot.',
    mimeType: 'application/json',
    read: () => jsonText(buildBrainSnapshot(workspaceRoot)),
  },
  {
    uri: 'helper://luau/scan',
    name: 'Luau scan',
    description: 'Current Luau workspace scan.',
    mimeType: 'application/json',
    read: () => jsonText(scanLuauWorkspace(workspaceRoot)),
  },
];

const resourceByUri = new Map(resourceDefinitions.map((resource) => [resource.uri, resource]));

function jsonText(value) {
  return JSON.stringify(value, null, 2);
}

function textResult(text) {
  return {
    content: [
      {
        type: 'text',
        text,
      },
    ],
  };
}

function resourceResult(uri, text, mimeType = 'text/plain') {
  return {
    contents: [
      {
        uri,
        mimeType,
        text,
      },
    ],
  };
}

function workspaceSummary() {
  const scan = scanLuauWorkspace(workspaceRoot);
  return {
    workspaceRoot,
    helperRoot: '.helper-mcp',
    totalLuauFiles: scan.totalFiles,
    totalCallbacks: scan.totalCallbacks,
    totalRemotes: scan.totalRemotes,
    totalRisks: scan.totalRisks,
  };
}

function resolveToolName(requestedName) {
  return aliasToCanonical.get(requestedName) || requestedName;
}

function healthcheckPayload() {
  return {
    ok: true,
    name,
    version,
    workspaceRoot,
    toolCount: tools.length,
    canonicalToolCount: toolDefinitions.length,
    resourceCount: resourceDefinitions.length,
    canonicalTools: toolDefinitions.map((tool) => tool.canonicalName),
    aliasesByTool: Object.fromEntries(canonicalToAliases),
  };
}

function handleTool(requestedName, args) {
  const name = resolveToolName(requestedName);

  switch (name) {
    case 'healthcheck':
      return textResult(jsonText(healthcheckPayload()));
    case 'workspace.summary':
      return textResult(jsonText(workspaceSummary()));
    case 'brain.add': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title,
        summary: args.summary,
        scope: args.scope || 'workspace',
        status: args.status || 'candidate',
        tags: args.tags || [],
        sourcePath: args.sourcePath || '',
        evidence: args.evidence || '',
      });
      return textResult(jsonText({
        ok: true,
        message: 'Brain note stored.',
        counts: snapshot.counts,
      }));
    }
    case 'brain.search': {
      const hits = searchBrainNotes(workspaceRoot, args.query);
      return textResult(jsonText({
        query: args.query,
        hits,
      }));
    }
    case 'brain.snapshot': {
      const snapshot = loadBrainSnapshot(workspaceRoot);
      return textResult(jsonText(snapshot));
    }
    case 'luau.scan': {
      const scan = scanLuauWorkspace(workspaceRoot);
      return textResult(jsonText(scan));
    }
    case 'luau.inspect': {
      const filePath = String(args.filePath || '').trim();
      const resolved = filePath ? (path.isAbsolute(filePath) ? filePath : path.resolve(workspaceRoot, filePath)) : '';
      const report = analyzeLuauText(readText(resolved), resolved);
      return textResult(formatLuauAnalysis(report));
    }
    case 'luau.compare': {
      const report = compareLuauFiles(workspaceRoot, args.filePath, args.baselinePath);
      return textResult(jsonText(report));
    }
    case 'luau.note': {
      const snapshot = appendBrainNote(workspaceRoot, {
        title: args.title,
        summary: args.summary,
        scope: 'luau',
        status: 'active',
        tags: args.tags || ['luau'],
        sourcePath: args.sourcePath || '',
        evidence: args.evidence || '',
      });
      return textResult(jsonText({
        ok: true,
        message: 'Luau lesson stored.',
        counts: snapshot.counts,
      }));
    }
    default:
      throw new Error(`Unknown tool: ${requestedName}`);
  }
}

function readResource(uri) {
  const resource = resourceByUri.get(uri);
  if (!resource) {
    throw new Error(`Unknown resource: ${uri}`);
  }
  return resourceResult(resource.uri, resource.read(), resource.mimeType);
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: resourceDefinitions.map(({ read, ...resource }) => resource),
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  return readResource(request.params.uri);
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name: toolName, arguments: args = {} } = request.params;
  return handleTool(toolName, args);
});

const transport = new StdioServerTransport();
await server.connect(transport);
