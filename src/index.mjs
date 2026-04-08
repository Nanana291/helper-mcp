#!/usr/bin/env node
import process from 'node:process';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { appendBrainNote, loadBrainSnapshot, searchBrainNotes } from './brain.mjs';
import { analyzeLuauText, compareLuauFiles, formatLuauAnalysis, scanLuauWorkspace } from './luau.mjs';
import { readText, resolveWorkspaceRoot } from './fs.mjs';

const name = 'helper-mcp';
const version = '0.1.0';
const workspaceRoot = resolveWorkspaceRoot();

const server = new Server(
  { name, version },
  {
    capabilities: {
      tools: {},
    },
  },
);

const tools = [
  {
    name: 'workspace.summary',
    description: 'Summarize the current workspace and Luau coverage.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'brain.add',
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
    name: 'brain.search',
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
    name: 'brain.snapshot',
    description: 'Return the current local brain snapshot summary.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'luau.scan',
    description: 'Scan the workspace for Luau files and summarize their patterns.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'luau.inspect',
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
    name: 'luau.compare',
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
    name: 'luau.note',
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

function handleTool(name, args) {
  switch (name) {
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
      const resolved = filePath ? (filePath.startsWith('/') ? filePath : `${workspaceRoot}/${filePath}`) : '';
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
      throw new Error(`Unknown tool: ${name}`);
  }
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name: toolName, arguments: args = {} } = request.params;
  return handleTool(toolName, args);
});

const transport = new StdioServerTransport();
await server.connect(transport);
