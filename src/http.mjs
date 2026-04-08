#!/usr/bin/env node
import process from 'node:process';
import { createHttpServer } from './http-server.mjs';

const port = Number(process.env.HELPER_MCP_PORT || process.argv[2] || 3333);
const host = process.env.HELPER_MCP_HOST || '127.0.0.1';

const { close } = createHttpServer({ port, host });

process.on('SIGINT', async () => {
  await close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await close();
  process.exit(0);
});
