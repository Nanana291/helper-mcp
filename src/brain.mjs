import fs from 'node:fs';
import path from 'node:path';
import { normalizeText, readText, relative, walkFiles, writeText, toPosix } from './fs.mjs';

const STORE_DIR = '.helper-mcp/brain';

function brainPaths(root) {
  const base = path.join(root, STORE_DIR);
  return {
    dir: base,
    notes: path.join(base, 'notes.jsonl'),
    current: path.join(base, 'current.json'),
  };
}

function parseNoteLine(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function loadNotes(root) {
  const { notes } = brainPaths(root);
  if (!fs.existsSync(notes)) {
    return [];
  }
  return readText(notes)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseNoteLine)
    .filter(Boolean);
}

function summarizeNotes(notes) {
  const counts = {
    total: notes.length,
    byStatus: {},
    byTag: {},
  };

  for (const note of notes) {
    const status = String(note.status || 'candidate');
    counts.byStatus[status] = (counts.byStatus[status] || 0) + 1;
    for (const tag of Array.isArray(note.tags) ? note.tags : []) {
      const clean = String(tag || '').trim().toLowerCase();
      if (!clean) continue;
      counts.byTag[clean] = (counts.byTag[clean] || 0) + 1;
    }
  }

  return counts;
}

function rebuildCurrentSnapshot(root, notes) {
  const { current } = brainPaths(root);
  const snapshot = {
    kind: 'helper-mcp-brain',
    generatedAt: new Date().toISOString(),
    workspaceRoot: root,
    counts: summarizeNotes(notes),
    notes: notes.slice(-50),
  };
  writeText(current, `${JSON.stringify(snapshot, null, 2)}\n`);
  return snapshot;
}

export function appendBrainNote(root, note) {
  const { dir, notes } = brainPaths(root);
  const createdAt = new Date().toISOString();
  const normalized = {
    kind: 'helper-mcp-brain-note',
    id: String(note.id || `${createdAt}-${Math.random().toString(16).slice(2)}`),
    title: String(note.title || note.summary || 'Untitled note').trim(),
    summary: String(note.summary || note.title || '').trim(),
    scope: String(note.scope || 'workspace').trim(),
    status: String(note.status || 'candidate').trim().toLowerCase(),
    tags: Array.isArray(note.tags) ? note.tags.map(String).map((tag) => tag.trim()).filter(Boolean) : [],
    sourcePath: String(note.sourcePath || '').trim(),
    evidence: String(note.evidence || '').trim(),
    createdAt,
    updatedAt: createdAt,
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(notes, `${JSON.stringify(normalized)}\n`, 'utf8');
  return rebuildCurrentSnapshot(root, loadNotes(root));
}

export function listBrainNotes(root) {
  return loadNotes(root);
}

export function searchBrainNotes(root, query) {
  const normalizedQuery = normalizeText(query);
  if (!normalizedQuery) {
    return [];
  }

  const notes = loadNotes(root);
  const files = walkFiles(root, (filePath) => {
    const relativePath = toPosix(relative(root, filePath));
    return relativePath.endsWith('.lua') || relativePath.endsWith('.luau') || relativePath.endsWith('.md') || relativePath.endsWith('.json');
  });

  const hits = [];
  for (const note of notes) {
    const haystack = normalizeText([
      note.id,
      note.title,
      note.summary,
      note.scope,
      note.status,
      note.tags.join(' '),
      note.sourcePath,
      note.evidence,
    ].join(' '));
    if (haystack.includes(normalizedQuery)) {
      hits.push({
        type: 'note',
        id: note.id,
        title: note.title,
        scope: note.scope,
        status: note.status,
        summary: note.summary,
      });
    }
  }

  for (const file of files) {
    const text = normalizeText(readText(file));
    if (!text) continue;
    if (text.includes(normalizedQuery)) {
      hits.push({
        type: 'file',
        path: toPosix(relative(root, file)),
      });
    }
  }

  return hits;
}

export function loadBrainSnapshot(root) {
  const notes = loadNotes(root);
  return rebuildCurrentSnapshot(root, notes);
}

export function brainResourceText(root) {
  const snapshot = loadBrainSnapshot(root);
  const lines = [
    '# helper-mcp brain',
    '',
    `Workspace: ${snapshot.workspaceRoot}`,
    `Total notes: ${snapshot.counts.total}`,
    `Statuses: ${Object.entries(snapshot.counts.byStatus).map(([key, value]) => `${key}=${value}`).join(', ') || 'none'}`,
    '',
  ];

  for (const note of snapshot.notes.slice().reverse()) {
    lines.push(`- [${note.status}] ${note.title}`);
    lines.push(`  scope=${note.scope}`);
    if (note.sourcePath) {
      lines.push(`  source=${note.sourcePath}`);
    }
  }

  return lines.join('\n');
}

