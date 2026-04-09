import crypto from 'node:crypto';
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
    history: path.join(base, 'history.jsonl'),
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

function rebuildNotesFile(root, notes) {
  const { dir, notes: notesPath } = brainPaths(root);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(notesPath, notes.map((n) => JSON.stringify(n)).join('\n') + '\n', 'utf8');
}

function appendBrainHistory(root, event) {
  const { dir, history } = brainPaths(root);
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(history, `${JSON.stringify({
    kind: 'helper-mcp-brain-event',
    generatedAt: new Date().toISOString(),
    ...event,
  })}\n`, 'utf8');
}

function loadBrainHistoryEntries(root) {
  const { history } = brainPaths(root);
  if (!fs.existsSync(history)) {
    return [];
  }
  return readText(history)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function compareNoteText(a, b) {
  const left = normalizeText(`${a.title || ''} ${a.summary || ''} ${(Array.isArray(a.tags) ? a.tags : []).join(' ')} ${a.evidence || ''}`);
  const right = normalizeText(`${b.title || ''} ${b.summary || ''} ${(Array.isArray(b.tags) ? b.tags : []).join(' ')} ${b.evidence || ''}`);
  if (!left || !right) return 0;
  const leftTokens = new Set(left.split(/\s+/).filter(Boolean));
  const rightTokens = new Set(right.split(/\s+/).filter(Boolean));
  let overlap = 0;
  for (const token of leftTokens) {
    if (rightTokens.has(token)) overlap++;
  }
  return overlap / Math.max(leftTokens.size, rightTokens.size, 1);
}

function loadBrainEvents(root) {
  return loadBrainHistoryEntries(root);
}

export function deriveFindingNoteId(finding = {}) {
  const parts = [
    String(finding.command || finding.sourceCommand || '').trim().toLowerCase(),
    String(finding.filePath || finding.path || '').trim().toLowerCase(),
    String(finding.line || 0).trim(),
    String(finding.label || '').trim().toLowerCase(),
    String(finding.evidence || finding.text || '').trim().toLowerCase(),
  ];
  return crypto.createHash('sha256').update(parts.join('|'), 'utf8').digest('hex');
}

function normalizeFindingStatus(severity) {
  const value = String(severity || 'review').trim().toLowerCase();
  if (value === 'high' || value === 'critical') return 'active';
  if (value === 'review' || value === 'warning') return 'candidate';
  return 'candidate';
}

function normalizeFindingTags(finding) {
  const tags = Array.isArray(finding.tags) ? finding.tags : [];
  return [...new Set([
    'luau',
    'finding',
    String(finding.command || finding.sourceCommand || '').trim().toLowerCase(),
    String(finding.severity || 'review').trim().toLowerCase(),
    String(finding.label || '').trim().toLowerCase(),
    ...tags.map((tag) => String(tag).trim().toLowerCase()).filter(Boolean),
  ])].filter(Boolean);
}

export function appendBrainFindingHistory(root, event) {
  appendBrainHistory(root, {
    kind: 'helper-mcp-brain-finding-event',
    ...event,
  });
}

export function upsertBrainFindingNote(root, finding = {}) {
  const notes = loadNotes(root);
  const now = new Date().toISOString();
  const noteId = deriveFindingNoteId(finding);
  const existingIndex = notes.findIndex((note) => note.id === noteId || note.findingId === noteId);
  const existing = existingIndex >= 0 ? notes[existingIndex] : null;
  const sourceCommand = String(finding.command || finding.sourceCommand || '').trim();
  const severity = String(finding.severity || 'review').trim().toLowerCase();
  const confidence = Number(finding.confidence ?? finding.confidenceAverage ?? existing?.findingConfidence ?? 0);
  const title = String(finding.title || `${finding.label || 'finding'} @ ${finding.filePath || 'workspace'}:${finding.line || 0}`).trim();
  const summary = String(finding.summary || finding.evidence || finding.explanation || '').trim();
  const updatedNote = {
    kind: 'helper-mcp-brain-finding',
    id: noteId,
    findingId: noteId,
    sourceCommand,
    findingSeverity: severity,
    findingConfidence: Number.isFinite(confidence) ? Number(confidence.toFixed(2)) : 0,
    findingLabel: String(finding.label || '').trim(),
    sourcePath: String(finding.filePath || finding.path || '').trim(),
    line: Number(finding.line || 0),
    title,
    summary,
    evidence: String(finding.evidence || finding.text || summary || '').trim(),
    suggestedFix: String(finding.suggestedFix || finding.after || '').trim(),
    status: normalizeFindingStatus(severity),
    tags: normalizeFindingTags(finding),
    links: Array.isArray(existing?.links) ? existing.links.slice() : [],
    bridgeable: Boolean(finding.bridgeable !== false),
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    finding: {
      command: sourceCommand,
      filePath: String(finding.filePath || finding.path || '').trim(),
      line: Number(finding.line || 0),
      label: String(finding.label || '').trim(),
      severity,
      confidence: Number.isFinite(confidence) ? Number(confidence.toFixed(2)) : 0,
      bridgeable: Boolean(finding.bridgeable !== false),
    },
  };

  if (existingIndex >= 0) {
    notes[existingIndex] = { ...existing, ...updatedNote, createdAt: existing.createdAt || updatedNote.createdAt };
  } else {
    notes.push(updatedNote);
  }

  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  appendBrainFindingHistory(root, {
    action: existingIndex >= 0 ? 'bridge_update' : 'bridge_create',
    findingId: noteId,
    sourceCommand,
    before: existing,
    after: updatedNote,
  });
  return { ok: true, note: updatedNote, counts: snapshot.counts };
}

export function listBrainFindingNotes(root, { status, severity, command, filePath, label, limit = 50 } = {}) {
  let notes = loadNotes(root).filter((note) => note.kind === 'helper-mcp-brain-finding' || note.findingId);
  if (status) {
    const wanted = String(status).trim().toLowerCase();
    notes = notes.filter((note) => String(note.status || '').toLowerCase() === wanted);
  }
  if (severity) {
    const wanted = String(severity).trim().toLowerCase();
    notes = notes.filter((note) => String(note.findingSeverity || '').toLowerCase() === wanted);
  }
  if (command) {
    const wanted = String(command).trim().toLowerCase();
    notes = notes.filter((note) => String(note.sourceCommand || '').toLowerCase() === wanted);
  }
  if (filePath) {
    const wanted = String(filePath).trim();
    notes = notes.filter((note) => String(note.sourcePath || '').includes(wanted));
  }
  if (label) {
    const wanted = String(label).trim().toLowerCase();
    notes = notes.filter((note) => String(note.findingLabel || '').toLowerCase() === wanted);
  }
  return notes
    .sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')))
    .slice(0, Math.max(1, Number(limit) || 50));
}

function saveBrainGraphNotes(root, notes) {
  rebuildNotesFile(root, notes);
  return rebuildCurrentSnapshot(root, notes);
}

function buildNoteGraph(notes) {
  const nodes = notes.map((note) => ({
    id: note.id,
    title: note.title,
    scope: note.scope,
    status: note.status,
    tags: Array.isArray(note.tags) ? note.tags : [],
    sourcePath: note.sourcePath || '',
    updatedAt: note.updatedAt || note.createdAt || '',
  }));
  const edges = [];
  for (let i = 0; i < notes.length; i += 1) {
    for (let j = i + 1; j < notes.length; j += 1) {
      const left = notes[i];
      const right = notes[j];
      const similarity = compareNoteText(left, right);
      if (left.sourcePath && right.sourcePath && left.sourcePath === right.sourcePath) {
        edges.push({ from: left.id, to: right.id, relation: 'same-source', weight: 1 });
      } else if (similarity >= 0.45) {
        edges.push({ from: left.id, to: right.id, relation: 'similar', weight: Number(similarity.toFixed(2)) });
      }
      for (const link of Array.isArray(left.links) ? left.links : []) {
        if (link?.id === right.id) {
          edges.push({ from: left.id, to: right.id, relation: link.relation || 'linked', weight: 1 });
        }
      }
    }
  }
  return { nodes, edges };
}

export function summarizeBrainNotes(notes) {
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

export function buildBrainSnapshot(root, notes = loadNotes(root)) {
  return {
    kind: 'helper-mcp-brain',
    generatedAt: new Date().toISOString(),
    workspaceRoot: root,
    counts: summarizeBrainNotes(notes),
    notes: notes.slice(-50),
  };
}

function rebuildCurrentSnapshot(root, notes) {
  const { current } = brainPaths(root);
  const snapshot = buildBrainSnapshot(root, notes);
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
    links: Array.isArray(note.links) ? note.links.map((link) => ({
      id: String(link?.id || '').trim(),
      relation: String(link?.relation || 'related').trim(),
      linkedAt: String(link?.linkedAt || createdAt).trim(),
    })).filter((link) => link.id) : [],
    createdAt,
    updatedAt: createdAt,
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(notes, `${JSON.stringify(normalized)}\n`, 'utf8');
  appendBrainHistory(root, { action: 'append', note: normalized });
  return rebuildCurrentSnapshot(root, loadNotes(root));
}

export function promoteBrainNote(root, id, newStatus) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const before = notes[idx];
  notes[idx] = { ...notes[idx], status: String(newStatus || 'active').trim().toLowerCase(), updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  appendBrainHistory(root, { action: 'promote', noteId: id, before, after: notes[idx] });
  return { ok: true, note: notes[idx], counts: snapshot.counts };
}

export function tagBrainNote(root, id, tagsToAdd) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const existing = Array.isArray(notes[idx].tags) ? notes[idx].tags : [];
  const merged = [...new Set([...existing, ...tagsToAdd.map(String).map((t) => t.trim()).filter(Boolean)])];
  const before = notes[idx];
  notes[idx] = { ...notes[idx], tags: merged, updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  appendBrainHistory(root, { action: 'tag', noteId: id, before, after: notes[idx], tagsAdded: tagsToAdd });
  return { ok: true, note: notes[idx], counts: snapshot.counts };
}

export function listBrainNotes(root, { status, tag, limit = 50 } = {}) {
  let notes = loadNotes(root);
  if (status) {
    const s = String(status).trim().toLowerCase();
    notes = notes.filter((n) => n.status === s);
  }
  if (tag) {
    const t = String(tag).trim().toLowerCase();
    notes = notes.filter((n) => Array.isArray(n.tags) && n.tags.some((x) => x.toLowerCase() === t));
  }
  return notes.slice(-Math.max(1, Number(limit) || 50));
}

export function exportBrainToMarkdown(root) {
  const notes = loadNotes(root);
  const byScope = {};
  for (const note of notes) {
    const scope = note.scope || 'workspace';
    if (!byScope[scope]) byScope[scope] = [];
    byScope[scope].push(note);
  }

  const lines = [
    '# Brain Export',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Total notes: ${notes.length}`,
    '',
  ];

  for (const [scope, scopeNotes] of Object.entries(byScope).sort()) {
    lines.push(`## ${scope}`, '');
    for (const note of scopeNotes) {
      lines.push(`### ${note.title}`);
      lines.push(`- **Status:** ${note.status}`);
      lines.push(`- **Tags:** ${note.tags && note.tags.length ? note.tags.join(', ') : 'none'}`);
      if (note.sourcePath) lines.push(`- **Source:** ${note.sourcePath}`);
      lines.push('');
      lines.push(note.summary);
      if (note.evidence) {
        lines.push('');
        lines.push(`**Evidence:** ${note.evidence}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Improved search: tokenized, weighted field scoring, ranked results, file snippets.
 *
 * Weights: title=4, tags=3, summary=2, scope=1, evidence=1
 * Bonuses: exact phrase in title (+5), all tokens matched (+3)
 */
export function searchBrainNotes(root, query, { limit = 30 } = {}) {
  const tokens = normalizeText(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [];

  const notes = loadNotes(root);
  const files = walkFiles(root, (filePath) => {
    const rel = toPosix(relative(root, filePath));
    return rel.endsWith('.lua') || rel.endsWith('.luau') || rel.endsWith('.md') || rel.endsWith('.json');
  });

  const hits = [];

  // Score notes
  for (const note of notes) {
    const fields = {
      title: normalizeText(note.title),
      tags: normalizeText(Array.isArray(note.tags) ? note.tags.join(' ') : ''),
      summary: normalizeText(note.summary),
      scope: normalizeText(note.scope),
      evidence: normalizeText(note.evidence),
    };
    const weights = { title: 4, tags: 3, summary: 2, scope: 1, evidence: 1 };

    let score = 0;
    let matched = 0;
    for (const token of tokens) {
      let tokenHit = false;
      for (const [field, text] of Object.entries(fields)) {
        if (text.includes(token)) {
          score += weights[field];
          tokenHit = true;
        }
      }
      if (tokenHit) matched++;
    }

    // Exact phrase bonus
    if (tokens.length > 1 && fields.title.includes(normalizeText(query))) {
      score += 5;
    }
    // All-tokens match bonus
    if (matched === tokens.length) {
      score += 3;
    }

    if (score > 0) {
      hits.push({
        type: 'note',
        score,
        id: note.id,
        title: note.title,
        scope: note.scope,
        status: note.status,
        summary: note.summary,
        tags: note.tags,
        sourcePath: note.sourcePath,
      });
    }
  }

  // Score files with snippets
  for (const file of files) {
    const text = readText(file);
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    let score = 0;
    let matched = 0;
    let snippet = '';
    let snippetLine = 0;

    for (let i = 0; i < lines.length; i++) {
      const normalized = normalizeText(lines[i]);
      let lineHit = false;
      for (const token of tokens) {
        if (normalized.includes(token)) {
          score++;
          lineHit = true;
        }
      }
      if (lineHit && !snippet) {
        snippet = lines[i].trim().slice(0, 120);
        snippetLine = i + 1;
      }
    }

    for (const token of tokens) {
      if (normalizeText(text).includes(token)) matched++;
    }
    if (matched === 0) continue;
    if (matched === tokens.length && tokens.length > 1) score += 2;

    hits.push({
      type: 'file',
      score,
      path: toPosix(relative(root, file)),
      snippet,
      snippetLine,
    });
  }

  return hits.sort((a, b) => b.score - a.score).slice(0, Math.max(1, Number(limit) || 30));
}

export function loadBrainSnapshot(root) {
  const notes = loadNotes(root);
  return rebuildCurrentSnapshot(root, notes);
}

export function brainHistory(root, { noteId = '', limit = 100 } = {}) {
  const { history } = brainPaths(root);
  if (!fs.existsSync(history)) {
    return { total: 0, events: [] };
  }
  const entries = readText(history)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .filter((entry) => !noteId || entry.noteId === noteId || entry.note?.id === noteId || entry.before?.id === noteId || entry.after?.id === noteId)
    .sort((a, b) => {
      const left = String(a.after?.updatedAt || a.note?.updatedAt || a.before?.updatedAt || a.generatedAt || '');
      const right = String(b.after?.updatedAt || b.note?.updatedAt || b.before?.updatedAt || b.generatedAt || '');
      return right.localeCompare(left);
    });

  return {
    total: entries.length,
    events: entries.slice(-Math.max(1, Number(limit) || 100)).map((entry) => ({
      generatedAt: entry.generatedAt,
      action: entry.action,
      noteId: entry.noteId || entry.note?.id || entry.after?.id || entry.before?.id || '',
      beforeStatus: entry.before?.status || '',
      afterStatus: entry.after?.status || entry.note?.status || '',
      beforeUpdatedAt: entry.before?.updatedAt || '',
      afterUpdatedAt: entry.after?.updatedAt || entry.note?.updatedAt || '',
      title: entry.after?.title || entry.note?.title || entry.before?.title || '',
      note: entry.note || entry.after || entry.before || null,
      tagsAdded: entry.tagsAdded || [],
    })),
  };
}

function scoreFindingNote(note, query = '') {
  const needle = normalizeText(query);
  if (!needle) return 0;
  const haystack = normalizeText([
    note.title,
    note.summary,
    note.evidence,
    note.findingLabel,
    note.sourceCommand,
    note.sourcePath,
    ...(Array.isArray(note.tags) ? note.tags : []),
  ].join(' '));
  let score = 0;
  for (const token of needle.split(/\s+/).filter(Boolean)) {
    if (haystack.includes(token)) score += 2;
  }
  if (normalizeText(note.title).includes(needle)) score += 4;
  if (normalizeText(note.summary).includes(needle)) score += 3;
  return score;
}

export function queryBrainFindingNotes(root, {
  query = '',
  severity,
  status,
  command,
  filePath,
  label,
  limit = 50,
} = {}) {
  let notes = listBrainFindingNotes(root, { severity, status, command, filePath, label, limit: Math.max(1, Number(limit) || 50) });
  const scored = notes.map((note) => ({
    ...note,
    score: scoreFindingNote(note, query),
  })).filter((note) => note.score > 0 || !String(query || '').trim());
  return {
    query,
    total: scored.length,
    notes: scored
      .sort((a, b) => b.score - a.score || String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')))
      .slice(0, Math.max(1, Number(limit) || 50)),
  };
}

export function brainFindingHistory(root, { noteId = '', filePath = '', command = '', severity = '', limit = 100 } = {}) {
  const events = loadBrainHistoryEntries(root)
    .filter((entry) => entry.kind === 'helper-mcp-brain-finding-event' || entry.action?.startsWith('bridge_'))
    .filter((entry) => !noteId || entry.findingId === noteId || entry.noteId === noteId || entry.after?.id === noteId || entry.before?.id === noteId)
    .filter((entry) => !filePath || entry.after?.sourcePath === filePath || entry.before?.sourcePath === filePath || entry.note?.sourcePath === filePath)
    .filter((entry) => !command || entry.sourceCommand === command || entry.after?.sourceCommand === command || entry.before?.sourceCommand === command)
    .filter((entry) => !severity || String(entry.after?.findingSeverity || entry.before?.findingSeverity || '').toLowerCase() === String(severity).toLowerCase())
    .sort((a, b) => String(b.generatedAt || '').localeCompare(String(a.generatedAt || '')));

  return {
    total: events.length,
    events: events.slice(0, Math.max(1, Number(limit) || 100)).map((entry) => ({
      generatedAt: entry.generatedAt,
      action: entry.action,
      findingId: entry.findingId || entry.noteId || entry.after?.id || entry.before?.id || '',
      sourceCommand: entry.sourceCommand || entry.after?.sourceCommand || entry.before?.sourceCommand || '',
      filePath: entry.after?.sourcePath || entry.before?.sourcePath || entry.note?.sourcePath || '',
      severity: entry.after?.findingSeverity || entry.before?.findingSeverity || entry.note?.findingSeverity || '',
      label: entry.after?.findingLabel || entry.before?.findingLabel || entry.note?.findingLabel || '',
      status: entry.after?.status || entry.before?.status || entry.note?.status || '',
      note: entry.after || entry.note || entry.before || null,
    })),
  };
}

export function buildBrainFindingGraph(root, { limit = 100 } = {}) {
  const findingNotes = listBrainFindingNotes(root, { limit: Math.max(1, Number(limit) || 100) });
  const regularNotes = loadNotes(root);
  const nodes = new Map();
  const edges = [];

  for (const note of findingNotes) {
    nodes.set(note.id, {
      id: note.id,
      kind: 'finding',
      title: note.title,
      status: note.status,
      severity: note.findingSeverity,
      sourceCommand: note.sourceCommand,
      sourcePath: note.sourcePath,
      label: note.findingLabel,
    });
  }

  for (const note of regularNotes) {
    if (!note.sourcePath) continue;
    if (!findingNotes.some((finding) => finding.sourcePath === note.sourcePath)) continue;
    nodes.set(note.id, {
      id: note.id,
      kind: 'note',
      title: note.title,
      status: note.status,
      sourcePath: note.sourcePath,
    });
  }

  const allNotes = [...findingNotes, ...regularNotes.filter((note) => note.sourcePath && findingNotes.some((finding) => finding.sourcePath === note.sourcePath))];
  for (let i = 0; i < allNotes.length; i += 1) {
    for (let j = i + 1; j < allNotes.length; j += 1) {
      const left = allNotes[i];
      const right = allNotes[j];
      if (left.id === right.id) continue;
      if (left.sourcePath && right.sourcePath && left.sourcePath === right.sourcePath) {
        edges.push({ from: left.id, to: right.id, relation: 'same-source', weight: 1 });
      }
      if (left.findingLabel && right.findingLabel && left.findingLabel === right.findingLabel) {
        edges.push({ from: left.id, to: right.id, relation: 'same-label', weight: 1 });
      }
      if (left.sourceCommand && right.sourceCommand && left.sourceCommand === right.sourceCommand) {
        edges.push({ from: left.id, to: right.id, relation: 'same-command', weight: 1 });
      }
      for (const link of Array.isArray(left.links) ? left.links : []) {
        if (link?.id === right.id) {
          edges.push({ from: left.id, to: right.id, relation: link.relation || 'linked', weight: 1 });
        }
      }
    }
  }

  return {
    summary: {
      totalNodes: nodes.size,
      totalEdges: edges.length,
      findingNodes: findingNotes.length,
      regularNodes: nodes.size - findingNotes.length,
    },
    nodes: [...nodes.values()],
    edges,
  };
}

export function pruneBrainFindingNotes(root, { apply = false, limit = 10, threshold = 0.7 } = {}) {
  const notes = listBrainFindingNotes(root, { limit: Math.max(1, Number(limit) || 10) });
  const buckets = new Map();
  for (const note of notes) {
    const key = [note.sourceCommand, note.sourcePath, note.findingLabel].map((part) => normalizeText(part)).join('|');
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(note);
  }

  const suggestions = [];
  const removedIds = [];
  for (const group of buckets.values()) {
    if (group.length < 2) continue;
    const sorted = group.slice().sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
    const keep = sorted[0];
    const drop = sorted.slice(1);
    suggestions.push({
      keepId: keep.id,
      keepTitle: keep.title,
      dropIds: drop.map((note) => note.id),
      sourcePath: keep.sourcePath,
      findingLabel: keep.findingLabel,
      score: 1,
    });
    removedIds.push(...drop.map((note) => note.id));
  }

  if (apply && removedIds.length > 0) {
    const remaining = loadNotes(root).filter((note) => !removedIds.includes(note.id));
    rebuildNotesFile(root, remaining);
    rebuildCurrentSnapshot(root, remaining);
    appendBrainFindingHistory(root, { action: 'finding_prune', removedIds, keptIds: suggestions.map((entry) => entry.keepId), threshold });
  }

  return {
    ok: true,
    total: suggestions.length,
    suggestions,
    removedIds,
    threshold,
    applied: apply && removedIds.length > 0,
  };
}

export function buildBrainGraph(root, { limit = 100 } = {}) {
  const notes = loadNotes(root).slice(-Math.max(1, Number(limit) || 100));
  const graph = buildNoteGraph(notes);
  return {
    summary: {
      totalNodes: graph.nodes.length,
      totalEdges: graph.edges.length,
      linkedNodes: graph.edges.filter((edge) => edge.relation === 'linked').length,
      similarNodes: graph.edges.filter((edge) => edge.relation === 'similar').length,
    },
    nodes: graph.nodes,
    edges: graph.edges,
  };
}

export function queryBrainAdvanced(root, query = '', { status, scope, tag, from, to, limit = 50 } = {}) {
  const needle = normalizeText(query);
  let notes = loadNotes(root);
  if (status) {
    const wanted = String(status).trim().toLowerCase();
    notes = notes.filter((note) => String(note.status || '').toLowerCase() === wanted);
  }
  if (scope) {
    const wanted = String(scope).trim().toLowerCase();
    notes = notes.filter((note) => String(note.scope || '').toLowerCase() === wanted);
  }
  if (tag) {
    const wanted = String(tag).trim().toLowerCase();
    notes = notes.filter((note) => Array.isArray(note.tags) && note.tags.some((entry) => String(entry).toLowerCase() === wanted));
  }
  if (from) {
    const fromTime = new Date(from).getTime();
    if (!Number.isNaN(fromTime)) {
      notes = notes.filter((note) => new Date(note.updatedAt || note.createdAt || 0).getTime() >= fromTime);
    }
  }
  if (to) {
    const toTime = new Date(to).getTime();
    if (!Number.isNaN(toTime)) {
      notes = notes.filter((note) => new Date(note.updatedAt || note.createdAt || 0).getTime() <= toTime);
    }
  }

  const scored = notes.map((note) => {
    const haystack = normalizeText([note.title, note.summary, note.evidence, note.scope, ...(Array.isArray(note.tags) ? note.tags : [])].join(' '));
    let score = 0;
    if (needle && haystack.includes(needle)) score += 5;
    if (needle && normalizeText(note.title).includes(needle)) score += 4;
    if (needle && normalizeText(note.summary).includes(needle)) score += 3;
    if (needle && normalizeText(note.evidence).includes(needle)) score += 2;
    if (needle && Array.isArray(note.tags) && note.tags.some((entry) => normalizeText(entry).includes(needle))) score += 3;
    if (String(note.status || '').toLowerCase() === 'active') score += 1;
    if (String(note.status || '').toLowerCase() === 'archived') score -= 1;
    return { ...note, score };
  }).filter((note) => note.score > 0 || !needle);

  return {
    query,
    total: scored.length,
    notes: scored.sort((a, b) => b.score - a.score || String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))).slice(0, Math.max(1, Number(limit) || 50)),
  };
}

export function linkBrainNotes(root, fromId, toId, relation = 'related') {
  const notes = loadNotes(root);
  const fromIdx = notes.findIndex((note) => note.id === fromId);
  const toIdx = notes.findIndex((note) => note.id === toId);
  if (fromIdx === -1) return { ok: false, error: `Note not found: ${fromId}` };
  if (toIdx === -1) return { ok: false, error: `Note not found: ${toId}` };

  const linkedAt = new Date().toISOString();
  const relationName = String(relation || 'related').trim() || 'related';
  const linkEntry = { id: toId, relation: relationName, linkedAt };
  const backLink = { id: fromId, relation: relationName, linkedAt };
  const fromLinks = Array.isArray(notes[fromIdx].links) ? notes[fromIdx].links.slice() : [];
  const toLinks = Array.isArray(notes[toIdx].links) ? notes[toIdx].links.slice() : [];
  if (!fromLinks.some((link) => link.id === toId)) fromLinks.push(linkEntry);
  if (!toLinks.some((link) => link.id === fromId)) toLinks.push(backLink);
  notes[fromIdx] = { ...notes[fromIdx], links: fromLinks, updatedAt: linkedAt };
  notes[toIdx] = { ...notes[toIdx], links: toLinks, updatedAt: linkedAt };
  saveBrainGraphNotes(root, notes);
  appendBrainHistory(root, { action: 'link', fromId, toId, relation: relationName });
  return { ok: true, from: notes[fromIdx], to: notes[toIdx] };
}

export function archiveBrainNote(root, id, { reason = '' } = {}) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((note) => note.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const archivedAt = new Date().toISOString();
  const before = notes[idx];
  notes[idx] = { ...notes[idx], status: 'archived', archivedAt, archivedReason: String(reason || '').trim(), updatedAt: archivedAt };
  saveBrainGraphNotes(root, notes);
  appendBrainHistory(root, { action: 'archive', noteId: id, before, after: notes[idx], reason: String(reason || '').trim() });
  return { ok: true, note: notes[idx] };
}

export function restoreBrainDiff(root, snapshotPath) {
  const current = buildBrainSnapshot(root);
  const resolved = path.isAbsolute(snapshotPath) ? snapshotPath : path.resolve(root, snapshotPath);
  if (!fs.existsSync(resolved)) {
    return { ok: false, error: `Snapshot not found: ${snapshotPath}` };
  }
  let snapshot;
  try {
    snapshot = JSON.parse(readText(resolved));
  } catch {
    return { ok: false, error: `Snapshot is not valid JSON: ${snapshotPath}` };
  }
  const currentById = new Map((current.notes || []).map((note) => [note.id, note]));
  const snapshotById = new Map((snapshot.notes || []).map((note) => [note.id, note]));
  const added = [];
  const removed = [];
  const changed = [];

  for (const note of current.notes || []) {
    if (!snapshotById.has(note.id)) {
      added.push({ id: note.id, title: note.title });
    } else {
      const previous = snapshotById.get(note.id);
      if (previous.status !== note.status || previous.title !== note.title || previous.summary !== note.summary) {
        changed.push({ id: note.id, before: previous, after: note });
      }
    }
  }
  for (const note of snapshot.notes || []) {
    if (!currentById.has(note.id)) {
      removed.push({ id: note.id, title: note.title });
    }
  }

  return {
    ok: true,
    snapshotPath: toPosix(snapshotPath),
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      snapshotCount: (snapshot.notes || []).length,
      currentCount: (current.notes || []).length,
    },
    added,
    removed,
    changed,
  };
}

export function diffBrainSnapshot(root, snapshotPath) {
  return restoreBrainDiff(root, snapshotPath);
}

export function pruneDuplicateBrainNotes(root, { apply = false, limit = 10, threshold = 0.7 } = {}) {
  const notes = loadNotes(root);
  const candidates = [];
  for (let i = 0; i < notes.length; i += 1) {
    for (let j = i + 1; j < notes.length; j += 1) {
      const similarity = compareNoteText(notes[i], notes[j]);
      if (similarity >= threshold) {
        candidates.push({
          keepId: notes[i].id,
          dropId: notes[j].id,
          keepTitle: notes[i].title,
          dropTitle: notes[j].title,
          similarity: Number(similarity.toFixed(2)),
        });
      }
    }
  }
  const suggestions = candidates.sort((a, b) => b.similarity - a.similarity).slice(0, Math.max(1, Number(limit) || 10));
  if (!apply) {
    return { ok: true, mode: 'suggest', total: suggestions.length, suggestions };
  }

  const dropIds = new Set(suggestions.map((entry) => entry.dropId));
  const mergedNotes = notes.filter((note) => !dropIds.has(note.id));
  saveBrainGraphNotes(root, mergedNotes);
  appendBrainHistory(root, { action: 'prune', droppedIds: [...dropIds], keptIds: suggestions.map((entry) => entry.keepId) });
  return { ok: true, mode: 'applied', prunedCount: dropIds.size, remainingCount: mergedNotes.length };
}

function inferTagsFromText(text) {
  const source = normalizeText(text);
  const tags = [];
  const tagMap = [
    ['luau', /\bluau\b/],
    ['config', /\bconfig\b/],
    ['baseline', /\bbaseline\b/],
    ['regression', /\bregression\b/],
    ['security', /\bsecurity\b|\bwebhook\b|\btoken\b|\bbackdoor\b/],
    ['performance', /\bperformance\b|\bhot\s*loop\b|\bmemory leak\b/],
    ['dependency', /\bdependency\b|\brequire\b/],
    ['template', /\btemplate\b|\bscaffold\b/],
    ['analysis', /\banalysis\b|\bscan\b|\binspect\b/],
  ];

  for (const [tag, pattern] of tagMap) {
    if (pattern.test(source)) {
      tags.push(tag);
    }
  }

  return tags;
}

export function brainResourceText(root) {
  const snapshot = buildBrainSnapshot(root);
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

function inferImportedTags(text) {
  const source = normalizeText(text);
  const tags = [];
  const tagMap = [
    ['luau', /\bluau\b/],
    ['config', /\bconfig\b/],
    ['baseline', /\bbaseline\b/],
    ['regression', /\bregression\b/],
    ['security', /\bsecurity\b|\bwebhook\b|\btoken\b|\bbackdoor\b/],
    ['performance', /\bperformance\b|\bhot\s*loop\b|\bmemory leak\b/],
    ['dependency', /\bdependency\b|\brequire\b/],
    ['template', /\btemplate\b|\bscaffold\b/],
    ['analysis', /\banalysis\b|\bscan\b|\binspect\b/],
  ];
  for (const [tag, pattern] of tagMap) {
    if (pattern.test(source)) {
      tags.push(tag);
    }
  }
  return tags;
}

function parseImportSource(filePath) {
  const text = readText(filePath);
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.json') {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object') {
        const title = String(parsed.title || parsed.name || parsed.id || path.basename(filePath)).trim();
        const summary = String(parsed.summary || parsed.description || parsed.note || '').trim() || `Imported from ${path.basename(filePath)}`;
        return { title, summary, tags: inferImportedTags(`${title} ${summary} ${JSON.stringify(parsed)}`), evidence: text.trim(), sourcePath: toPosix(filePath) };
      }
    } catch {
      // fall through to text parsing
    }
  }

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const titleLine = lines.find((line) => /^#{1,3}\s+/.test(line)) || lines[0] || path.basename(filePath);
  const title = titleLine.replace(/^#{1,3}\s+/, '').trim();
  const summary = lines.slice(1, 6).join(' ').slice(0, 240) || `Imported from ${path.basename(filePath)}`;
  return {
    title,
    summary,
    tags: inferImportedTags(`${title} ${summary} ${text}`),
    evidence: lines.slice(0, 12).join('\n'),
    sourcePath: toPosix(filePath),
  };
}

export function importBrainNotes(root, sources = []) {
  const normalizedSources = (Array.isArray(sources) ? sources : [sources]).flat().filter(Boolean);
  const files = [];
  for (const source of normalizedSources) {
    const resolved = path.isAbsolute(source) ? source : path.resolve(root, source);
    if (!fs.existsSync(resolved)) {
      continue;
    }
    const stat = fs.statSync(resolved);
    if (stat.isFile()) {
      files.push(resolved);
    } else if (stat.isDirectory()) {
      files.push(...walkFiles(resolved, (filePath) => ['.md', '.json', '.txt'].includes(path.extname(filePath).toLowerCase())));
    }
  }

  const imported = [];
  for (const file of files) {
    const note = parseImportSource(file);
    const snapshot = appendBrainNote(root, {
      title: note.title,
      summary: note.summary,
      scope: 'workspace',
      status: 'candidate',
      tags: note.tags,
      sourcePath: note.sourcePath,
      evidence: note.evidence,
    });
    imported.push({
      filePath: toPosix(path.relative(root, file) || file),
      title: note.title,
      tags: note.tags,
      counts: snapshot.counts,
    });
  }
  appendBrainHistory(root, { action: 'import', imported: imported.map((entry) => entry.filePath) });

  return {
    importedCount: imported.length,
    imported,
  };
}

export function deleteBrainNote(root, id) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const removed = notes[idx];
  notes.splice(idx, 1);
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  appendBrainHistory(root, { action: 'delete', noteId: id, before: removed });
  return { ok: true, removed: { id: removed.id, title: removed.title }, counts: snapshot.counts };
}

export function updateBrainNote(root, id, fields = {}) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const allowed = ['title', 'summary', 'evidence', 'scope'];
  const updates = {};
  for (const key of allowed) {
    if (fields[key] !== undefined) updates[key] = String(fields[key]).trim();
  }
  if (Object.keys(updates).length === 0) return { ok: false, error: 'No updatable fields provided (allowed: title, summary, evidence, scope).' };
  const before = notes[idx];
  notes[idx] = { ...notes[idx], ...updates, updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  appendBrainHistory(root, { action: 'update', noteId: id, before, after: notes[idx], fields: updates });
  return { ok: true, note: notes[idx], counts: snapshot.counts };
}

/**
 * Store a structured lesson in mistake→fix→rule format.
 * Automatically tagged as 'learned' and set to status 'active'.
 */
export function teachBrainLesson(root, { mistake, fix, rule, sourcePath, tags }) {
  if (!mistake || !fix || !rule) return { ok: false, error: 'mistake, fix, and rule are all required.' };
  const summary = `Mistake: ${String(mistake).trim()}\n\nFix: ${String(fix).trim()}\n\nRule: ${String(rule).trim()}`;
  const snapshot = appendBrainNote(root, {
    title: String(rule).trim(),
    summary,
    scope: 'learned',
    status: 'active',
    tags: ['learned', ...Array.isArray(tags) ? tags.map(String).map((t) => t.trim()).filter(Boolean) : []],
    sourcePath: String(sourcePath || '').trim(),
    evidence: String(mistake).trim(),
  });
  appendBrainHistory(root, { action: 'teach', noteId: snapshot?.notes?.at?.(-1)?.id || '', mistake: String(mistake).trim(), rule: String(rule).trim() });
  return { ok: true, message: 'Lesson stored.', counts: snapshot.counts };
}

export function mergeBrainNotes(root, { noteId = '', mergeIds = [], apply = false, limit = 5 } = {}) {
  const notes = loadNotes(root);
  const primary = noteId ? notes.find((note) => note.id === noteId) : null;
  if (noteId && !primary) {
    return { ok: false, error: `Note not found: ${noteId}` };
  }

  const candidates = primary
    ? notes
        .filter((note) => note.id !== primary.id)
        .map((note) => ({ ...note, similarity: compareNoteText(primary, note) }))
        .filter((note) => note.similarity > 0)
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, Math.max(1, Number(limit) || 5))
    : notes
        .flatMap((note) => notes
          .filter((other) => other.id !== note.id)
          .map((other) => ({ source: note, target: other, similarity: compareNoteText(note, other) })))
        .filter((pair) => pair.similarity > 0.5)
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, Math.max(1, Number(limit) || 5));

  if (apply && (!primary || mergeIds.length === 0)) {
    return { ok: false, error: 'apply requires noteId and mergeIds.' };
  }

  if (!apply || !primary || mergeIds.length === 0) {
    return {
      ok: true,
      mode: 'suggest',
      primaryId: primary?.id || '',
      candidates,
    };
  }

  const ids = new Set([primary.id, ...mergeIds.map(String)]);
  const selected = notes.filter((note) => ids.has(note.id));
  if (selected.length < 2) {
    return { ok: false, error: 'Need at least two notes to merge.' };
  }

  const mergedTags = [...new Set(selected.flatMap((note) => Array.isArray(note.tags) ? note.tags : []))];
  const mergedSummary = selected.map((note) => note.summary).filter(Boolean).join('\n\n');
  const mergedEvidence = selected.map((note) => note.evidence).filter(Boolean).join('\n\n');
  const mergedSource = selected.map((note) => note.sourcePath).find(Boolean) || '';
  const mergedNote = {
    ...primary,
    summary: mergedSummary || primary.summary,
    evidence: mergedEvidence || primary.evidence,
    tags: mergedTags,
    sourcePath: mergedSource,
    updatedAt: new Date().toISOString(),
  };

  const mergedNotes = notes
    .filter((note) => !ids.has(note.id))
    .concat(mergedNote);
  rebuildNotesFile(root, mergedNotes);
  const snapshot = rebuildCurrentSnapshot(root, mergedNotes);
  appendBrainHistory(root, { action: 'merge', primaryId: primary.id, mergedIds: mergeIds, after: mergedNote });

  return {
    ok: true,
    mode: 'merged',
    primary: mergedNote,
    mergedIds: mergeIds,
    counts: snapshot.counts,
  };
}

// ── Findings Tracker ─────────────────────────────────────────────────────────

const FINDINGS_FILE = 'findings.jsonl';

function findingsPath(root) {
  const dir = path.join(root, STORE_DIR);
  fs.mkdirSync(dir, { recursive: true });
  return { dir, file: path.join(dir, FINDINGS_FILE) };
}

function loadFindings(root) {
  const { file } = findingsPath(root);
  if (!fs.existsSync(file)) return [];
  return readText(file)
    .split(/\r?\n/)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

function saveFindings(root, findings) {
  const { file } = findingsPath(root);
  fs.writeFileSync(file, findings.map(f => JSON.stringify(f)).join('\n') + '\n', 'utf8');
}

export function addBrainFinding(root, finding) {
  const findings = loadFindings(root);
  const entry = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    file: String(finding.file || '').trim(),
    line: finding.line || 0,
    severity: String(finding.severity || 'info').toLowerCase(),
    rule: String(finding.rule || '').trim(),
    message: String(finding.message || finding.summary || '').trim(),
    status: 'open',
    source: String(finding.source || 'manual').trim(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  findings.push(entry);
  saveFindings(root, findings);
  return { ok: true, finding: entry, total: findings.length };
}

export function listBrainFindings(root, { status, severity, file, limit = 50 } = {}) {
  let findings = loadFindings(root);
  if (status) findings = findings.filter(f => f.status === String(status).toLowerCase());
  if (severity) findings = findings.filter(f => f.severity === String(severity).toLowerCase());
  if (file) findings = findings.filter(f => f.file && f.file.toLowerCase().includes(String(file).toLowerCase()));
  return findings.slice(-Math.max(1, Number(limit) || 50));
}

export function updateBrainFinding(root, id, fields = {}) {
  const findings = loadFindings(root);
  const idx = findings.findIndex(f => f.id === id);
  if (idx === -1) return { ok: false, error: `Finding not found: ${id}` };
  const allowed = ['status', 'message', 'severity'];
  for (const key of allowed) {
    if (fields[key] !== undefined) findings[idx][key] = String(fields[key]).trim();
  }
  findings[idx].updatedAt = new Date().toISOString();
  saveFindings(root, findings);
  return { ok: true, finding: findings[idx] };
}

export function brainFindingStats(root) {
  const findings = loadFindings(root);
  const byStatus = {};
  const bySeverity = {};
  const byFile = {};
  for (const f of findings) {
    byStatus[f.status] = (byStatus[f.status] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    if (f.file) byFile[f.file] = (byFile[f.file] || 0) + 1;
  }
  return {
    total: findings.length,
    byStatus,
    bySeverity,
    topFiles: Object.entries(byFile).sort((a, b) => b[1] - a[1]).slice(0, 10),
  };
}

// ── Auto-Capture from Analysis ───────────────────────────────────────────────

function buildTitleFromAnalysis(result) {
  const { type, data, filePath } = result;
  const fileName = filePath ? path.basename(filePath) : 'unknown';

  switch (type) {
    case 'scan':
      return `Luau scan: ${fileName} — ${data.callbackCount || 0} callbacks, ${data.remoteCount || 0} remotes, ${data.riskCount || 0} risks`;
    case 'inspect': {
      const keyFinding = data.keyFinding || data.finding || data.summary || 'inspection complete';
      return `Analysis: ${fileName} — ${keyFinding}`;
    }
    case 'audit': {
      const issue = data.issue || data.finding || data.summary || 'audit complete';
      return `Audit finding: ${fileName} — ${issue}`;
    }
    case 'risk': {
      const riskLabel = data.label || data.risk || data.finding || 'risk detected';
      const line = data.line || 0;
      return `Risk: ${fileName} — ${riskLabel} at line ${line}`;
    }
    case 'security': {
      const findingLabel = data.label || data.finding || data.summary || 'security issue';
      return `Security: ${fileName} — ${findingLabel}`;
    }
    case 'performance': {
      const findingLabel = data.label || data.finding || data.summary || 'performance issue';
      return `Performance: ${fileName} — ${findingLabel}`;
    }
    case 'migration': {
      const oldName = data.oldName || data.source || 'unknown';
      const newName = data.newName || data.target || 'unknown';
      const verdict = data.verdict || data.status || 'migration analysis';
      return `Migration: ${oldName} → ${newName} — ${verdict}`;
    }
    default:
      return `Analysis: ${fileName} — ${data.summary || data.finding || type}`;
  }
}

function inferTagsFromAnalysis(result) {
  const { type, data, filePath } = result;
  const tags = new Set();
  const ext = filePath ? path.extname(filePath).toLowerCase() : '';

  // File type tags
  if (ext === '.lua' || ext === '.luau') {
    tags.add('luau');
  }

  // Analysis type tag
  if (type) {
    tags.add(type);
  }

  // Severity tags from data
  const severity = String(data.severity || data.riskLevel || '').toLowerCase();
  if (severity.includes('high') || severity.includes('critical')) {
    tags.add('high-risk');
  } else if (severity.includes('medium') || severity.includes('moderate')) {
    tags.add('medium-risk');
  } else if (severity.includes('low') || severity === 'info') {
    tags.add('low-risk');
  }

  // Structural tags from data
  if (data.callbackCount || data.callbacks) tags.add('callbacks');
  if (data.remoteCount || data.remotes) tags.add('remotes');
  if (data.esp || data.espDetected) tags.add('esp');
  if (data.ui || data.uiElements) tags.add('ui');
  if (data.riskCount || data.risks) tags.add('risk');
  if (data.security || data.securityIssue) tags.add('security');
  if (data.performance || data.performanceIssue) tags.add('performance');

  // Merge with any tags already in data
  if (Array.isArray(data.tags)) {
    for (const tag of data.tags) {
      tags.add(String(tag).trim().toLowerCase());
    }
  }

  // Fallback tag
  if (tags.size === 0) {
    tags.add('analysis');
  }

  return [...tags];
}

function buildSummaryFromAnalysis(result) {
  const { type, data } = result;
  const parts = [];

  if (data.summary) parts.push(data.summary);
  if (data.finding) parts.push(data.finding);
  if (data.evidence) parts.push(data.evidence);
  if (data.details) parts.push(data.details);
  if (data.message) parts.push(data.message);

  // Add structured info for scan types
  if (type === 'scan') {
    if (data.callbackCount) parts.push(`Callbacks: ${data.callbackCount}`);
    if (data.remoteCount) parts.push(`Remotes: ${data.remoteCount}`);
    if (data.riskCount) parts.push(`Risks: ${data.riskCount}`);
  }

  if (data.suggestedFix) parts.push(`Suggested fix: ${data.suggestedFix}`);
  if (data.verdict) parts.push(`Verdict: ${data.verdict}`);

  return parts.join('\n\n') || `${type} analysis result`;
}

export function autoCaptureBrain(root, analysisResults, options = {}) {
  const {
    skipExisting = true,
    minConfidence = 0.3,
    autoTags = true,
    status = 'candidate',
    autoUpdate = false,
  } = options;

  if (!Array.isArray(analysisResults) || analysisResults.length === 0) {
    return { ok: true, summary: { totalProcessed: 0, created: 0, skipped: 0, updated: 0, similarityThreshold: 10 }, notes: [], brainNoteIds: [] };
  }

  const created = [];
  const skipped = [];
  const updated = [];
  const brainNoteIds = [];

  for (const result of analysisResults) {
    const { type, data, filePath } = result;
    if (!type || !data) {
      skipped.push({
        action: 'skipped',
        title: filePath || 'unknown',
        reason: 'Missing type or data fields',
      });
      continue;
    }

    const confidence = Number(data.confidence ?? data.confidenceAverage ?? 1);
    if (!Number.isFinite(confidence) || confidence < minConfidence) {
      skipped.push({
        action: 'skipped',
        title: filePath || 'unknown',
        reason: `Confidence ${confidence} below threshold ${minConfidence}`,
      });
      continue;
    }

    const title = buildTitleFromAnalysis(result);
    const summary = buildSummaryFromAnalysis(result);
    const tags = autoTags ? inferTagsFromAnalysis(result) : (Array.isArray(data.tags) ? data.tags : []);

    // Check for existing similar notes
    if (skipExisting) {
      const searchResults = searchBrainNotes(root, title, { limit: 5 });
      const similarHit = searchResults.find((hit) => hit.type === 'note' && hit.score > 10);

      if (similarHit) {
        if (autoUpdate) {
          // Update the existing note
          const noteUpdate = {
            title,
            summary,
          };
          const updateResult = updateBrainNote(root, similarHit.id, noteUpdate);
          if (updateResult.ok) {
            // Also update tags if needed
            if (autoTags && tags.length > 0) {
              tagBrainNote(root, similarHit.id, tags);
            }
            updated.push({
              action: 'updated',
              id: similarHit.id,
              title,
              reason: `Updated existing similar note (score: ${similarHit.score})`,
            });
            brainNoteIds.push(similarHit.id);
          } else {
            skipped.push({
              action: 'skipped',
              title,
              reason: `Similar note found (score: ${similarHit.score}) but update failed: ${updateResult.error}`,
            });
          }
        } else {
          skipped.push({
            action: 'skipped',
            title,
            reason: `Similar note exists with score ${similarHit.score} (threshold: 10), autoUpdate is false`,
          });
        }
        continue;
      }
    }

    // Create new note
    const snapshot = appendBrainNote(root, {
      title,
      summary,
      scope: type,
      status,
      tags,
      sourcePath: filePath || '',
      evidence: String(data.evidence || data.text || '').trim(),
    });

    const noteId = snapshot?.notes?.at?.(-1)?.id;
    created.push({
      action: 'created',
      id: noteId,
      title,
      reason: `New note created from ${type} analysis`,
    });
    if (noteId) brainNoteIds.push(noteId);
  }

  return {
    ok: true,
    summary: {
      totalProcessed: analysisResults.length,
      created: created.length,
      skipped: skipped.length,
      updated: updated.length,
      similarityThreshold: 10,
    },
    notes: [...created, ...skipped, ...updated],
    brainNoteIds,
  };
}

// ── Snapshot Comparison ──────────────────────────────────────────────────────

export function compareBrainSnapshots(root, snapshotPathA, snapshotPathB) {
  const resolvedA = path.isAbsolute(snapshotPathA) ? snapshotPathA : path.resolve(root, snapshotPathA);
  const resolvedB = path.isAbsolute(snapshotPathB) ? snapshotPathB : path.resolve(root, snapshotPathB);

  // Validate snapshot files exist
  if (!fs.existsSync(resolvedA)) {
    return { ok: false, error: `Snapshot A not found: ${snapshotPathA}` };
  }
  if (!fs.existsSync(resolvedB)) {
    return { ok: false, error: `Snapshot B not found: ${snapshotPathB}` };
  }

  // Parse snapshot files
  let snapshotA, snapshotB;
  try {
    snapshotA = JSON.parse(readText(resolvedA));
  } catch (err) {
    return { ok: false, error: `Snapshot A is not valid JSON: ${snapshotPathA} — ${err.message}` };
  }
  try {
    snapshotB = JSON.parse(readText(resolvedB));
  } catch (err) {
    return { ok: false, error: `Snapshot B is not valid JSON: ${snapshotPathB} — ${err.message}` };
  }

  const notesA = Array.isArray(snapshotA.notes) ? snapshotA.notes : [];
  const notesB = Array.isArray(snapshotB.notes) ? snapshotB.notes : [];

  const mapA = new Map(notesA.map((n) => [n.id, n]));
  const mapB = new Map(notesB.map((n) => [n.id, n]));

  const added = [];
  const removed = [];
  const modified = [];
  let unchanged = 0;
  let statusChanges = 0;
  let tagChanges = 0;

  // Notes in B but not in A → added
  for (const note of notesB) {
    if (!mapA.has(note.id)) {
      added.push({
        id: note.id,
        title: note.title,
        status: note.status || 'candidate',
        tags: Array.isArray(note.tags) ? note.tags : [],
        snapshot: 'b',
      });
    }
  }

  // Notes in A but not in B → removed
  for (const note of notesA) {
    if (!mapB.has(note.id)) {
      removed.push({
        id: note.id,
        title: note.title,
        status: note.status || 'candidate',
        tags: Array.isArray(note.tags) ? note.tags : [],
        snapshot: 'a',
      });
    }
  }

  // Notes in both → compare fields
  for (const [id, noteB] of mapB) {
    const noteA = mapA.get(id);
    if (!noteA) continue; // already handled in added

    const changes = {};
    let hasChanges = false;

    // Title comparison
    if (noteA.title !== noteB.title) {
      changes.title = { before: noteA.title, after: noteB.title };
      hasChanges = true;
    }

    // Summary comparison
    if (noteA.summary !== noteB.summary) {
      changes.summary = { changed: true };
      hasChanges = true;
    }

    // Status comparison
    if (noteA.status !== noteB.status) {
      changes.status = { before: noteA.status || 'candidate', after: noteB.status || 'candidate' };
      hasChanges = true;
      statusChanges++;
    }

    // Tags comparison
    const tagsA = new Set(Array.isArray(noteA.tags) ? noteA.tags : []);
    const tagsB = new Set(Array.isArray(noteB.tags) ? noteB.tags : []);
    const tagsAdded = [...tagsB].filter((t) => !tagsA.has(t));
    const tagsRemoved = [...tagsA].filter((t) => !tagsB.has(t));
    if (tagsAdded.length > 0 || tagsRemoved.length > 0) {
      changes.tags = { added: tagsAdded, removed: tagsRemoved };
      hasChanges = true;
      tagChanges++;
    }

    // Evidence comparison
    if (noteA.evidence !== noteB.evidence) {
      changes.evidence = { changed: true };
      hasChanges = true;
    }

    if (hasChanges) {
      modified.push({
        id,
        title: noteB.title,
        changes,
      });
    } else {
      unchanged++;
    }
  }

  // Compute drift
  const noteGrowth = notesB.length - notesA.length;

  // Status drift: count changes in status between A and B
  const statusDriftParts = [];
  const statusCountA = {};
  const statusCountB = {};
  for (const note of notesA) {
    const s = note.status || 'candidate';
    statusCountA[s] = (statusCountA[s] || 0) + 1;
  }
  for (const note of notesB) {
    const s = note.status || 'candidate';
    statusCountB[s] = (statusCountB[s] || 0) + 1;
  }
  const allStatuses = new Set([...Object.keys(statusCountA), ...Object.keys(statusCountB)]);
  for (const status of allStatuses) {
    const countA = statusCountA[status] || 0;
    const countB = statusCountB[status] || 0;
    const diff = countB - countA;
    if (diff !== 0) {
      statusDriftParts.push(`${diff > 0 ? '+' : ''}${diff} ${status}`);
    }
  }
  const statusDrift = statusDriftParts.length > 0 ? statusDriftParts.join(', ') : 'no change';

  // Tag trends: tags that increased in B vs A
  const tagCountA = {};
  const tagCountB = {};
  for (const note of notesA) {
    for (const tag of Array.isArray(note.tags) ? note.tags : []) {
      tagCountA[tag] = (tagCountA[tag] || 0) + 1;
    }
  }
  for (const note of notesB) {
    for (const tag of Array.isArray(note.tags) ? note.tags : []) {
      tagCountB[tag] = (tagCountB[tag] || 0) + 1;
    }
  }
  const tagTrends = {};
  const allTags = new Set([...Object.keys(tagCountA), ...Object.keys(tagCountB)]);
  for (const tag of allTags) {
    const diff = (tagCountB[tag] || 0) - (tagCountA[tag] || 0);
    if (diff !== 0) {
      tagTrends[tag] = diff;
    }
  }

  return {
    snapshots: {
      a: {
        path: toPosix(snapshotPathA),
        generatedAt: snapshotA.generatedAt || '',
        noteCount: notesA.length,
      },
      b: {
        path: toPosix(snapshotPathB),
        generatedAt: snapshotB.generatedAt || '',
        noteCount: notesB.length,
      },
    },
    summary: {
      totalA: notesA.length,
      totalB: notesB.length,
      added: added.length,
      removed: removed.length,
      modified: modified.length,
      unchanged,
      statusChanges,
      tagChanges,
    },
    added,
    removed,
    modified,
    unchanged,
    drift: {
      noteGrowth,
      statusDrift,
      tagTrends,
    },
  };
}
