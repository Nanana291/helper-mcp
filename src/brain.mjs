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

function rebuildNotesFile(root, notes) {
  const { dir, notes: notesPath } = brainPaths(root);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(notesPath, notes.map((n) => JSON.stringify(n)).join('\n') + '\n', 'utf8');
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
    createdAt,
    updatedAt: createdAt,
  };
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(notes, `${JSON.stringify(normalized)}\n`, 'utf8');
  return rebuildCurrentSnapshot(root, loadNotes(root));
}

export function promoteBrainNote(root, id, newStatus) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  notes[idx] = { ...notes[idx], status: String(newStatus || 'active').trim().toLowerCase(), updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
  return { ok: true, note: notes[idx], counts: snapshot.counts };
}

export function tagBrainNote(root, id, tagsToAdd) {
  const notes = loadNotes(root);
  const idx = notes.findIndex((n) => n.id === id);
  if (idx === -1) return { ok: false, error: `Note not found: ${id}` };
  const existing = Array.isArray(notes[idx].tags) ? notes[idx].tags : [];
  const merged = [...new Set([...existing, ...tagsToAdd.map(String).map((t) => t.trim()).filter(Boolean)])];
  notes[idx] = { ...notes[idx], tags: merged, updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
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
  notes[idx] = { ...notes[idx], ...updates, updatedAt: new Date().toISOString() };
  rebuildNotesFile(root, notes);
  const snapshot = rebuildCurrentSnapshot(root, notes);
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
  return { ok: true, message: 'Lesson stored.', counts: snapshot.counts };
}
