'use strict';
// Adaptador do Codex CLI (0.129+): payload do PreToolUse/PostToolUse ⇄ tentativa normalizada.
//
// O formato de resposta é o mesmo do Claude. O que muda é a entrada:
//   - todo shell chega como tool "Bash", inclusive PowerShell no Windows;
//   - não existe tool de leitura: arquivo se lê pelo shell;
//   - escrita é "apply_patch", com o patch cru em tool_input.command. Um patch
//     pode mexer em vários arquivos, então vira uma tentativa por arquivo.
//
// Codex trata deny sem reason como inválido e deixa passar, por isso o render
// nunca manda reason vazio.

const path = require('path');
const claude = require('./claude');

function base(data) {
  return {
    tool: data.tool_name || '',
    cwd: data.cwd || process.cwd(),
    agent: data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal',
  };
}

/**
 * Lê o formato de patch do Codex (`*** Begin Patch` … `*** End Patch`).
 * @returns {Array<{path:string, added:string[], hunks:Array<{old:string,new:string}>}>}
 */
function parsePatch(text) {
  const files = [];
  let cur = null;
  let hunk = null;
  const flush = () => {
    if (cur && hunk && (hunk.old.length || hunk.new.length)) {
      cur.hunks.push({ old: hunk.old.join('\n'), new: hunk.new.join('\n') });
    }
    hunk = null;
  };

  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(line);
    if (m) {
      flush();
      cur = { path: m[2].trim(), added: [], hunks: [] };
      files.push(cur);
      continue;
    }
    const mv = /^\*\*\* Move to: (.+)$/.exec(line);
    if (mv && cur) {
      // O conteúdo vai para o destino; é ele que precisa ser checado.
      cur.path = mv[1].trim();
      continue;
    }
    if (!cur || line.startsWith('*** ')) continue;
    if (line.startsWith('@@')) {
      flush();
      continue;
    }
    hunk = hunk || { old: [], new: [] };
    if (line.startsWith('+')) {
      cur.added.push(line.slice(1));
      hunk.new.push(line.slice(1));
    } else if (line.startsWith('-')) {
      hunk.old.push(line.slice(1));
    } else {
      const ctx = line.startsWith(' ') ? line.slice(1) : line;
      hunk.old.push(ctx);
      hunk.new.push(ctx);
    }
  }
  flush();
  return files;
}

/** @returns {object|object[]} uma tentativa, ou uma por arquivo do patch */
function normalize(data) {
  const b = base(data);
  const ti = data.tool_input || {};

  if (b.tool === 'Bash') return { ...b, kind: 'shell', command: ti.command || '' };

  if (b.tool === 'apply_patch' || b.tool === 'Edit' || b.tool === 'Write') {
    const files = parsePatch(ti.command || ti.patch || '');
    if (!files.length) return { ...b, kind: 'other' };
    return files.map((f) => ({
      ...b,
      kind: 'write',
      path: path.resolve(b.cwd, f.path),
      body: f.added.join('\n'),
      // Arquivo novo não tem "antes": o corpo é o arquivo inteiro.
      edits: f.hunks.length && f.hunks.some((h) => h.old) ? f.hunks.map((h) => ({ ...h, all: false })) : null,
    }));
  }

  return { ...b, kind: 'other' };
}

function render(result) {
  if (result.action !== 'deny') return '';
  return claude.render({ ...result, reason: result.reason || 'wardenv: blocked.' });
}

// ---- PostToolUse -------------------------------------------------------

function normalizePost(data) {
  return { ...base(data), output: data.tool_response };
}

// Codex não tem campo para trocar o output. Um "block" com reason substitui
// o resultado que o modelo vê pelo reason; o comando já rodou.
function renderPost(clean, unique) {
  const text = typeof clean === 'string' ? clean : JSON.stringify(clean);
  return JSON.stringify({
    decision: 'block',
    reason:
      `wardenv redacted ${unique.length} secret(s) from this output: ${unique.join(', ')}. ` +
      'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
      'never try to recover the literal value. Redacted output follows.\n\n' + text,
  });
}

module.exports = { normalize, render, normalizePost, renderPost, parsePatch };
