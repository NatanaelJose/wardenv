'use strict';
// Adaptador do GitHub Copilot CLI: payload do preToolUse/postToolUse ⇄ tentativa normalizada.
//
// Dois formatos de entrada, conforme o nome do evento registrado:
//   - `preToolUse` (camelCase, o que o wardenv registra): toolName + toolArgs,
//     com toolArgs como STRING JSON — ou texto cru, no apply_patch;
//   - `PreToolUse` (1.0.21+): tool_name + tool_input objeto, com nomes no
//     estilo do Claude. Aceito também, para não depender de qual chegou.
//
// Num deny o modelo lê "Denied by preToolUse hook: <reason>", então a
// estrutura do .env vai junto no reason.

const path = require('path');
const { parsePatch } = require('./codex');

const READ = new Set(['view', 'show_file', 'Read']);
const SHELL = new Set(['bash', 'powershell', 'Bash', 'PowerShell']);
// Digitam num shell assíncrono já aberto: o texto digitado é um comando.
const SHELL_INPUT = new Set(['write_bash', 'write_powershell']);

function parseArgs(raw) {
  if (raw && typeof raw === 'object') return raw;
  if (typeof raw !== 'string') return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : { _raw: raw };
  } catch {
    return { _raw: raw };
  }
}

function base(data) {
  return {
    tool: data.toolName || data.tool_name || '',
    cwd: data.cwd || process.cwd(),
    agent: 'principal',
  };
}

function write(b, file, body, edits) {
  return { ...b, kind: 'write', path: path.resolve(b.cwd, String(file || '')), body: body || '', edits };
}

function normalize(data) {
  const b = base(data);
  const a = parseArgs(data.toolArgs !== undefined ? data.toolArgs : data.tool_input);
  const t = b.tool;
  const file = a.path || a.file_path;

  if (READ.has(t)) return { ...b, kind: 'read', path: file ? path.resolve(b.cwd, String(file)) : '' };
  if (SHELL.has(t)) return { ...b, kind: 'shell', command: a.command || '' };
  if (SHELL_INPUT.has(t)) return { ...b, kind: 'shell', command: a.input || '' };

  if (t === 'create' || t === 'Write') return write(b, file, a.file_text ?? a.content, null);
  if (t === 'edit' || t === 'Edit') {
    const oldS = a.old_str ?? a.old_string;
    const newS = a.new_str ?? a.new_string;
    return write(b, file, newS, oldS != null ? [{ old: oldS, new: newS, all: false }] : null);
  }

  if (t === 'str_replace_editor') {
    if (a.command === 'view') return { ...b, kind: 'read', path: file ? path.resolve(b.cwd, String(file)) : '' };
    if (a.command === 'create') return write(b, file, a.file_text, null);
    if (a.command === 'str_replace' || a.command === 'edit') {
      return write(b, file, a.new_str, a.old_str != null ? [{ old: a.old_str, new: a.new_str, all: false }] : null);
    }
    // insert: não há "antes" a comparar; o texto inserido ainda passa pelo scan de segredo.
    if (a.command === 'insert') return write(b, file, a.new_str, null);
    return { ...b, kind: 'other' };
  }

  if (t === 'apply_patch') {
    const files = parsePatch(a._raw || a.command || a.input || '');
    if (!files.length) return { ...b, kind: 'other' };
    return files.map((f) => write(
      b,
      f.path,
      f.added.join('\n'),
      f.hunks.length && f.hunks.some((h) => h.old) ? f.hunks.map((h) => ({ ...h, all: false })) : null
    ));
  }

  return { ...b, kind: 'other' };
}

function render(result) {
  if (result.action !== 'deny') return '';
  return JSON.stringify({
    permissionDecision: 'deny',
    permissionDecisionReason: result.context ? `${result.reason}\n\n${result.context}` : result.reason,
  });
}

// ---- postToolUse -------------------------------------------------------
// Na 1.0.11 a saída de um hook de comando no postToolUse é descartada; versões
// novas aceitam `modifiedResult`. Nas antigas isto não faz nada — e não quebra.

function normalizePost(data) {
  const r = data.toolResult || data.tool_response || {};
  return { ...base(data), output: typeof r === 'string' ? r : r.textResultForLlm };
}

function renderPost(clean, unique) {
  const text = typeof clean === 'string' ? clean : JSON.stringify(clean);
  return JSON.stringify({
    modifiedResult: { resultType: 'success', textResultForLlm: text },
    additionalContext:
      `wardenv redacted ${unique.length} secret(s) from this output: ${unique.join(', ')}. ` +
      'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
      'never try to recover the literal value.',
  });
}

module.exports = { normalize, render, normalizePost, renderPost };
