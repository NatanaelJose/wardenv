'use strict';
// Adaptador do Google Antigravity 2.0: payload do PreToolUse ⇄ tentativa normalizada.
//
// O contrato oficial usa camelCase no envelope (`toolCall.name` / `.args`),
// PascalCase nos argumentos das tools e exige uma decisão até para liberar.
// Não há como reescrever o resultado no PostToolUse, então este adaptador
// fecha leitura, shell, escrita e exfiltração antes da tool rodar.

const fs = require('fs');
const path = require('path');
const { classifyPath } = require('../../src/lib/targets');

const MAX_GREP_DIRS = 512;
// Árvores geradas que não descem na contagem: node_modules (JS) e target
// (Rust/Tauri) sozinhos estouram o limite e negavam todo grep na raiz. O
// ripgrep já pula .git e, via .gitignore, as demais. build/dist ficam DENTRO
// de propósito: ali já apareceu credencial de verdade. Buscar dentro de uma
// destas continua avaliado, porque a raiz da busca nunca é pulada.
const GREP_SKIP_DIRS = new Set(['.git', 'node_modules', 'target', '.venv', 'venv', '__pycache__']);

function vaultFiles(searchPath) {
  let stat;
  try {
    stat = fs.statSync(searchPath);
  } catch {
    return { files: [], complete: true };
  }

  if (stat.isFile()) {
    return { files: classifyPath(searchPath).secret ? [searchPath] : [], complete: true };
  }
  if (!stat.isDirectory()) return { files: [], complete: true };

  const found = [];
  const pending = [searchPath];
  let visited = 0;
  let complete = true;
  while (pending.length && visited < MAX_GREP_DIRS) {
    const dir = pending.shift();
    visited++;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (GREP_SKIP_DIRS.has(entry.name)) continue;
        if (visited + pending.length < MAX_GREP_DIRS) pending.push(file);
        else complete = false;
      } else if (entry.isFile() && classifyPath(file).secret) found.push(file);
    }
  }
  return { files: found, complete: complete && pending.length === 0 };
}

function normalizeGrep(base, ti, abs) {
  // With MatchPerLine=false Antigravity returns filenames, never matching
  // lines. The path itself is not secret content, so no read is exposed.
  if (ti.MatchPerLine === false) return { ...base, kind: 'other' };

  const searchPaths = Array.isArray(ti.SearchPath) ? ti.SearchPath : [ti.SearchPath];
  const matches = [];
  let incompleteTarget = null;

  for (const requested of searchPaths) {
    const target = abs(requested);
    const reachable = vaultFiles(target);
    if (!reachable.complete) incompleteTarget = incompleteTarget || target;
    matches.push(...reachable.files);
  }

  const unique = [...new Set(matches)];
  if (unique.length) return unique.map((file) => ({ ...base, kind: 'read', path: file }));
  // A busca real alcançaria mais arquivos do que o hook conseguiu avaliar
  // dentro do limite. Negar é mais seguro que declarar essa área limpa.
  if (incompleteTarget) return { ...base, kind: 'read', path: path.join(incompleteTarget, '.env') };
  return { ...base, kind: 'other' };
}

function normalize(data) {
  const call = data.toolCall || {};
  const ti = call.args || {};
  const roots = Array.isArray(data.workspacePaths) ? data.workspacePaths : [];
  const cwd = ti.Cwd || roots[0] || process.cwd();
  const abs = (p) => (p ? path.resolve(cwd, String(p)) : '');
  const base = { tool: call.name || '', cwd, agent: 'principal' };

  switch (base.tool) {
    case 'view_file':
      return { ...base, kind: 'read', path: abs(ti.AbsolutePath) };

    // Não reimplementa regex/glob/encoding do ripgrep: se a busca alcança
    // qualquer cofre, nega. MatchPerLine=false só devolve nomes e segue livre.
    case 'grep_search':
      return normalizeGrep(base, ti, abs);

    case 'run_command':
      return { ...base, kind: 'shell', command: ti.CommandLine || '' };

    case 'write_to_file':
      return { ...base, kind: 'write', path: abs(ti.TargetFile), body: ti.CodeContent || '', edits: null };

    case 'replace_file_content':
      return {
        ...base,
        kind: 'write',
        path: abs(ti.TargetFile),
        body: ti.ReplacementContent || '',
        edits: [{ old: ti.TargetContent, new: ti.ReplacementContent, all: !!ti.AllowMultiple }],
      };

    case 'multi_replace_file_content': {
      const chunks = Array.isArray(ti.ReplacementChunks) ? ti.ReplacementChunks : [];
      return {
        ...base,
        kind: 'write',
        path: abs(ti.TargetFile),
        body: chunks.map((c) => c && c.ReplacementContent).filter((s) => typeof s === 'string').join('\n'),
        edits: chunks.map((c) => ({
          old: c && c.TargetContent,
          new: c && c.ReplacementContent,
          all: !!(c && c.AllowMultiple),
        })),
      };
    }

    default:
      return { ...base, kind: 'other' };
  }
}

function render(result) {
  if (result.action !== 'deny') {
    return JSON.stringify({ decision: 'ask', reason: 'wardenv found no secret risk; apply normal Antigravity permissions.' });
  }
  return JSON.stringify({
    decision: 'deny',
    reason: result.context ? `${result.reason}\n\n${result.context}` : result.reason,
  });
}

module.exports = { normalize, render };
