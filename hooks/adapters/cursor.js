'use strict';
// Adaptador do Cursor (3.x): payload do preToolUse ⇄ tentativa normalizada.
//
// O Cursor chega aqui por dois caminhos:
//   - ~/.cursor/hooks.json, onde o wardenv se registra com `--agent cursor`;
//   - ~/.claude/settings.json: o Cursor também carrega os hooks do Claude Code
//     (ligado por padrão), mas manda o payload no formato DELE e só respeita a
//     resposta no formato do Claude atrás de uma feature flag. Por isso
//     pre-tool.js reconhece o payload do Cursor venha de onde vier.
//
// O Cursor exige JSON no stdout em todo caminho: saída vazia ou inválida num
// hook de permissão BLOQUEIA a ação. Liberar é `{}`.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { classifyPath } = require('../../src/lib/targets');

/** O payload é do Cursor? Todo evento dele traz cursor_version. */
function detect(data) {
  return !!(data && (data.cursor_version || (Array.isArray(data.workspace_roots) && data.conversation_id)));
}

/**
 * O wardenv já está registrado direto no ~/.cursor/hooks.json? Aí a cópia que
 * chega pela config do Claude cala, para não bloquear e logar tudo em dobro.
 */
function registeredNatively() {
  try {
    const text = fs.readFileSync(path.join(os.homedir(), '.cursor', 'hooks.json'), 'utf8');
    return /wardenv[\\/]+hooks[\\/]+pre-tool\.js[^"]*--agent cursor/i.test(text);
  } catch {
    return false;
  }
}

// `/c:/Users/...` aparece em workspace_roots no Windows.
function fixDrive(p) {
  return String(p || '').replace(/^\/([a-zA-Z]:[\\/])/, '$1');
}

function normalize(data) {
  const ti = data.tool_input || {};
  const roots = Array.isArray(data.workspace_roots) ? data.workspace_roots : [];
  const cwd = fixDrive(data.cwd || ti.cwd || ti.working_directory || roots[0] || process.cwd());
  const abs = (p) => (p ? path.resolve(cwd, fixDrive(p)) : '');
  const event = data.hook_event_name || 'preToolUse';
  const b = { tool: data.tool_name || event, cwd, agent: 'principal' };

  if (event === 'beforeShellExecution') return { ...b, tool: 'Shell', kind: 'shell', command: data.command || '' };
  if (event === 'beforeReadFile') return { ...b, tool: 'Read', kind: 'read', path: abs(data.file_path) };

  switch (data.tool_name) {
    case 'Shell':
      return { ...b, kind: 'shell', command: ti.command || '' };
    case 'Read':
      return { ...b, kind: 'read', path: abs(ti.file_path) };
    // Grep num .env devolve as linhas com os valores: é uma leitura.
    case 'Grep':
      return classifyPath(ti.file_path || '').secret ? { ...b, kind: 'read', path: abs(ti.file_path) } : { ...b, kind: 'other' };
    case 'Write':
      return { ...b, kind: 'write', path: abs(ti.file_path), body: ti.content || '', edits: null };
    // Apagar é escrever vazio: pega quem remove a config que registra o wardenv.
    case 'Delete':
      return { ...b, kind: 'write', path: abs(ti.file_path), body: '', edits: null };
    default:
      return { ...b, kind: 'other' };
  }
}

function render(result) {
  if (result.action !== 'deny') return '{}';
  // O texto que o modelo lê é o user_message; agent_message vai igual por garantia.
  const msg = result.context ? `${result.reason}\n\n${result.context}` : result.reason;
  return JSON.stringify({ continue: true, permission: 'deny', user_message: msg, agent_message: msg });
}

module.exports = { detect, registeredNatively, normalize, render };
