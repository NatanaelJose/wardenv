'use strict';
// Adaptador do Gemini CLI (0.34): payload do BeforeTool/AfterTool ⇄ tentativa normalizada.
//
// Diferenças que importam em relação ao Claude:
//   - caminhos chegam como o modelo escreveu, muitas vezes relativos ao cwd;
//   - num deny, `reason` é o ÚNICO texto que chega ao modelo (additionalContext
//     é ignorado no BeforeTool), então a estrutura do .env vai junto nele;
//   - o AfterTool não tem campo para trocar o output. O que existe é negar o
//     resultado: o modelo vê "Tool result blocked: <reason>", e o reason leva
//     o texto já redigido.

const path = require('path');
const { classifyPath } = require('../../src/lib/targets');

function abs(cwd, p) {
  return p ? path.resolve(cwd, String(p)) : '';
}

function base(data) {
  return {
    tool: data.tool_name || '',
    cwd: data.cwd || process.cwd(),
    agent: 'principal',
  };
}

function normalize(data) {
  const b = base(data);
  const ti = data.tool_input || {};

  switch (b.tool) {
    case 'read_file':
      return { ...b, kind: 'read', path: abs(b.cwd, ti.file_path) };

    case 'read_many_files': {
      // Vários alvos numa chamada só. Basta um ser cofre para negar a chamada
      // inteira. Glob (`*.env`) não é classificado aqui — limite documentado.
      const list = (Array.isArray(ti.include) ? ti.include : []).map((p) => abs(b.cwd, p));
      const hit = list.find((p) => classifyPath(p).secret);
      return { ...b, kind: 'read', path: hit || list[0] || '' };
    }

    case 'run_shell_command':
      return { ...b, kind: 'shell', command: ti.command || '' };

    case 'write_file':
      return { ...b, kind: 'write', path: abs(b.cwd, ti.file_path), body: ti.content || '', edits: null };

    case 'replace':
      return {
        ...b,
        kind: 'write',
        path: abs(b.cwd, ti.file_path),
        body: typeof ti.new_string === 'string' ? ti.new_string : '',
        edits: [{ old: ti.old_string, new: ti.new_string, all: !!ti.allow_multiple }],
      };

    default:
      return { ...b, kind: 'other' };
  }
}

function render(result) {
  if (result.action !== 'deny') return '';
  return JSON.stringify({
    decision: 'deny',
    reason: result.context ? `${result.reason}\n\n${result.context}` : result.reason,
    systemMessage: result.reason,
  });
}

// ---- AfterTool ---------------------------------------------------------

function normalizePost(data) {
  const r = data.tool_response || {};
  return { ...base(data), output: r.llmContent };
}

function renderPost(clean, unique) {
  const text = typeof clean === 'string' ? clean : JSON.stringify(clean);
  return JSON.stringify({
    decision: 'deny',
    reason:
      `wardenv redacted ${unique.length} secret(s) from this output: ${unique.join(', ')}. ` +
      'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
      'never try to recover the literal value. Redacted output follows.\n\n' + text,
    systemMessage: `wardenv redacted ${unique.join(', ')} from the tool output.`,
  });
}

module.exports = { normalize, render, normalizePost, renderPost };
