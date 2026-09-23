'use strict';
// Adaptador do Claude Code: payload do PreToolUse ⇄ tentativa normalizada.

const TOOLS_FILE = new Set(['Read', 'NotebookRead']);
const TOOLS_SHELL = new Set(['Bash', 'PowerShell']);
const TOOLS_WRITE = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

function normalize(data) {
  const tool = data.tool_name || '';
  const ti = data.tool_input || {};
  const base = {
    tool,
    cwd: data.cwd || process.cwd(),
    agent: data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal',
  };

  if (TOOLS_FILE.has(tool)) return { ...base, kind: 'read', path: ti.file_path || '' };
  if (TOOLS_SHELL.has(tool)) return { ...base, kind: 'shell', command: ti.command || '' };

  if (TOOLS_WRITE.has(tool)) {
    // MultiEdit não traz o texto num campo escalar: ele vem em `edits[]`,
    // cada item com seu próprio `new_string`. Ler só os campos soltos fazia
    // o corpo chegar sempre vazio aqui — a tool estava registrada no matcher
    // e em TOOLS_WRITE, parecia guardada, e passava qualquer segredo.
    const body = [
      ti.content, ti.file_text, ti.new_string, ti.new_str,
      ...(Array.isArray(ti.edits) ? ti.edits.map((e) => e && (e.new_string || e.new_str)) : []),
    ].filter((s) => typeof s === 'string' && s).join('\n');

    const pair = (e) => e && { old: e.old_string ?? e.old_str, new: e.new_string ?? e.new_str, all: !!e.replace_all };
    const edits = Array.isArray(ti.edits)
      ? ti.edits.map(pair)
      : ti.old_string != null || ti.old_str != null
        ? [pair(ti)]
        : null;

    return { ...base, kind: 'write', path: ti.file_path || '', body, edits };
  }

  return { ...base, kind: 'other' };
}

/** @returns {string} o que vai para o stdout; '' libera sem opinião */
function render(result) {
  if (result.action !== 'deny') return '';
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: result.reason,
      ...(result.context ? { additionalContext: result.context } : {}),
    },
  });
}

// ---- PostToolUse -------------------------------------------------------

function normalizePost(data) {
  return {
    tool: data.tool_name || '',
    cwd: data.cwd || process.cwd(),
    agent: data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal',
    // tool_output vem como string ou como objeto (`{stdout, stderr}`).
    output: data.tool_output,
  };
}

// `updatedOutput` substitui o texto que o modelo vê. O arquivo real e o
// terminal do usuário não são tocados — só o contexto do agente.
function renderPost(clean, unique) {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      updatedOutput: clean,
      systemMessage:
        `wardenv redacted ${unique.length} secret(s) from this output: ${unique.join(', ')}. ` +
        'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
        'never try to recover the literal value.',
    },
  });
}

module.exports = { normalize, render, normalizePost, renderPost };
