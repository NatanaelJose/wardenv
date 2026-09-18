#!/usr/bin/env node
'use strict';
// wardenv — PostToolUse
//
// Fecha a porta do RICOCHETE: o comando era inocente, mas o segredo saiu no
// output. `printenv`, `docker compose config`, `vercel env pull`, um `curl`
// que ecoa o token, um stack trace que imprime a connection string.
//
// Usa `updatedOutput`, que substitui o texto que o modelo vê. O arquivo real
// e o terminal do usuário não são tocados — só o contexto do agente.

const { collectKnownSecrets, redactText } = require('../src/lib/redact');
const { log } = require('../src/lib/audit');

let input = '';
const timer = setTimeout(() => process.exit(0), 4000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  clearTimeout(timer);
  let data;
  try {
    data = JSON.parse(input);
  } catch {
    process.exit(0);
  }

  try {
    const cwd = data.cwd || process.cwd();
    const tool = data.tool_name || '';
    const raw = data.tool_output;

    // tool_output pode vir como string ou objeto; normaliza para texto.
    const text = typeof raw === 'string' ? raw : raw == null ? '' : JSON.stringify(raw);
    if (!text || text.length > 400_000) process.exit(0); // saída gigante: não vale o custo

    const known = collectKnownSecrets(cwd);
    const { text: clean, hits } = redactText(text, known);

    if (!hits.length) process.exit(0);

    log({
      event: 'redact-output',
      tool,
      hits,
      agent: data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal',
      cwd,
    });

    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        updatedOutput: clean,
        systemMessage:
          `wardenv redacted ${hits.length} secret(s) from this output: ${hits.join(', ')}. ` +
          'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
          'never try to recover the literal value.',
      },
    }));
  } catch {
    process.exit(0);
  }
});
