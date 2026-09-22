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

    // tool_output vem como string ou como objeto (`{stdout, stderr}`).
    // Serializar o objeto inteiro e devolver o JSON como updatedOutput trocava
    // a saída estruturada por um blob — só quando havia redação, o que tornava
    // o efeito invisível. Aqui a forma é preservada: redige campo a campo.
    const known = collectKnownSecrets(cwd);
    const hits = [];

    const scrub = (value, depth = 0) => {
      if (typeof value === 'string') {
        if (value.length > 400_000) return value; // trecho gigante: não vale o custo
        const r = redactText(value, known);
        hits.push(...r.hits);
        return r.text;
      }
      if (depth >= 4 || value == null || typeof value !== 'object') return value;
      if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = scrub(v, depth + 1);
      return out;
    };

    if (raw == null || (typeof raw === 'string' && !raw)) process.exit(0);
    const clean = scrub(raw);

    if (!hits.length) process.exit(0);

    // O mesmo segredo pode aparecer em stdout e stderr; o relato conta
    // segredos distintos, não ocorrências.
    const unique = [...new Set(hits)];

    log({
      event: 'redact-output',
      tool,
      hits: unique,
      agent: data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal',
      cwd,
    });

    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        updatedOutput: clean,
        systemMessage:
          `wardenv redacted ${unique.length} secret(s) from this output: ${unique.join(', ')}. ` +
          'Values were replaced with «wardenv:NAME». Use the variable name in code; ' +
          'never try to recover the literal value.',
      },
    }));
  } catch {
    process.exit(0);
  }
});
