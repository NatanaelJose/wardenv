#!/usr/bin/env node
'use strict';
// wardenv — PostToolUse
//
// Fecha a porta do RICOCHETE: o comando era inocente, mas o segredo saiu no
// output. `printenv`, `docker compose config`, `vercel env pull`, um `curl`
// que ecoa o token, um stack trace que imprime a connection string.
//
// Uso: post-tool.js [--agent <nome>]   (padrão: claude)
// Cada adaptador sabe como o seu agente deixa trocar o output que o modelo vê.

const { collectKnownSecrets, redactText } = require('../src/lib/redact');
const { log } = require('../src/lib/audit');

// Só agentes cujo evento pós-tool deixa trocar o que o modelo vê.
const ADAPTERS = {
  claude: () => require('./adapters/claude'),
  gemini: () => require('./adapters/gemini'),
  codex: () => require('./adapters/codex'),
  copilot: () => require('./adapters/copilot'),
};

function agentName(argv) {
  const i = argv.indexOf('--agent');
  return i >= 0 && argv[i + 1] ? argv[i + 1] : 'claude';
}

let input = '';
const timer = setTimeout(() => process.exit(0), 4000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  clearTimeout(timer);
  let data;
  try {
    data = JSON.parse(input.replace(/^﻿/, ''));
  } catch {
    process.exit(0);
  }

  try {
    const load = ADAPTERS[agentName(process.argv.slice(2))];
    if (!load) process.exit(0);
    const adapter = load();
    const { tool, cwd, agent, output: raw } = adapter.normalizePost(data);

    // Serializar um objeto inteiro e devolvê-lo como output trocava a saída
    // estruturada por um blob — só quando havia redação, o que tornava o
    // efeito invisível. Aqui a forma é preservada: redige campo a campo.
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

    log({ event: 'redact-output', tool, hits: unique, agent, cwd });

    process.stdout.write(adapter.renderPost(clean, unique));
  } catch {
    process.exit(0);
  }
});
