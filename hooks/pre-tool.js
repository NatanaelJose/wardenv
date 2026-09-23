#!/usr/bin/env node
'use strict';
// wardenv — PreToolUse
//
// Fecha a porta de ENTRADA: impede que conteúdo de segredo chegue ao contexto.
//
// Roda mesmo em bypassPermissions / --dangerously-skip-permissions, porque
// PreToolUse é enforcement de policy e não um prompt de permissão. É por isso
// que isto vive num hook e não em permissions.deny.
//
// Uso: pre-tool.js [--agent <nome>]   (padrão: claude)
// O adaptador traduz o payload do agente; a política vive em decide.js.

const { decide } = require('./decide');

const ADAPTERS = {
  claude: () => require('./adapters/claude'),
  gemini: () => require('./adapters/gemini'),
  codex: () => require('./adapters/codex'),
  copilot: () => require('./adapters/copilot'),
  cursor: () => require('./adapters/cursor'),
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
    process.exit(0); // nunca travar por payload malformado
  }

  try {
    let name = agentName(process.argv.slice(2));

    // O Cursor também carrega ~/.claude/settings.json (ligado por padrão) e
    // manda o payload DELE ali, não o do Claude. Sem isto, o hook registrado
    // como --agent claude leria os campos errados e deixaria tudo passar.
    const cursor = require('./adapters/cursor');
    if (cursor.detect(data)) {
      // Já registrado direto em ~/.cursor/hooks.json: essa cópia se cala,
      // para não negar (e logar) a mesma tentativa duas vezes.
      if (name !== 'cursor' && cursor.registeredNatively()) process.exit(0);
      name = 'cursor';
    }

    const load = ADAPTERS[name];
    if (!load) process.exit(0);
    const adapter = load();
    // Uma chamada pode mirar vários arquivos (patch do Codex): o primeiro
    // deny vale pela chamada inteira.
    let result = { action: 'allow' };
    for (const attempt of [].concat(adapter.normalize(data))) {
      result = decide(attempt);
      if (result.action === 'deny') break;
    }
    // O Cursor exige JSON em todo caminho: seu render devolve "{}" mesmo ao
    // liberar. Os outros agentes não precisam de resposta quando não há deny.
    const out = adapter.render(result);
    if (out) process.stdout.write(out);
    process.exit(0);
  } catch {
    process.exit(0); // falha aberta: nunca quebrar a sessão
  }
});
