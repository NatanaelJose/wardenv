#!/usr/bin/env node
'use strict';
// Instalador: registra os hooks do wardenv no agente escolhido.
//
// Regras que este instalador segue por princípio:
//   - nunca sobrescreve config sem backup;
//   - é idempotente (rodar duas vezes não duplica hook);
//   - preserva hooks de terceiros que já estejam lá (rtk, gsd, etc.);
//   - wardenv entra PRIMEIRO: se ele bloqueia, nada mais precisa rodar.

const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const NODE = process.execPath;
const PRE = `"${NODE}" "${path.join(ROOT, 'hooks', 'pre-tool.js')}"`;
const POST = `"${NODE}" "${path.join(ROOT, 'hooks', 'post-tool.js')}"`;

// Cobre tools nativas e MCP. PreToolUse roda mesmo em bypassPermissions,
// e também dentro de subagentes — que é o vetor mais esquecido.
const PRE_MATCHER = '^(Read|NotebookRead|Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell)$';
const POST_MATCHER = '^(Bash|PowerShell|Read|mcp__.*)$';

/**
 * Alvos suportados.
 *
 * `verified` diz se a integração foi testada de ponta a ponta contra o agente
 * real. Um adaptador não verificado ainda é útil — o formato é o mesmo — mas o
 * usuário merece saber a diferença antes de confiar nele para segurança.
 */
const TARGETS = {
  claude: {
    label: 'Claude Code',
    file: path.join(os.homedir(), '.claude', 'settings.json'),
    verified: true,
    // hooks ficam sob a chave "hooks" na raiz
    root: (s) => (s.hooks = s.hooks || {}),
  },
  codex: {
    label: 'Codex CLI',
    file: path.join(os.homedir(), '.codex', 'hooks.json'),
    verified: false,
    note:
      'Codex usa o mesmo formato (matcher + command + JSON no stdin), mas esta\n' +
      '   integração não foi verificada de ponta a ponta. Teste com um .env de\n' +
      '   mentira antes de confiar nela.',
    root: (s) => (s.hooks = s.hooks || {}),
  },
};

function isWardenv(h) {
  return typeof h?.command === 'string' && /wardenv[\\/](hooks|src)/i.test(h.command);
}

function ensure(hooks, event, matcher, command, timeout) {
  hooks[event] = hooks[event] || [];
  // remove entradas antigas do wardenv (idempotência / upgrade)
  for (const group of hooks[event]) {
    if (Array.isArray(group.hooks)) {
      group.hooks = group.hooks.filter((h) => !isWardenv(h));
    }
  }
  hooks[event] = hooks[event].filter((g) => !Array.isArray(g.hooks) || g.hooks.length);

  hooks[event].unshift({
    matcher,
    hooks: [{ type: 'command', command, timeout }],
  });
}

function stripWardenv(hooks) {
  for (const event of Object.keys(hooks)) {
    if (!Array.isArray(hooks[event])) continue;
    for (const group of hooks[event]) {
      if (Array.isArray(group.hooks)) group.hooks = group.hooks.filter((h) => !isWardenv(h));
    }
    hooks[event] = hooks[event].filter((g) => !Array.isArray(g.hooks) || g.hooks.length);
  }
}

function loadConfig(file) {
  if (!fs.existsSync(file)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    return {};
  }
  const raw = fs.readFileSync(file, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.error(`✖ ${file} is not valid JSON. Fix it before installing.`);
    process.exit(1);
  }
  const backup = `${file}.bak-${Date.now()}`;
  fs.writeFileSync(backup, raw);
  console.log(`backup: ${backup}`);
  return parsed;
}

function main() {
  const args = process.argv.slice(2);
  const uninstall = args.includes('--uninstall');
  const named = args.find((a) => !a.startsWith('--'));

  // Sem alvo explícito: instala em todo agente cuja config já exista.
  const chosen = named
    ? [named]
    : Object.keys(TARGETS).filter((k) => fs.existsSync(path.dirname(TARGETS[k].file)));

  if (!chosen.length) {
    console.error('✖ No supported agent found. Pass one explicitly: wardenv install claude');
    process.exit(1);
  }

  for (const key of chosen) {
    const target = TARGETS[key];
    if (!target) {
      console.error(`✖ Unknown target "${key}". Known: ${Object.keys(TARGETS).join(', ')}`);
      process.exit(1);
    }

    const cfg = loadConfig(target.file);
    target.root(cfg);

    if (uninstall) {
      stripWardenv(cfg.hooks);
      fs.writeFileSync(target.file, JSON.stringify(cfg, null, 2));
      console.log(`🔓 wardenv removed from ${target.label}.`);
      continue;
    }

    ensure(cfg.hooks, 'PreToolUse', PRE_MATCHER, PRE, 5);
    ensure(cfg.hooks, 'PostToolUse', POST_MATCHER, POST, 5);
    fs.writeFileSync(target.file, JSON.stringify(cfg, null, 2));

    console.log(`🔒 wardenv installed for ${target.label}.`);
    if (!target.verified) {
      console.log(`⚠  UNVERIFIED adapter.\n   ${target.note}`);
    }
  }

  if (!uninstall) {
    console.log('\nRestart your agent to activate.');
    console.log('Try:  wardenv check "cat .env"');
  }
}

main();
