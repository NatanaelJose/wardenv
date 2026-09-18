#!/usr/bin/env node
'use strict';
// Instalador: registra os hooks do wardenv no settings.json do Claude Code.
//
// Regras que este instalador segue por princípio:
//   - nunca sobrescreve settings.json sem backup;
//   - é idempotente (rodar duas vezes não duplica hook);
//   - preserva hooks de terceiros que já estejam lá (rtk, gsd, etc.).

const fs = require('fs');
const os = require('os');
const path = require('path');

const SETTINGS = path.join(os.homedir(), '.claude', 'settings.json');
const ROOT = path.resolve(__dirname, '..');
const NODE = process.execPath;

const PRE = `"${NODE}" "${path.join(ROOT, 'hooks', 'pre-tool.js')}"`;
const POST = `"${NODE}" "${path.join(ROOT, 'hooks', 'post-tool.js')}"`;

// Cobre tools nativas e MCP. PreToolUse roda mesmo em bypassPermissions,
// e também dentro de subagentes — que é o vetor mais esquecido.
const PRE_MATCHER = '^(Read|NotebookRead|Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell)$';
const POST_MATCHER = '^(Bash|PowerShell|Read|mcp__.*)$';

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

  // wardenv entra PRIMEIRO: se ele bloqueia, nenhum outro hook precisa rodar
  hooks[event].unshift({
    matcher,
    hooks: [{ type: 'command', command, timeout }],
  });
}

function main() {
  const uninstall = process.argv.includes('--uninstall');

  let settings = {};
  if (fs.existsSync(SETTINGS)) {
    const raw = fs.readFileSync(SETTINGS, 'utf8');
    try {
      settings = JSON.parse(raw);
    } catch {
      console.error(`✖ ${SETTINGS} is not valid JSON. Fix it before installing.`);
      process.exit(1);
    }
    const backup = `${SETTINGS}.bak-${Date.now()}`;
    fs.writeFileSync(backup, raw);
    console.log(`backup: ${backup}`);
  } else {
    fs.mkdirSync(path.dirname(SETTINGS), { recursive: true });
  }

  settings.hooks = settings.hooks || {};

  if (uninstall) {
    for (const event of Object.keys(settings.hooks)) {
      for (const group of settings.hooks[event]) {
        if (Array.isArray(group.hooks)) group.hooks = group.hooks.filter((h) => !isWardenv(h));
      }
      settings.hooks[event] = settings.hooks[event].filter(
        (g) => !Array.isArray(g.hooks) || g.hooks.length
      );
    }
    fs.writeFileSync(SETTINGS, JSON.stringify(settings, null, 2));
    console.log('🔓 wardenv removed. Restart Claude Code.');
    return;
  }

  ensure(settings.hooks, 'PreToolUse', PRE_MATCHER, PRE, 5);
  ensure(settings.hooks, 'PostToolUse', POST_MATCHER, POST, 5);

  fs.writeFileSync(SETTINGS, JSON.stringify(settings, null, 2));

  console.log('🔒 wardenv installed.');
  console.log(`   PreToolUse   ${PRE_MATCHER}`);
  console.log(`   PostToolUse  ${POST_MATCHER}`);
  console.log('\nReinicie o Claude Code para ativar.');
  console.log('Try:  wardenv check "cat .env"');
}

main();
