#!/usr/bin/env node
'use strict';
// Instalador: registra os hooks do wardenv no agente escolhido.
//
// Regras que este instalador segue por princípio:
//   - nunca sobrescreve config sem backup;
//   - é idempotente (rodar duas vezes não duplica hook);
//   - preserva hooks de terceiros que já estejam lá (rtk, gsd, etc.);
//   - wardenv entra PRIMEIRO: se ele bloqueia, nada mais precisa rodar;
//   - grava de forma atômica: uma queda no meio não deixa a config pela metade.

const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const NODE = process.execPath;
const WIN = process.platform === 'win32';

function hookCmd(script, agent) {
  const base = `"${NODE}" "${path.join(ROOT, 'hooks', script)}"`;
  return agent ? `${base} --agent ${agent}` : base;
}

// O Gemini roda o comando do hook dentro do PowerShell no Windows, e lá um
// caminho entre aspas no começo da linha é só uma string: precisa do `&`.
function psSafe(cmd) {
  return WIN ? `& ${cmd}` : cmd;
}

function home(envVar, ...rest) {
  return process.env[envVar] ? path.join(process.env[envVar], ...rest.slice(1)) : path.join(os.homedir(), ...rest);
}

/** Está no PATH? Sem executar nada além de `where`/`command -v`. */
function onPath(bin) {
  const r = require('child_process').spawnSync(WIN ? 'where' : 'sh', WIN ? [bin] : ['-c', `command -v ${bin}`], {
    stdio: 'ignore',
  });
  return r.status === 0;
}

/** `<bin> --version` é pelo menos `major.minor.patch`? undefined se não der para checar. */
function versionAtLeast(bin, major, minor) {
  // No Windows um binário instalado via npm é um .cmd; sem shell:true o
  // spawnSync não resolve a extensão pelo PATH e falha silenciosamente. `bin`
  // só chega aqui como literal fixo no código (nunca de fora), então montar
  // a linha como string é seguro apesar do aviso de depreciação do Node.
  const r = require('child_process').spawnSync(`${bin} --version`, { encoding: 'utf8', shell: WIN });
  if (r.status !== 0 || !r.stdout) return undefined;
  const m = r.stdout.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return undefined;
  const [, a, b] = m.map(Number);
  return a !== major ? a > major : b >= minor;
}

/**
 * Alvos suportados.
 *
 * `verified` diz se a integração foi testada de ponta a ponta contra o agente
 * real. Um adaptador não verificado ainda é útil — o formato foi conferido no
 * código do agente — mas o usuário merece saber a diferença antes de confiar
 * nele para segurança.
 *
 * `layout`:
 *   - 'nested': { hooks: { Evento: [ { matcher, hooks: [ {type, command, timeout} ] } ] } }
 *   - 'own':    arquivo só do wardenv, reescrito inteiro (Copilot).
 */
const TARGETS = {
  claude: {
    label: 'Claude Code',
    file: path.join(os.homedir(), '.claude', 'settings.json'),
    verified: true,
    layout: 'nested',
    // Cobre tools nativas e MCP. PreToolUse roda mesmo em bypassPermissions,
    // e também dentro de subagentes — que é o vetor mais esquecido.
    events: {
      PreToolUse: ['^(Read|NotebookRead|Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell)$', hookCmd('pre-tool.js')],
      PostToolUse: ['^(Bash|PowerShell|Read|mcp__.*)$', hookCmd('post-tool.js')],
    },
    timeout: 5,
  },
  gemini: {
    label: 'Gemini CLI',
    file: path.join(os.homedir(), '.gemini', 'settings.json'),
    verified: false,
    layout: 'nested',
    // O matcher do Gemini é regex SEM âncora: sem ^$, `read_file` casaria
    // também com qualquer tool MCP que tivesse isso no nome.
    events: {
      BeforeTool: ['^(read_file|read_many_files|run_shell_command|write_file|replace)$', psSafe(hookCmd('pre-tool.js', 'gemini'))],
      AfterTool: ['^(run_shell_command|read_file|read_many_files|mcp_.*)$', psSafe(hookCmd('post-tool.js', 'gemini'))],
    },
    timeout: 10000, // milissegundos, no Gemini
    extra: { name: 'wardenv' },
    note:
      'Checked against the Gemini CLI 0.34 source, not yet against a live session.\n' +
      '   Gemini cannot rewrite a tool result: a leak is replaced by an error that carries\n' +
      '   the redacted text. `@.env` typed in your own prompt skips tool hooks.',
  },
  cursor: {
    label: 'Cursor',
    file: path.join(os.homedir(), '.cursor', 'hooks.json'),
    verified: false,
    layout: 'cursor', // {version:1, hooks:{evento:[{command, matcher}]}} — entrada PLANA, sem "hooks:[...]"
    // Cursor roda o comando via `powershell -c`, sem -NoProfile: um caminho
    // entre aspas no começo da linha só vira string, não chamada — precisa do `&`.
    events: {
      preToolUse: ['Shell|Read|Write|Delete|Grep', psSafe(hookCmd('pre-tool.js', 'cursor'))],
    },
    timeout: 10,
    note:
      'Checked against Cursor 3.4.20, not yet against a live session. Cursor also loads\n' +
      "   ~/.claude/settings.json by default (\"Include Third-Party Plugins\" setting); wardenv\n" +
      '   detects that payload shape on its own, so the two registrations do not double-fire.\n' +
      '   Output redaction is not possible in Cursor: only reads and writes can be blocked.\n' +
      '   If your PowerShell profile prints anything, permission hooks may misfire — see docs.',
  },
  codex: {
    label: 'Codex CLI',
    file: home('CODEX_HOME', '.codex', 'hooks.json'),
    verified: false,
    layout: 'nested',
    // Todo shell chega como "Bash", inclusive PowerShell no Windows. Escrita é
    // apply_patch. Não existe tool de leitura: arquivo se lê pelo shell.
    //
    // O Codex Desktop roda o comando do hook via PowerShell. Sem o `&`, um
    // caminho entre aspas no início da linha ("C:\...\node.exe" "...") não é
    // uma chamada — é só uma string — e o `--agent` seguinte quebra o parser
    // (o `--` é interpretado como operador de decremento). O hook nunca roda,
    // não produz JSON, e falha aberto: a leitura do .env passa sem bloqueio
    // nenhum, silenciosamente. Reproduzido e confirmado nesta máquina.
    events: {
      PreToolUse: ['^(Bash|apply_patch)$', psSafe(hookCmd('pre-tool.js', 'codex'))],
      PostToolUse: ['^(Bash|mcp__.*)$', psSafe(hookCmd('post-tool.js', 'codex'))],
    },
    timeout: 5,
    // Tool hooks (PreToolUse/PostToolUse) só existem a partir do Codex 0.129;
    // versões antigas (esta máquina tinha 0.116) não têm NENHUM evento antes
    // ou depois de uma tool. Instalar mesmo assim imprimia "🔒 installed" e
    // deixava o .env exposto — o instalador agora recusa de vez, como fazia
    // antes desta integração existir.
    precheck: () =>
      versionAtLeast('codex', 0, 129) === false
        ? 'Codex CLI tool hooks (PreToolUse/PostToolUse) need 0.129 or newer. Your version\n' +
          '   has none at all, so wardenv would never be called and .env stays exposed.\n' +
          '   Update with: npm install -g @openai/codex@latest'
        : null,
    note:
      'Checked against the Codex CLI source, not yet against a live session. Codex trusts\n' +
      '   a hook by a hash of its exact command, so it only runs after you review and\n' +
      '   approve it: open /hooks in Codex and approve the wardenv entries. Re-running\n' +
      '   this installer changes the command and invalidates that approval every time —\n' +
      '   reopen /hooks and re-approve after every reinstall, or the hook silently stops\n' +
      '   running and wardenv sees nothing.',
  },
  copilot: {
    label: 'GitHub Copilot CLI',
    file: home('COPILOT_HOME', '.copilot', 'hooks', 'wardenv.json'),
    detect: home('COPILOT_HOME', '.copilot'),
    verified: false,
    layout: 'own',
    // Sem matcher: até a 1.0.36 o Copilot ignorava o matcher do preToolUse.
    // O adaptador filtra pela tool. `powershell` roda via pwsh.exe -c, que
    // exige o `&`; `bash` não — por isso os dois campos divergem.
    events: {
      preToolUse: { bash: hookCmd('pre-tool.js', 'copilot'), powershell: psSafe(hookCmd('pre-tool.js', 'copilot')) },
      postToolUse: { bash: hookCmd('post-tool.js', 'copilot'), powershell: psSafe(hookCmd('post-tool.js', 'copilot')) },
    },
    timeout: 10,
    // No Windows o Copilot roda o campo `powershell` com pwsh.exe (PowerShell 7).
    // Sem ele o hook nem sobe — e a 1.0.x deixa a tool rodar quando o hook
    // falha. Instalar assim só daria a impressão de proteção.
    precheck: () =>
      WIN && !onPath('pwsh')
        ? 'Copilot CLI runs hooks on Windows through pwsh.exe (PowerShell 7), which is not\n' +
          '   on your PATH. The hook would never start, and Copilot lets the tool run when a\n' +
          '   hook fails. Install PowerShell 7 (winget install Microsoft.PowerShell) and retry.'
        : null,
    note:
      'Checked against the Copilot CLI 1.0.11 source, not yet against a live session.\n' +
      '   Before 1.0.57 Copilot lets a tool run when the hook errors or times out, and\n' +
      '   output redaction needs a release newer than 1.0.11. Update Copilot CLI.',
  },
};

function isWardenv(h) {
  const cmd = [h?.command, h?.bash, h?.powershell].find((c) => typeof c === 'string');
  return !!cmd && /wardenv[\\/](hooks|src)/i.test(cmd);
}

function ensure(hooks, event, matcher, command, timeout, extra) {
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
    hooks: [{ ...(extra || {}), type: 'command', command, timeout }],
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

// Cursor: cada entrada É o hook — {command, matcher} — sem "hooks:[...]" aninhado.
function ensureCursor(hooks, event, matcher, command, timeout) {
  hooks[event] = (hooks[event] || []).filter((h) => !isWardenv(h));
  hooks[event].unshift({ command, matcher, timeout });
}

function stripWardenvCursor(hooks) {
  for (const event of Object.keys(hooks)) {
    if (!Array.isArray(hooks[event])) continue;
    hooks[event] = hooks[event].filter((h) => !isWardenv(h));
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
    // Editores no Windows costumam gravar com BOM, que o JSON.parse recusa.
    parsed = JSON.parse(raw.replace(/^﻿/, ''));
  } catch {
    console.error(`✖ ${file} is not valid JSON. Fix it before installing.`);
    process.exit(1);
  }
  const backup = `${file}.bak-${Date.now()}`;
  fs.writeFileSync(backup, raw);
  console.log(`backup: ${backup}`);
  return parsed;
}

/** Grava num temporário ao lado e renomeia: ou a config nova inteira, ou a antiga intacta. */
function writeAtomic(file, text) {
  const tmp = `${file}.wardenv-${process.pid}.tmp`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
}

function installOwn(target) {
  // Um item de target.events pode ser um comando único (mesma sintaxe nos
  // dois shells) ou {bash, powershell} quando eles precisam divergir — no
  // Windows o Copilot roda `powershell` via pwsh.exe, que exige o prefixo
  // `&` para um caminho entre aspas ser chamada e não string; `bash` não.
  const entry = (command) => {
    const c = typeof command === 'string' ? { bash: command, powershell: command } : command;
    return { type: 'command', ...c, timeoutSec: target.timeout };
  };
  const cfg = { version: 1, hooks: {} };
  for (const [event, command] of Object.entries(target.events)) cfg.hooks[event] = [entry(command)];
  if (fs.existsSync(target.file)) loadConfig(target.file); // só pelo backup
  else fs.mkdirSync(path.dirname(target.file), { recursive: true });
  writeAtomic(target.file, JSON.stringify(cfg, null, 2));
}

function uninstallOwn(target) {
  // O arquivo é do wardenv, mas só apaga se ainda for: nunca remove algo que
  // o usuário tenha reaproveitado com hooks próprios.
  //
  // Layout 'own' é PLANO como o do Cursor — cada entrada do array JÁ é o hook
  // ({type, bash, powershell, ...}), sem "hooks:[...]" aninhado. stripWardenv
  // olha para dentro de group.hooks[] e nunca encontra nada nesse formato: a
  // limpeza virava um no-op silencioso, então usa a mesma função do Cursor.
  const cfg = loadConfig(target.file);
  stripWardenvCursor(cfg.hooks || {});
  const left = Object.values(cfg.hooks || {}).some((v) => Array.isArray(v) && v.some((h) => !isWardenv(h)));
  if (left) writeAtomic(target.file, JSON.stringify(cfg, null, 2));
  else fs.unlinkSync(target.file);
}

function main() {
  const args = process.argv.slice(2);
  const uninstall = args.includes('--uninstall');
  const named = args.find((a) => !a.startsWith('--'));

  // Sem alvo explícito: instala em todo agente suportado cuja config já exista.
  // O uninstall passa por todos, inclusive os não suportados, para limpar
  // instalações feitas antes de o suporte ser retirado.
  const chosen = named
    ? [named]
    : Object.keys(TARGETS).filter(
        (k) => fs.existsSync(TARGETS[k].detect || path.dirname(TARGETS[k].file)) && (uninstall || TARGETS[k].supported !== false)
      );

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

    if (!uninstall && target.supported === false) {
      console.error(`✖ ${target.label} is not supported.\n   ${target.unsupported}`);
      process.exit(1);
    }

    // Uninstall de um agente que nunca teve config: nada a limpar, e
    // loadConfig criaria a pasta dele à toa.
    if (uninstall && !fs.existsSync(target.file)) {
      console.log(`${target.label}: nothing to remove.`);
      continue;
    }

    if (!uninstall && target.precheck) {
      const problem = target.precheck();
      if (problem) {
        console.error(`✖ ${target.label}: nothing was installed.\n   ${problem}`);
        // Com alvo explícito é erro; na detecção automática, segue para os outros.
        if (named) process.exit(1);
        continue;
      }
    }

    if (target.layout === 'own') {
      if (uninstall) uninstallOwn(target);
      else installOwn(target);
    } else if (target.layout === 'cursor') {
      const cfg = loadConfig(target.file);
      cfg.hooks = cfg.hooks || {};
      cfg.version = cfg.version || 1;
      if (uninstall) {
        stripWardenvCursor(cfg.hooks);
      } else {
        for (const [event, [matcher, command]] of Object.entries(target.events)) {
          ensureCursor(cfg.hooks, event, matcher, command, target.timeout);
        }
      }
      writeAtomic(target.file, JSON.stringify(cfg, null, 2));
    } else {
      const cfg = loadConfig(target.file);
      cfg.hooks = cfg.hooks || {};
      if (uninstall) {
        stripWardenv(cfg.hooks);
      } else {
        for (const [event, [matcher, command]] of Object.entries(target.events)) {
          ensure(cfg.hooks, event, matcher, command, target.timeout, target.extra);
        }
      }
      writeAtomic(target.file, JSON.stringify(cfg, null, 2));
    }

    if (uninstall) {
      console.log(`🔓 wardenv removed from ${target.label}.`);
      continue;
    }

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
