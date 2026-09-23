#!/usr/bin/env node
'use strict';
// wardenv CLI — a interface do humano.
//
// O agente não usa isto: `wardenv unlock` é ele próprio um comando bloqueado
// no PreToolUse, justamente para que o agente não possa se auto-liberar.

const path = require('path');
const fs = require('fs');
const { grant, listGrants, revokeAll } = require('./lib/unlock');
const { tail, log } = require('./lib/audit');
const { classifyPath } = require('./lib/targets');
const { analyzeCommand } = require('./lib/command');
const { summarizeEnvFile, collectKnownSecrets, redactText } = require('./lib/redact');

const [, , cmd, ...rest] = process.argv;

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function help() {
  console.log(`wardenv — a warden for your env

  wardenv install [agent]     register hooks (claude, gemini, codex, copilot)
  wardenv uninstall [agent]   remove hooks
  wardenv status              what's guarded here, and any open passes
  wardenv keys [file]         key NAMES from .env — never the values
  wardenv unlock <file> [-n N] [-t MIN]
                              grant a one-off read (default: 1 use, 10 min)
  wardenv lock                revoke all passes now
  wardenv log [n]             last n audit entries (default 20)
  wardenv check <command>     what would wardenv do with this command?
  wardenv scan [file]         look for leaked secrets in a file/stdin
`);
}

switch (cmd) {
  case 'install': {
    // O exit code do filho precisa chegar até quem chamou `wardenv install`:
    // sem propagar, `install codex` numa versão sem tool hooks recusava e
    // imprimia o erro, mas a CLI ainda saía com 0 — script nenhum detectava
    // a falha.
    const r = require('child_process').spawnSync(
      process.execPath,
      [path.join(__dirname, 'install.js'), ...rest],
      { stdio: 'inherit' }
    );
    process.exit(r.status ?? 1);
  }

  case 'uninstall': {
    const r = require('child_process').spawnSync(
      process.execPath,
      [path.join(__dirname, 'install.js'), '--uninstall', ...rest],
      { stdio: 'inherit' }
    );
    process.exit(r.status ?? 1);
  }

  case 'status': {
    const cwd = process.cwd();
    let envs = [];
    try {
      envs = fs.readdirSync(cwd).filter((f) => /^\.env($|\.)/i.test(f));
    } catch (err) {
      die(`could not read ${cwd}: ${err.code || err.message}`);
    }
    console.log(`directory: ${cwd}`);
    if (!envs.length) {
      console.log('no .env files here.');
    } else {
      for (const e of envs) {
        const v = classifyPath(e);
        const s = summarizeEnvFile(path.join(cwd, e));
        const n = s && s.keys ? s.keys.length : 0;
        console.log(`  ${v.secret ? '🔒' : '📖'} ${e}  (${n} keys)`);
      }
    }
    const g = listGrants();
    console.log(`\nopen passes: ${g.length}`);
    for (const x of g) {
      const min = Math.max(0, Math.round((x.expiresAt - Date.now()) / 60000));
      console.log(`  ${x.path}  ${x.usesLeft} use(s), ~${min} min`);
    }
    break;
  }

  case 'keys': {
    const f = rest[0] || '.env';
    const p = path.resolve(process.cwd(), f);
    const s = summarizeEnvFile(p);
    if (!s) die(`could not read ${f}`);
    if (!s.keys.length) {
      console.log('(no key=value pairs)');
      break;
    }
    for (const k of s.keys) console.log(`${k.key}=<set, ${k.chars} chars>`);
    break;
  }

  case 'unlock': {
    const f = rest[0];
    if (!f) die('usage: wardenv unlock <file> [-n N] [-t MIN]');
    const nIdx = rest.indexOf('-n');
    const tIdx = rest.indexOf('-t');
    const uses = nIdx >= 0 ? parseInt(rest[nIdx + 1], 10) || 1 : 1;
    const mins = tIdx >= 0 ? parseInt(rest[tIdx + 1], 10) || 10 : 10;
    const p = path.resolve(process.cwd(), f);
    if (!fs.existsSync(p)) die(`file does not exist: ${f}`);

    // O unlock é um ato do humano. Bloquear `wardenv unlock` no hook não basta:
    // `node .../cli.js unlock`, `& wardenv unlock` e `cmd /c` passavam por fora
    // da regra de texto. O que o agente não tem é um terminal: o shell dele
    // roda sem TTY. E a confirmação digitada fecha o `Start-Process`, que abre
    // uma janela com TTY mas sem ninguém para digitar.
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      die(
        'wardenv unlock must be run by you, in an interactive terminal.\n' +
          'It refuses to run without one, so an agent cannot grant itself access.\n' +
          '(Git Bash/mintty users: run it from PowerShell, Windows Terminal, or `winpty wardenv unlock`.)'
      );
    }

    const base = path.basename(p);
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`Grant ${uses} read(s) of ${p} for ${mins} min? Type "${base}" to confirm: `, (answer) => {
      rl.close();
      if (answer.trim() !== base) {
        log({ event: 'unlock-refused', path: p, cwd: process.cwd() });
        die('not confirmed. Nothing was unlocked.');
      }
      const g = grant(process.cwd(), f, { uses, ttlMs: mins * 60000 });
      // Até aqui só o USO do unlock ia para o log, nunca a criação — não havia
      // como saber depois quem abriu a porta.
      log({ event: 'unlock-granted', path: g.path, uses, minutes: mins, tty: true, cwd: process.cwd() });
      console.log(`🔓 unlocked: ${g.path}`);
      console.log(`   ${uses} read(s), expires in ${mins} min`);
      console.log('   the agent may read this file on its next attempt.');
    });
    break;
  }

  case 'lock': {
    revokeAll();
    console.log('🔒 all passes revoked.');
    break;
  }

  case 'log': {
    const n = parseInt(rest[0], 10) || 20;
    const rows = tail(n);
    if (!rows.length) {
      console.log('(no records)');
      break;
    }
    for (const r of rows) {
      const when = (r.ts || '').replace('T', ' ').slice(0, 19);
      const what = r.path || r.command || (r.hits ? r.hits.join(',') : '');
      console.log(`${when}  ${String(r.event).padEnd(14)} ${r.tool || ''}  ${what}`);
    }
    break;
  }

  case 'check': {
    const c = rest.join(' ');
    if (!c) die('usage: wardenv check "<command>"');
    const v = analyzeCommand(c);
    const label = { block: '🚫 BLOCKED', redact: '🩹 OUTPUT REDACTED', allow: '✅ ALLOWED' }[v.action];
    console.log(`${label}  ${c}`);
    if (v.reason) console.log(`   reason: ${v.reason}`);
    break;
  }

  case 'scan': {
    const f = rest[0];
    let text;
    try {
      text = f ? fs.readFileSync(path.resolve(f), 'utf8') : fs.readFileSync(0, 'utf8');
    } catch (err) {
      die(f ? `could not read ${f}: ${err.code || err.message}` : 'no input on stdin');
    }
    const known = collectKnownSecrets(process.cwd());
    const { hits } = redactText(text, known);
    if (!hits.length) {
      console.log('✅ no secrets found.');
      process.exit(0);
    }
    console.log(`🚨 ${hits.length} secret(s): ${hits.join(', ')}`);
    process.exit(1);
  }

  default:
    help();
}
