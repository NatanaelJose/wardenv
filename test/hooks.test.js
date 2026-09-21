'use strict';
// Testes de integração do hooks/pre-tool.js — ponta a ponta, via stdin/stdout
// real, exatamente como o Claude Code invoca.
//
// Existe porque o bug mais grave já encontrado no wardenv não estava em
// nenhum módulo de src/lib/: estava na cola em hooks/pre-tool.js. O bloco
// de Read consultava isUnlocked(); o bloco de Bash/PowerShell nunca
// consultava. Resultado: `wardenv unlock .env` liberava a tool Read, mas
// `cat .env` e `grep ... .env` continuavam bloqueados para sempre — o
// caminho de leitura mais comum no dia a dia. Testes de unidade em
// lib/unlock.js e lib/command.js separadamente nunca pegariam isto, porque
// cada peça funcionava sozinha; só a integração expunha a lacuna.

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const HOOK = path.join(__dirname, '..', 'hooks', 'pre-tool.js');
const CLI = path.join(__dirname, '..', 'src', 'cli.js');
const { revokeAll } = require('../src/lib/unlock');

function runHook(payload) {
  try {
    const out = execFileSync(process.execPath, [HOOK], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
    });
    return out.trim() ? JSON.parse(out) : null; // null = allowed, sem output
  } catch (e) {
    throw new Error('hook process failed: ' + e.message);
  }
}

function isDenied(result) {
  return !!(result && result.hookSpecificOutput && result.hookSpecificOutput.permissionDecision === 'deny');
}

function unlock(cwd, file, args = []) {
  return execFileSync(process.execPath, [CLI, 'unlock', file, ...args], { cwd, encoding: 'utf8' });
}

// Sandbox isolado por teste: cada um cria seu próprio .env e cwd, para não
// competir por grants com outros testes rodando os mesmos caminhos.
function makeSandbox(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `wardenv-hook-${name}-`));
  fs.writeFileSync(path.join(dir, '.env'), 'SECRET_KEY=abcdefghijklmnop\n');
  return dir;
}

test('setup: limpa grants residuais de execuções anteriores', () => {
  revokeAll();
});

test('Read: bloqueia .env sem unlock', () => {
  const dir = makeSandbox('read-block');
  const res = runHook({ cwd: dir, tool_name: 'Read', tool_input: { file_path: path.join(dir, '.env') } });
  assert.ok(isDenied(res), 'deveria negar leitura sem unlock');
});

test('Read: unlock via CLI libera a tool Read', () => {
  const dir = makeSandbox('read-unlock');
  unlock(dir, '.env');
  const res = runHook({ cwd: dir, tool_name: 'Read', tool_input: { file_path: path.join(dir, '.env') } });
  assert.equal(res, null, 'deveria liberar após unlock');
});

test('Bash: unlock via CLI libera `grep ... .env` (regressão do bug real)', () => {
  const dir = makeSandbox('bash-unlock');

  const before = runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'grep SECRET .env' } });
  assert.ok(isDenied(before), 'deveria negar antes do unlock');

  unlock(dir, '.env');

  const after = runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'grep SECRET .env' } });
  assert.equal(after, null, 'unlock deveria liberar o comando Bash também, não só a tool Read');
});

test('Bash: unlock via CLI libera `cat .env`', () => {
  const dir = makeSandbox('bash-cat');
  unlock(dir, '.env');
  const res = runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } });
  assert.equal(res, null);
});

test('Bash: o unlock é de uso único — segunda leitura volta a bloquear', () => {
  const dir = makeSandbox('bash-single-use');
  unlock(dir, '.env', ['-n', '1']);

  const first = runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } });
  assert.equal(first, null, 'primeira leitura deveria passar');

  const second = runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } });
  assert.ok(isDenied(second), 'segunda leitura deveria bloquear — grant já consumido');
});

test('Bash: unlock respeita o número de usos concedido (-n 2)', () => {
  const dir = makeSandbox('bash-two-uses');
  unlock(dir, '.env', ['-n', '2']);

  assert.equal(runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } }), null);
  assert.equal(runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } }), null);
  assert.ok(isDenied(runHook({ cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } })));
});

test('Bash: unlock de um arquivo não libera outro', () => {
  const dirA = makeSandbox('scope-a');
  const dirB = makeSandbox('scope-b');
  unlock(dirA, '.env');

  const resB = runHook({ cwd: dirB, tool_name: 'Bash', tool_input: { command: 'cat .env' } });
  assert.ok(isDenied(resB), 'unlock não deveria vazar para outro diretório/arquivo');
});
