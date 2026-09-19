'use strict';
// Testes da interface de linha de comando.
//
// A outra suíte cobre a lógica; esta cobre o que o humano vê. Um erro de
// filesystem vazando como stack trace do Node é o tipo de coisa que faz a
// ferramenta parecer quebrada mesmo quando a decisão de segurança está certa.

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');

function run(args, cwd) {
  try {
    const out = execFileSync(process.execPath, [CLI, ...args], {
      cwd: cwd || path.join(__dirname, '..'),
      encoding: 'utf8',
      stdio: 'pipe',
    });
    return { out, code: 0 };
  } catch (e) {
    return { out: (e.stdout || '') + (e.stderr || ''), code: e.status };
  }
}

test('cli: sem argumento mostra ajuda', () => {
  const { out } = run([]);
  assert.match(out, /wardenv install/);
  assert.match(out, /wardenv unlock/);
});

test('cli: check classifica corretamente', () => {
  assert.match(run(['check', 'cat .env']).out, /BLOCKED/);
  assert.match(run(['check', 'npm run build']).out, /ALLOWED/);
  assert.match(run(['check', 'printenv']).out, /REDACTED/);
});

test('cli: erro de filesystem não vaza stack trace', () => {
  const { out, code } = run(['scan', '/definitivamente/nao/existe.txt']);
  assert.equal(code, 1, 'deveria sair com código de erro');
  assert.match(out, /could not read/);
  assert.doesNotMatch(out, /at Object\.|node:internal|node:fs/, 'stack trace vazou');
});

test('cli: unlock exige argumento e valida existência', () => {
  assert.match(run(['unlock']).out, /usage:/);
  const { out, code } = run(['unlock', 'nao-existe.env']);
  assert.equal(code, 1);
  assert.match(out, /does not exist/);
});

test('cli: check exige argumento', () => {
  assert.match(run(['check']).out, /usage:/);
});

test('cli: comando desconhecido cai na ajuda, sem crash', () => {
  const { out, code } = run(['foobar']);
  assert.equal(code, 0);
  assert.match(out, /wardenv install/);
});
