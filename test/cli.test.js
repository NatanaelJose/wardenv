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

test('cli: unlock recusa sem terminal interativo', () => {
  // O shell do agente não tem TTY. Antes, `node .../cli.js unlock .env` rodado
  // pelo agente criava o grant: foi o que o Codex fez no teste real.
  const fs = require('node:fs');
  const os = require('node:os');
  // Só olha o grant DESTE arquivo: os arquivos de teste rodam em paralelo e
  // dividem ~/.wardenv/grants.json, então limpar ou contar tudo disputaria
  // com os testes de hook.
  const { isUnlocked } = require('../src/lib/unlock');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-cli-tty-'));
  fs.writeFileSync(path.join(dir, '.env'), 'K=abcdefghijklmnop\n');

  const { out, code } = run(['unlock', '.env'], dir);
  assert.equal(code, 1, 'deveria sair com erro');
  assert.match(out, /interactive terminal/);
  assert.equal(isUnlocked(dir, '.env'), false, 'nenhum grant deveria ter sido criado');
});

test('install: Codex não é instalado, mas o uninstall limpa entrada antiga', () => {
  // No codex-cli 0.116 os hooks de ferramenta nunca disparam. Instalar
  // mesmo assim imprimia "🔒 installed" e deixava o .env exposto.
  const fs = require('node:fs');
  const os = require('node:os');
  const { spawnSync } = require('node:child_process');
  const INSTALL = path.join(__dirname, '..', 'src', 'install.js');

  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-install-'));
  fs.mkdirSync(path.join(home, '.claude'));
  fs.mkdirSync(path.join(home, '.codex'));
  const codexFile = path.join(home, '.codex', 'hooks.json');
  fs.writeFileSync(codexFile, JSON.stringify({ hooks: {
    PreToolUse: [{ matcher: '^(Bash)$', hooks: [{ type: 'command', command: '"node" "C:/x/wardenv/hooks/pre-tool.js"' }] }],
    SessionStart: [{ matcher: 'startup', hooks: [{ type: 'command', command: 'echo third-party' }] }],
  } }));

  // os.homedir() é trocado antes de carregar o instalador: no Windows ele não
  // obedece HOME/USERPROFILE, e sem isto o teste gravaria na config real.
  const runInstall = (args) => spawnSync(process.execPath, ['-e', [
    `require('os').homedir = () => ${JSON.stringify(home)};`,
    `process.argv = [process.execPath, 'install.js', ...${JSON.stringify(args)}];`,
    `require(${JSON.stringify(INSTALL)});`,
  ].join('\n')], { encoding: 'utf8' });

  const hooked = (f) => /wardenv[\\/]+hooks/i.test(fs.readFileSync(f, 'utf8'));

  assert.equal(runInstall([]).status, 0);
  assert.ok(hooked(path.join(home, '.claude', 'settings.json')), 'Claude Code deveria receber o hook');

  const explicit = runInstall(['codex']);
  assert.equal(explicit.status, 1, 'install codex deveria recusar');
  assert.match(explicit.stderr, /not supported/);

  assert.equal(runInstall(['codex', '--uninstall']).status, 0);
  assert.equal(hooked(codexFile), false, 'entrada antiga do wardenv deveria sair');
  assert.match(fs.readFileSync(codexFile, 'utf8'), /third-party/, 'hook de terceiro deveria ficar');
});
