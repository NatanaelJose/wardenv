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

// Monta um comando `codex` fake no PATH do processo filho, que só responde a
// `--version`, para o precheck do instalador ver a versão que o teste quer —
// independente de qual Codex esteja de fato instalado nesta máquina.
function withFakeCodexVersion(home, version, run) {
  const fs = require('node:fs');
  const path = require('node:path');
  const bin = path.join(home, 'fakebin');
  fs.mkdirSync(bin, { recursive: true });
  const script = process.platform === 'win32'
    ? `@echo off\r\necho codex-cli ${version}\r\n`
    : `#!/bin/sh\necho "codex-cli ${version}"\n`;
  const file = path.join(bin, process.platform === 'win32' ? 'codex.cmd' : 'codex');
  fs.writeFileSync(file, script);
  if (process.platform !== 'win32') fs.chmodSync(file, 0o755);
  return run({ ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` });
}

test('install: Codex com hooks de ferramenta (0.129+) instala, reinstala sem duplicar; uninstall preserva hook de terceiro', () => {
  // Sem uma sessão real ainda não foi verificado ponta a ponta — daí o aviso
  // UNVERIFIED. O que este teste garante é o instalador em si, numa versão
  // que TEM tool hooks: não duplica entrada, e o uninstall não some com
  // hooks de outra ferramenta.
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
  const runInstall = (args, env) => spawnSync(process.execPath, ['-e', [
    `require('os').homedir = () => ${JSON.stringify(home)};`,
    `process.argv = [process.execPath, 'install.js', ...${JSON.stringify(args)}];`,
    `require(${JSON.stringify(INSTALL)});`,
  ].join('\n')], { encoding: 'utf8', env: env || process.env });

  const hooked = (f) => /wardenv[\\/]+hooks/i.test(fs.readFileSync(f, 'utf8'));

  withFakeCodexVersion(home, '0.156.0', (env) => {
    assert.equal(runInstall([], env).status, 0);
    assert.ok(hooked(path.join(home, '.claude', 'settings.json')), 'Claude Code deveria receber o hook');
    assert.ok(hooked(codexFile), 'Codex 0.156 deveria receber o hook (não verificado, mas instalado)');
    assert.match(fs.readFileSync(codexFile, 'utf8'), /third-party/, 'hook de terceiro deveria sobreviver à instalação');

    const beforeReinstall = (fs.readFileSync(codexFile, 'utf8').match(/wardenv[\\/]+hooks/gi) || []).length;
    const explicit = runInstall(['codex'], env);
    assert.equal(explicit.status, 0, 'reinstalar não deveria falhar');
    const afterReinstall = (fs.readFileSync(codexFile, 'utf8').match(/wardenv[\\/]+hooks/gi) || []).length;
    assert.equal(afterReinstall, beforeReinstall, 'reinstalar não deveria duplicar a entrada');

    assert.equal(runInstall(['codex', '--uninstall'], env).status, 0);
    assert.equal(hooked(codexFile), false, 'entrada antiga do wardenv deveria sair');
    assert.match(fs.readFileSync(codexFile, 'utf8'), /third-party/, 'hook de terceiro deveria ficar');
  });
});

test('install: Codex sem hooks de ferramenta (< 0.129) recusa a instalação em vez de fingir proteção', () => {
  // Regressão do achado de auditoria: o instalador antigo recusava de vez
  // quando o Codex não tinha tool hooks. Isso foi perdido na refatoração
  // multi-agente — install "funcionava" e imprimia sucesso, mas o hook nunca
  // rodava porque a versão instalada não dispara PreToolUse/PostToolUse.
  const fs = require('node:fs');
  const os = require('node:os');
  const { spawnSync } = require('node:child_process');
  const INSTALL = path.join(__dirname, '..', 'src', 'install.js');

  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-install-old-codex-'));
  fs.mkdirSync(path.join(home, '.codex'));

  const runInstall = (args, env) => spawnSync(process.execPath, ['-e', [
    `require('os').homedir = () => ${JSON.stringify(home)};`,
    `process.argv = [process.execPath, 'install.js', ...${JSON.stringify(args)}];`,
    `require(${JSON.stringify(INSTALL)});`,
  ].join('\n')], { encoding: 'utf8', env: env || process.env });

  withFakeCodexVersion(home, '0.116.0', (env) => {
    const r = runInstall(['codex'], env);
    assert.equal(r.status, 1, 'install codex numa versão sem tool hooks deveria recusar');
    assert.match(r.stderr, /0\.129|tool hooks/i);
    const codexFile = path.join(home, '.codex', 'hooks.json');
    assert.ok(!fs.existsSync(codexFile), 'nada deveria ter sido escrito');
  });
});
