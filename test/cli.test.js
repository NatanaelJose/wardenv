'use strict';
// Testes da interface de linha de comando.
//
// A outra suíte cobre a lógica; esta cobre o que o humano vê. Um erro de
// filesystem vazando como stack trace do Node é o tipo de coisa que faz a
// ferramenta parecer quebrada mesmo quando a decisão de segurança está certa.

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync, spawnSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');
const INSTALL = path.join(__dirname, '..', 'src', 'install.js');

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

// O precheck do Codex em install.js chama `codex --version` de verdade
// (versionAtLeast() em src/install.js). Um teste não pode depender de qual
// Codex, se algum, está instalado na máquina que roda `npm test` — nem esta,
// nem o CI, nem a de outro contribuidor — então este stub cria um `codex`
// (ou `codex.cmd` no Windows) que só sabe responder `--version`, na frente
// do PATH herdado por um processo filho.
function fakeExecutableOnPath(dir, name, version) {
  const bin = path.join(dir, 'fakebin');
  fs.mkdirSync(bin, { recursive: true });
  const script = process.platform === 'win32'
    ? `@echo off\r\necho ${name}-cli ${version}\r\n`
    : `#!/bin/sh\necho "${name}-cli ${version}"\n`;
  const file = path.join(bin, process.platform === 'win32' ? `${name}.cmd` : name);
  fs.writeFileSync(file, script);
  if (process.platform !== 'win32') fs.chmodSync(file, 0o755);
  return { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` };
}

test('fakeExecutableOnPath: o stub de versão responde no formato que install.js espera', () => {
  // O stub em si merece um teste próprio: se ele quebrar silenciosamente (um
  // problema de quoting no .cmd do Windows, por exemplo), os testes que o
  // usam passariam por acidente — o precheck cairia no caminho de "não
  // consigo checar a versão", que também não bloqueia, mascarando o defeito.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-fakebin-'));
  const env = fakeExecutableOnPath(home, 'codex', '0.156.0');
  const cmd = process.platform === 'win32' ? 'codex.cmd' : 'codex';
  const r = spawnSync(cmd, ['--version'], { encoding: 'utf8', env, shell: process.platform === 'win32' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /codex-cli 0\.156\.0/);
});

test('install: Codex com hooks de ferramenta (0.129+) instala, reinstala sem duplicar; uninstall preserva hook de terceiro', () => {
  // Sem uma sessão real ainda não foi verificado ponta a ponta — daí o aviso
  // UNVERIFIED. O que este teste garante é o instalador em si, numa versão
  // que TEM tool hooks: não duplica entrada, e o uninstall não some com
  // hooks de outra ferramenta.
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

  const env = fakeExecutableOnPath(home, 'codex', '0.156.0');
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

test('install: Codex sem hooks de ferramenta (< 0.129) recusa a instalação em vez de fingir proteção', () => {
  // Regressão do achado de auditoria: o instalador antigo recusava de vez
  // quando o Codex não tinha tool hooks. Isso foi perdido na refatoração
  // multi-agente — install "funcionava" e imprimia sucesso, mas o hook nunca
  // rodava porque a versão instalada não dispara PreToolUse/PostToolUse.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-install-old-codex-'));
  fs.mkdirSync(path.join(home, '.codex'));

  const runInstall = (args, env) => spawnSync(process.execPath, ['-e', [
    `require('os').homedir = () => ${JSON.stringify(home)};`,
    `process.argv = [process.execPath, 'install.js', ...${JSON.stringify(args)}];`,
    `require(${JSON.stringify(INSTALL)});`,
  ].join('\n')], { encoding: 'utf8', env: env || process.env });

  const env = fakeExecutableOnPath(home, 'codex', '0.116.0');
  const r = runInstall(['codex'], env);
  assert.equal(r.status, 1, 'install codex numa versão sem tool hooks deveria recusar');
  assert.match(r.stderr, /0\.129|tool hooks/i);
  const codexFile = path.join(home, '.codex', 'hooks.json');
  assert.ok(!fs.existsSync(codexFile), 'nada deveria ter sido escrito');
});

test('install: o comando registrado para Cursor é sintaxe PowerShell válida no Windows', () => {
  // Achado real: o hooks.json registrava o comando do hook sem o prefixo `&`.
  // No Windows, quando o agente spawna o comando via PowerShell (Cursor e o
  // Codex Desktop fazem isso; o Copilot roda seu campo powershell via
  // pwsh.exe), um caminho entre aspas no início da linha é só uma STRING, não
  // uma chamada: o parser lia até o próximo token como nova expressão e
  // travava em "--agent" (o `--` é o operador de decremento do PowerShell).
  // O hook nunca produzia JSON e o wardenv falhava aberto -- silenciosamente,
  // sem nenhum erro visível ao usuário. Reproduzido ao vivo contra um Codex
  // Desktop real antes deste fix.
  if (process.platform !== 'win32') return; // o bug é específico do PowerShell no Windows

  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wardenv-ps-syntax-'));
  const cursorDir = path.join(home, '.cursor');
  fs.mkdirSync(cursorDir);

  const runInstall = (args) => spawnSync(process.execPath, ['-e', [
    `require('os').homedir = () => ${JSON.stringify(home)};`,
    `process.argv = [process.execPath, 'install.js', ...${JSON.stringify(args)}];`,
    `require(${JSON.stringify(INSTALL)});`,
  ].join('\n')], { encoding: 'utf8' });

  runInstall(['cursor']);
  const cursorFile = path.join(cursorDir, 'hooks.json');
  const cfg = JSON.parse(fs.readFileSync(cursorFile, 'utf8'));
  const registeredCommand = cfg.hooks.preToolUse[0].command;

  // Roda a string de comando REGISTRADA de verdade dentro de um .ps1, o
  // mesmo jeito que quebrava antes -- sem simular o payload direto no node.
  const script = path.join(home, 'probe.ps1');
  fs.writeFileSync(script, registeredCommand);
  const payload = JSON.stringify({ cwd: home, tool_name: 'Shell', tool_input: { command: 'cat .env' } });
  const r = spawnSync('powershell', ['-NoProfile', '-File', script], { input: payload, encoding: 'utf8' });

  assert.equal(r.status, 0, `comando registrado deveria rodar em PowerShell sem erro de sintaxe\n${r.stderr}`);
  const out = JSON.parse(r.stdout.trim());
  assert.equal(out.permission, 'deny', 'deveria negar `cat .env`');
});
