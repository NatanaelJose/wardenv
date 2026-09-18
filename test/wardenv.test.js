'use strict';
// Suíte do wardenv. Roda com `node --test`.
//
// Duas classes de teste importam aqui, e a segunda é a que mais importa:
//   - VAZAMENTO  (falso negativo): um segredo passou. Falha de segurança.
//   - ATRITO     (falso positivo): algo legítimo foi bloqueado. Falha de uso.
// Uma ferramenta que só testa a primeira vira insuportável e acaba desligada.

const { test } = require('node:test');
const assert = require('node:assert');

const { classifyPath } = require('../src/lib/targets');
const { analyzeCommand } = require('../src/lib/command');
const { redactText, parseEnv } = require('../src/lib/redact');

// ---------------------------------------------------------------- caminhos

test('cofre: arquivos de segredo são reconhecidos', () => {
  const secrets = [
    '.env', '.env.local', '.env.production', '.env.development.local',
    'app/.env', 'C:/proj/.env', 'id_rsa', '.ssh/id_ed25519',
    'certs/server.pem', 'private.key', 'service-account.json',
    '.npmrc', 'terraform.tfstate', '.aws/credentials',
  ];
  for (const p of secrets) {
    assert.equal(classifyPath(p).secret, true, `deveria bloquear: ${p}`);
  }
});

test('vitrine: templates nunca são bloqueados', () => {
  const ok = [
    '.env.example', '.env.sample', '.env.template', '.env.dist',
    'env.example', '.env.defaults',
  ];
  for (const p of ok) {
    assert.equal(classifyPath(p).secret, false, `não deveria bloquear: ${p}`);
  }
});

test('atrito: código normal passa ileso', () => {
  const ok = [
    'src/index.ts', 'README.md', 'package.json', 'environment.ts',
    'src/environments/environment.prod.ts', 'keyboard.tsx', 'env-utils.js',
    'docs/env.example.md', 'monkey.ts',
  ];
  for (const p of ok) {
    assert.equal(classifyPath(p).secret, false, `falso positivo: ${p}`);
  }
});

// ---------------------------------------------------------------- comandos

test('bloqueia leitura direta de segredo', () => {
  const blocked = [
    'cat .env', 'type .env', 'head -5 .env.local', 'tail .env',
    'grep API_KEY .env', 'rg SECRET .env.production',
    'Get-Content .env', 'base64 .env', 'cp .env /tmp/x',
    'git show HEAD:.env', 'cat ~/.ssh/id_rsa', 'less .env | grep KEY',
  ];
  for (const c of blocked) {
    assert.equal(analyzeCommand(c).action, 'block', `deveria bloquear: ${c}`);
  }
});

test('redige comandos que emitem ambiente', () => {
  const redacted = [
    'printenv', 'docker compose config', 'vercel env pull',
    'heroku config', 'kubectl get secret my-secret -o yaml',
    'fly secrets list', 'gh secret list',
  ];
  for (const c of redacted) {
    assert.equal(analyzeCommand(c).action, 'redact', `deveria redigir: ${c}`);
  }
});

test('atrito: comandos de trabalho normal passam', () => {
  const ok = [
    'npm run build', 'npm test', 'git status', 'git commit -m "fix"',
    'cat package.json', 'cat .env.example', 'ls -la',
    'node -e "console.log(1)"', 'env FOO=1 npm test',
    'docker build -t app .', 'tsc --noEmit',
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
});

// ---------------------------------------------------------------- redação

test('redige valores conhecidos vindos do .env', () => {
  const known = new Map([['Sup3rS3cr3tPassword123', 'DB_PASSWORD']]);
  const { text, hits } = redactText('conectando com Sup3rS3cr3tPassword123 ok', known);
  assert.ok(!text.includes('Sup3rS3cr3tPassword123'), 'valor vazou');
  assert.ok(text.includes('«wardenv:DB_PASSWORD»'));
  assert.deepEqual(hits, ['DB_PASSWORD']);
});

test('rotula cada forma de segredo corretamente', () => {
  const cases = [
    ['sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAA', 'anthropic-key'],
    ['sk-proj-AAAAAAAAAAAAAAAAAAAAAA', 'openai-project-key'],
    ['ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'github-token'],
    ['AKIAIOSFODNN7EXAMPLE', 'aws-key-id'],
    ['sk_live_AAAAAAAAAAAAAAAAAAAA', 'stripe-key'],
    ['postgresql://u:p4ssw0rd@host:5432/db', 'postgres-url'],
  ];
  for (const [secret, label] of cases) {
    const { text, hits } = redactText(`valor=${secret}`, new Map());
    assert.ok(!text.includes(secret), `vazou: ${secret}`);
    assert.ok(hits.includes(label), `rótulo errado para ${secret}: ${hits.join(',')}`);
  }
});

test('atrito: não redige valores públicos nem texto comum', () => {
  const known = new Map();
  const inputs = [
    'NODE_ENV=production',
    'PORT=3000',
    'a chave sk- sozinha não é segredo',
    'import { sk } from "./sk"',
  ];
  for (const t of inputs) {
    const { hits } = redactText(t, known);
    assert.equal(hits.length, 0, `falso positivo em: ${t}`);
  }
});

test('valor curto não é redigido (evitaria apagar "production")', () => {
  // collectKnownSecrets filtra <12 chars; aqui garantimos a política
  const { hits } = redactText('NODE_ENV=production', new Map());
  assert.equal(hits.length, 0);
});

test('chave privada PEM multilinha é redigida inteira', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----';
  const { text, hits } = redactText(`key:\n${pem}\nfim`, new Map());
  assert.ok(!text.includes('AAAA'), 'corpo da chave vazou');
  assert.ok(hits.includes('private-key'));
  assert.ok(text.includes('fim'), 'redação comeu texto demais');
});

// ---------------------------------------------------------------- parser

test('parseEnv lida com aspas, export e comentários', () => {
  const raw = [
    '# comentário',
    'A=1',
    'export B="dois"',
    "C='tres'",
    'D=',
    'E=com=igual',
  ].join('\n');
  const got = Object.fromEntries(parseEnv(raw));
  assert.equal(got.A, '1');
  assert.equal(got.B, 'dois');
  assert.equal(got.C, 'tres');
  assert.equal(got.D, undefined, 'valor vazio não deve virar par');
  assert.equal(got.E, 'com=igual');
});

// ------------------------------------------------------- auto-desarme

test('o agente não consegue desarmar o wardenv', () => {
  const attacks = [
    'wardenv unlock .env',
    'wardenv uninstall',
    'node src/install.js --uninstall',
    'rm -rf ~/.wardenv',
    'cat ~/.wardenv/grants.json',
    'echo "{}" > ~/.claude/settings.json && wardenv',
  ];
  for (const c of attacks) {
    assert.equal(analyzeCommand(c).action, 'block', `deveria bloquear: ${c}`);
  }
});

test('atrito: falar de wardenv sem desarmar é permitido', () => {
  assert.equal(analyzeCommand('npm test').action, 'allow');
  assert.equal(analyzeCommand('git commit -m "add wardenv docs"').action, 'allow');
});
