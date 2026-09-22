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
    'node /c/dev/wardenv/src/install.js --uninstall',
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

// --------------------------- literais: dado não é alvo (regressão real)
//
// Estes casos vieram de dois bloqueios que o wardenv aplicou ao próprio
// desenvolvimento: uma mensagem de commit que citava ".env" e um array de
// teste contendo 'secrets/prod.json'. Texto citado é DADO, não alvo.

test('atrito: .env citado em mensagem de commit não bloqueia', () => {
  const ok = [
    'git commit -m "fix .env parsing"',
    'git commit -m "docs: explain why .env is blocked"',
    'echo "read .env.example instead"',
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
});

test('atrito: caminho de segredo dentro de string de código não bloqueia', () => {
  const c = `node -e "for (const p of ['secrets/prod.json','my-secrets/']) check(p)"`;
  assert.equal(analyzeCommand(c).action, 'allow');
});

test('atrito: heredoc com menção a segredo não bloqueia', () => {
  const c = [
    'git commit -F - <<EOF',
    'fix: stop reading .env directly',
    'EOF',
  ].join('\n');
  assert.equal(analyzeCommand(c).action, 'allow');
});

test('o alvo real continua bloqueado mesmo com literais por perto', () => {
  assert.equal(analyzeCommand('cat .env').action, 'block');
  assert.equal(analyzeCommand('echo "reading now" && cat .env').action, 'block');
  assert.equal(analyzeCommand('grep KEY .env | head -2').action, 'block');
});

test('atrito: install.js de OUTRO projeto não é auto-desarme', () => {
  // A regra original casava com qualquer caminho contendo "install.js",
  // o que bloquearia o instalador de qualquer projeto no mundo.
  const ok = [
    'node scripts/install.js',
    'node /tmp/t-install.js',
    'npm run install.js',
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
  // mas o instalador do próprio wardenv continua protegido
  assert.equal(analyzeCommand('node C:/dev/wardenv/src/install.js').action, 'block');
});

test('auto-desarme é detectado via executor (bash -c, npx)', () => {
  // `wardenv` precisa estar em posição de COMANDO — no início do segmento ou
  // logo após um executor. Isso cobre a evasão sem bloquear documentação.
  const disarm = [
    ['bash -c ', '"', 'wardenv unlock .env', '"'].join(''),
    ['npx ', 'wardenv', ' unlock .env'].join(''),
    ['echo oi && ', 'wardenv', ' unlock .env'].join(''),
  ];
  for (const c of disarm) {
    assert.equal(analyzeCommand(c).action, 'block', `deveria bloquear: ${c}`);
  }
});

test('atrito: procurar ou documentar o comando não é desarme', () => {
  // Estes vieram de bloqueios reais durante o desenvolvimento: buscar a
  // string na documentação não é tentar desarmar a ferramenta.
  const ok = [
    ['grep -n ', '"', 'wardenv install', '"', ' README.md'].join(''),
    ['echo ', '"', 'run wardenv unlock to grant access', '"'].join(''),
    ['git commit -m ', '"', 'docs: explain wardenv install', '"'].join(''),
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
});

// ------------------------------------------------ alvo entre aspas (#1)

test('cofre: alvo entre aspas é reconhecido', () => {
  // As aspas são sintaxe do shell, não parte do nome: `cat ".env"` mira o
  // mesmo arquivo que `cat .env`. Antes disto, `stripLiterals` apagava a
  // string inteira e o comando passava como `allow` — o comentário da função
  // afirmava que o token sobrevivia, e não sobrevivia.
  const E = ['.e', 'nv'].join('');
  const quoted = [
    ['cat "', E, '"'].join(''),
    ["cat '", E, "'"].join(''),
    ['cat "', E, '.local"'].join(''),
    ['grep KEY "', E, '"'].join(''),
  ];
  for (const c of quoted) {
    assert.equal(analyzeCommand(c).action, 'block', `deveria bloquear: ${c}`);
  }
  assert.equal(classifyPath(['"', E, '"'].join('')).secret, true);
  assert.equal(classifyPath([' ', E, ' '].join('')).secret, true);
});

test('atrito: menção entre aspas continua liberada', () => {
  // A contraparte do teste acima: o literal que é FRASE sobre o arquivo
  // segue sendo dado, não alvo. Sem isto, o fix de aspas reintroduziria
  // exatamente os falsos positivos que stripLiterals existe para evitar.
  const E = ['.e', 'nv'].join('');
  const ok = [
    ['git commit -m "fix ', E, ' parsing"'].join(''),
    ['echo "the ', E, ' file holds credentials"'].join(''),
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
});

// --------------------------------------- interpretador na linha (#3)

test('cofre: interpretador lendo segredo na própria linha é bloqueado', () => {
  // `node -e "...readFileSync('.env')"` passava como `allow`: o caminho vive
  // dentro de uma string, então stripLiterals o removia antes da análise.
  // Ler config por one-liner é movimento comum de agente, não ofuscação.
  const E = ['.e', 'nv'].join('');
  const cases = [
    ['node -e "console.log(require(', "'fs'", ").readFileSync('", E, "'))\""].join(''),
    ['python -c "print(open(', "'", E, "'", ').read())"'].join(''),
    ["ruby -e 'puts File.read(\"", E, '")\''].join(''),
    ['echo oi && node -e "require(', "'fs'", ").readFileSync('", E, "')\""].join(''),
  ];
  for (const c of cases) {
    assert.equal(analyzeCommand(c).action, 'block', `deveria bloquear: ${c}`);
  }
});

test('atrito: one-liner que não toca segredo continua liberado', () => {
  const ok = [
    'node -e "console.log(1+1)"',
    'node -e "console.log(process.env.PORT)"',
    'node scripts/build.js',
    'python -c "import sys; print(sys.version)"',
  ];
  for (const c of ok) {
    assert.equal(analyzeCommand(c).action, 'allow', `falso positivo: ${c}`);
  }
});

// ------------------------------------------------ rotação do log (#5)

test('auditoria: rotação preserva histórico em vez de sobrescrever', () => {
  // Antes guardava só `.1`: cada rotação apagava a anterior e a trilha parava
  // em ~4MB. Num log de segurança, truncamento silencioso some justo com o
  // histórico antigo que se quer auditar depois.
  const fs = require('node:fs');
  const os = require('node:os');
  const pathMod = require('node:path');
  const { execFileSync } = require('node:child_process');

  const home = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'wardenv-rotate-'));
  const auditPath = pathMod.join(__dirname, '..', 'src', 'lib', 'audit.js');

  // Roda num processo isolado com os.homedir() sobrescrito ANTES de carregar
  // o módulo: LOG_DIR é resolvido na carga, e no Windows os.homedir() lê do
  // SO em vez de HOME/USERPROFILE — sem este stub o teste escreveria no log
  // real do usuário em vez do sandbox.
  //
  // `sanitize()` trunca cada string em 400 chars, então o volume tem de vir
  // do NÚMERO de entradas, não do tamanho de uma só.
  const script = [
    'const os = require("node:os");',
    `os.homedir = () => ${JSON.stringify(home)};`,
    `const { log, LOG_FILE } = require(${JSON.stringify(auditPath)});`,
    `if (!LOG_FILE.startsWith(${JSON.stringify(home)})) throw new Error("stub falhou: " + LOG_FILE);`,
    'const big = "x".repeat(1000);',
    'for (let i = 0; i < 20000; i++) log({ event: "t", path: big });',
  ].join('\n');

  execFileSync(process.execPath, ['-e', script]);

  const files = fs.readdirSync(pathMod.join(home, '.wardenv'))
    .filter((f) => f.startsWith('audit.jsonl'));

  assert.ok(files.includes('audit.jsonl.1'), 'deveria existir o primeiro rotacionado');
  assert.ok(files.includes('audit.jsonl.2'), 'o histórico anterior deveria sobreviver, não ser sobrescrito');
  assert.ok(files.length <= 6, `deveria parar em 5 rotacionados + o atual, veio ${files.length}`);
});
