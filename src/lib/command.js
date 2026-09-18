'use strict';
// Análise de linha de comando.
//
// Duas famílias de risco, deliberadamente separadas porque a resposta é diferente:
//
//   LEITURA DIRETA  — `cat .env`, `type .env`, `Get-Content .env`
//                     O alvo aparece no comando. Detectável com alta confiança.
//
//   RICOCHETE       — `printenv`, `docker compose config`, `git show HEAD:.env`
//                     O comando é inocente; o SEGREDO SAI NO OUTPUT.
//                     Não dá pra saber pelo texto do comando se vai vazar —
//                     por isso estes são tratados no PostToolUse, redigindo
//                     a saída, e não bloqueados na entrada (bloquear `printenv`
//                     inteiro seria insuportável no dia a dia).

const { classifyPath } = require('./targets');

// Comandos cujo propósito é despejar conteúdo de arquivo.
const READERS = [
  'cat', 'bat', 'head', 'tail', 'less', 'more', 'nl', 'strings', 'xxd', 'od',
  'type', 'get-content', 'gc', 'sed', 'awk', 'grep', 'rg', 'ripgrep',
  'select-string', 'sls', 'cp', 'copy', 'mv', 'move', 'rsync', 'scp',
  'base64', 'openssl', 'tee', 'dd', 'jq', 'yq', 'sort', 'uniq', 'wc',
];

// Comandos que *emitem* ambiente/segredo no stdout sem citar o arquivo.
// Não bloqueiam — marcam a saída para redação.
const EMITTERS = [
  /^printenv\b/i,
  /^env\b(?!\s+[A-Z_]+=)/i,          // `env` sozinho lista tudo; `env FOO=1 cmd` não
  /^set\b\s*$/i,
  /\bGet-ChildItem\s+Env:/i,
  /\bdir\s+env:/i,
  /\$Env:/i,
  /\bdocker\s+(compose\s+)?config\b/i,
  /\bdocker\s+inspect\b/i,
  /\bkubectl\s+get\s+secret/i,
  /\bkubectl\s+describe\s+secret/i,
  /\bvercel\s+env\b/i,
  /\bnetlify\s+env\b/i,
  /\bfly\s+secrets\b/i,
  /\bheroku\s+config\b/i,
  /\bwrangler\s+secret\b/i,
  /\bdoppler\s+secrets\b/i,
  /\bgh\s+secret\b/i,
  /\bsupabase\s+secrets\b/i,
  /\baws\s+secretsmanager\b/i,
  /\baws\s+ssm\s+get-parameter/i,
  /\bgcloud\s+secrets\b/i,
  /\bop\s+(read|item)\b/i,           // 1Password CLI
  /\bpass\s+show\b/i,
];

// `git show HEAD:.env`, `git cat-file`, `git log -p` sobre arquivo de segredo.
const GIT_REVEAL = /\bgit\s+(show|cat-file|log|diff)\b/i;

function stripQuotes(tok) {
  return tok.replace(/^['"]|['"]$/g, '');
}

/**
 * Quebra a linha em tokens, achatando pipes/&&/; para varrer tudo.
 */
function tokenize(cmd) {
  return String(cmd || '')
    .split(/[\s|;&()<>]+/)
    .map(stripQuotes)
    .filter(Boolean);
}

/**
 * Procura qualquer token que seja caminho de segredo.
 * @returns {{hit: boolean, token?: string, reason?: string}}
 */
function findSecretPathToken(cmd) {
  for (const raw of tokenize(cmd)) {
    // `git show HEAD:.env` — o alvo vem depois de `:`
    const candidates = raw.includes(':') ? [raw, raw.split(':').pop()] : [raw];
    for (const tok of candidates) {
      if (!tok || tok.startsWith('-')) continue;
      const verdict = classifyPath(tok);
      if (verdict.secret) {
        return { hit: true, token: tok, reason: verdict.reason };
      }
    }
  }
  return { hit: false };
}

/**
 * Analisa um comando bash/powershell.
 *
 * @returns {{action: 'allow'|'block'|'redact', reason?: string, token?: string}}
 *   block  — leitura direta de arquivo de segredo
 *   redact — comando que pode emitir segredo no output; deixa passar e
 *            marca para redação no PostToolUse
 */
// O agente não pode quebrar o próprio wardenv. Sem isto, todo o resto é teatro:
// bastaria o agente rodar `wardenv unlock .env` e ler o arquivo em seguida.
// O unlock é um ato do humano, no terminal dele.
const SELF_DISARM = [
  /\bwardenv\s+(unlock|uninstall|install)\b/i,
  /\bwardenv\b[\s\S]*--uninstall/i,
  /install\.js\b/i,
  /(^|[\s/\\])\.wardenv([\\/]|\b)/i,      // mexer no estado (grants.json, audit.jsonl)
  /settings\.json[\s\S]*wardenv|wardenv[\s\S]*settings\.json/i,
];

function analyzeCommand(cmd) {
  const text = String(cmd || '');
  if (!text.trim()) return { action: 'allow' };

  for (const re of SELF_DISARM) {
    if (re.test(text)) {
      return {
        action: 'block',
        reason: 'attempt to disarm wardenv',
      };
    }
  }

  const found = findSecretPathToken(text);

  if (found.hit) {
    const first = (tokenize(text)[0] || '').toLowerCase();
    const bin = first.split('/').pop().split('\\').pop();

    // Comando de leitura + alvo de segredo = bloqueio duro.
    if (READERS.includes(bin)) {
      return { action: 'block', reason: `${bin} on ${found.token}`, token: found.token };
    }

    // git revelando conteúdo versionado de um .env
    if (GIT_REVEAL.test(text)) {
      return { action: 'block', reason: `git exposing ${found.token}`, token: found.token };
    }

    // Qualquer outra menção a arquivo de segredo: não bloqueia (pode ser
    // `ls -la .env` ou `echo X >> .env`, ambos legítimos), mas a saída é
    // redigida por precaução.
    return { action: 'redact', reason: `mentions ${found.token}`, token: found.token };
  }

  for (const re of EMITTERS) {
    if (re.test(text)) {
      return { action: 'redact', reason: 'command may emit environment variables' };
    }
  }

  return { action: 'allow' };
}

module.exports = { analyzeCommand, findSecretPathToken, READERS, EMITTERS };
