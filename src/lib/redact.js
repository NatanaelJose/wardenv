'use strict';
// Redação de saída.
//
// Duas estratégias combinadas, porque sozinha nenhuma basta:
//
//   1. VALOR CONHECIDO — lê os .env do projeto, coleta os valores reais e
//      apaga literalmente esses valores de qualquer texto. É a mais forte:
//      pega o segredo mesmo quando ele sai sem o nome da chave do lado
//      (ex.: um curl que ecoa o token no meio de uma URL).
//
//   2. FORMA DE SEGREDO — regex de formatos conhecidos (sk-..., ghp_...,
//      JWT, chave PEM). Pega segredo que nunca passou por um .env, como
//      um token que veio de resposta de API.

const fs = require('fs');
const path = require('path');

const MASK = (name) => `«wardenv:${name}»`;

// Valores curtos demais geram falso positivo catastrófico
// (ex.: NODE_ENV=production apagaria a palavra "production" do mundo).
const MIN_VALUE_LEN = 12;

// Chaves cujo valor é notoriamente não-secreto — nunca redigir.
const PUBLIC_KEYS = /^(NODE_ENV|PORT|HOST|TZ|LANG|LOG_LEVEL|NEXT_PUBLIC_VERCEL_ENV|CI|DEBUG)$/i;

const DASHES = '-'.repeat(5);
const PEM_OPEN = `${DASHES}BEGIN `;
const PEM_CLOSE = `${DASHES}END `;

const SHAPES = [
  // Ordem importa: a forma mais específica precisa casar antes da genérica,
  // senão `sk-ant-...` seria rotulado como chave OpenAI.
  [/\bsk-ant-[A-Za-z0-9_-]{16,}/g, 'anthropic-key'],
  [/\bsk-proj-[A-Za-z0-9_-]{16,}/g, 'openai-project-key'],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, 'openai-key'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, 'github-token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, 'github-pat'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, 'slack-token'],
  [/\bAKIA[0-9A-Z]{16}\b/g, 'aws-key-id'],
  [/\bASIA[0-9A-Z]{16}\b/g, 'aws-temp-key'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'google-key'],
  [/\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'jwt'],
  [/\bsbp_[A-Za-z0-9]{20,}/g, 'supabase-token'],
  [/\bglpat-[A-Za-z0-9_-]{16,}/g, 'gitlab-token'],
  [/\bdop_v1_[A-Za-z0-9]{32,}/g, 'doppler-token'],
  [/\bshpat_[A-Za-z0-9]{20,}/g, 'shopify-token'],
  [/\bre_[A-Za-z0-9_]{16,}/g, 'resend-key'],
  [/\brk_(live|test)_[A-Za-z0-9]{16,}/g, 'stripe-restricted'],
  [/\bsk_(live|test)_[A-Za-z0-9]{16,}/g, 'stripe-key'],
  [/\bpostgres(ql)?:\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+/gi, 'postgres-url'],
  [/\bmongodb(\+srv)?:\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+/gi, 'mongo-url'],
  [/\bmysql:\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+/gi, 'mysql-url'],
  [/\bredis:\/\/[^\s"'<>]*:[^\s"'<>]+@[^\s"'<>]+/gi, 'redis-url'],
  [/\bamqps?:\/\/[^\s"'<>]+:[^\s"'<>]+@[^\s"'<>]+/gi, 'amqp-url'],
  // Os marcadores PEM são montados em vez de escritos literalmente: escrever
  // `-----BEGIN ... PRIVATE KEY-----` aqui faria este próprio arquivo casar
  // com a regra, e qualquer scan do repositório acusaria um falso positivo.
  [new RegExp(`${PEM_OPEN}[A-Z ]*PRIVATE KEY-----[\\s\\S]*?${PEM_CLOSE}[A-Z ]*PRIVATE KEY-----`, 'g'), 'private-key'],
];

const ENV_FILE_RE = /^\.env($|\.)/i;

/**
 * Lê os arquivos .env alcançáveis a partir de um diretório (o próprio e
 * até 2 níveis acima, cobrindo monorepo) e devolve pares nome→valor.
 */
function collectKnownSecrets(cwd, maxUp = 2) {
  const found = new Map();
  let dir = cwd;

  for (let i = 0; i <= maxUp && dir; i++) {
    let entries = [];
    try {
      entries = fs.readdirSync(dir);
    } catch {
      break;
    }

    for (const name of entries) {
      if (!ENV_FILE_RE.test(name)) continue;
      // Template não tem segredo — e ler ele só geraria ruído.
      if (/\.(example|sample|template|dist|defaults)$/i.test(name)) continue;

      let raw = '';
      try {
        raw = fs.readFileSync(path.join(dir, name), 'utf8');
      } catch {
        continue;
      }
      for (const [k, v] of parseEnv(raw)) {
        if (v.length >= MIN_VALUE_LEN && !PUBLIC_KEYS.test(k)) {
          found.set(v, k);
        }
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return found;
}

function parseEnv(raw) {
  const out = [];
  for (const line of String(raw).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq < 1) continue;
    const key = t.slice(0, eq).replace(/^export\s+/, '').trim();
    let val = t.slice(eq + 1).trim();
    val = val.replace(/^(['"])([\s\S]*)\1$/, '$2');
    if (!key || !val) continue;
    out.push([key, val]);
  }
  return out;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Redige um texto.
 * @returns {{text: string, hits: string[]}}
 */
function redactText(text, knownSecrets) {
  let out = String(text == null ? '' : text);
  const hits = [];

  // 1. Valores conhecidos — do mais longo para o mais curto, para que um
  //    valor que contenha outro seja substituído inteiro primeiro.
  if (knownSecrets && knownSecrets.size) {
    const sorted = [...knownSecrets.entries()].sort((a, b) => b[0].length - a[0].length);
    for (const [value, key] of sorted) {
      const re = new RegExp(escapeRe(value), 'g');
      if (re.test(out)) {
        out = out.replace(re, MASK(key));
        hits.push(key);
      }
    }
  }

  // 2. Formas conhecidas de segredo.
  for (const [re, label] of SHAPES) {
    if (re.test(out)) {
      out = out.replace(re, MASK(label));
      hits.push(label);
    }
    re.lastIndex = 0;
  }

  return { text: out, hits: [...new Set(hits)] };
}

/**
 * Resumo seguro de um arquivo .env: nomes das chaves, nunca os valores.
 * É o que o agente recebe no lugar do conteúdo bloqueado.
 */
function summarizeEnvFile(filePath) {
  let raw = '';
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
  const pairs = parseEnv(raw);
  if (!pairs.length) return { keys: [], lines: 0 };
  return {
    keys: pairs.map(([k, v]) => ({ key: k, chars: v.length })),
    lines: raw.split(/\r?\n/).length,
  };
}

module.exports = {
  collectKnownSecrets,
  redactText,
  summarizeEnvFile,
  parseEnv,
  MASK,
  SHAPES,
};
