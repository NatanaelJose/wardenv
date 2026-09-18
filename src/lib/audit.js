'use strict';
// Log de auditoria — append-only, JSONL.
//
// Registra o que foi bloqueado e o que foi liberado. Nunca registra VALOR
// de segredo: só nome de chave, caminho e motivo. Um log de segurança que
// vaza segredo é pior que log nenhum.

const fs = require('fs');
const os = require('os');
const path = require('path');

const LOG_DIR = path.join(os.homedir(), '.wardenv');
const LOG_FILE = path.join(LOG_DIR, 'audit.jsonl');
const MAX_BYTES = 2 * 1024 * 1024;

// Campos que jamais entram no log em texto puro.
const SENSITIVE = new Set(['content', 'file_text', 'new_string', 'value', 'values']);

function sanitize(entry) {
  const out = {};
  for (const [k, v] of Object.entries(entry || {})) {
    if (SENSITIVE.has(k)) continue;
    if (k === 'command' && typeof v === 'string') {
      // guarda o comando truncado, sem o que vier depois de um '=' longo
      out[k] = v.slice(0, 200).replace(/=[^\s]{12,}/g, '=<...>');
      continue;
    }
    out[k] = typeof v === 'string' ? v.slice(0, 400) : v;
  }
  return out;
}

function rotate() {
  try {
    const st = fs.statSync(LOG_FILE);
    if (st.size > MAX_BYTES) {
      fs.renameSync(LOG_FILE, LOG_FILE + '.1');
    }
  } catch {}
}

function log(entry) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    rotate();
    const line = JSON.stringify({ ts: new Date().toISOString(), ...sanitize(entry) });
    fs.appendFileSync(LOG_FILE, line + '\n', { mode: 0o600 });
  } catch {
    // auditoria nunca pode quebrar o fluxo
  }
}

function tail(n = 20) {
  try {
    const raw = fs.readFileSync(LOG_FILE, 'utf8').trim();
    if (!raw) return [];
    return raw.split(/\r?\n/).slice(-n).map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    }).filter(Boolean);
  } catch {
    return [];
  }
}

module.exports = { log, tail, LOG_FILE };
