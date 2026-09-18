'use strict';
// Janela de liberação pontual.
//
// O cofre só é suportável se existir uma saída explícita. Regras do unlock:
//   - o USUÁRIO concede, nunca o agente (o agente não pode rodar `wardenv unlock`,
//     porque o próprio comando é bloqueado no PreToolUse — ver command.js);
//   - vale para UM arquivo;
//   - tem contador de usos (padrão 1) e expira no tempo (padrão 10 min);
//   - é consumido na primeira leitura e registrado no log.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const STATE_DIR = path.join(os.homedir(), '.wardenv');
const GRANTS = path.join(STATE_DIR, 'grants.json');

const DEFAULT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_USES = 1;

function ensureDir() {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  } catch {}
}

function keyFor(cwd, filePath) {
  const abs = path.isAbsolute(filePath) ? filePath : path.resolve(cwd || '.', filePath);
  return crypto.createHash('sha256').update(abs.replace(/\\/g, '/').toLowerCase()).digest('hex').slice(0, 16);
}

function readGrants() {
  try {
    const raw = fs.readFileSync(GRANTS, 'utf8');
    const obj = JSON.parse(raw);
    return obj && typeof obj === 'object' ? obj : {};
  } catch {
    return {};
  }
}

function writeGrants(g) {
  ensureDir();
  try {
    fs.writeFileSync(GRANTS, JSON.stringify(g, null, 2), { mode: 0o600 });
  } catch {}
}

function prune(g) {
  const now = Date.now();
  let changed = false;
  for (const [k, v] of Object.entries(g)) {
    if (!v || v.expiresAt < now || v.usesLeft <= 0) {
      delete g[k];
      changed = true;
    }
  }
  return changed;
}

function grant(cwd, filePath, { uses = DEFAULT_USES, ttlMs = DEFAULT_TTL_MS, keys = null } = {}) {
  const g = readGrants();
  prune(g);
  const k = keyFor(cwd, filePath);
  g[k] = {
    path: path.resolve(cwd || '.', filePath),
    usesLeft: uses,
    expiresAt: Date.now() + ttlMs,
    keys, // null = arquivo inteiro; array = só estas chaves
    grantedAt: new Date().toISOString(),
  };
  writeGrants(g);
  return g[k];
}

function isUnlocked(cwd, filePath) {
  const g = readGrants();
  if (prune(g)) writeGrants(g);
  const v = g[keyFor(cwd, filePath)];
  return !!(v && v.usesLeft > 0 && v.expiresAt > Date.now());
}

function consumeUnlock(cwd, filePath) {
  const g = readGrants();
  const k = keyFor(cwd, filePath);
  if (!g[k]) return false;
  g[k].usesLeft -= 1;
  if (g[k].usesLeft <= 0) delete g[k];
  writeGrants(g);
  return true;
}

function listGrants() {
  const g = readGrants();
  prune(g);
  return Object.values(g);
}

function revokeAll() {
  writeGrants({});
}

module.exports = { grant, isUnlocked, consumeUnlock, listGrants, revokeAll, GRANTS };
