'use strict';
// O agente não pode desarmar o wardenv pelas ferramentas de ESCRITA.
//
// A regra de auto-desarme em command.js só olha comando de shell. Write e Edit
// passavam direto por três portas:
//   - ~/.wardenv/grants.json   escrever um grant forjado;
//   - settings.json/hooks.json arrancar o hook da config do agente, ou ligar
//                              `disableAllHooks`;
//   - hooks/ e src/            trocar o próprio hook por `process.exit(0)`.

const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const STATE_DIR = path.join(os.homedir(), '.wardenv');

// Num checkout de desenvolvimento (tem .git), editar src/ e hooks/ é o
// trabalho em si: proteger ali impediria qualquer agente de mexer no wardenv.
// Instalado via npm, não há .git e o código fica protegido.
const CODE_PROTECTED = !fs.existsSync(path.join(ROOT, '.git'));

const AGENT_CONFIG_RE = new RegExp(
  [
    /[\\/]\.claude[\\/]settings(\.local)?\.json$/,
    /[\\/]\.codex[\\/]hooks\.json$/,
    /[\\/]\.gemini[\\/]settings\.json$/,
    /[\\/]\.cursor[\\/]hooks\.json$/,
    /[\\/]\.copilot[\\/]hooks[\\/][^\\/]+\.json$/,
  ].map((r) => r.source).join('|'),
  'i'
);

function norm(p) {
  return path.resolve(String(p || '')).replace(/\\/g, '/').toLowerCase();
}

function inside(file, dir) {
  const f = norm(file);
  const d = norm(dir).replace(/\/$/, '');
  return f === d || f.startsWith(d + '/');
}

/**
 * Hooks do wardenv numa config, como assinaturas `evento|matcher|comando`.
 * @returns {Set<string>|null} null quando o texto não é JSON válido
 */
function wardenvHooks(text) {
  let cfg;
  try {
    cfg = JSON.parse(text);
  } catch {
    return null;
  }
  const out = new Set();
  const hooks = (cfg && cfg.hooks) || {};
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      // Aninhado ({matcher, hooks: [...]}) ou plano (Copilot, Cursor: a
      // própria entrada é o hook, com o comando em command/bash/powershell).
      const list = g && Array.isArray(g.hooks) ? g.hooks : g ? [g] : [];
      for (const h of list) {
        for (const cmd of [h.command, h.bash, h.powershell]) {
          if (typeof cmd === 'string' && /wardenv[\\/]+hooks[\\/]+(pre|post)-tool\.js/i.test(cmd)) {
            out.add(`${event}|${g.matcher}|${cmd}`);
          }
        }
      }
    }
  }
  return out;
}

/** Aplica os pares old→new de um Edit/MultiEdit ao texto atual, como a tool faria. */
function applyEdits(current, edits) {
  let text = current;
  for (const e of edits) {
    if (!e || typeof e.old !== 'string') continue;
    text = e.all ? text.split(e.old).join(e.new || '') : text.replace(e.old, () => e.new || '');
  }
  return text;
}

/**
 * @param {object} w
 * @param {string} w.filePath
 * @param {string} [w.body]    Write: o arquivo inteiro. Edit: texto novo (para o scan de segredo).
 * @param {Array<{old: string, new: string, all?: boolean}>} [w.edits]  pares de Edit/MultiEdit
 * @param {{root?: string, codeProtected?: boolean}} [opts] para teste
 * @returns {{block: boolean, reason?: string}}
 */
function checkWrite({ filePath, body = '', edits = null }, opts = {}) {
  if (!filePath) return { block: false };
  const root = opts.root || ROOT;
  const codeProtected = opts.codeProtected ?? CODE_PROTECTED;

  if (inside(filePath, STATE_DIR)) {
    return { block: true, reason: 'writes wardenv state (grants/audit)' };
  }

  if (codeProtected && (inside(filePath, path.join(root, 'hooks')) || inside(filePath, path.join(root, 'src')))) {
    return { block: true, reason: 'modifies wardenv itself' };
  }

  if (AGENT_CONFIG_RE.test(filePath)) {
    let current = '';
    try {
      current = fs.readFileSync(filePath, 'utf8');
    } catch {}
    // Compara a config inteira ANTES e DEPOIS da escrita. Olhar só o trecho
    // editado não basta: trocar `pre-tool.js` por `noop.js` não menciona o
    // caminho completo e aponta o hook para um arquivo que não existe.
    const after = edits ? applyEdits(current, edits) : body;

    if (/"disableAllHooks"\s*:\s*true/i.test(after) && !/"disableAllHooks"\s*:\s*true/i.test(current)) {
      return { block: true, reason: 'disables all hooks in the agent config' };
    }

    const before = wardenvHooks(current);
    if (before && before.size) {
      const now = wardenvHooks(after);
      // JSON quebrado também desarma: o agente ignora a config inválida.
      if (!now) return { block: true, reason: 'breaks the agent config that registers wardenv' };
      for (const sig of before) {
        if (!now.has(sig)) return { block: true, reason: 'removes or alters the wardenv hook in the agent config' };
      }
    }
  }

  return { block: false };
}

module.exports = { checkWrite, CODE_PROTECTED };
