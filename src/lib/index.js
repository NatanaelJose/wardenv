'use strict';
// Superfície pública do wardenv como biblioteca.
//
// Existe para que o motor seja usável fora dos hooks do Claude Code:
// adaptadores para outros agentes, CI, pre-commit, ou um MCP server.
// Nada aqui conhece Claude Code — essa parte vive em hooks/.

const { classifyPath } = require('./targets');
const { analyzeCommand, findSecretPathToken } = require('./command');
const {
  collectKnownSecrets,
  redactText,
  summarizeEnvFile,
  parseEnv,
} = require('./redact');
const { grant, isUnlocked, consumeUnlock, listGrants, revokeAll } = require('./unlock');
const { log, tail } = require('./audit');

/**
 * Decide o que fazer com uma tentativa de acesso, de forma agnóstica de runtime.
 * É a função que um adaptador novo deve chamar.
 *
 * @param {object} req
 * @param {'read'|'command'|'write'} req.kind
 * @param {string} [req.path]     alvo, para kind 'read' e 'write'
 * @param {string} [req.command]  linha de comando, para kind 'command'
 * @param {string} [req.content]  conteúdo a gravar, para kind 'write'
 * @param {string} [req.cwd]
 * @returns {{decision:'allow'|'deny'|'redact', reason?:string, context?:string, hits?:string[]}}
 */
function inspect(req) {
  const cwd = req.cwd || process.cwd();

  if (req.kind === 'read') {
    const verdict = classifyPath(req.path);
    if (!verdict.secret) return { decision: 'allow' };
    if (isUnlocked(cwd, req.path)) {
      consumeUnlock(cwd, req.path);
      return { decision: 'allow', reason: 'unlock consumido' };
    }
    const summary = summarizeEnvFile(req.path);
    const context = summary && summary.keys.length
      ? summary.keys.map((k) => `${k.key}=<set, ${k.chars} chars>`).join('\n')
      : undefined;
    return { decision: 'deny', reason: `${req.path} é arquivo de segredo`, context };
  }

  if (req.kind === 'command') {
    const v = analyzeCommand(req.command);
    if (v.action === 'block') return { decision: 'deny', reason: v.reason };
    if (v.action === 'redact') return { decision: 'redact', reason: v.reason };
    return { decision: 'allow' };
  }

  if (req.kind === 'write') {
    if (classifyPath(req.path).secret) return { decision: 'allow' };
    const { hits } = redactText(req.content || '', collectKnownSecrets(cwd));
    if (hits.length) {
      return { decision: 'deny', reason: `conteúdo contém segredo: ${hits.join(', ')}`, hits };
    }
    return { decision: 'allow' };
  }

  return { decision: 'allow' };
}

/**
 * Redige um texto de saída. Usado por adaptadores no ponto pós-execução.
 */
function scrub(text, cwd) {
  return redactText(text, collectKnownSecrets(cwd || process.cwd()));
}

module.exports = {
  inspect,
  scrub,
  // primitivas
  classifyPath,
  analyzeCommand,
  findSecretPathToken,
  collectKnownSecrets,
  redactText,
  summarizeEnvFile,
  parseEnv,
  grant,
  isUnlocked,
  consumeUnlock,
  listGrants,
  revokeAll,
  log,
  tail,
};
