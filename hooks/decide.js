'use strict';
// wardenv — decisão do PreToolUse, sem saber de qual agente veio o pedido.
//
// Recebe a tentativa já normalizada por um adaptador (hooks/adapters/) e
// devolve allow/deny. O formato de entrada e de resposta de cada agente fica
// no adaptador; aqui só mora a política.

const path = require('path');
const { classifyPath } = require('../src/lib/targets');
const { analyzeCommand } = require('../src/lib/command');
const { summarizeEnvFile, redactText, collectKnownSecrets } = require('../src/lib/redact');
const { isUnlocked, consumeUnlock } = require('../src/lib/unlock');
const { log } = require('../src/lib/audit');
const { checkWrite } = require('../src/lib/selfguard');

const ALLOW = { action: 'allow' };

function deny(reason, context) {
  return { action: 'deny', reason, context };
}

/**
 * Monta a estrutura do .env sem os valores, para o agente saber QUAIS chaves
 * existem em vez de só ouvir "não". Compartilhado entre leitura direta
 * (`Read`) e leitura por shell (`cat`/`grep`/...) — antes só a primeira
 * mostrava a estrutura, e a segunda (o caminho mais comum no dia a dia) só
 * dizia "this would expose credentials", sem listar nada.
 */
function envStructure(filePath) {
  const summary = summarizeEnvFile(filePath);
  if (!summary || !summary.keys || !summary.keys.length) return null;
  const base = path.basename(filePath);
  const list = summary.keys.map((k) => `  ${k.key}=<set, ${k.chars} chars>`).join('\n');
  return (
    `\n\nFile structure (names only, values withheld):\n${list}` +
    `\n\nIf you need a specific value, ask the user to run:\n  wardenv unlock ${base}`
  );
}

/**
 * @param {object} n  tentativa normalizada
 * @param {'read'|'shell'|'write'|'other'} n.kind
 * @param {string} n.tool      nome da tool no agente, só para o log
 * @param {string} [n.path]    alvo, para 'read' e 'write'
 * @param {string} [n.command] linha de comando, para 'shell'
 * @param {string} [n.body]    texto novo, para 'write'
 * @param {Array<{old:string,new:string,all:boolean}>|null} [n.edits] pares de edição
 * @param {string} n.cwd
 * @param {string} n.agent     'principal' ou 'subagente:<tipo>'
 * @returns {{action:'allow'}|{action:'deny', reason:string, context?:string}}
 */
function decide(n) {
  const { tool, cwd, agent } = n;

  // ---- Leitura de arquivo ---------------------------------------------
  if (n.kind === 'read') {
    const fp = n.path || '';
    const verdict = classifyPath(fp);
    if (!verdict.secret) return ALLOW;

    if (isUnlocked(cwd, fp)) {
      consumeUnlock(cwd, fp);
      log({ event: 'unlock-used', tool, path: fp, agent, cwd });
      return ALLOW;
    }

    const base = path.basename(fp);
    // Em vez de só negar, entrega a FORMA sem o conteúdo: o agente quase
    // sempre quer saber quais chaves existem, não os valores.
    const structure = envStructure(fp);
    const ctx = `wardenv blocked reading "${base}".` +
      (structure || ' This file holds credentials and does not enter the context.');

    log({ event: 'block-read', tool, path: fp, agent, cwd });
    return deny(`wardenv: "${base}" is a secret file — read blocked.`, ctx);
  }

  // ---- Shell ----------------------------------------------------------
  if (n.kind === 'shell') {
    const cmd = n.command || '';
    const verdict = analyzeCommand(cmd);

    if (verdict.action === 'block' && verdict.upload) {
      log({ event: 'block-upload', tool, command: cmd, reason: verdict.reason, agent, cwd });
      return deny(
        `wardenv: command sends a secret file over the network (${verdict.reason}).`,
        'Secret files never leave the machine through an agent command, and ' +
          'wardenv unlock does not change that. If a request needs a credential, ' +
          'reference it by name from the environment instead of uploading the file.'
      );
    }

    if (verdict.action === 'block') {
      // O unlock granted via `wardenv unlock <file>` precisa valer aqui
      // também — não só para a tool Read. Sem isto, `wardenv unlock .env`
      // nunca destrava `cat .env`/`grep ... .env`, que é o caminho mais
      // comum de leitura no dia a dia.
      if (verdict.token && isUnlocked(cwd, verdict.token)) {
        consumeUnlock(cwd, verdict.token);
        log({ event: 'unlock-used', tool, path: verdict.token, agent, cwd });
        return ALLOW;
      }

      log({ event: 'block-cmd', tool, command: cmd, reason: verdict.reason, agent, cwd });
      // Mesma estrutura de chaves que a leitura direta mostra — antes o shell
      // (`cat`/`grep`, o caminho mais comum no dia a dia) só dizia "isto
      // exporia credenciais", sem listar nada, mesmo sabendo o arquivo exato.
      const structure = verdict.token ? envStructure(path.resolve(cwd, verdict.token)) : null;
      return deny(
        `wardenv: command reads a secret file (${verdict.reason}).`,
        structure ||
          'This command would expose credentials in the context. If you only need to ' +
            'know WHICH keys exist, read .env.example. For a real value, ask the ' +
            'user to run: wardenv unlock <file>'
      );
    }
    return ALLOW;
  }

  // ---- Escrita: impedir que segredo vá para arquivo versionado --------
  if (n.kind === 'write') {
    const fp = n.path || '';
    const body = n.body || '';

    // Antes de tudo: a escrita desarma o wardenv? Vale até para destino que
    // é cofre, então precisa vir antes do allow logo abaixo.
    const disarm = checkWrite({ filePath: fp, body, edits: n.edits || null });
    if (disarm.block) {
      log({ event: 'block-disarm', tool, path: fp, reason: disarm.reason, agent, cwd });
      return deny(
        `wardenv: this write would disarm wardenv (${disarm.reason}).`,
        'The agent cannot change wardenv, its state, or its hook registration. ' +
          'If this change is intended, ask the user to make it themselves.'
      );
    }

    // Escrever NO .env é legítimo (criar/editar credencial local).
    // O risco é o inverso: escrever segredo em arquivo NÃO-secreto.
    if (classifyPath(fp).secret) return ALLOW;

    const known = collectKnownSecrets(cwd);
    const { hits } = redactText(body, known);

    if (hits.length) {
      log({ event: 'block-write', tool, path: fp, hits, agent, cwd });
      return deny(
        `wardenv: this content contains a secret (${hits.join(', ')}) and the destination "${path.basename(fp)}" is not a vault.`,
        'Store the credential in .env and reference it by name (process.env.NAME). ' +
          'Never write the literal value into a versioned file.'
      );
    }
    return ALLOW;
  }

  return ALLOW;
}

module.exports = { decide };
