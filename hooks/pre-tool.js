#!/usr/bin/env node
'use strict';
// wardenv — PreToolUse
//
// Fecha a porta de ENTRADA: impede que conteúdo de segredo chegue ao contexto.
//
// Roda mesmo em bypassPermissions / --dangerously-skip-permissions, porque
// PreToolUse é enforcement de policy e não um prompt de permissão. É por isso
// que isto vive num hook e não em permissions.deny.

const path = require('path');
const { classifyPath } = require('../src/lib/targets');
const { analyzeCommand } = require('../src/lib/command');
const { summarizeEnvFile } = require('../src/lib/redact');
const { isUnlocked, consumeUnlock } = require('../src/lib/unlock');
const { log } = require('../src/lib/audit');

const TOOLS_FILE = new Set(['Read', 'NotebookRead']);
const TOOLS_WRITE = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

function deny(reason, extra) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
      ...(extra ? { additionalContext: extra } : {}),
    },
  }));
  process.exit(0);
}

function allow() {
  process.exit(0);
}

let input = '';
const timer = setTimeout(() => process.exit(0), 4000);
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  clearTimeout(timer);
  let data;
  try {
    data = JSON.parse(input);
  } catch {
    process.exit(0); // nunca travar por payload malformado
  }

  try {
    const tool = data.tool_name || '';
    const ti = data.tool_input || {};
    const cwd = data.cwd || process.cwd();
    const agent = data.agent_id ? `subagente:${data.agent_type || '?'}` : 'principal';

    // ---- Leitura de arquivo -------------------------------------------
    if (TOOLS_FILE.has(tool)) {
      const fp = ti.file_path || '';
      const verdict = classifyPath(fp);
      if (!verdict.secret) allow();

      if (isUnlocked(cwd, fp)) {
        consumeUnlock(cwd, fp);
        log({ event: 'unlock-used', tool, path: fp, agent, cwd });
        allow();
      }

      const base = path.basename(fp);
      let ctx = `wardenv blocked reading "${base}".`;

      // Em vez de só negar, entrega a FORMA sem o conteúdo: o agente quase
      // sempre quer saber quais chaves existem, não os valores.
      const summary = summarizeEnvFile(fp);
      if (summary && summary.keys && summary.keys.length) {
        const list = summary.keys
          .map((k) => `  ${k.key}=<set, ${k.chars} chars>`)
          .join('\n');
        ctx += `\n\nFile structure (names only, values withheld):\n${list}`;
        ctx += `\n\nIf you need a specific value, ask the user to run:\n  wardenv unlock ${base}`;
      } else {
        ctx += ' This file holds credentials and does not enter the context.';
      }

      log({ event: 'block-read', tool, path: fp, agent, cwd });
      deny(`wardenv: "${base}" is a secret file — read blocked.`, ctx);
    }

    // ---- Bash / PowerShell --------------------------------------------
    if (tool === 'Bash' || tool === 'PowerShell') {
      const cmd = ti.command || '';
      const verdict = analyzeCommand(cmd);

      if (verdict.action === 'block') {
        // O unlock granted via `wardenv unlock <file>` precisa valer aqui
        // também — não só para a tool Read. Sem isto, `wardenv unlock .env`
        // nunca destrava `cat .env`/`grep ... .env`, que é o caminho mais
        // comum de leitura no dia a dia.
        if (verdict.token && isUnlocked(cwd, verdict.token)) {
          consumeUnlock(cwd, verdict.token);
          log({ event: 'unlock-used', tool, path: verdict.token, agent, cwd });
          allow();
        }

        log({ event: 'block-cmd', tool, command: cmd, reason: verdict.reason, agent, cwd });
        deny(
          `wardenv: command reads a secret file (${verdict.reason}).`,
          'This command would expose credentials in the context. If you only need to ' +
            'know WHICH keys exist, read .env.example. For a real value, ask the ' +
            'user to run: wardenv unlock <file>'
        );
      }
      allow();
    }

    // ---- Escrita: impedir que segredo vá para arquivo versionado ------
    if (TOOLS_WRITE.has(tool)) {
      const fp = ti.file_path || '';
      const body = ti.content || ti.file_text || ti.new_string || ti.new_str || '';
      // Escrever NO .env é legítimo (criar/editar credencial local).
      // O risco é o inverso: escrever segredo em arquivo NÃO-secreto.
      if (classifyPath(fp).secret) allow();

      const { redactText, collectKnownSecrets } = require('../src/lib/redact');
      const known = collectKnownSecrets(cwd);
      const { hits } = redactText(body, known);

      if (hits.length) {
        log({ event: 'block-write', tool, path: fp, hits, agent, cwd });
        deny(
          `wardenv: this content contains a secret (${hits.join(', ')}) and the destination "${path.basename(fp)}" is not a vault.`,
          'Store the credential in .env and reference it by name (process.env.NAME). ' +
            'Never write the literal value into a versioned file.'
        );
      }
      allow();
    }

    allow();
  } catch {
    process.exit(0); // falha aberta: nunca quebrar a sessão
  }
});
