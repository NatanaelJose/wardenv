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

// Interpretador rodando programa na própria linha: `node -e "...readFileSync('.env')"`,
// `python -c "open('.env').read()"`. O caminho vive DENTRO de uma string, então
// `stripLiterals` o apagava e o comando passava como `allow` — sem nem cair no
// `redact`. Ler config por `node -e` é movimento comum de agente, não ofuscação,
// então entra no modelo de ameaça. Estes são avaliados sobre o texto cru.
const INLINE_SCRIPT = /(?:^|[\s|;&])(?:node|deno|bun|python[0-9.]*|python3|ruby|perl|php|Rscript)\s+(?:-\w+\s+)*-(?:e|c|p|pe|ne|E)\b/i;

// Dentro do script, o caminho só conta quando está sendo ABERTO. Um literal
// solto (`x=['secrets/a']`) é dado, e tratá-lo como leitura quebrava o teste
// de atrito que já existia para esse caso.
const SCRIPT_READ = /\b(?:readFileSync|readFile|createReadStream|open|openSync|File\.read|IO\.read|file_get_contents|read_text|readlines|load)\s*\(/i;

// Cliente de rede enviando um arquivo: `curl -F f=@.env`, `wget --post-file=.env`.
// Aqui a redação não serve de rede de proteção: ela limpa o que o agente VÊ de
// volta, e o arquivo já saiu pela rede antes disso. Por isso é bloqueio.
const UPLOADERS = [
  'curl', 'wget', 'http', 'https', 'xh', 'nc', 'ncat', 'netcat', 'socat', 'telnet',
  'invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm',
];

// Só conta o segredo que é a ORIGEM do envio. `curl -o .env` grava NO arquivo
// e continua passando.
const UPLOAD_SOURCES = [
  // curl -F f=@x, -d @x, --data-urlencode c@x, httpie @x; -F f=<x, nc host < x
  /[@<]\s*(["']?)([^\s"'@<;|&]+)\1/g,
  // curl -T x / --upload-file x, wget --post-file=x / --body-file=x, pwsh -InFile x
  /(?:^|\s)(?:-T|--upload-file|--post-file|--body-file|-InFile)(?:\s+|=)(["']?)([^\s"']+)\1/gi,
];

function findUploadSource(seg) {
  for (const re of UPLOAD_SOURCES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(seg))) {
      if (classifyPath(m[2]).secret) return m[2];
    }
  }
  return null;
}

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
// Cada segmento é testado com `wardenv` em posição de COMANDO — início do
// segmento, ou logo após um executor como `bash -c`, `sh -c`, `npx`, `cmd /c`.
// Testar a frase solta bloqueava `grep "wardenv install" README.md`, que é
// leitura de documentação e não desarme.
// `&` é o operador de chamada do PowerShell (`& wardenv unlock`), e `cmd /c`
// usa flag com barra. Os dois passavam por fora. O nome pode vir com a extensão
// do shim que o npm instala no Windows (`wardenv.cmd`, `wardenv.ps1`).
const CMD_HEAD = String.raw`(?:^\s*(?:&\s*)?(?:(?:bash|sh|zsh|cmd|powershell|pwsh|npx|npm\s+exec|env|eval|exec)\s+(?:[-/]\w+\s+)*)?)`;
const WARDENV_BIN = String.raw`["']?wardenv(?:\.cmd|\.ps1|\.exe)?["']?`;

const SELF_DISARM = [
  new RegExp(`${CMD_HEAD}${WARDENV_BIN}\\s+(unlock|uninstall|install)\\b`, 'i'),
  new RegExp(`${CMD_HEAD}${WARDENV_BIN}\\b[^|;&]*--uninstall`, 'i'),
  // A CLI chamada pelo caminho, sem passar pelo nome `wardenv` em posição de comando.
  /wardenv[\\/]+src[\\/]+cli\.js["']?\s+(unlock|install|uninstall)\b/i,
  // Carregar a biblioteca de grants para criar um unlock sem a CLI.
  /wardenv[\\/]+(?:src[\\/]+)?lib[\\/]+unlock/i,
  /\bStart-Process\b[^|;&]*wardenv[^|;&]*\b(unlock|uninstall)\b/i,
  // Forjar o terminal que a CLI de unlock exige. Atribuir isTTY numa linha de
  // comando não tem uso legítimo.
  /\bisTTY\s*=[^=]/,
  // Script na linha carregando o código do wardenv (cli.js, lib/*). Sem isto,
  // `node -e "...require('.../wardenv/src/cli.js')"` chamava a CLI por dentro.
  /\b(?:node|deno|bun)\b[^|;&]*\s-(?:e|p|-eval|-print)\b[^|;&]*wardenv[\\/]+src[\\/]/i,
  // Só o instalador DO wardenv. `install\.js` sozinho pegava qualquer projeto
  // que tivesse um arquivo com esse nome — largo demais para uma regra que bloqueia.
  /wardenv[\\/]src[\\/]install\.js/i,
  /(^|[\s/\\])\.wardenv([\\/]|\b)/i,      // mexer no estado (grants.json, audit.jsonl)
  // Reescrever a config do agente para arrancar o wardenv de lá.
  /(>|>>|tee|Set-Content|Out-File)[^|;&]*(settings|hooks)\.json/i,
  // Apagar ou mover a config de hooks de um agente. O Copilot guarda o hook do
  // wardenv num arquivo só dele (~/.copilot/hooks/wardenv.json): removê-lo é
  // desarmar sem editar nada.
  /(^|\s)(rm|del|erase|mv|move|ren|rename|Remove-Item|Move-Item|Rename-Item)\b[^|;&]*[\\/]\.(claude|codex|gemini|cursor|copilot)[\\/][^|;&]*(settings(\.local)?|hooks)(\.json|[\\/]|\s|$)/i,
  /(>|>>|tee|Set-Content|Out-File)[^|;&]*[\\/]\.copilot[\\/]+hooks[\\/]/i,
];

/** Testa desarme em cada segmento, para pegar `foo && wardenv unlock`. */
function isSelfDisarm(raw) {
  const segments = String(raw).split(/&&|\|\||[;|]/).map((s) => s.trim()).filter(Boolean);
  return segments.some((seg) => SELF_DISARM.some((re) => re.test(seg)));
}

/**
 * Remove trechos que são DADO e não alvo de leitura: corpos de heredoc e
 * strings entre aspas.
 *
 * Sem isto, `git commit -m "fix .env parsing"` é bloqueado porque a palavra
 * `.env` aparece na mensagem, e `node -e "... 'secrets/x' ..."` é bloqueado
 * por um literal dentro de um array de teste. O caminho que importa para
 * `cat`/`grep`/`cp` é o que está solto na linha, não o que está citado.
 *
 * Uma exceção: a string que é EXATAMENTE um caminho de segredo (`cat ".env"`)
 * é alvo, não dado — quem escreve aspas ali está citando o arquivo, não
 * falando sobre ele. Ela sobrevive sem as aspas para ser tokenizada adiante.
 * A frase que só MENCIONA o nome no meio de outras palavras
 * (`-m "fix .env parsing"`) continua sendo apagada.
 *
 * Ver 'cofre: alvo entre aspas é reconhecido' e o par de atrito na suíte.
 */
function keepIfTarget(m) {
  // Redirecionamento/pipe dentro da string: devolve intacto, como antes.
  if (/[|>;&]/.test(m)) return m;
  const inner = m.slice(1, -1).trim();
  // Só o literal que é o caminho inteiro conta como alvo; com espaço no meio
  // é frase, e frase é dado.
  if (inner && !/\s/.test(inner) && classifyPath(inner).secret) return ` ${inner} `;
  return ' ';
}

function stripLiterals(text) {
  return String(text)
    // corpo de heredoc: <<EOF ... EOF  /  <<'EOF' ... EOF
    .replace(/<<-?\s*(['"]?)(\w+)\1[\s\S]*?^\s*\2\s*$/gm, ' ')
    // heredoc sem terminador na mesma string (comando truncado)
    .replace(/<<-?\s*(['"]?)(\w+)\1[\s\S]*$/m, ' ')
    // strings com aspas, desde que não contenham redirecionamento/pipe
    .replace(/"[^"]*"/g, keepIfTarget)
    .replace(/'[^']*'/g, keepIfTarget);
}

function analyzeCommand(cmd) {
  const raw = String(cmd || '');
  if (!raw.trim()) return { action: 'allow' };

  // A análise de alvo roda sobre o comando sem literais; o auto-desarme roda
  // sobre o texto completo, porque ali qualquer menção é suspeita.
  const text = stripLiterals(raw);

  if (isSelfDisarm(raw)) {
    return { action: 'block', reason: 'attempt to disarm wardenv' };
  }

  // Interpretador com script na linha: o alvo está dentro da string, então
  // precisa ser procurado no texto CRU, antes de `stripLiterals`. Cada segmento
  // é testado separadamente para não confundir `node -e "..."` com um `cat .env`
  // que venha depois de um `&&`.
  // Envio de segredo pela rede. Também no texto cru: `-F "f=@.env"` entre aspas
  // seria apagado por stripLiterals.
  for (const seg of raw.split(/&&|\|\||[;|]/)) {
    const bin = (tokenize(seg)[0] || '').toLowerCase().split('/').pop().split('\\').pop();
    if (!UPLOADERS.includes(bin)) continue;
    const src = findUploadSource(seg);
    if (src) {
      // O unlock é para o agente LER o valor, não para despachar o arquivo
      // para fora. Um grant ativo não libera este bloqueio.
      return { action: 'block', reason: `${bin} uploads ${src}`, token: src, upload: true };
    }
  }

  for (const seg of raw.split(/&&|\|\||[;|]/)) {
    if (!INLINE_SCRIPT.test(seg) || !SCRIPT_READ.test(seg)) continue;
    const found = findSecretPathToken(seg.replace(/["']/g, ' '));
    if (found.hit) {
      return { action: 'block', reason: `inline script reads ${found.token}`, token: found.token };
    }
  }

  // Uma linha pode encadear vários comandos: `echo oi && cat .env`. Avaliar
  // só o primeiro binário deixaria passar tudo que viesse depois de um `&&`,
  // `;` ou `|` — cada segmento precisa do próprio veredito.
  const segments = text.split(/&&|\|\||[;|]/).map((s) => s.trim()).filter(Boolean);
  let mention = null;

  for (const seg of segments) {
    const found = findSecretPathToken(seg);
    if (!found.hit) continue;

    const first = (tokenize(seg)[0] || '').toLowerCase();
    const bin = first.split('/').pop().split('\\').pop();

    // Comando de leitura + alvo de segredo = bloqueio duro.
    if (READERS.includes(bin)) {
      return { action: 'block', reason: `${bin} on ${found.token}`, token: found.token };
    }

    // git revelando conteúdo versionado de um .env
    if (GIT_REVEAL.test(seg)) {
      return { action: 'block', reason: `git exposing ${found.token}`, token: found.token };
    }

    // Menção sem leitura (`ls -la .env`, `echo X >> .env`) é legítima, mas a
    // saída é redigida por precaução. Guarda e segue: um segmento adiante
    // ainda pode merecer bloqueio.
    mention = mention || found;
  }

  if (mention) {
    return { action: 'redact', reason: `mentions ${mention.token}`, token: mention.token };
  }

  for (const re of EMITTERS) {
    if (re.test(text)) {
      return { action: 'redact', reason: 'command may emit environment variables' };
    }
  }

  return { action: 'allow' };
}

module.exports = { analyzeCommand, findSecretPathToken, READERS, EMITTERS };
