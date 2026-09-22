'use strict';
// Quais caminhos são cofre, e quais são a vitrine.
//
// Regra central: `.env.example` (e irmãos de template) NÃO são segredo —
// são a documentação da forma. Bloquear eles quebra o trabalho legítimo
// sem proteger nada, porque por definição não têm valor real dentro.

const path = require('path');

// Arquivos que parecem `.env` mas são templates públicos.
const TEMPLATE_NAMES = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
  '.env.dist',
  '.env.defaults',
  'env.example',
  'env.sample',
  'env.template',
]);

// Nome de arquivo que é cofre por si só, em qualquer diretório.
const SECRET_FILE_RE = [
  /^\.env($|\.)/i,              // .env .env.local .env.production .env.x
  /^env\.[a-z0-9]+$/i,          // env.local (convenção de alguns stacks)
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.keystore$/i,
  /\.jks$/i,
  /^id_rsa$/i,
  /^id_ed25519$/i,
  /^id_ecdsa$/i,
  /^\.npmrc$/i,                 // costuma ter _authToken
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /^\.htpasswd$/i,
  /^credentials$/i,             // ~/.aws/credentials
  /^service-account.*\.json$/i,
  /^gha-creds-.*\.json$/i,
  /^\.terraform\.tfstate.*/i,   // tfstate carrega segredo em claro
  /^terraform\.tfstate.*/i,
  /^\.dockercfg$/i,
];

// Diretórios inteiros que são cofre.
//
// Cada regra exige uma barra de verdade em pelo menos um lado do segmento
// (`[\\/]X` ou `X[\\/]`) — nunca a palavra sozinha ocupando a string inteira.
// Sem isto, `(^|[\\/])secrets?([\\/]|$)` casava com o argumento nu `SECRET`
// de `grep SECRET .env`, que não é caminho nenhum: é o padrão de busca do
// grep. Bloqueava o comando pelo motivo errado e, pior, o unlock concedido
// para `.env` nunca destravava porque o token capturado era "SECRET".
const SECRET_DIR_RE = [
  /[\\/]\.ssh(?:[\\/]|$)|^\.ssh[\\/]/i,
  /[\\/]\.gnupg(?:[\\/]|$)|^\.gnupg[\\/]/i,
  /[\\/]\.aws(?:[\\/]|$)|^\.aws[\\/]/i,
  /[\\/]\.kube(?:[\\/]|$)|^\.kube[\\/]/i,
  /[\\/]\.docker(?:[\\/]|$)|^\.docker[\\/]/i,
  /[\\/]secrets?(?:[\\/]|$)|^secrets?[\\/]/i,
];

// Aspas ao redor do caminho são sintaxe do shell, não parte do nome do
// arquivo: `cat ".env"` mira o mesmo alvo que `cat .env`. Sem tirar elas
// aqui, `".env"` era classificado como não-segredo e o comando passava
// inteiro. Espaço nas pontas cai no mesmo caso.
function unquote(p) {
  let s = String(p || '').trim();
  while (s.length > 1 && /^['"]/.test(s) && s[s.length - 1] === s[0]) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function normalize(p) {
  return unquote(p).replace(/\\/g, '/');
}

/**
 * @returns {{secret: boolean, reason?: string, kind?: string}}
 */
function classifyPath(filePath) {
  if (!filePath) return { secret: false };

  const norm = normalize(filePath);
  const base = path.posix.basename(norm);
  const lower = base.toLowerCase();

  // Vitrine explícita: template vence tudo.
  if (TEMPLATE_NAMES.has(lower)) {
    return { secret: false, kind: 'template' };
  }

  // `.env.example.something` também é template.
  if (/^\.?env\.(example|sample|template|dist|defaults)\b/i.test(lower)) {
    return { secret: false, kind: 'template' };
  }

  for (const re of SECRET_FILE_RE) {
    if (re.test(base)) {
      return { secret: true, kind: 'arquivo', reason: base };
    }
  }

  for (const re of SECRET_DIR_RE) {
    if (re.test(norm)) {
      return { secret: true, kind: 'diretorio', reason: norm };
    }
  }

  return { secret: false };
}

module.exports = { classifyPath, TEMPLATE_NAMES };
