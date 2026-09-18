# wardenv

**Keep your `.env` out of the AI's context.**

*A warden for your env.*

Coding agents read files. That's the job. But the moment an agent runs `cat .env`, your
production database URL, your Stripe live key and your Anthropic token are in a context
window — on its way to a model provider, into a transcript on disk, and possibly into the
next file the agent writes.

`wardenv` stands at that door. The agent keeps working; the secrets stay home.

```
$ cat .env                      # you, in your terminal
DATABASE_URL=postgresql://admin:hunter2@prod.db/main

# the agent, one second later:
🔒 wardenv blocked reading ".env".

Structure (names only, values withheld):
  DATABASE_URL=<set, 48 chars>
  STRIPE_SECRET=<set, 31 chars>
```

The agent knows the key exists, knows its shape, and writes `process.env.DATABASE_URL`
correctly — without ever seeing `hunter2`.

---

## Why a hook and not `permissions.deny`

Claude Code can deny `Read(.env)` in settings. That closes one door out of four:

| # | Door | `permissions.deny` | `wardenv` |
|---|------|--------------------|---------|
| 1 | `Read(.env)` | ✅ | ✅ |
| 2 | `cat .env`, `type .env`, `Get-Content .env` | partial, pattern by pattern | ✅ |
| 3 | **Ricochet** — `printenv`, `docker compose config`, `vercel env pull` | ❌ | ✅ redacts output |
| 4 | **Exfiltration** — agent writes a live key into `config.ts` or a commit | ❌ | ✅ |

Door 3 is the one that bites. The command is innocent; the *output* is the leak. And
`permissions.deny` is skipped under `--dangerously-skip-permissions`, while a `PreToolUse`
hook is policy enforcement and still runs.

`wardenv` hooks also fire **inside subagents**, which is where most guardrails quietly fail.

---

## Install

```bash
npm install -g wardenv
wardenv install
```

Restart Claude Code. That's it.

The installer backs up your `settings.json`, is idempotent, and leaves every other hook
(rtk, gsd, your own) untouched — `wardenv` just goes first in the chain.

```bash
wardenv uninstall    # removes cleanly
```

---

## Using it

```bash
wardenv status              # what's protected here, and any open passes
wardenv keys                # key NAMES from .env — never the values
wardenv check "cat .env"    # what would wardenv do with this command?
wardenv log                 # audit trail
wardenv scan build.log      # did a secret leak into this file?
```

### When the agent genuinely needs a value

The door opens on purpose, visibly, and only by your hand:

```bash
wardenv unlock .env          # one read, 10 minutes
wardenv unlock .env -n 3 -t 30
wardenv lock                 # revoke everything now
```

The agent **cannot** grant itself an unlock — `wardenv unlock` is itself a blocked command
in the agent's Bash, along with anything that would tamper with wardenv's own state. The
key is yours.

Every pass is logged:

```
2026-09-18 22:52:14  unlock-used    Read   /proj/.env
2026-09-18 22:51:58  redact-output  Bash   DATABASE_URL, ANTHROPIC_API_KEY
2026-09-18 22:51:58  block-write    Write  /proj/config.ts
```

---

## What counts as a secret

**Guarded:** `.env` and every variant, `*.pem`, `*.key`, `id_rsa`, `.npmrc`, `.netrc`,
`service-account*.json`, `terraform.tfstate`, and anything under `.ssh/`, `.aws/`,
`.gnupg/`, `.kube/`, `secrets/`.

**Never guarded:** `.env.example`, `.env.sample`, `.env.template` and friends. Templates
are documentation — blocking them breaks real work and protects nothing.

**Redaction** works two ways at once: it learns the actual values from your `.env` files
and erases those strings wherever they surface, *and* it matches known secret shapes
(`sk-ant-`, `ghp_`, `AKIA`, JWTs, PEM blocks, connection strings with passwords) so it
also catches secrets that never lived in a `.env`.

Values under 12 characters are never redacted — otherwise `NODE_ENV=production` would
erase the word "production" from every log you read.

---

## Design principles

1. **Fail open, never break the session.** A malformed payload, an unreadable file, a
   crash in `wardenv` — the tool call proceeds. A security tool that breaks your workflow
   gets uninstalled, and then it protects nothing.
2. **Block the value, not the knowledge.** Denying a read without telling the agent what
   keys exist just makes it guess. `wardenv` always hands back the structure.
3. **False positives are a real failure.** The test suite tests *friction* as hard as it
   tests leaks: `npm run build`, `environment.ts` and `cat .env.example` must always pass.
4. **The audit log never contains a secret.** Key names, paths and reasons only.

---

## Testing

```bash
npm test
```

---

## Status

Early. The core (block / redact / unlock / audit) is tested and working on Claude Code.
Adapters for other agent runtimes are the obvious next step — the `src/lib/` core has no
Claude-specific code in it.

Issues and PRs welcome, especially: secret shapes I'm missing, and false positives.

MIT.
