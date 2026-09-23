<div align="center">

# wardenv

**Your coding agent never sees your `.env`. It still writes correct code.**

[![npm](https://img.shields.io/npm/v/wardenv?color=black)](https://www.npmjs.com/package/wardenv)
[![license](https://img.shields.io/badge/license-MIT-black)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-52%20passing-black)](./test/wardenv.test.js)
[![deps](https://img.shields.io/badge/dependencies-0-black)](./package.json)

<a href="https://www.buymeacoffee.com/natanaelisidoro"><img src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=&slug=natanaelisidoro&button_colour=FF5F5F&font_colour=ffffff&font_family=Poppins&outline_colour=000000&coffee_colour=FFDD00" alt="Buy me a coffee" height="40"></a>

</div>

---

Coding agents read files. That's the job.

But the second an agent runs `cat .env`, your production database URL, your payment
provider's live key and your model API token are inside a context window. On the wire to
a provider. Written to a transcript on disk. One turn away from being pasted into the next
file the agent writes.

You find out three weeks later, in a public repo, in a log aggregator, or never.

wardenv stands at that door.

```console
$ cat .env                       # you, in your own terminal
DATABASE_URL=postgresql://…redacted in this README by wardenv itself…
STRIPE_SECRET=sk_live_…
```

```console
# your agent, one second later:

🔒 wardenv: ".env" is a secret file — read blocked.

File structure (names only, values withheld):
  DATABASE_URL=<set, 48 chars>
  STRIPE_SECRET=<set, 31 chars>
```

The agent learns the key exists, learns its shape, and writes `process.env.DATABASE_URL`
correctly, without ever seeing the password.

That's the whole idea: block the value, keep the knowledge. A guard that only says "no"
makes the agent guess, thrash, and work around you. Hand back the structure and it stays
productive while the secret stays home.

> Yes, really. The first draft of this README had a fake connection string and a fake
> `sk_live_` key in that code block. wardenv blocked the write. It can't tell a plausible
> fake from the real thing, which is correct behavior for door 4 below. The examples above
> are shaped to make the point without carrying a credential's form.

---

## The four doors

Most setups lock the front door and leave three open. Here's what has to be closed, and
what each approach covers:

| # | Door | How it leaks | `.gitignore` | `permissions.deny` | wardenv |
|---|------|--------------|:---:|:---:|:---:|
| 1 | Direct read | `Read(.env)` | ❌ | ✅ | ✅ |
| 2 | Shell | `cat .env`, `Get-Content .env`, `git show HEAD:.env` | ❌ | ⚠️ pattern by pattern | ✅ |
| 3 | Ricochet | `printenv`, `docker compose config`, `vercel env pull` | ❌ | ❌ | ✅ redacts output |
| 4 | Exfiltration | agent writes a live key into `config.ts` or a commit | ❌ | ❌ | ✅ |

Door 3 is the one that gets people. The command is innocent. The leak is in the output.
No permission rule can catch it, because there's nothing suspicious to match on. You have
to read what came back.

Door 4 runs the other way. Once a secret is in context, the agent can helpfully inline it
into a config file. wardenv scans outbound writes too, as this README found out.

And two structural facts that decide the whole thing:

> `permissions.deny` is skipped under `--dangerously-skip-permissions`.
> A `PreToolUse` hook is policy enforcement, so it still runs.

> Most guardrails are never wired into subagents.
> wardenv hooks fire inside subagents too, where the blast radius is largest.

---

## Install

```bash
npm install -g wardenv
wardenv install
```

Restart your agent. Done.

The installer backs up your `settings.json` first, is idempotent, and leaves every other
hook untouched. wardenv takes the front of the chain, so nothing else even processes a
blocked command.

```bash
wardenv uninstall     # clean removal, same care
```

<sub>Works alongside other `PreToolUse` tooling. Verified running with rtk and an 11-hook
GSD setup on the same machine.</sub>

### Agent support

`wardenv install` detects the supported agents you have and installs into each.

| Agent | Status | Config |
|-------|--------|--------|
| Claude Code | ✅ verified end to end | `~/.claude/settings.json` |
| Codex CLI | ❌ not supported (tested on 0.116.0) | |

We tested Codex against a real session with a throwaway `.env`. It read the file, printed
the values, ran a `curl` upload of it (which only failed because nothing was listening)
and ran `wardenv unlock` on itself, and wardenv never saw any of it. Codex reads `~/.codex/hooks.json`, but in 0.116.0 it only fires
`SessionStart`, `UserPromptSubmit` and `Stop`. There is no event before or after a tool
runs, so there is nothing for wardenv to hook into.

The installer now refuses `wardenv install codex` instead of printing "installed" over a
guard that never runs. If an older version put wardenv into your Codex config, remove it
with `wardenv uninstall codex`. If a later Codex release adds tool hooks, the adapter can
come back.

Blocking hooks also exist in Gemini CLI (`BeforeTool`), Cursor (`beforeShellExecution`,
`beforeReadFile`) and Amp (`tool.call`). Adapters are straightforward, since the engine in
`src/lib/` is runtime-agnostic and exposes `inspect()` / `scrub()`.

One caveat worth knowing before you port it: only Claude Code and Amp let a hook rewrite a
tool's output. Gemini and Cursor (outside MCP) can block and modify input, but can't
redact what came back. Door 3 degrades there from "redact the leak" to "block the
command", which is blunter.

---

## Daily use

You will mostly forget it's there. That's the design.

```bash
wardenv status              # what's guarded here, and any open passes
wardenv keys                # key NAMES from .env, never the values
wardenv check "cat .env"    # what would wardenv do with this command?
wardenv log                 # audit trail
wardenv scan build.log      # did a secret leak into this file?
```

```console
$ wardenv check "docker compose config"
🩹 OUTPUT REDACTED  docker compose config
   reason: command may emit environment variables

$ wardenv check "npm run build"
✅ ALLOWED  npm run build
```

### When the agent genuinely needs a value

The door opens on purpose, visibly, and only by your hand:

```bash
wardenv unlock .env            # one read, 10 minutes
wardenv unlock .env -n 3 -t 30 # three reads, 30 minutes
wardenv lock                   # revoke everything, now
```

The grant is scoped to one file, burns on use, and expires on a clock. Before it's
created, wardenv asks you to type the file name back:

```console
$ wardenv unlock .env
Grant 1 read(s) of /proj/.env for 10 min? Type ".env" to confirm: .env
🔓 unlocked: /proj/.env
```

That prompt is what keeps the key yours. An agent's shell has no terminal, so
`wardenv unlock` refuses to run there however it's invoked: by name, through `node
…/cli.js`, `cmd /c` or PowerShell's `&`. The hook also blocks those forms outright, and
blocks Write or Edit calls that would forge a grant in `~/.wardenv/`, change wardenv's own
files, or drop its hook from your agent config.

If you use Git Bash's mintty terminal, run `wardenv unlock` from PowerShell or Windows
Terminal, or through `winpty`. Node can't see a terminal in mintty.

Every pass is written down:

```
2026-09-18 22:52:14  unlock-used    Read   /proj/.env
2026-09-18 22:52:03  unlock-granted        /proj/.env
2026-09-18 22:51:58  redact-output  Bash   DATABASE_URL, ANTHROPIC_API_KEY
2026-09-18 22:51:58  block-write    Write  /proj/config.ts
```

The audit log records key names, paths and reasons, never a value. A security log that
leaks secrets is worse than no log.

---

## What counts as a secret

Guarded: `.env` and every variant, `*.pem`, `*.key`, `id_rsa`, `.npmrc`, `.netrc`,
`service-account*.json`, `terraform.tfstate`, and anything under `.ssh/`, `.aws/`,
`.gnupg/`, `.kube/`, `secrets/`.

Never guarded: `.env.example`, `.env.sample`, `.env.template` and friends. Templates are
documentation. Blocking them breaks real work and protects nothing.

### Redaction works two ways at once

It learns your actual values. wardenv reads your `.env` files and erases those exact
strings wherever they surface, even when the key name isn't next to them, like a token
buried in a URL inside a stack trace.

It also knows what secrets look like: Anthropic and OpenAI key prefixes, GitHub tokens,
AWS access key IDs, JWTs, PEM blocks, connection strings carrying a password. That catches
secrets that never lived in a `.env`, like a token that came back from an API call.

Values under 12 characters are never redacted. Otherwise `NODE_ENV=production` would erase
the word "production" from every log you read.

---

## Design principles

**1. Fail open. Never break the session.**
Malformed payload, unreadable file, a bug in wardenv itself: the tool call proceeds. A
security tool that breaks your workflow gets uninstalled, and then it protects nothing at
all. Availability is a security property.

**2. Block the value, keep the knowledge.**
Denying a read without saying which keys exist just makes the agent guess. wardenv always
hands back the structure.

**3. False positives are a real failure, tested as hard as leaks.**
The suite tests friction alongside security: `npm run build`, `environment.ts`,
`cat .env.example` and `env FOO=1 npm test` must always pass. A guard that cries wolf gets
switched off.

**4. The agent cannot disarm the guard by accident or by the obvious path.**
Self-disarm attempts are blocked and tested, and an unlock needs a human at a terminal.
Otherwise every other guarantee is theater. This isn't a hard boundary, though: an agent
set on it could write a script that edits your files and run it. See `SECURITY.md`.

**5. Zero dependencies.**
A tool that reads your secrets shouldn't pull a supply chain along with it.

---

## How it works

```
┌─────────────┐
│    agent    │  Read / Bash / Write / MCP
└──────┬──────┘
       │
┌──────▼──────────────────────┐
│  PreToolUse   hooks/         │   direct read, shell, exfiltration
│  ├─ targets.js  is it a vault?
│  ├─ command.js  does it open one?
│  └─ unlock.js   is there a pass?
└──────┬──────────────────────┘
       │  allow ──► tool runs
       │  deny  ──► blocked + structure handed back
       │
┌──────▼──────────────────────┐
│  PostToolUse  hooks/         │   ricochet
│  └─ redact.js   scrub output before the agent reads it
└──────┬──────────────────────┘
       │
   agent sees redacted text; your terminal and files are untouched
```

`src/lib/` holds the whole engine with no agent-specific code in it: `targets`, `command`,
`redact`, `unlock`, `audit`. The Claude Code bindings live entirely in `hooks/`, which is
what makes adapters for other runtimes straightforward.

---

## Testing

```bash
npm test
```

52 tests. The engine suite covers two classes, and the second matters as much as the
first:

- Leak (false negative): a secret got through. A security failure.
- Friction (false positive): legitimate work got blocked. A usability failure that ends
  with the tool uninstalled.

A separate CLI suite covers what the human sees, including that a filesystem error
surfaces as a message instead of a Node stack trace.

---

## Limits, honestly

Redaction is not hermetic. It catches known values from your `.env` files and known secret
shapes. A secret in an exotic format that never passed through a `.env` can slip through.
The surface shrinks a lot; it doesn't reach zero.

It doesn't retroactively clean context from sessions that ran before install.

Shell parsing is heuristic. Deliberate obfuscation like `c""at .e""nv` sits outside the
threat model. A helpful agent taking the obvious path is inside it. wardenv is a guardrail
against accident, not an adversary sandbox.

---

## Contributing

The two most valuable issues you can open:

1. A secret shape I'm missing: a token format that should be redacted and isn't.
2. A false positive: something legitimate that got blocked. These get fixed fast, see
   principle 3.

MIT.
