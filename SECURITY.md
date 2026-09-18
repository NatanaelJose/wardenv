# Security

## Threat model

wardenv defends against a **helpful agent taking the obvious path** — reading a `.env`
because it needs a variable name, running `printenv` to debug a config, inlining a value
it already saw into a file it is writing.

It is **not** an adversary sandbox. It does not defend against a deliberately malicious
agent, obfuscated shell (`c""at .e""nv`), a compromised MCP server, or code that reads
`process.env` at runtime inside a program the agent legitimately ran.

If your threat model includes an actively hostile agent, you need process isolation and
a real secret manager, not a guardrail.

## Known limits

These are real and documented rather than hidden:

**1. IDE selection bypasses hooks.**
If you select the contents of a `.env` in your editor and the IDE forwards that selection
as context, it reaches the model without passing through any tool call — so no hook sees
it. This is outside wardenv's reach by construction. *Don't paste or select secrets into
agent context.*

**2. Redaction is not hermetic.**
Known values from your `.env` files plus known secret shapes are caught. A secret in an
unusual format that never lived in a `.env` can pass through. The surface is drastically
reduced, not eliminated.

**3. No retroactive cleanup.**
Secrets already in a session's context before install stay there.

**4. Values under 12 characters are never redacted.**
A shorter threshold makes redaction destroy ordinary output (`NODE_ENV=production`). Short
secrets are not protected by the value-matching path — only by shape matching, if they
match a known shape.

**5. Runtime access is out of scope.**
An agent that runs `node -e "console.log(process.env.SECRET)"` produces output that
wardenv *will* redact on the way back, but a program that sends a secret over the network
is not something a context guardrail can stop.

## Reporting a vulnerability

Open a GitHub issue for anything that is already public or low risk (a missed secret
shape, a false positive).

For a bypass that would leak real secrets and isn't obvious from the source, use GitHub's
**private vulnerability reporting** on this repository instead of a public issue.

Please include the command or file path that bypasses the guard, and what you expected to
happen. A failing test case in the style of `test/wardenv.test.js` is the fastest path to
a fix.

## What wardenv never does

- Never writes a secret **value** to its audit log — key names, paths and reasons only.
- Never sends anything over the network. There is no telemetry and no dependencies.
- Never modifies your files or your terminal output. Redaction only changes what the
  *agent* sees.
