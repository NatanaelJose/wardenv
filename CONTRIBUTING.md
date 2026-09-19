# Contributing

## The two most valuable contributions

**1. A secret shape that isn't caught.**
A token format that should be redacted and isn't. Open an issue with the *shape*, never a
real token — `prefix_` plus length and character class is enough.

**2. A false positive.**
Something legitimate that got blocked. These are treated as real bugs, not papercuts: a
guard that cries wolf gets uninstalled, and then it protects nothing. See principle 3 in
the README.

Every false positive fixed so far was found the same way — wardenv blocked its own
development. Those cases are now regression tests at the bottom of
[`test/wardenv.test.js`](./test/wardenv.test.js), each with a comment saying what real
command triggered it. Add yours in the same style.

## Running the suite

```bash
npm test
```

CI runs it on Linux, macOS and Windows across Node 18, 20 and 22, plus a self-scan job
that fails the build if a secret lands in a tracked file. Windows is not optional here:
path separators and PowerShell are part of what the tool parses.

## Adding a test

The suite has two classes, and the second matters as much as the first:

```js
test('cofre: ...', () => { /* a secret must be blocked */ });
test('atrito: ...', () => { /* legitimate work must pass */ });
```

A change that blocks a new leak but breaks `npm run build` is not an improvement. Add both
sides.

## Writing an adapter for another agent

The engine in `src/lib/` knows nothing about any specific agent. An adapter is a thin
translation layer in `hooks/`:

```js
const { inspect, scrub } = require('wardenv');

// pre-execution
const verdict = inspect({ kind: 'read', path: '.env', cwd });
// → { decision: 'deny', reason, context }

const verdict = inspect({ kind: 'command', command: 'cat .env' });
// → { decision: 'deny' | 'redact' | 'allow', reason }

const verdict = inspect({ kind: 'write', path: 'config.ts', content, cwd });
// → { decision: 'deny', hits: ['DATABASE_URL'] }

// post-execution
const { text, hits } = scrub(toolOutput, cwd);
```

Then register it in `TARGETS` in [`src/install.js`](./src/install.js) with its config path
and an honest `verified` flag. **Do not mark an adapter verified until you have run it
against that agent with a throwaway `.env` and watched it block.** A security tool that
claims coverage it doesn't have is worse than one that admits the gap.

Known landscape, if it helps you pick: Gemini CLI (`BeforeTool`), Cursor
(`beforeShellExecution`, `beforeReadFile`) and Amp (`tool.call`) all support blocking.
Only Claude Code and Amp support rewriting a tool's *output*, which is what door 3 needs.

## Style

Match the file you're editing. Comments explain *why*, not *what* — especially for a
regex, where the interesting part is which false positive it was shaped to avoid.
