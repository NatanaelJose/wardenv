# Changelog

## 0.2.0 — 2026-09-23

Adds support for four more agents — Gemini CLI, Cursor, Codex CLI, GitHub Copilot CLI —
alongside the existing Claude Code one. Hooks split into a per-agent adapter
(`hooks/adapters/<agent>.js`) plus one shared policy (`hooks/decide.js`), so a new agent
means writing one adapter, not touching the guard logic. Install and test with
`wardenv install gemini|cursor|codex|copilot`.

Only Claude Code is fully `✅ verified end to end`. Codex CLI is close: a live 0.156.1
Desktop session blocked every one of 8 real attack/friction scenarios. Gemini, Cursor and
Copilot CLI are checked against source/docs and covered by `test/adapters.test.js`, not
yet run live — see the agent support table in `README.md` for exactly what's verified.

This work went through an unusually thorough hardening pass before release: a code audit
after the initial multi-agent merge, then two live test sessions (Codex Desktop, Claude
Code) that each found a real bypass the audit and the simulated-payload tests had missed.
That pattern — live testing catching what code review and unit tests didn't — is worth
knowing before trusting any "unverified" adapter for anything real.

### Fixed

- **`wardenv install codex` had stopped refusing on Codex versions with no tool hooks.**
  The hard refusal that existed before multi-agent support was lost in the refactor:
  installing on Codex 0.116–0.128 (no `PreToolUse`/`PostToolUse` at all) printed
  `🔒 installed` with only an easy-to-miss `⚠ UNVERIFIED` note, exit code 0, while the
  guard never actually ran. Fixed: the installer now checks the installed Codex's version
  and refuses outright below 0.129.
- **`wardenv uninstall copilot` didn't remove the hook.** It called the removal function
  written for the nested `{matcher, hooks:[...]}` layout that Claude/Gemini/Codex use;
  Copilot's own hooks file is flat (each array entry *is* the hook), so the function
  silently matched nothing and the wardenv entries stayed registered while the command
  printed success. Fixed: uninstall now uses the flat-layout removal (shared with Cursor).
- **`wardenv install`/`uninstall` always exited 0**, even when the underlying `install.js`
  process failed — including the Codex refusal above. `src/cli.js` spawned it but never
  propagated its exit code. Fixed: the CLI now exits with the child process's actual code.
- **Gemini's `read_many_files` didn't recognize a glob that targets a secret.** `include`
  accepts patterns like `*.env`, not just literal paths; comparing the glob string itself
  against known secret filenames never matched. Fixed: a glob is now checked against
  secret-shaped filenames it would actually expand to.
- **On Windows, the registered hook command was invalid PowerShell syntax, and the guard
  never ran for Codex Desktop or Cursor.** Found live, testing against a real Codex
  Desktop session: a `.env` read went straight through with no block, no error, nothing
  in the log. Codex Desktop and Cursor spawn the hook command through PowerShell (not
  `cmd.exe`), where a bare quoted path at the start of the line is a string, not a call —
  the parser choked on the following `--agent` (`--` is PowerShell's decrement operator),
  the hook never produced JSON, and wardenv failed open exactly as its own comment
  documents ("never break the session"). Fixed: the installer now prefixes the command
  with `&` for Codex, Cursor, and Copilot's `powershell` field (its `bash` field is
  unaffected). Confirmed live: the exact registered command now runs correctly under
  PowerShell.
- **A prompt-level wrapper rule bypassed detection entirely.** A project instructing the
  agent to always prefix shell commands with some proxy (found live via a real
  `AGENTS.md` → `RTK.md` chain telling Codex to run everything through `rtk`) made
  `rtk cat .env` read as "block" downgraded to "redact" (mentions, not a read), and
  `rtk curl -F f=@.env ...` — the most critical exfiltration case — read as fully allowed.
  The upload/read/self-disarm checks all took "the first token" as the real binary; with a
  wrapper in front, that token was `rtk`, not `cat`/`curl`. `sudo`/`doas` had the identical
  gap independent of any RTK.md. Fixed: `rtk`, `sudo`, `doas` and `env VAR=value` are now
  recognized and skipped to find the actual binary, in both the tokenizer and the
  self-disarm patterns.
- **`curl.exe` didn't match the uploader list.** Only `curl` did; Codex commonly invokes
  `curl.exe` explicitly (to avoid a PowerShell alias), and `curl.exe -F f=@.env ...` was
  fully allowed. Fixed: the Windows executable extension (`.exe`/`.cmd`/`.bat`) is now
  stripped before matching a binary name, shared between the uploader and reader checks.
- **`cat .env` (and any shell read) never showed the key structure the README's own
  example promises.** Only the native `Read` tool did. A shell read — `cat`, `grep`,
  `Get-Content`, the most common way anyone actually reads a file — got a generic "this
  would expose credentials" instead of `SECRET_KEY=<set, 16 chars>` plus the `wardenv
  unlock` suggestion. Found live testing a Claude Code session. Fixed: both paths now
  share the same key-listing logic.
- **`versionAtLeast()` (added for the Codex version check above) never worked outside
  Windows.** `spawnSync` without `shell:true` treats a command string as one literal
  executable name and always fails — on any platform, not just Windows. The precheck
  silently never triggered on Linux/macOS. Caught by CI failing across the whole
  ubuntu/macOS matrix.
- 9 new tests since #1's merge (91 → 100), all passing on Windows, Linux and macOS across
  Node 18/20/22.

## 0.1.6 — 2026-09-22

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
