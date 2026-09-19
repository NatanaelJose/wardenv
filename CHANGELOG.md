# Changelog

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
