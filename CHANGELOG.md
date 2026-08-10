# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-10

Initial release.

### Added

- `secretscan-loop` (binary: `secretscan`): a multi-persona review + discourse
  cross-examination CLI that triages raw secret-scanner candidates (from a built-in
  regex/entropy fallback scanner, and gitleaks/trufflehog if installed) through
  independent persona review, adversarial cross-examination, and a deterministic
  verdict, instead of either blocking every push on a noisy scan or being ignored.
- `scan`, `describe`, `improve`, and `ask` subcommands; `--scope` filesystem / staged /
  commit-range / full-history scanning; a `--backend openrouter` alternative to the
  default `claude -p` subprocess backend.
- Deterministic policy checks (`checks.rs`): `.gitignore` coverage for required
  sensitive-file patterns, tracked-sensitive-filename detection, raw candidate volume —
  none of which depend on LLM judgment.
- Regression test suite covering: masking correctness and reveal-percentage bounds,
  fingerprint/dedup behavior across rules and sources, `files_scanned` accuracy,
  cross-round finding-id stability, empty input, files at/over the size cap, corrupt/
  non-UTF-8 files, symlinked files, directory symlink cycles, very deep directory
  trees, and secrets split across file/line boundaries.
- `CHANGELOG.md` (this file).

### Fixed

- Finding ids could collide across discourse rounds in a multi-round `--prior` chain
  (`"{lens_id}-{i+1}"` had no round number), letting a prior round's `STILL_OPEN`
  carry-forward silently overwrite an unrelated current-round finding's resolution.
  Fixed by threading the round number into the id.
- `files_scanned` counted every file physically present under the target directory,
  including everything inside `.git`, `node_modules`, `target`, `dist`, `build`,
  `.venv`/`venv`, `__pycache__` — directories the scanner itself always skips —
  inflating reported scan coverage by orders of magnitude in realistic repos.
- The same secret matched by two different rules/sources (e.g. builtin
  `aws_access_key_id` vs. gitleaks `aws-access-token` vs. trufflehog `AWS`) could
  produce duplicate, un-deduped candidates because the dedup fingerprint included
  `rule_id`. Fixed by excluding `rule_id` from the fingerprint and OR-ing
  `hard_verified` across every duplicate sharing a fingerprint.
- README's documented masking formula (`clamp(n/5, 3, 6)`) went stale after the
  formula itself was fixed to `clamp(n/5, 1, 6)` — invisible for secrets ≥15
  characters, only visible in the 9–14 character range the fix specifically targeted.
- `builtin_scan()` read a file's full contents into memory (`std::fs::read`) before
  checking the 5MB size cap against `bytes.len()`, so the cap never actually bounded
  memory use for oversized files. Now checks `entry.metadata().len()` first and skips
  oversized files without reading them at all.

### Security

- **`mask()` fed the whole regex match, not the secret, for the generic high-entropy
  rule.** For `generic_high_entropy_assignment`, `mask()` received the entire regex
  match (keyword + operator + quotes + secret) instead of the capture group holding
  the actual secret value. Since `mask()` keeps a few trailing characters of whatever
  it's given, the tail of the real secret plus the closing quote leaked into
  `masked_preview` / `context_line` in plaintext — fields that flow directly into the
  LLM review prompt and `report.md`. Fixed by giving each rule a `secret_group` field
  and masking only that capture group.
- **`mask()` revealed up to 67% of short secrets.** The reveal formula's clamp floor
  (`clamp(n/5, 3, 6)`) forced 3 head + 3 tail characters into plaintext even just above
  the full-mask cutoff (`n<=8`), so a 9-character secret showed 6/9 characters — far
  above the documented "first 4 / last 4" ceiling. Fixed by lowering the clamp floor
  from 3 to 1, so the ~40% reveal ceiling that already held for longer secrets applies
  uniformly down to 9-character secrets too.
- **`mask_line_all()` could leave a secret almost entirely in plaintext on partial
  overlap.** The masking pass sorted matched secrets longest-first and repeatedly did
  `result.contains(raw)` → `result.replace(raw, mask(raw))` against a mutating string.
  When two matched secrets on the same line *partially* overlapped without either
  containing the other, masking the longer one first consumed characters shared with
  the shorter one, so the shorter one's exact text no longer existed in `result` and
  its `.contains()` check silently skipped masking it — leaving most of it in
  plaintext. Confirmed with a direct repro (19 of 20 characters of a secret left
  unmasked) before fixing. Rewritten to a byte-range/merge approach: find every
  occurrence of every value as a byte range, merge overlapping ranges, mask each
  merged range as a block — no combination of overlapping matches can leave a
  character unmasked. Realistically triggerable via gitleaks integration, where
  multiple community rules commonly fire on the same line with overlapping-but-not-
  identical spans.
- **`builtin_scan()` was a resource-exhaustion vector for oversized files** — see
  "Fixed" above; recorded here too since the security implication (a maliciously or
  accidentally huge file forcing full in-memory reads regardless of the intended cap)
  is the primary reason it was fixed.
- Audited and confirmed **not** vulnerable (no fix needed): regex catastrophic
  backtracking (the `regex` crate guarantees linear-time matching, not a backtracking
  engine); symlink loops causing unbounded traversal (`WalkDir`'s default is to not
  follow symlinks, confirmed with a directory-cycle regression test); path traversal
  via scanner-reported paths (raw secret values and scanner-reported file paths never
  reach a filesystem write call — output paths are only ever the CLI `--out` argument).

### Changed

- Dependency bumps: `ureq` 2.12.1 → 3.3.0, `toml` 0.8.23 → 1.1.0 (spec 1.1), `clap`
  4.6.4 → 4.6.6, `actions/checkout` 4 → 7. Dependabot enabled for `cargo` and
  `github-actions` ecosystems (weekly).
