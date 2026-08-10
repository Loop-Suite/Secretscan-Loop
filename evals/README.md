# Empirical review findings

This directory records what actually happened when this repo (`secretscan-loop`, a Rust CLI
that scans a directory for hardcoded secrets, triages candidates through an LLM persona
pipeline, and gates CI/pre-push on the verdict) was reviewed and then actually run. Two rounds
were static code review (reading `src/`, `README.md`, and `docs/design-spec.md` against each
other, no LLM API calls); the third round was real execution — actual `claude -p --model haiku`
calls against the repo's own scanner, with real cost. A fourth, "production hardening" round
went back with an adversarial mindset (specifically hunting for safety-guarantee bypasses, not
general correctness), expanded the regression suite to cover filesystem/encoding/topology edge
cases, cut a versioned `v0.1.0` release, and closed with a second real-execution pass against a
denser fake-secret fixture — including an honest accounting of a cost mistake made during that
pass. All numbers below are from things that were actually checked (`grep`, `git log`, reading
generated `report.md`/`state.json`/`describe.md`, or a disposable/committed Rust test), not
estimated or asserted from memory.

## TL;DR — issues found and real cost

| Round | What | Issues filed | Issues closed | Real LLM cost |
|---|---|---|---|---|
| 1 — static review | Read `scanners.rs`, `lens.rs`, `main.rs` against `README.md`'s safety claims | #2, #3, #4 | #2, #3 fixed same round; #4 left open (stated low confidence) | $0 |
| 2 — deepened static review | Re-examined masking/fingerprint/coverage-count logic specifically | #5, #6, #7 | #5, #6 fixed (same commit also closes #4); #7 fixed | $0 |
| 3 — real CLI execution | `claude -p --model haiku`: scan x2, describe x1, against a small AWS-key/GitHub-token test fixture | #8 | #8 fixed | $0.7846 |
| 4 — production hardening | Adversarial re-audit + edge-case tests (10→24) + `CHANGELOG.md`/`v0.1.0` + real execution against a 6-type fake-secret fixture | #15, #16 | #15, #16 fixed (PR #17); CHANGELOG/tag in PR #18 | **$1.9781** |
| **Total** | | **9 issues (#2–#8, #15, #16)** | **9/9 closed** | **$2.7627** |

Cost breakdown for rounds 3 and 4 (the only rounds that made real API calls — rounds 1, 2, and
the static half of round 4 were reading code, not calling the model):

Round 3:

| Call | Purpose | Cost |
|---|---|---|
| scan #1 (`manual-test`) | Full pipeline scan of a 4-file test tree (AWS key + secret pair + GitHub token) | $0.3525 |
| describe (`manual-test`) | `describe.md` generation from the same scan | $0.0308 |
| scan #2 (`exit-check`) | Independent rerun, used to check the exit-code contract | $0.4013 |
| **Total** | | **$0.7846** |

Round 4:

| Call | Purpose | Model | Cost |
|---|---|---|---|
| scan (6-fake-secret fixture) | Full pipeline scan of a directory with 6 planted fake secret types (AWS, Anthropic, OpenAI, GitHub, Slack webhook, PEM) | **no `--model` flag passed — fell back to the backend's default (non-haiku) model** | $1.9477 |
| describe (same fixture) | `describe.md` generation from the same scan | `--model haiku` (correct) | $0.0304 |
| **Total** | | | **$1.9781** |

Round 4's cost is not a finding about the tool — it's an operator mistake, documented rather than
smoothed over: the `scan` invocation omitted `--model haiku`, so it ran on the CLI backend's
default (more expensive) model instead. That single scan call cost roughly **5x** what either of
round 3's `--model haiku` scans cost ($1.9477 vs. $0.3525 / $0.4013), on a comparably-sized
fixture. The `describe` call in the same round, run correctly with `--model haiku` against the
same fixture, cost $0.0304 — about **1/64th** of the mis-flagged scan's cost. Scan and describe
aren't identical workloads (scan fans out across multiple lens + discourse calls; describe is one
call), so this isn't an exact apples-to-apples multiplier, but it's consistent with the user's own
estimate that a correctly-flagged haiku scan would have landed "around 1/60th" of what was
actually spent — i.e. the fixture wasn't the reason this round cost 2.5x round 3's total; the
missing flag was.

## What this bought

- **A real safety-guarantee violation, not a style nit.** #2: for the
  `generic_high_entropy_assignment` rule, `mask()` was fed the *whole regex match*
  (`m.as_str()`, keyword + operator + quotes + secret) instead of the actual secret capture
  group. Since `mask()` keeps a few characters at the tail of whatever it's given, the tail of
  the whole match — the end of the real secret plus the closing quote — leaked into
  `masked_preview` and `context_line` in plaintext. Those two fields flow straight into the LLM
  review prompt and into `report.md`. This directly contradicted the README's stated core
  guarantee ("Nothing in this tool ever prints, logs, or serializes a raw secret value") for
  the one rule most likely to fire on arbitrary `KEY = "..."`-shaped code. Fixed in `73d2231` by
  giving each `Rule` a `secret_group` field and using `captures_iter` + that group instead of
  the whole match.
- **A low-confidence issue confirmed, not dismissed, in the next round.** #4 was explicitly
  filed as "[Low confidence, needs verification]" — the concern (dedup `fingerprint()` includes
  `rule_id`, so builtin `aws_access_key_id` vs. gitleaks `aws-access-token` vs. trufflehog `AWS`
  could all describe the same secret without deduping) could not be tested because gitleaks and
  trufflehog binaries weren't available in the review environment. Round 2's #6 reproduced the
  *identical* root-cause mechanism entirely within the builtin scanner — no external tools
  needed — with a deterministic repro: a one-line `config.env` fixture matched both
  `aws_access_key_id` and `generic_high_entropy_assignment`, producing two un-deduped
  `Candidate`s for the same physical secret, each separately penalized in `quantify::score`.
  Commit `4bf3f3f` fixed both in one change (drop `rule_id` from the fingerprint) and its footer
  reads `Fixes #5, Fixes #6, Closes #4` — a concrete instance of "flagged with low confidence"
  turning into "verified true" one round later, not a hedge that just sat there.
- **#5 — the masking formula itself under-delivered on its own spec.** `mask()`'s
  `clamp(n/5, 3, 6)` forced 3 head + 3 tail characters to show in plaintext even just above the
  `n<=8` full-mask cutoff — up to 67% of a 9-character secret, against `docs/design-spec.md`
  §3's documented contract of "first 4 and last 4 characters" only. Confirmed by iterating
  `mask()` over lengths 9–20 in a disposable test and printing the actual reveal ratio, not by
  inspection alone. Fixed by lowering the clamp floor from 3 to 1 (same commit as #6, `4bf3f3f`).
- **#7 — reported scan coverage was fabricated by an order of magnitude in realistic repos.**
  `files_scanned` counted every file under the target directory, including everything inside
  `.git`, `node_modules`, `target`, `dist`, `build`, `.venv`/`venv`, `__pycache__` — directories
  `builtin_scan` itself always skips. Measured, not assumed: a test directory with 20 files under
  `node_modules/` plus 1 real source file reported `files_scanned=21` while exactly 1 file's
  content was actually regex-scanned. In a populated real repo this inflation is orders of
  magnitude larger, and it feeds a number a PASS verdict's credibility depends on. Fixed in
  `19de6aa` by reusing the same `should_skip` filter `builtin_scan` already applies.
- **#3 — a correctness bug in the discourse-carryover path, not a scanning bug.** `Finding.id`
  was generated as `"{lens_id}-{i+1}"` with no round number, unlike `discourse.rs`'s own
  round-scoped surface-finding ids (`"surface-r{round}-{i+1}"`). Across a multi-round `--prior`
  chain, two separate rounds of the same lens could produce colliding ids, and the
  `STILL_OPEN` carry-forward path in `main.rs` re-inserts a prior-round finding into the
  *current* round's `resolved` map keyed by that id — silently overwriting an unrelated
  current-round finding's already-computed discourse resolution. Fixed in `f8ff490` by threading
  the round number into the id (`"{lens_id}-r{round}-{i+1}"`), matching the convention
  `discourse.rs` already used.
- **Actually running the CLI found a bug static reading missed: stale documentation of a
  just-fixed security-relevant formula.** #8 was found only by executing `claude -p` end to end
  against a real test fixture (AWS key + secret pair in `src/config.py`, a GitHub token in
  `src/deploy.sh`) and manually cross-checking the real `masked_preview` values in `report.md`
  against README.md's Safety design section. The code and its inline comment were correctly
  updated by #5's fix; the README's prose was not, and still described the disproven
  `clamp(n/5, 3, 6)` formula. The divergence is invisible for secrets ≥15 characters (the two
  clamp floors give the same result there) and only shows up in the 9–14 character range #5 was
  specifically about — exactly the kind of gap that reading the diff, rather than running the
  tool and reading its actual output, would miss. Fixed in `d6b8e0e`.
- **Execution surfaced real, verifiable positive evidence too, not just one more bug.** Both real
  scan runs (`runs/manual-test/`, `runs/exit-check/`) reported `files_scanned=4` (correct for the
  4-file fixture tree, consistent with #7's fix — no inflation observed). Hand-checked every
  `masked_preview` value against the post-#5 formula: `AKIA****...****MNOP (len=20)` →
  `keep = clamp(20/5, 1, 6) = 4` ✓; `wJalrX****...****PLEKEY (len=40)` and
  `ghp_AB****...****456789 (len=40)` → `keep = clamp(40/5, 1, 6) = 6` ✓ — both correct. Grepped
  both `report.md` files and both `state.json` files for any unmasked occurrence of the actual
  scanned secret strings: none found. One apparent hit needs a caveat, recorded honestly rather
  than dropped: `exit-check/report.md` contains the literal string `AKIAIOSFODNN7EXAMPLE` — but
  that's the LLM reviewer's own free-text reference to AWS's *publicly published* documentation
  placeholder key ("Verify if this matches AWS example key (AKIAIOSFODNN7EXAMPLE)"), not the
  tool re-emitting the actual scanned fixture value, which was a different string ending in
  `...MNOP`. Both real runs produced `Verdict: BLOCK`, which by the documented and implemented
  contract (`README.md:403`, `src/main.rs:49`, `BLOCK => 3`) maps to exit code 3 — consistent
  with what round 3 set out to check, though the numeric exit code itself was captured during
  the live run, not re-executed for this write-up.
- **All 7 issues filed across all three rounds were closed**, each by a commit that fixed the
  underlying code (or, for #8, the stale doc) rather than by discussion — every fix commit's
  message includes the concrete root cause, the fix, and a `Fixes #N` footer.

## Round 1 — static code review

Read `src/scanners.rs`, `src/lens.rs`, `src/main.rs`, `README.md`, and `docs/design-spec.md`
against each other, no code execution. Filed:

- **#2 — Secret suffix leaks into `masked_preview`/`context_line`** for
  `generic_high_entropy_assignment`. Security-priority: this breaks the tool's own core
  guarantee. Fixed in `73d2231`.
- **#3 — Finding ids collide across rounds**, `STILL_OPEN` carry-forward can overwrite an
  unrelated finding's resolution. Fixed in `f8ff490`.
- **#4 — [Low confidence, needs verification] dedup fingerprint's `rule_id` may block
  cross-source dedup.** Explicitly filed as unverified — gitleaks/trufflehog binaries weren't
  available to test the cross-source claim directly, so this was reasoning from reading the
  code, stated as such rather than presented as confirmed. Left open pending round 2.

## Round 2 — deepened static review

Went back specifically at the masking/fingerprint/coverage-count logic that round 1's reading
had flagged as worth a second, more skeptical pass. Filed:

- **#5 — `mask()` reveals up to 67% of a secret in plaintext for lengths 9–19**, violating
  `design-spec.md` §3. Confirmed with an actual reveal-ratio test across lengths 9–20, not by
  eyeballing the clamp math.
- **#6 — `fingerprint()`'s `rule_id` lets the same secret produce duplicate un-deduped
  candidates.** This is what turned #4 from a stated-low-confidence hypothesis into a confirmed
  bug: instead of needing gitleaks/trufflehog, #6 found the exact same failure mode reproducible
  purely within the builtin scanner (one secret matched by two builtin rules on one line). Fixed
  together with #5 in `4bf3f3f`, whose commit footer explicitly closes #4 alongside fixing #5
  and #6.
- **#7 — `files_scanned` counts files inside skipped directories** (`.git`, `node_modules`,
  `target`, `dist`, `build`, `.venv`/`venv`, `__pycache__`), wildly inflating reported coverage.
  Measured with a 21-file/1-actually-scanned test directory. Fixed in `19de6aa`.

## Round 3 — real CLI execution

This round stopped reading code and actually ran the shipped binary end to end:
`claude -p --model haiku` against a small, self-contained test fixture (`src/config.py` with an
AWS access key + secret key pair, `src/deploy.sh` with a GitHub token — 4 files total). Two
scans and one describe call were made; outputs are preserved at `runs/manual-test/` (scan +
describe) and `runs/exit-check/` (independent rescan used to check the exit-code contract).

- Both runs correctly classified all three candidates, reached `Verdict: BLOCK`, `Score: 0/100`,
  and correctly rejected the two candidates that matched well-known public documentation
  placeholder values (AWS's published `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` example secret,
  a GitHub token with an implausibly sequential numeric suffix) via discourse `CHALLENGE`/reject,
  rather than blindly flagging every regex match as confirmed.
- `files_scanned=4` in both runs — correct, and consistent with #7's fix already being in place
  by this round.
- **#8 — README masking formula is stale after #5's fix**, found by cross-checking real
  `masked_preview` output against README.md's Safety design section during this run, not by
  reading the diff. The code itself was already safe (verified: the actual masked values in both
  `report.md`s match the post-#5 `clamp(n/5, 1, 6)` formula exactly); only the documentation
  still described the pre-fix `clamp(n/5, 3, 6)` formula #5 had disproven. Fixed in `d6b8e0e`.
- Grepped both real run directories (`runs/manual-test/`, `runs/exit-check/`) for the actual
  scanned secret strings in unmasked form: not found in either `report.md` or either
  `state.json`. See the caveat above about `AKIAIOSFODNN7EXAMPLE` — a real string match, but the
  LLM reviewer citing a public AWS documentation placeholder by name in its own reasoning text,
  not the tool disclosing the fixture's actual (different) secret value.
- Exit-code contract: both runs' `Verdict: BLOCK` corresponds to exit code `3` per the documented
  and implemented contract (`README.md:403`: "`PASS=0`, `WARN=2`, `BLOCK=3`, run/config error=4";
  `src/main.rs:49`: `"BLOCK" => 3`) — the report output and the code agree with each other.

## Round 4 — production hardening

This round had four parts: an adversarial re-audit specifically looking for ways the tool's own
safety guarantees could be bypassed (not general correctness reading), an expansion of the test
suite into filesystem/encoding/topology edge cases, cutting a first versioned release, and a
second real-execution pass to check the fixes against live output. Everything here landed in
[PR #17](https://github.com/Loop-Suite/Secretscan-Loop/pull/17) (issues + tests) and
[PR #18](https://github.com/Loop-Suite/Secretscan-Loop/pull/18) (CHANGELOG/release), both merged.

### Adversarial re-audit

Read `scanners.rs` again specifically hunting for ways an attacker or an unlucky input could
defeat the "nothing raw ever gets printed" guarantee or the memory/size safety of the scanner
itself — not re-checking things already covered by rounds 1–3.

- **#15 — `mask_line_all()` skipped masking entirely when two matched secrets partially
  overlapped without either containing the other.** The prior implementation sorted raw values
  longest-first and repeatedly did `result.contains(raw)` → `result.replace(raw, mask(raw))`
  against a mutating string. Masking the longer match first consumed the characters it shared
  with the shorter match, so the shorter match's exact substring no longer existed in `result`
  and its `.contains()` check silently no-opped — leaving that match's text in plaintext. This
  was reproduced directly, not just reasoned about: a constructed test case (`line[0..20]` and
  `line[15..36]`, overlapping at `[15,20)`) left **19 of 20 characters of one secret unmasked**
  after the "fix." Rewritten from scratch to a byte-range approach: find every occurrence of
  every candidate value as a `(start, end)` byte range in the line, merge overlapping/adjacent
  ranges, then rebuild the line masking each merged range as one block — no combination of
  overlapping matches can leave a fragment unmasked, because masking no longer depends on the
  literal substring still being findable after an earlier replacement. A second test
  (`mask_line_all_handles_three_way_chained_overlap`) checks a 3-way pairwise-overlap chain (A↔B,
  B↔C, A and C not touching) merges into one masked run with nothing left over, and that an
  untouched tail past the merged range stays visible (proving the fix doesn't over-mask the whole
  line). Fixed in `c263768`.
  - This isn't a purely theoretical bug gated behind an unlikely input. It's not reproducible with
    only the 10 builtin regex rules shipped in this repo — none of them are shaped to overlap each
    other on realistic input, so a direct end-to-end repro through `builtin_scan()` alone wasn't
    found. But it's realistically triggerable through the `gitleaks` integration path, where
    hundreds of community rules commonly fire on the same line with overlapping-but-not-identical
    spans (e.g. a broad generic-secret rule and a provider-specific rule both matching different
    but overlapping substrings of the same credential). More importantly, `mask_line_all()` is a
    shared library function that every detection source's output flows through — it has to be
    safe regardless of which rule set produced the overlapping matches, not just safe against the
    10 rules that happen to ship today. Treating it as security-priority and fixing it before a
    concrete gitleaks repro existed was the correct call, not an overreaction.
- **#16 — `builtin_scan()` read a file's entire contents into memory before checking the 5MB size
  cap.** The cap was checked against `bytes.len()` *after* `std::fs::read()` had already loaded
  the whole file — for a multi-GB file, the cap did nothing to bound memory use; it just decided,
  after the fact, whether to also scan what had already been fully read. Fixed by checking
  `entry.metadata().len()` before ever calling `read()`, skipping oversized files without reading
  a single byte of them. Regression test `builtin_scan_skips_file_over_size_cap` deliberately puts
  a real-looking secret right at the end of a 5,000,001-byte file, so a regression back to
  "read-then-check" would still (accidentally) find it — the fixed version must skip the file
  before ever reading it, so the secret must never appear in output either way. Fixed in
  `c263768`.
- **Audited and confirmed not vulnerable — recorded so the negative result isn't lost:**
  - **ReDoS / catastrophic backtracking**: the `regex` crate used throughout is a finite-automaton
    engine with a documented linear-time worst case, not a backtracking engine — the class of bug
    doesn't apply here regardless of how adversarial the input pattern is.
  - **Symlink loops causing unbounded traversal**: `WalkDir`'s default is to not follow symlinks
    (`follow_links` defaults to `false`), confirmed with a dedicated regression test
    (`builtin_scan_does_not_hang_on_symlink_loop`) that creates a directory symlink cycling back
    to an ancestor and asserts the scan terminates and finds exactly the one real file.
  - **Path traversal via scanner-reported paths**: raw secret values and scanner-reported file
    paths never reach a filesystem *write* call anywhere in the codebase — output paths are only
    ever derived from the CLI's own `--out` argument, so a maliciously-named scanned path can't
    redirect where anything gets written.

### Edge-case test expansion

The regression suite grew from **10 to 24 tests** (`grep -rn '#\[test\]' src/ | wc -l`), adding
coverage for inputs the original suite never exercised:

- Empty target directory, empty file (`builtin_scan_handles_empty_target_dir`,
  `builtin_scan_handles_empty_file`) — both must scan clean, not panic or misreport.
- A corrupted/non-UTF-8 file (`builtin_scan_ignores_non_utf8_file`, a byte sequence starting with
  `0xFF`, never a valid UTF-8 lead byte) — must not panic.
- A symlinked file (`builtin_scan_does_not_follow_symlinked_files`) — the symlink itself is never
  followed (`WalkDir`'s default), so only the real underlying file is scanned; also closes off
  reading-outside-the-target-directory via a symlink.
- A directory symlink loop (`builtin_scan_does_not_hang_on_symlink_loop`) — must terminate.
- A 150-level-deep directory tree (`builtin_scan_handles_very_deep_directory_tree`) — must not
  stack-overflow or hang.
- A secret split across two different files (`builtin_scan_does_not_merge_secrets_split_across_two_files`)
  and a secret wrapped across two lines in one file
  (`builtin_scan_does_not_merge_secret_split_across_two_lines`) — both must produce *no* match
  (characterization tests documenting a real, intentional detection-coverage limit: this scanner
  is line-by-line, it does not synthesize cross-file or cross-line matches — not a masking leak,
  since nothing unmasked is ever reported when no candidate is produced).
- A Unicode secret, Korean text plus an emoji plus ASCII
  (`mask_handles_unicode_secret_without_panicking_or_leaking`) — must not panic on multi-byte
  char-boundary slicing and must never reveal the raw value.
- Very short secrets down to the empty string
  (`mask_fully_masks_very_short_secrets`, lengths 0–8) — must be fully masked (all `*`).
- A very long secret, 200,000 characters
  (`mask_handles_very_long_secret_without_panicking`) — must not panic, and the reveal must stay
  clamped to 6 head + 6 tail characters regardless of length.
- The #15 and #16 regression tests above are also part of this same 10→24 expansion.

### Versioning

[`CHANGELOG.md`](../CHANGELOG.md) was added (Keep a Changelog format, Semantic Versioning,
including a `### Security` section that names #15, #16, and the two "audited, not vulnerable"
findings above) in PR #18, and the repo was tagged and released as
[**`v0.1.0`**](https://github.com/Loop-Suite/Secretscan-Loop/releases/tag/v0.1.0) — the first
versioned release, after 4 rounds of review and 9 closed issues.

### Real execution against a denser fake-secret fixture

Round 3's execution used a 4-file fixture with one secret type family (AWS key/secret pair +
GitHub token). This round planted **6 different fake secret types** in a test directory — AWS,
Anthropic, OpenAI, GitHub, a Slack webhook URL, and a PEM private key — and ran `scan` followed by
`describe` against it, specifically to check the just-fixed #15/#16 masking path against more
varied, real-shaped input than the builtin rule set's own unit tests use.

- Grepped `report.md`, `state.json`, and `describe.md` for the actual raw fake-secret strings
  planted in the fixture: **none found** in any of the three output files.
- `masked_preview` values for all 6 planted secrets looked correct (consistent with the post-#5,
  post-#15 masking formula/merge logic).
- Dedup behaved normally — no un-deduped duplicate candidates for the same underlying secret.
- **Cost honesty note**: this pass is where the round's entire $1.9781 real-LLM-cost went, and
  $1.9477 of it (98%) was avoidable — the `scan` command was run without `--model haiku`, so it
  ran on the backend's default (non-haiku) model instead. `describe`, run correctly afterward with
  `--model haiku` against the same fixture, cost $0.0304. See the cost breakdown table above for
  the full comparison against round 3's haiku-only scans. This was a flag-omission mistake made
  during this round, not a cost inherent to checking a denser fixture, and it's recorded here
  rather than folded quietly into a total.

## Caveats

- Round 1 and round 2 were static review — no LLM API calls, $0 real cost, and no execution of
  the scanner against real input. Everything found there is reasoning from reading the code, not
  observed runtime behavior. #4 is the explicit example of that limitation being stated honestly
  instead of glossed over, and of it then actually mattering (round 2 found the same bug through
  execution-adjacent reasoning that didn't need the missing binaries).
- Round 3 is two scans and one describe call against one small, synthetic 4-file fixture. This
  confirms the specific things checked (files_scanned count, masked_preview values, exit code for
  a BLOCK verdict, one doc/code drift) on that one fixture — it is not a benchmark and doesn't
  establish detection recall/precision or non-determinism across repeated runs the way, e.g.,
  Code-Review-Loop's own `evals/README.md` does for that project's discourse pipeline.
- All fixes from rounds 1–3 were verified by either a disposable Rust test (#5, #6, #7 — since
  removed after confirming) or direct inspection of real run output (#2, #8); none of those 7
  fixes were re-run through a second live `claude -p` call after fixing to reconfirm end-to-end
  (that would need additional real API spend beyond the $0.7846 already spent, and wasn't done).
- **#15 has no direct end-to-end repro through this repo's own 10 builtin rules** — the partial-
  overlap condition was reproduced with a hand-constructed unit test operating on `mask_line_all()`
  directly, not by finding two builtin rules that actually overlap on realistic input. The
  realistic trigger path (`gitleaks`'s much larger community ruleset) was reasoned about, not
  executed — `gitleaks` wasn't run against a crafted overlap fixture as part of this round. The
  fix itself doesn't depend on that trigger path existing today, though: it changes
  `mask_line_all()`'s own algorithm to be correct for any input, independent of which rule
  produced which match.
- **Round 4's real-execution cost ($1.9781) is dominated by a mistake, not by the fixture.**
  $1.9477 of it — 98% — came from one `scan` call run without `--model haiku`, landing on the
  backend's default (more expensive) model by accident. This is disclosed, not smoothed into the
  running total, specifically so the $2.7627 grand total isn't misread as "what a scan+describe
  pair against a 6-secret-type fixture normally costs" — it's roughly 5x that, because of the
  missing flag.
- The 6-fake-secret-type execution pass's output files (`report.md`, `state.json`, `describe.md`)
  were written to a local, gitignored `runs/` subdirectory (per `.gitignore`'s `/runs` entry, same
  as round 3's `runs/manual-test` and `runs/exit-check`) and are not committed to this repo — the
  `grep`-for-no-raw-secrets check described above was run against those local files at the time,
  not against anything checked into version control.
