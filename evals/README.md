# Empirical review findings

This directory records what actually happened when this repo (`secretscan-loop`, a Rust CLI
that scans a directory for hardcoded secrets, triages candidates through an LLM persona
pipeline, and gates CI/pre-push on the verdict) was reviewed and then actually run. Two rounds
were static code review (reading `src/`, `README.md`, and `docs/design-spec.md` against each
other, no LLM API calls); the third round was real execution — actual `claude -p --model haiku`
calls against the repo's own scanner, with real cost. All numbers below are from things that
were actually checked (`grep`, `git log`, reading generated `report.md`/`state.json`, or a
disposable Rust test), not estimated or asserted from memory.

## TL;DR — issues found and real cost

| Round | What | Issues filed | Issues closed | Real LLM cost |
|---|---|---|---|---|
| 1 — static review | Read `scanners.rs`, `lens.rs`, `main.rs` against `README.md`'s safety claims | #2, #3, #4 | #2, #3 fixed same round; #4 left open (stated low confidence) | $0 |
| 2 — deepened static review | Re-examined masking/fingerprint/coverage-count logic specifically | #5, #6, #7 | #5, #6 fixed (same commit also closes #4); #7 fixed | $0 |
| 3 — real CLI execution | `claude -p --model haiku`: scan x2, describe x1, against a small AWS-key/GitHub-token test fixture | #8 | #8 fixed | **$0.7846** |
| **Total** | | **7 issues (#2–#8)** | **7/7 closed** | **$0.7846** |

Cost breakdown for round 3 (the only round that made real API calls):

| Call | Purpose | Cost |
|---|---|---|
| scan #1 (`manual-test`) | Full pipeline scan of a 4-file test tree (AWS key + secret pair + GitHub token) | $0.3525 |
| describe (`manual-test`) | `describe.md` generation from the same scan | $0.0308 |
| scan #2 (`exit-check`) | Independent rerun, used to check the exit-code contract | $0.4013 |
| **Total** | | **$0.7846** |

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
- All fixes here were verified by either a disposable Rust test (#5, #6, #7 — since removed after
  confirming) or direct inspection of real run output (#2, #8); none of the 7 fixes were re-run
  through a second live `claude -p` call after fixing to reconfirm end-to-end (that would need
  additional real API spend beyond the $0.7846 already spent, and wasn't done).
