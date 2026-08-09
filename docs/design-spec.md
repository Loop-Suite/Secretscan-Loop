# secretscan-loop Design Spec

secretscan-loop ports Code-Review-Loop (persona independent review → discourse cross-verification → deterministic verdict) into the **"secrets scan before git push / going public"** domain. Unlike research-loop and marketing-loop, this domain is fundamentally different in that **mature deterministic scanners (gitleaks/trufflehog/detect-secrets) already exist** — so the porting approach differs too: personas don't play the role of "finding problems from scratch," but instead **sort real risk from false positives among the candidates an existing scanner already emitted**.

## 0. Research basis (2026-08-01)

- **gitleaks/trufflehog/detect-secrets are regex + entropy based, so they produce many false positives on test fixtures, doc examples, and placeholders.** Without custom tuning, Gitleaks has a higher false-positive rate than GitGuardian, and empirical comparisons report that entropy-based matching is especially weak on test fixtures.
- **TruffleHog's key differentiator is "live verification"** — it confirms whether a detected credential is actually still valid via a safe, read-only API call, and holds verifiers for 700+ secret types. This is not qualitative judgment but **empirical confirmation**, putting it in the same category as research-loop's dead_link_check "real verification" approach.
- **GitHub itself introduced LLM contextual reasoning into its secret-scanning validation stage in June 2026** — judging from context whether a value assigned to a variable is actually used in a real API call, achieving a 75.76% reduction in customer-confirmed false-positive cases (exceeding the 65% target).
- **Open-source Atalaia (juanfont/atalaia)**: runs gitleaks+trufflehog → a single local LLM (default Gemma) call judges each finding as confirmed/dismissed. **Single-pass LLM judgment**; no independent-persona/discourse structure.
- **Conclusion**: Both GitHub and Atalaia are 2-stage "detection (deterministic) → LLM verification (single-pass)" structures. **No precedent has been found in this domain either for the 3-stage structure of multiple independent personas → discourse cross-verification → deterministic verdict** — the same gap research-loop and marketing-loop each confirmed in their own domains.

## 1. Mapping against the Code-Review-Loop 12-stage pipeline

| Stage | Module | codereview original | secretscan-loop substitute |
|---|---|---|---|
| Input normalization | input.rs | reads diff | reads the target path (directory or git diff) to get the file list |
| **Detection (new stage, absent from original)** | scanners.rs | (none; semgrep.rs only displays) | **runs gitleaks/trufflehog if present on PATH (same fallback pattern as semgrep.rs::try_run) + a built-in regex/entropy scanner that always runs**, producing the Candidate list — this list becoming the input to persona review is the key difference from the original |
| Lens selection | lens.rs::select_lenses | based on diff characteristics | based on candidate type (cloud key / OAuth token / private key / PII / other high-entropy) |
| Deterministic vs semantic split | report.rs | — | same structure. Except "detection" and "verification" are a 2-stage split of determinism (scanner detection is deterministic; live verification is optional) |
| Policy checks | policy.rs | coding policy | binary gates such as whether .env is tracked in git, whether .gitignore includes common secret file patterns |
| Per-lens independent review | lens.rs::review_lens | — | each persona independently judges (CONFIRMED_SECRET/FALSE_POSITIVE/NEEDS_HUMAN_REVIEW) against the **entire candidate list** |
| Discourse debate | discourse.rs | AGREE/CHALLENGE/CONNECT/SURFACE | CHALLENGE condition: "present evidence this value is part of a test fixture/example/real API schema" or conversely "present evidence it looks like a placeholder but matches the real format" |
| Requirement verification | requirements.rs | PR requirements | cross-checks a policy checklist (e.g. "no AWS keys", "no PII") against confirmed findings |
| Quantitative summarization | quantify.rs | P0=25/P1=12/P2=5/P3=1 | numbers kept, only the severity definitions reinterpreted (§5) |
| Prior-run fix check | fixcheck.rs | FIXED/STILL_OPEN/UNKNOWN | +**ROTATED** (new) — the value still remains in code, but the key itself has been revoked/rotated and is no longer valid. An extension of the same category as research-loop's REVERSED |
| Human-voice rewrite | humanvoice.rs | — | not applied (same call as research-loop) |
| Final report assembly | report.rs | — | **the report itself never writes the raw secret** — masking is mandatory (§6, a safety requirement unique to this tool) |

## 2. Personas (7)

| Lens | Persona (real) | Rationale | Persona tone | Tier |
|---|---|---|---|---|
| credential_liveness | Troy Hunt | Founder of Have I Been Pwned, expert in analyzing leaked credentials/breach data | repeatedly asks "is this value actually still a live credential, or a pattern that has already appeared in leaked databases" | 1 |
| exploitability | HD Moore | Founder of Metasploit, practical penetration from an attacker's perspective | repeatedly asks "what can an attacker actually do with this value right now," distinguishing theoretical risk from actual exploitability | 1 |
| false_positive_discipline | Tanya Janca | Founder of We Hack Purple, AppSec education | checks first whether "this is a test fixture/placeholder/doc example," strict against promoting unsubstantiated false positives | 1 |
| pipeline_pragmatism | Kelsey Hightower | Infrastructure/CI-CD practitioner and purist | distinguishes by code pattern whether "this is a normal environment-variable reference pattern, or actually hardcoded" | 1 |
| blast_radius_risk | Bruce Schneier | Leading author on security risk framing | systematically reasons about "what systems/data this would actually reach if it leaked" | 1 |
| disclosure_process | Katie Moussouris | Responsible vulnerability disclosure (RVD) policy expert | checks from a process standpoint "whether rotation/disclosure procedure after discovery is appropriate" | 2 |
| compliance_exposure | Rebecca Herold | Privacy/compliance (PCI-DSS/GDPR) expert | frames leaks involving PII/payment info as regulatory exposure | 2 |

## 3. Safety requirements (unique to this tool, absent from the original)

- **Never write the raw secret verbatim anywhere — report, state.json, or terminal output.** Matched strings are always handled masked (`sk-ab12****...****ef34`, exposing only the first 4 and last 4 characters). This is to prevent the tool itself from becoming a leak vector.
- **Live verification (confirming via API call whether a credential is actually still alive) defaults to OFF, opt-in only via `--verify-live`.** Informed by TruffleHog's verifier philosophy, but scope is limited to what the user has explicitly allowed (a design decision — automatically making live-verification API calls without authorization for every finding was judged to carry its own risk of misuse; not implemented in v1, documented only as a backlog item).

## 4. Redefinition of the discourse CHALLENGE condition

Narrower than the original (evidence/counterexample/scope rebuttal): CHALLENGE is only accepted as one of **"evidence it's a test fixture/example" or "evidence it matches the real format."** Subjective rebuttals ("this looks dangerous" alone) are insufficient — evidence required — and get downgraded to SURFACE.

## 5. Severity redefinition

| Severity | Definition |
|---|---|
| P0 | Confirmed real credential (pattern + context both match), not yet rotated — requires immediate rotation/revoke |
| P1 | Credential pattern matches but rotation status uncertain, or personal information (PII) exposure |
| P2 | Ambiguous (remains UNCERTAIN in discourse) — needs human review |
| P3 | Low-confidence entropy match, likely a test fixture |

verdict: **BLOCK** (P0 CONFIRMED exists) / **WARN** (P1~P2 CONFIRMED or policy FAIL) / **PASS**.
