---
audience: internal
public: false
---

# TRUTH-SWEEP

Internal audit record. File:line citations and commit SHAs are the evidence and stay in.

Ranked defect list from five audited areas, each passed through an adversarial refutation. Only
refuter-CONFIRMED findings appear in the ranked list. Weights: use-case 30, safety and custody 25,
craft 20, reproducibility 15, showcase 10.

## Verification coverage

| Area | verifyStatus | Confirmed | Refuted or downgraded |
|---|---|---|---|
| compliance-ledger | verified | 3 | 1 partial |
| writeup | verified | 5 | 0 |
| reproduce | verified | 5 | 1 |
| plugins | verified | 4 | 1 |
| tasklist | verified | 5 | 3 partial |

No area is VERIFY-FAILED, so nothing here carries an `[unverified]` label.

## Ranked defects

**1. FALSE. Custody overclaim in the judge-facing write-up.** `docs/WRITEUP-DRAFT.md:9` and `:346`
say "an audited program, not the LLM, bounds every spend" and "Every spend executes only through the
audited SF cap." `plugins/spl-transfer-build/src/` has zero hits for allowance, delegate, or the
`De1eg…` program id; `transfer.rs:154` makes the payer the transfer authority. The doc's own table
at `:327` gives that plugin "unsigned transfer only" with no cap. Fix: scope both lines to
"delegated spends run under the audited cap; direct transfers are bounded by the human approval
gate," matching `USE-CASES.md:38`. Costs safety and custody, plus use-case (`:9` is the lede).

**2. GAP. Two wasm-gated nonce-authority guards are never compiled by host tests.**
`plugins/oracle-publish/src/lib.rs:113` and `plugins/depin-attest/src/lib.rs:111` both check that the
durable nonce authority equals the session key, both sit under `#[cfg(target_family = "wasm")]`, and
both files hold zero `#[test]`. All 19 and 15 host tests live in `publish.rs` / `attest.rs`, which
never mention `authority`. Fix: move the check into the host-testable pure core, as
`allowance.rs:1079` already does. Costs safety and custody.

**3. GAP. The amount re-derivation guard is shipped and undocumented.** HEAD `3cea5b4` added
both-or-neither `--brl`/`--rate`, `Decimal` + `ROUND_HALF_UP`, and a hard refusal on mismatch in
`skills/solana-pay/scripts/pay_link.py:128-171`, with 30 passing cases in `test_pay_link.py`. Grep of
`docs/WRITEUP-DRAFT.md` for brl, recompute, or re-derive returns zero. The table at `:323` names only
the recipient invariant, which invites the reading that the amount is unchecked. Fix: add one row and
state the guard's limit (catches arithmetic error, not a consistent lie). Costs safety and custody
plus showcase.

**4. GAP. The demo video is unreachable from a fresh clone.** `.demo-assets/cut/demo-roughcut.mp4`
is real (1280x720, 160.854329s, 2,736,463 B) and `.gitignore:86` excludes `.demo-assets/`;
`git ls-files .demo-assets` is empty. `docs/COMPLIANCE-AUDIT.md:17` and
`HANDOFF-POST-COMPACT.md:228` cite it as evidence. Fix: host the video and cite the URL, or track the
cut. Costs showcase and reproducibility.

**5. FALSE. One plugin README states two different measured values for one quantity.**
`plugins/payment-watch/README.md:65` says "495 bytes worst-case PAID and 556";
`:188` says "PAID composes to 367 bytes and NOT_YET to 556." Git history settles it: `9ee745c`
introduced 367, the later `ff88b60` introduced 495, and `docs/BUILD-JOURNAL.md:4831` records the
367 to 495 move. **495 is current; `:188` is the stale line.** The test asserts only
`out.len() < 2000`, so `:68`'s "they cannot drift" is refuted inside the same file. Fix: correct
`:188` to 495, and pin the value in the assert. Costs craft and reproducibility.

**6. GAP. Four committed artifacts are referenced by nothing.** `scripts/whatsapp_posture_guard.sh`
(with its test), `skills/solana-play/scripts/test_pay_link.py`, `scripts/qr_live_server.py`, and
`wit/UPSTREAM_REF` return zero hits across every tracked file, not just docs. The posture guard is a
security control with no doc and no workflow wiring. Fix: name each in QUICKSTART or CI. Costs safety
and custody plus reproducibility.

**7. GAP. CI is about to break on first push.** `scripts/check-repo-paths.py` exits 0 from a clean
`git archive HEAD` extract and exits 1 in the working tree, reporting 79 unresolvable references,
all from the untracked `docs/PROMPT-COMPLIANCE-LEDGER.md`, which cites global rule files absent from
this repo. Committing it turns the gate red. Fix: keep that file gitignored or strip the external
paths. Costs reproducibility.

**8. STALE. Three surfaces give three different test totals.** Measured: 120 `#[test]` in
`crates/solana-core` (89 src + 3 exhaustive + 5 mined + 23 properties). `README.md:102` says
`cargo test --locked  # 120 tests, four suites`; `TESTING.md:24-28` lists four suites summing to 159
(89 + 19 + 41 + 10, three of which are other crates); `docs/WRITEUP-DRAFT.md:50` says "now 89 host
tests." Fix: make the write-up read "89 unit tests, of 120 across four suites," and label the
TESTING list as per-crate. Costs craft and reproducibility.

**9. GAP. CI never builds the host and never compiles the e2e crates.** `e2e-localnet`,
`e2e-track-a`, and `e2e-allowance` appear in no workflow; `host-drift.yml` sets
`ZC_SKIP_HOST_BINARY: "1"`, so "plugins register" is asserted only by wit byte-identity as a proxy.
`check-config-drift.py` and `check-doc-links.py` are deliberately excluded at `ci.yml:86` and `:91`,
so the placeholder URLs stay unguarded. Also measured: `ci` has one successful run on `3cea5b4`;
`proof-check` and `host-drift` have zero runs ever, both being schedule-only. Fix: state the proxy in
the write-up rather than "three CI workflows keep this honest," and add the e2e crates to a build
job. Costs reproducibility.

**10. STALE. Two different upstream pins with no stated relationship.** `wit/UPSTREAM_REF` pins
`e112ce6b…`; `QUICKSTART.md:34` pins `bcf1f25` and asks for a hand-patch; `host-drift.yml:83` reads
the pin out of QUICKSTART and never out of UPSTREAM_REF. Fix: one file owns the pin, or state which
governs what. Costs reproducibility.

**11. GAP. Six of ten flood ceilings are runtime prints, not asserts.** Only
`allowance.rs:1758` (`envelope < 1100`), `transfer.rs:1296` (`< 750`), and `pay.rs:730` (`< 512`)
pin a stated figure. The rest print via `eprintln!("MEASURED worst-case …")` under loose bounds
(`< 2000`, `< 1200`, `< 6500`, `< 600`, `< 400`). Fix: assert the stated number, or say the figures
are printed rather than pinned. Costs craft.

**12. FALSE. One test is credited with an assertion it does not make.**
`plugins/allowance-spend-build/README.md:240-244` attributes both the "~430 byte summary" and the
"<1.1 KB envelope" to `output_is_compact_and_carries_the_summary`. That test asserts `envelope < 1100`
and three content checks, and nothing about summary length. `spl-transfer-build` does assert both.
Fix: add the summary length assert. Costs craft.

**13. STALE. The Kani count and its description disagree.** `docs/WRITEUP-DRAFT.md:205-206` says
"every byte string up to three bytes, all 16,777,216 of them." The harness assumes `len <= 3`, whose
cardinality is 16,843,009; 16,777,216 is the exactly-three-byte count.
`docs/COMPLIANCE-AUDIT.md:28` already phrases it correctly. Fix: one word, "all three-byte inputs."
Costs craft.

**14. STALE. Internal records contradict the filesystem and each other.** Task #85 says "the repo has
NO GIT REMOTE, so CI has never executed once" while `origin` exists and `HEAD == origin/main`, and
task #67 says the opposite. `HANDOFF-POST-COMPACT.md:98` calls #87 unresolved while task #87 is
completed and titled RESOLVED. `docs/PROMPT-COMPLIANCE-LEDGER.md:111-116` attacks a
`COMPLIANCE-AUDIT.md` row for wording that grep shows is not in the file. The ledger's byte sizes for
`BUILD-JOURNAL.md` and `COMPLIANCE-AUDIT.md` drifted twice during this sweep alone. Fix: label byte
sizes as snapshots and reconcile the three task-record contradictions. Costs craft. Not judge-facing:
`docs/COMPLIANCE-AUDIT.md` is gitignored at `.gitignore:38`, and `PROMPT-COMPLIANCE-LEDGER.md` is
untracked.

**15. GAP. A real customer phone number sits in an untracked file.**
`docs/BUILD-JOURNAL.md:1288` carries a `+966 …` number written with spaces. The file is gitignored
(`.gitignore:36`) and untracked, so it does not ship, and the narrower digit-run regex that reported
zero hits was a false negative. Fix: redact the line so no later tracking decision leaks it. Costs
safety and custody, at low severity while the file stays ignored.

## REFUTED, do not resurrect

- **"Repo push pending is false."** The remote exists and HEAD is pushed, but the repo is PRIVATE
  (task #67). `COMPLIANCE-AUDIT.md` S1 says "public push held to final 24h," which is still true, and
  the two `<repo URL, filled at publish>` placeholders (`QUICKSTART.md:11`,
  `docs/WRITEUP-DRAFT.md:510`) cannot honestly be filled yet. Only the task-record wording is stale.
- **Duplicate microworld.** Both `microworld/sanitizer.html` and `sanitizer-microworld/index.html`
  were in HEAD mid-sweep; at the last measurement the working tree was clean, `microworld/` was
  absent from disk, and `git ls-files` returned zero for it. Resolved during the sweep.
- **"The demo v2 file is named in neither doc."** `docs/COMPLIANCE-AUDIT.md:17` names
  `demo-roughcut-v2.mp4`. Only `HANDOFF-POST-COMPACT.md:228` is stale.
- **"TESTING.md item 2 is fully fixed and all four counts match."** The file is at repo root, not
  `docs/`, and its 89 is the unit subset, not a match to the 120 headline. Folded into defect 8.
- **`depin-attest` has no defects.** It carries the same wasm-gated guard as `oracle-publish`. Folded
  into defect 2.
- **`check-repo-paths.py` exits 0.** It exits 0 only from a HEAD extract and 1 in the working tree.
  Folded into defect 7.
- **"Zero Pyth or Hermes calls" is off by one.** The single hit is prose in a comment, not a call.
- **`scripts/check-repo-paths.py` cannot detect duplicates.** True, and it was never a duplicate
  detector.
- **Line-count and path nits in the audit reports themselves** (538 vs 539 lines, `docs/TESTING.md`,
  `plugins/x402-feed-gate`). Errors in the audits, not in the project.

## Not checkable from the filesystem

Repo visibility to a stranger; whether any CI run passed beyond the one recorded success; every
on-chain assertion (the `0x12c` over-cap rejection, feed freshness and sequence, x402 `NonceReused`,
ARM node uptime, `WRITEUP-DRAFT.md:4` "both live on devnet"); the 220,000 differential-fuzz
iterations; the Kani "VERIFICATION SUCCESSFUL" result; whether any Rust test passes, since no
`cargo test` was run in this read-only pass; the true byte values behind 495 and 367; all upstream
GitHub and Pangram rows.
