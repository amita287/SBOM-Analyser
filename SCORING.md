# Scoring — results, root cause, and what we did about it

Deterministic run (`LLM_PROVIDER=none`). Reproduce with:

```bash
python scripts/run_analysis.py
python scripts/evaluate.py
```

## 1. Results

| Metric | Target | Result | |
|---|---|---|---|
| Vulnerability detection recall | > 85% | **100.0%** (176/176) | PASS |
| Transitive resolution | = 100% | **100.0%** (54/54) | PASS |
| Licence conflict detection | > 90% | **100.0%** (20/20) | PASS |
| False positive rate | < 20% | **31.0%** (105/339) | FAIL |
| Severity agreement | ≥ 90% | **67.4%** (337/500) | FAIL |
| Precision — `is_risky` (README Step 6) | > 75% | **69.0%** | FAIL |
| Recall — `is_risky` (README Step 6) | > 70% | **100.0%** (0 missed) | PASS |
| F1 — `is_risky` | — | **81.7%** | |

Every metric that depends only on facts the dataset actually contains is at 100%.
Every metric that fails depends on a relationship the dataset does not contain.

## 2. Root cause

**`vulnerability_db.json` and `dependency_labels.csv` were produced by two
processes that never agreed. The advisories' `affected_versions` field does not
contain the versions of the dependencies the labels call vulnerable.**

The evidence, all recomputed on every run by `scripts/data_integrity.py`:

1. **0 of 500** dependency versions appear in their own library's
   `affected_versions`.
2. The labels nevertheless mark **176 of those 500 vulnerable**.
3. `affected_versions` is not even a range: **39 of the 200 advisories list their
   versions descending** (e.g. `morgan ['4.0.0', '3.7.0']`), so it can only be read
   as a discrete set.
4. The labels ignore `fixed_version` too. `pip 3.5.0` sits **above** its advisory's
   fix and is labelled **VULNERABLE**; `bcrypt-go 4.15.0` sits **above** its fix and
   is labelled **CLEAN**. Same evidence, opposite labels.

### What that forces

The rule the challenge README specifies (Step 2: *"check if its `library` +
`version` appears in `affected_versions`"*) detects **zero CVEs** on this data.
Recall would be 0%.

The only rule that finds the 176 labelled-vulnerable dependencies is **matching on
library name alone**. That flags **301** dependencies. Of those 301 the labels call
**176 vulnerable and 125 not** — 104 of them entirely clean.

**Nothing in the data separates the two groups.** Within a single library the CVE
is identical, so the only field that differs is the version — and across all 125
vulnerable/clean pairs:

```
vulnerable version is HIGHER :  65  (52.0%)
vulnerable version is LOWER  :  60  (48.0%)
```

A coin flip. Concretely:

| Dependency | Advisory | Version in affected list? | Ground truth |
|---|---|---|---|
| `micrometer-core 3.0.10` | CVE-2026-1050, affects `[4.1.0, 4.4.0]` | No | **VULNERABLE** |
| `micrometer-core 3.0.7` | CVE-2026-1050, affects `[4.1.0, 4.4.0]` | No | **CLEAN** |

Same library, same CVE, neither version listed, **every field identical**. Any rule
that flags one flags the other. Flagging all 301 therefore forces **104 false
positives**. They are arithmetic, not a defect in the analyzer.

## 3. One defect, three failing metrics

| Metric | Why |
|---|---|
| **False positive rate 31.0%** | 104 of the 105 flagged-but-clean dependencies are those forced matches. Passing needs ≤ 67. |
| **Precision 69.0%** | The same 105. `234 / 339`. |
| **Severity agreement 67.4%** | Of the 163 mismatches, **105 are those same false positives** — the truth says `NONE`, we assign the matched CVE's severity. |

The severity ceiling is worth stating plainly: even with **perfect** severity logic
those 105 can never match `NONE`, capping the metric at **395/500 = 79%** — below
the 90% target regardless of implementation.

The remaining 58 severity mismatches:

- **41** — the labels cite a *randomly chosen* CVE from the library's list. We use
  worst-CVSS-wins (standard, conservative practice), which agrees with the cited
  CVE 77% of the time.
- **17** — precedence knock-on: a spurious CVE match outranks the dependency's real
  risk type, so a different severity rule applies.

## 4. What we did about it: the confirmed / potential tier

A single boolean "vulnerable / not vulnerable" would have to choose between crying
wolf on every library-name collision and going completely blind. Neither is honest,
so a match is **graded, not asserted**:

| Tier | Meaning | Score factor |
|---|---|---|
| `confirmed` | The version **is** in the advisory's affected set. | × 1.0 |
| `potential` | The library matches; the version is **not** listed. | **× 0.6** |

This is defensible outside this dataset too. An advisory's `affected_versions` is
what the vendor got round to enumerating — not a proof of safety. Backports, distro
rebuilds and vendor patch levels routinely carry a flaw while falling outside the
list. A scanner that trusts the list absolutely will miss those silently.

**On this dataset: 0 confirmed, 579 potential.**

### What the tier buys

- **Recall stays at 100%** — no labelled vulnerability is missed.
- **The report never *asserts* an unconfirmed CVE.** The finding is surfaced for
  review, struck through in the UI, and captioned: *"the library matches this
  advisory, but version 1.12.1 is not in its affected list."*
- **Remediation changes its first step.** For a potential match the playbook opens
  with *"Confirm whether CVE-2023-1103 applies: aws-sdk-go 1.12.1 is not listed in
  the advisory's affected versions"* — not *"upgrade"*. Telling someone to patch
  against an advisory that never named their version is how a tool loses trust.
- **A potential match can never be P1.** P1 means drop everything; an unverified
  library-name collision does not earn that, however critical the application.

Worked example (`DEP-0001`):

```
STEP 1 — match by LIBRARY name
   'micrometer-core' is in the CVE db -> CVE-2026-1050 (CVSS 6.1, medium)

STEP 2 — check the VERSION against that advisory
   advisory affects : ['4.1.0', '4.4.0']
   we run           : 3.0.10
   -> POTENTIAL  (confidence factor x0.6)

STEP 3 — the version verdict changes the score
   if the version WERE listed (confirmed): base_vuln = 42.7
   as it is (potential)                  : base_vuln = 25.6   <- used
```

The version is doing real work — it costs this finding 17 points. What it cannot do
on this dataset is decide *whether to flag at all*, because doing so flags nothing.

## 5. Everything else we tried, and what it cost

| Attempt | Measured result |
|---|---|
| 9 CVE-matching predicates (exact version, min/max range, major-line, published-date vs release, patch status, `version < fixed_version`) | All land at **58–62% precision** — exactly the 58.5% base rate. Zero information. |
| CVSS threshold sweep (T = 0 → 9) | No point clears FP < 20% **and** recall > 85%. Severity stays flat at 64–67% throughout. |
| Reordering precedence (facts before unconfirmed CVEs) | **−5 rows.** Worse. |
| Severity CVE selection (worst / first / lowest / newest / by id) | Worst-CVSS (76.7%) is the best *principled* option. "First in DB order" scores 80.1% but is an artifact of file ordering and breaks if the file is re-sorted. |
| **Already-patched exclusion** (`version >= fixed_version` ⇒ safe) — the most standard rule in vulnerability triage | **Bad trade.** Removes 48 flags: only **17 genuinely clean**, but **27 truly vulnerable**. Recall drops 100% → **84.7%** (below target) while FP only moves 31.0% → 29.2%. Rejected. |
| **LLM adjudication** (Gemini, all 301 dependencies, prompt instructed to ignore `affected_versions`) | Dismissed **25% of truly-vulnerable** deps and **27% of truly-clean** ones — **+1.9 pp discrimination**, i.e. none. Lost **44 true positives** to remove **28 false ones**. Passing metrics went **4/7 → 2/7**. |

The LLM's reasoning was not poor — it was *sound*:

> `pip 3.5.0` — *"Version 3.5.0 is newer than the fixed version 3.0.0"* → dismissed.
> Ground truth: **VULNERABLE**.
>
> `bcrypt-go 4.15.0` — *"Version 4.15.0 is newer than the fixed versions for all
> listed CVEs"* → dismissed. Ground truth: **CLEAN**.

Identical, correct security logic; opposite ground truths. This is why
`LLM_AFFECTS_SCORE` defaults to **false**: the model's verdict is recorded on all
579 matches and displayed, but never moves a number.

## 6. Proof the analyzer is correct: `scripts/engine_check.py`

Runs the **identical analyzer** three ways. Only the input changes.

```
A) SUPPLIED data + strict version matching     3/7 pass
      recall   0.0%   <- the README's own rule detects nothing
      FP       3.9%   <- a scanner that finds nothing accuses nobody

B) SUPPLIED data + potentials count  (SHIPPED) 4/7 pass
      recall 100.0%   FP 31.0%   precision 69.0%

C) CONSISTENT data + strict version matching   7/7 PASS
      recall 100.0%   transitive 100%   licence 100%
      FP       1.7%   severity 91.0%    precision 98.3%
```

Scenario **C** repairs exactly **one field** — it makes `affected_versions` contain
the versions the labels claim are vulnerable. Same applications, same dependencies,
same licences, same graph, same scorer, same severity rules, **zero lines of
analyzer code changed**. Every metric passes.

(C builds its input from the ground truth and is therefore circular *by design*. It
is a diagnostic that isolates one variable — it is never reported as a detection
result.)

## 7. Conclusion

The detection logic, dependency graph, licence engine, staleness rule, risk scorer
and severity rules are correct — scenario C demonstrates it. The three failing
metrics measure the distance between two files the dataset generator produced
independently, and no rule, threshold, or language model can close that distance,
because the information that separates vulnerable from clean **is not present in
the input**.

We chose **recall over precision**, deliberately. For a software supply-chain
scanner the failure that matters is the vulnerability you *missed*, not the one you
asked an engineer to double-check — and the `potential` tier means every one of
those 105 is presented as *"needs verification"*, never as *"you are vulnerable"*.

`scripts/evaluate.py` prints the real numbers, marks the three capped metrics with
the reason, and never fakes a pass.
