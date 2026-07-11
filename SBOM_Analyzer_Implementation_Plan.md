# SBOM Analyzer — End-to-End Implementation Plan

**Challenge:** PB-10 Software Supply Chain Risk Scorer (SBOM Analyzer)
**Architecture:** Hybrid — deterministic graph + scoring core, LLM only for fuzzy reasoning and narratives
**Audience:** Implementation team (junior devs, LLM-assisted coding)
**Status:** Build-ready spec. Follow phases in order. Do not skip Phase 1.

---

## 0. Read This First (Non-Negotiable Rules)

These are the mistakes that will sink this project. Every dev must internalize them before writing code.

1. **The LLM never produces numbers that feed a metric.** Risk scores, severities, vulnerability matches, and transitive paths are all computed deterministically. The LLM only produces: exploitability *judgments* (bounded modifiers), *narratives*, and *remediation text*. If you find yourself asking an LLM "what's the risk score of this library," stop — that's a bug.
2. **The dependency graph is built by parsing, never by an LLM.** The SBOM data is already structured. Building the graph is deterministic. This protects the one metric with **zero tolerance**: transitive resolution at 100%.
3. **Transitive resolution must be exhaustive and deterministic.** Use real graph traversal. Every path from an app to a vulnerable library must be found. This is unit-testable — test it.
4. **Version matching is done with a real version library, not string comparison.** `"2.9" > "2.14"` is `True` as strings and `False` as versions. Use `packaging.specifiers.SpecifierSet`. Never compare version strings with `<`, `>`, or `==` on the raw string.
5. **The data generator is written first and is deterministic (seeded).** All ground truth is embedded by construction. The analyzer's job is to *independently rediscover* what the generator injected. The two must never share code paths — that would make the eval meaningless.
6. **All LLM calls are `temperature=0`, return JSON, and are validated against a Pydantic schema.** An unvalidated LLM response is a crash waiting to happen.
7. **Everything is reproducible.** Same seed → same data. Same data → same analysis. If a re-run gives different numbers, something is non-deterministic and must be fixed.

---

## 1. Target Metrics (What "Done" Means)

The whole build exists to hit these. Wire them into the eval harness (Phase 8) early and watch them.

| Metric | Target | Owner (which layer) |
| --- | --- | --- |
| Vulnerability detection recall | > 85% | Deterministic vuln matcher |
| Transitive resolution | **100%** | Graph traversal |
| License conflict detection | > 90% | License rule engine |
| False positive rate | < 20% | All matchers + LLM FP adjudication |
| Risk score accuracy | within ±10% of ground truth | Scoring formula |

---

## 2. Tech Stack (Fixed — Don't Substitute)

- **Language:** Python 3.11+
- **API:** FastAPI + Uvicorn
- **Data validation:** Pydantic v2
- **Graph:** NetworkX
- **Version handling:** `packaging` (`SpecifierSet`, `Version`)
- **Data wrangling in the generator:** standard library + `random` (seeded). Pandas optional for CSV I/O.
- **Storage:** In-memory during analysis; SQLite only for run history (optional). **Do not stand up Postgres** — the dataset is tiny (10 apps, 500 deps) and a DB adds nothing but setup friction.
- **LLM:** Provider-agnostic client behind one interface. Support OpenAI-compatible and Anthropic. `temperature=0`, JSON mode.
- **Reporting:** Jinja2 → HTML; JSON as the canonical machine-readable output. PDF via `weasyprint` (optional).
- **Frontend (bonus only):** static HTML dashboard + Cytoscape.js for the graph. Not required for core delivery.
- **Testing:** pytest.

> **Rationale for juniors:** we keep the moving parts minimal on purpose. Fewer services = fewer things to misconfigure. The intelligence is in the analysis logic, not the infrastructure.

---

## 3. Project Structure

```
sbom-analyzer/
├── README.md
├── pyproject.toml              # or requirements.txt
├── .env.example                # LLM_PROVIDER, LLM_API_KEY, LLM_MODEL
├── data/                       # generated sample data lands here (gitignored)
├── reports/                    # analysis output lands here (gitignored)
├── src/sbom_analyzer/
│   ├── config.py               # settings from env
│   ├── models/                 # Pydantic schemas (Section 4)
│   │   ├── entities.py         # Application, Dependency, Vulnerability, LicenseRule
│   │   └── findings.py         # DependencyFinding, AppRiskReport, analysis output
│   ├── ingestion/
│   │   └── loaders.py          # load + validate the 5 data files
│   ├── graph/
│   │   ├── builder.py          # build NetworkX graph from dependencies
│   │   └── traversal.py        # path-finding, transitive resolution
│   ├── analysis/
│   │   ├── vulnerabilities.py  # version-range matching against vuln DB
│   │   ├── licenses.py         # license rule engine
│   │   ├── maintenance.py      # staleness check
│   │   └── transitive.py       # inherited-vuln analysis via graph
│   ├── scoring/
│   │   └── risk.py             # the formula (Section 7) — single source of truth
│   ├── llm/
│   │   ├── client.py           # provider abstraction, JSON+schema enforcement
│   │   ├── prompts.py          # prompt templates (Section 8)
│   │   └── reasoners.py        # exploitability, narratives, remediation, FP adjudication
│   ├── reporting/
│   │   ├── report.py           # assemble final report object
│   │   └── html.py             # Jinja2 rendering
│   └── api/
│       └── main.py             # FastAPI app + routers
├── scripts/
│   ├── generate_sample_data.py # Phase 1 — RUN FIRST
│   ├── run_analysis.py         # CLI entrypoint for a full run
│   └── evaluate.py             # eval harness vs ground truth
└── tests/
    ├── test_version_matching.py
    ├── test_graph_traversal.py
    ├── test_licenses.py
    └── test_scoring.py
```

---

## 4. Data Contracts (Schemas)

These schemas are the contract between the generator, the loaders, and the analyzer. **The generator writes exactly these fields; the loaders validate exactly these fields.** If they drift, everything breaks silently.

### 4.1 `applications.json` — 10 records

```json
{
  "app_id": "APP-001",
  "name": "customer-portal",
  "business_criticality": "critical",   // critical | high | medium | low
  "owner": "team-payments",
  "environment": "production",          // production | staging | internal
  "internet_facing": true,
  "distributed": true                   // true = shipped to external parties (matters for GPL)
}
```

### 4.2 `sbom_dependencies.csv` — 500 rows (10 apps × 50 occurrences)

Each row is **one occurrence** of a library inside one app. The same library can appear in many apps and at many depths — each occurrence is its own row with its own `dependency_id`.

| Column | Type | Notes |
| --- | --- | --- |
| `dependency_id` | string | Unique per row, e.g. `DEP-00001`. This is the node key. |
| `app_id` | string | FK to applications. |
| `library_name` | string | e.g. `log4j-core`. |
| `version` | string | PEP 440 / semver-clean, e.g. `2.14.1`. |
| `license` | string | SPDX id (`MIT`, `Apache-2.0`, `GPL-3.0`, `LGPL-2.1`, `BSD-3-Clause`) or `""` for unknown. |
| `dependency_type` | string | `direct` or `transitive`. |
| `parent_dependency_id` | string | `""` for direct; else the `dependency_id` that pulled this one in (the graph edge). |
| `last_updated` | date | ISO `YYYY-MM-DD`. |
| `ecosystem` | string | `npm` \| `pypi` \| `maven`. |
| `usage_signal` | string | Simulated code-usage hint for exploitability: `calls_vulnerable_function` \| `imports_only` \| `not_referenced`. Only meaningful for vulnerable libs; `not_referenced` otherwise. |

> **Graph rule:** within one app, `parent_dependency_id` chains form a tree rooted at the app. Direct deps have the app as implicit parent. This is how transitive chains are encoded — see Section 6.

### 4.3 `vulnerability_db.json` — 200 records (simulated NVD)

```json
{
  "cve_id": "CVE-2021-44228",
  "library_name": "log4j-core",
  "affected_versions": ">=2.0,<2.15.0",   // SpecifierSet string
  "cvss_score": 10.0,                      // 0.0–10.0
  "cvss_severity": "critical",             // critical | high | medium | low
  "patch_available": true,
  "fixed_version": "2.15.0",               // null if no patch
  "vulnerable_function": "JndiLookup.lookup",
  "backported_patch_builds": ["2.14.1-patched"],  // FP trap: versions matching range but actually safe
  "description": "Remote code execution via JNDI lookup..."
}
```

### 4.4 `license_rules.json` — 15 records

```json
{
  "licenses": {
    "MIT":          { "category": "permissive",       "base_risk": "low" },
    "Apache-2.0":   { "category": "permissive",       "base_risk": "low" },
    "BSD-3-Clause": { "category": "permissive",       "base_risk": "low" },
    "LGPL-2.1":     { "category": "copyleft-weak",    "base_risk": "medium" },
    "GPL-3.0":      { "category": "copyleft-strong",  "base_risk": "high" },
    "AGPL-3.0":     { "category": "copyleft-network", "base_risk": "high" },
    "":             { "category": "unknown",          "base_risk": "medium" }
  },
  "compatibility": {
    // resolved outcome keyed by (category, distribution_context)
    // distribution_context is derived from the app: "distributed" if app.distributed else "internal"
    "copyleft-strong":  { "distributed": "conflict", "internal": "review" },
    "copyleft-network": { "distributed": "conflict", "internal": "review" },
    "copyleft-weak":    { "distributed": "review",   "internal": "ok" },
    "permissive":       { "distributed": "ok",       "internal": "ok" },
    "unknown":          { "distributed": "review",   "internal": "review" }
  }
}
```

### 4.5 `dependency_labels.csv` — 500 rows (GROUND TRUTH, generator output only)

The analyzer must **never read this file** except inside the eval harness.

| Column | Type | Notes |
| --- | --- | --- |
| `dependency_id` | string | FK to a dependency occurrence. |
| `is_risk` | bool | Any issue present. |
| `risk_types` | string | Pipe-separated: `vulnerable`, `transitive_vulnerable`, `license_conflict`, `unmaintained`, or `clean`. |
| `severity` | string | `critical` \| `high` \| `medium` \| `low` \| `none` (max across issues). |
| `risk_score` | float | 0–100, computed by the canonical formula (Section 7). Enables the ±10% metric. |
| `explanation` | string | Human-readable why. |

> **We added `risk_score` to the labels** (the brief's label spec only lists status/type/severity/explanation). This is a deliberate extension so the "±10% of ground truth" metric is measurable against a number, not a band. Note it in the README.

---

## 5. Phase 1 — Synthetic Data Generator (BUILD THIS FIRST)

`scripts/generate_sample_data.py`. Deterministic, seeded, writes all five files into `data/`. Everything downstream depends on it, and the eval depends on the ground truth it embeds.

> **AGENT: READ THIS BEFORE WRITING ANY CODE FOR THIS PHASE.**
> This section is the highest-risk part of the project and the part you are most likely to get subtly wrong. The failure mode is: you generate random data, *then* try to figure out which rows are risky. **Do the opposite.** You will decide *in advance* exactly which dependency occurrences carry which issues, inject those issues deterministically, and record the label in the *same step* that injects the issue. Data and labels are produced together, never inferred afterward. If you ever find yourself writing a function like `detect_issues(generated_data)` inside the generator, you have made the mistake — delete it. The generator *knows* the truth because it *created* it.
>
> Follow the numbered plan in 5.3 literally. Do not reorder it. Do not "optimize" it. Each dependency occurrence gets exactly one `issue_plan` assigned up front, and everything else follows from that plan.

### 5.1 Target distributions (match the brief)

Across the 500 dependency occurrences, assign each occurrence a **primary issue class** so the counts land here:

| Primary class | Count (of 500) | Meaning |
| --- | --- | --- |
| `vulnerable` | 90 (18%) | Its own (library, version) matches a CVE. |
| `transitive_vulnerable` | 50 (10%) | Clean itself, but sits on a path to a vulnerable descendant. |
| `license_conflict` | 60 (12%) | Copyleft/unknown license in a distributed app. |
| `unmaintained` | 75 (15%) | `last_updated` > 2 years before `TODAY`. |
| `clean` | 225 (45%) | No issues. |

> These are **primary** classes chosen to make the arithmetic exact and reproducible. A dependency may *additionally* pick up a secondary issue (e.g. a `vulnerable` dep that is also old) — that is allowed and realistic. The `risk_types` label is the full set; `is_risk` is the OR; `severity`/`risk_score` are computed from all issues via Section 7. But the *primary* assignment above is what you use to hit the distribution exactly. Use exact integer counts, not probabilities, so the distribution is deterministic.

### 5.2 Constants (define once, at the top of the file)

```python
SEED       = 42
TODAY      = date(2026, 4, 15)     # frozen "now" — NEVER use datetime.now()
N_APPS     = 10
DEPS_PER_APP = 50                  # => 500 occurrences total
N_LIBRARIES  = 150                 # size of the library universe

# exact primary-class counts (sum == 500)
CLASS_COUNTS = {
    "vulnerable": 90,
    "transitive_vulnerable": 50,
    "license_conflict": 60,
    "unmaintained": 75,
    "clean": 225,
}

ECOSYSTEMS = ["npm", "pypi", "maven"]
PERMISSIVE_LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause"]
```

### 5.3 Generation algorithm — DO THESE STEPS IN THIS EXACT ORDER

**Step 0 — Seed.** First line of `main()`: `random.seed(SEED)`. Every random choice in the whole script goes through this one seeded `random` module. Do not create secondary RNGs, do not call `datetime.now()`, do not use `set()` iteration order for anything that affects output (sets are unordered — sort before iterating).

**Step 1 — Build the library universe.** Create `N_LIBRARIES` library records:
```python
# each: {library_name, ecosystem, versions: [list of 1-3 semver-clean strings], base_license}
# names: mix of realistic ("log4j-core","openssl","lodash","requests","jackson-databind")
#        and synthetic ("lib-0007"). Versions like "1.4.2", "2.14.1" — always PEP 440 parseable.
```
Keep the universe in a dict keyed by `library_name`. This is the pool everything draws from.

**Step 2 — Create 10 applications.** Fixed list, not random, so the demo is legible:
```python
# At least 3 apps with distributed=True (proprietary, shipped externally) -> GPL here = conflict.
# At least 3 apps with distributed=False (internal only)                  -> GPL here = review.
# Spread business_criticality across critical/high/medium/low.
```

**Step 3 — Lay out the dependency SKELETON for each app (structure only, no issues yet).**
For each app, create 50 occurrence "slots" arranged as a valid dependency forest:
```python
for app in apps:
    slots = []
    # 15-20 direct deps (parent = None)
    n_direct = random.randint(15, 20)
    for _ in range(n_direct):
        slots.append(new_slot(app, parent=None, depth=0))
    # fill the rest as transitive children, attaching to an existing shallower slot
    while len(slots) < DEPS_PER_APP:
        parent = random.choice([s for s in slots if s.depth < 3])   # cap depth at 3
        slots.append(new_slot(app, parent=parent, depth=parent.depth + 1))
    assert len(slots) == 50
```
Each slot at this point has: a unique `dependency_id` (`DEP-00001`… global running counter, zero-padded), `app_id`, `parent_dependency_id`, `depth`. **No library, license, version, or issue assigned yet.** Also assign each slot a library+version+ecosystem from the universe now (needed for realism), plus a *default* recent `last_updated` (within the last 12 months) and a *default* permissive license. Issues in later steps will overwrite these defaults.

**Step 4 — Assign primary issue classes to slots (exact counts).**
Flatten all 500 slots into one list, shuffle it (seeded), then slice by `CLASS_COUNTS`:
```python
all_slots = [s for app in apps for s in app.slots]
random.shuffle(all_slots)
cursor = 0
for cls, count in CLASS_COUNTS.items():          # iterate in the fixed dict order above
    for s in all_slots[cursor:cursor+count]:
        s.primary_class = cls
    cursor += count
assert cursor == 500
```
Now every slot has exactly one `primary_class`. **This is the single source of truth for the distribution.**

**Step 5 — INJECT each issue and RECORD its label in the same loop.**
This is the heart of the phase. For every slot, mutate the slot to carry the issue *and* append to a running `labels` list. Injection and labeling are never separated.

```python
labels = {}   # dependency_id -> {risk_types:set, explanation_parts:[]}
cve_records = []   # accumulates vulnerability_db.json entries

for s in all_slots:
    rt = set()
    why = []

    if s.primary_class == "vulnerable":
        make_slot_vulnerable(s, cve_records)      # see 5.4 (a)
        rt.add("vulnerable"); why.append(...)

    elif s.primary_class == "transitive_vulnerable":
        # handled in Step 6 (needs graph context) — mark it, resolve later
        s.needs_transitive_wiring = True

    elif s.primary_class == "license_conflict":
        make_slot_license_conflict(s)             # see 5.4 (b)
        rt.add("license_conflict"); why.append(...)

    elif s.primary_class == "unmaintained":
        make_slot_unmaintained(s)                 # see 5.4 (c)
        rt.add("unmaintained"); why.append(...)

    # clean: leave defaults (recent date, permissive license, non-vulnerable version)

    # OPTIONAL secondary issues for realism (seeded, ~15% chance each, but NEVER on 'clean'):
    if s.primary_class != "clean":
        maybe_add_secondary_unmaintained(s, rt, why)   # may add "unmaintained"

    labels[s.dependency_id] = {"risk_types": rt, "explanation": " ".join(why)}
```

**Step 6 — Wire the transitive-vulnerable chains (needs the tree, do it after Step 5).**
For every slot marked `needs_transitive_wiring`, guarantee a real vulnerable descendant exists beneath it:
```python
for s in slots_with(needs_transitive_wiring):
    # find a descendant slot in the SAME app that is currently clean-ish
    victim = pick_clean_descendant(s)      # a slot below s in the parent-chain
    if victim is None:
        victim = attach_new_child_leaf(s)  # if none exists, create one leaf under s
    make_slot_vulnerable(victim, cve_records)   # the LEAF becomes vulnerable
    labels[victim.dependency_id]["risk_types"].add("vulnerable")
    # s itself stays clean but is now on a path to a vulnerable node:
    labels[s.dependency_id]["risk_types"].add("transitive_vulnerable")
    record_injected_chain(app_root -> ... -> s -> ... -> victim)   # for the verifier (5.5)
```
**Critical:** the intermediate slot `s` must remain non-vulnerable (that's what makes it *transitive*), and the vulnerable node must be a genuine descendant reachable by following `parent_dependency_id` upward from the victim to `s`. Keep an explicit list of every injected chain — the verifier and the eval both consume it.

**Step 7 — Compute labels' numeric fields.** For every slot, run the **canonical scoring rubric (Section 7)** over the slot's now-final facts (its CVEs, license outcome, staleness, and transitive status from the graph) to fill `risk_score` and `severity`. `is_risk = bool(risk_types - {"clean"})`. If `risk_types` is empty, set it to `{"clean"}`, `severity="none"`, `risk_score=0`.

> **AGENT NOTE:** import and call the *same* `score_dependency()` function the analyzer uses (Section 7 / `scoring/risk.py`). Do **not** re-implement the formula here. One formula, two callers. This is the only shared code between generator and analyzer, and it must be the scorer only — never the *detectors*.

**Step 8 — Write all five files** to `data/` using the exact schemas in Section 4. Sort every file by its id column before writing so output is byte-stable. Write `vulnerability_db.json` from the accumulated `cve_records` (dedupe by `cve_id`; pad to ~200 by adding extra CVEs for libraries/versions that no occurrence uses — realistic "noise" the analyzer must correctly ignore).

**Step 9 — Run the self-verifier (5.5) automatically at the end of the script** and hard-fail (`raise`) if any check fails. The generator is not "done" until the verifier passes.

### 5.4 Injection helper specifications

**(a) `make_slot_vulnerable(slot, cve_records)`**
```
- Ensure a CVE exists covering (slot.library_name, slot.version):
    - create/reuse a CVE with affected_versions as a SpecifierSet string that INCLUDES slot.version
      (verify with packaging: Version(slot.version) in SpecifierSet(affected_versions) -> must be True)
    - pick cvss_score from a spread: ~15% critical(9.0-10.0), ~35% high(7.0-8.9),
      ~35% medium(4.0-6.9), ~15% low(0.1-3.9); set cvss_severity to match the band.
    - patch_available: True ~70% of the time, with fixed_version just above the range.
    - vulnerable_function: a plausible symbol name.
- Set slot.usage_signal to one of {calls_vulnerable_function, imports_only, not_referenced}
  (spread them; this drives exploitability in scoring).
- FP TRAP: for at least 2 vulnerable slots total across the whole run, set slot.version to a
  string that is inside affected_versions BUT also add that exact version to the CVE's
  backported_patch_builds. Label these slots 'clean' for the vulnerable dimension (they are FP
  traps — a correct analyzer must NOT flag them). Record them in an injected_fp_traps list.
```

**(b) `make_slot_license_conflict(slot)`**
```
- If slot's app.distributed is True: set slot.license to a strong-copyleft license
  (GPL-3.0 or AGPL-3.0). This is a real conflict.
- Ensure enough conflict slots land in distributed apps to hit the count; if a license_conflict
  slot happens to sit in an internal app, MOVE it (reassign to a distributed app's slot) or
  swap classes — do not emit a 'conflict' label for an internal-only GPL dep, because per the
  rules that's only 'review'. The label must match what a correct analyzer would conclude.
- For a few slots, set license = "" (unknown) instead, and label risk_type accordingly only if
  the resolved outcome per Section 4.4 is 'conflict' or 'review' -> these count as license_conflict
  findings for eval ONLY when outcome == 'conflict'. Keep 'review'/'unknown' out of the strict
  license_conflict count to avoid ambiguous ground truth. (Simplest: make the 60 primary
  license_conflict slots all GPL/AGPL in distributed apps = unambiguous conflicts.)
```

**(c) `make_slot_unmaintained(slot)`**
```
- Set slot.last_updated to a date between 2 and 6 years before TODAY (seeded).
- (age_in_years > 2 is the analyzer's rule, so any of these trips it.)
```

### 5.5 Self-verifier (runs at the end of the generator; hard-fails on any miss)

Write `verify_generated_data()` and call it before the script exits. It re-reads nothing — it checks the in-memory structures and the injected-truth lists:

```
[ ] Row counts EXACT: apps==10, dependency rows==500, labels==500, license rules==15,
    vulnerabilities ~200 (>=180).
[ ] Primary-class counts EXACT per CLASS_COUNTS (90/50/60/75/225).
[ ] Every parent_dependency_id references a real dependency_id IN THE SAME app (no dangling,
    no cross-app edges).
[ ] No cycles: following parent pointers always terminates at a direct dep (parent=None).
[ ] For EVERY injected transitive chain: walking parent pointers from the vulnerable leaf up to
    the intermediate slot succeeds, AND the intermediate slot is itself NON-vulnerable, AND it is
    labeled transitive_vulnerable. (This guards the 100% metric.)
[ ] For EVERY vulnerable slot (except FP traps): Version(version) in SpecifierSet(cve.affected_versions)
    is True. (No "vulnerable" label without a real version match.)
[ ] For EVERY FP-trap slot: version IS in affected_versions AND IS in backported_patch_builds AND the
    slot is NOT labeled vulnerable. (At least 2 exist.)
[ ] For EVERY license_conflict slot: license is strong-copyleft AND the app is distributed=True.
[ ] For EVERY unmaintained label: age_in_years(last_updated, TODAY) > 2.
[ ] Every label's risk_score/severity equals score_dependency() recomputed from the slot's facts
    (i.e., generator and Section-7 scorer agree — they must, since it's the same function).
[ ] Re-running the whole script produces byte-identical files (test by hashing outputs across two runs).
```
If any check fails, `raise AssertionError` with a message naming the specific slot/chain. **A green verifier is the definition of done for Phase 1.**

### 5.6 Why this design (context for the agent, so you don't "simplify" it away)

- **Exact integer counts, not probabilities** → the distribution is reproducible and the eval denominators are known.
- **Inject-and-label-together** → labels are true by construction; they can never disagree with the data.
- **Transitive chains recorded explicitly** → the 100%-transitive metric has a known ground-truth set to score against, and the verifier proves the chains are real *before* any analyzer runs.
- **FP traps are labeled clean** → the false-positive metric has real bait; an analyzer that naively version-matches will be caught.
- **Shared scorer, separate detectors** → the only code the generator and analyzer share is the Section-7 formula. All *detection* (does this version match a CVE? is this license a conflict?) is implemented independently on each side, so the eval measures the analyzer's detection, not a tautology.

---

## 6. Phase 3 — Dependency Graph

`graph/builder.py` and `graph/traversal.py`. (Phase 2 is ingestion — straightforward Pydantic-validated loaders; write those first but they need no special design notes beyond "validate against Section 4 and fail loudly on bad rows.")

### 6.1 Build

- Use a **`networkx.DiGraph`**.
- Nodes: one per dependency occurrence (`dependency_id`), plus one node per application (`app_id`). Store all row fields as node attributes.
- Edges: `app_id → dependency_id` for direct deps; `parent_dependency_id → dependency_id` for transitive. Edge direction = "depends on / pulls in".
- The graph is per-app forests joined at app nodes. Keep it as one graph; filter by app when needed.

### 6.2 Traversal (this is where the 100% metric lives)

Implement and test these:

- `descendants_of(dep_id)` → all transitive deps below a node. Use `networkx.descendants`.
- `paths_to_vulnerable(app_id)` → for each vulnerable dependency reachable from the app, return **every** simple path from the app node to it (`networkx.all_simple_paths`). This is the attack-chain data the report and LLM narrative consume.
- `is_on_path_to_vulnerable(dep_id)` → True if any descendant is vulnerable. Drives the `transitive_vulnerable` classification.

### 6.3 Acceptance criteria

- Unit test with a hand-built fixture graph containing a known `App → A → B → C(vuln)` chain and a diamond (`A→B→D`, `A→C→D`): assert all paths are found, including both arms of the diamond.
- `paths_to_vulnerable` recovers **100%** of the transitive chains the generator injected (cross-check against a generator-emitted debug list of chains).

---

## 7. Phase 5 — Risk Scoring (Single Source of Truth)

`scoring/risk.py`. **This exact formula is implemented once and used by both the analyzer and (conceptually mirrored in) the generator's label computation.** Do not let two versions drift.

### 7.1 Per-dependency risk score (0–100)

```
# --- vulnerability component (worst CVE wins) ---
base_vuln = 0
for each CVE matching (library_name, version) and NOT in backported_patch_builds:
    sev      = cvss_score / 10.0                       # 0.0–1.0
    patch    = 0.6 if patch_available else 1.0          # a patch existing lowers urgency
    exploit  = exploitability_factor(usage_signal)      # see 7.2
    cve_score = sev * patch * exploit * 100
    base_vuln = max(base_vuln, cve_score)

# --- transitive component (inherited, decayed by distance) ---
transitive_vuln = 0
if dep is clean itself but on a path to a vulnerable descendant:
    d = shortest hop-distance to the nearest vulnerable descendant
    transitive_vuln = nearest_descendant_base_vuln * (0.7 ** d)

# --- license component ---
license_penalty = { "conflict": 80, "review": 40, "ok": 0 }[license_outcome]
# license_outcome from compatibility matrix using the dep's app.distributed flag

# --- maintenance component ---
years_stale        = max(0, age_in_years(last_updated, TODAY) - 2)
maintenance_penalty = min(40, years_stale * 15)         # 0, 15, 30, 40 (capped)

# --- combine + clamp ---
dep_risk = clamp(
    max(base_vuln, transitive_vuln)                     # vuln dominates
    + 0.5 * license_penalty
    + 0.5 * maintenance_penalty,
    0, 100)
```

### 7.2 Exploitability factor

```
exploitability_factor(usage_signal):
    calls_vulnerable_function -> 1.0
    imports_only              -> 0.85
    not_referenced            -> 0.7
```
In the deterministic path, read `usage_signal` directly. The **LLM reasoner (Phase 6) may refine this** for ambiguous cases, but it must return one of these three buckets — it cannot invent a continuous multiplier. This keeps the ±10% budget safe.

### 7.3 Severity band (from score)

```
>= 75 -> critical
>= 50 -> high
>= 25 -> medium
>  0  -> low
== 0  -> none
```

### 7.4 Per-application risk score

```
dep_scores = [dep_risk for each dependency in app]
app_raw = 0.5 * max(dep_scores)
        + 0.3 * mean(top_5(dep_scores))
        + 0.2 * min(100, 20 * count(deps with severity in {critical, high}))

criticality_multiplier = { critical:1.2, high:1.1, medium:1.0, low:0.9 }[app.business_criticality]
app_score = clamp(app_raw * criticality_multiplier, 0, 100)
```

### 7.5 Acceptance criteria

- Golden-value unit tests: feed fixed inputs, assert exact expected scores (compute a few by hand first).
- Analyzer's per-dependency `risk_score` is within **±10%** of `dependency_labels.csv` `risk_score` for ≥ 90% of rows (this IS the metric).

---

## 8. Phase 6 — LLM Reasoning Layer

`llm/client.py`, `llm/prompts.py`, `llm/reasoners.py`. The LLM is advisory. Every call: `temperature=0`, JSON output, Pydantic-validated, with a deterministic fallback if the call fails or fails validation.

### 8.1 Client contract

- One `LLMClient.complete_json(system, user, schema)` method. Providers (OpenAI-compatible, Anthropic) behind it, selected by env var.
- On any error or schema-validation failure: log and return the deterministic fallback for that reasoner. **A failed LLM call must never crash the analysis or corrupt a metric.**

### 8.2 Reasoner A — Exploitability adjudication

- **Input:** CVE description, `vulnerable_function`, `usage_signal`, dependency context.
- **Output schema:** `{ "exploitability": "calls_vulnerable_function" | "imports_only" | "not_referenced", "confidence": 0.0-1.0, "reasoning": str }`.
- **Constraint:** output must be one of the three buckets (Section 7.2). Fallback = the raw `usage_signal`.
- **Why LLM:** lets the system reason about mismatches (e.g. signal says `imports_only` but description implies the import path is the exploit). Bounded, so ±10% stays safe.

### 8.3 Reasoner B — False-positive adjudication

- **Input:** the matched CVE, the dependency version, `backported_patch_builds`, `fixed_version`.
- **Output schema:** `{ "is_false_positive": bool, "confidence": 0.0-1.0, "reasoning": str }`.
- **Deterministic pre-check first:** if version ∈ `backported_patch_builds`, it's a FP without asking the LLM. The LLM only handles genuinely ambiguous cases. Fallback = deterministic result.

### 8.4 Reasoner C — Attack-chain narrative (pure Option-A value)

- **Input:** a resolved path from `paths_to_vulnerable` (App → … → vulnerable lib) with the CVE details. **Fully grounded — the LLM is told the exact path, it does not discover anything.**
- **Output schema:** `{ "narrative": str }` — 2–4 sentences explaining the chain in plain language for the security team.
- Low hallucination risk precisely because every fact is supplied.

### 8.5 Reasoner D — Remediation playbook

- **Input:** a finding (vuln/license/maintenance) with `fixed_version`, license outcome, staleness.
- **Output schema:** `{ "steps": [str], "priority": "P1"|"P2"|"P3" }`.
- Grounded in the concrete fix data (e.g. "upgrade log4j-core 2.14.1 → 2.15.0").

### 8.6 Acceptance criteria

- With the LLM disabled (`LLM_PROVIDER=none`), the full pipeline runs to completion using only fallbacks, and all core metrics still pass. **The LLM is enhancement, not dependency.**
- Every reasoner output validates against its schema; malformed responses trigger the fallback path (test with a mocked bad response).

---

## 9. Phase 7 — Reporting & API

### 9.1 Report object

Assemble a single `AnalysisReport` (Pydantic) containing:
- Per-app: `app_score`, severity band, ranked list of dependency findings.
- Per-dependency finding: id, library, version, `risk_score`, severity, `risk_types`, matched CVEs, license outcome, maintenance status, attack paths, LLM narrative, remediation.
- Global: totals per risk type, top-N riskiest dependencies across all apps, dedup note (a shared vulnerable lib is reported per-app but linked by library+version so the team sees the blast radius).

### 9.2 Outputs

- `reports/analysis.json` — canonical machine-readable output (also what the eval reads).
- `reports/report.html` — Jinja2-rendered, with traffic-light severity indicators, sorted by app risk. PDF optional via weasyprint.

### 9.3 API (FastAPI)

- `POST /analyze` → trigger a run over the files in `data/` (or an uploaded set), return a run id. Given the tiny dataset, synchronous is fine; if you add the LLM narratives for all findings it may take a minute — if so, make it a background task with `GET /runs/{id}` for status.
- `GET /runs/{id}/report` → the JSON report.
- `GET /apps/{app_id}` → per-app findings.
- `GET /findings?risk_type=vulnerable` → filtered findings.

---

## 10. Phase 8 — Evaluation Harness

`scripts/evaluate.py`. Reads `reports/analysis.json` and `data/dependency_labels.csv`, prints a scorecard. **Build this as soon as Phase 5 works** so you can measure every subsequent change.

Compute:
- **Vulnerability detection recall** = (correctly flagged `vulnerable` deps) / (labeled `vulnerable` deps). Target > 85%.
- **Transitive resolution** = (found transitive chains) / (labeled transitive chains). Target = 100%.
- **License conflict detection** = recall on `license_conflict` labels. Target > 90%.
- **False positive rate** = (deps flagged as risk that are labeled `clean`) / (all deps flagged). Target < 20%.
- **Risk score accuracy** = share of deps whose computed `risk_score` is within ±10% of the label `risk_score`. Target: ≥ 90% within band.

Print a pass/fail table with color. This scorecard is your demo centerpiece.

---

## 11. Phase 9 — Bonus (Only After Core Metrics Pass)

From the brief's Level-1 items (the higher levels are copy-pasted from a different challenge and don't apply):
- Interactive dependency graph (Cytoscape.js), nodes colored by risk, click to see obligations/CVEs and attack paths.
- Live alert dashboard (static HTML polling the API).
- Remediation playbook export (already produced by Reasoner D — just render it).

---

## 12. Build Order & Rough Effort

| Phase | Deliverable | Effort |
| --- | --- | --- |
| 0 | Scaffold, config, LLM client stub | 2–3h |
| 1 | **Data generator + ground truth** | 6–8h |
| 2 | Ingestion + Pydantic schemas | 2–3h |
| 3 | Graph build + traversal (+ tests) | 4–5h |
| 4 | Deterministic analysis (vuln/license/maintenance/transitive) | 5–7h |
| 5 | Scoring formula (+ golden tests) | 3–4h |
| 6 | LLM reasoners + fallbacks | 4–6h |
| 7 | Reporting + API | 4–5h |
| 8 | Eval harness | 2–3h |
| 9 | Bonus (dashboard/graph viz) | as time allows |

**Core (Phases 0–8): ~32–44 hours.** Matches the Option-A effort band while being lower-risk, because every metric-critical path is deterministic and unit-testable.

---

## 13. Definition of Done (Core)

- `python scripts/generate_sample_data.py` produces all five files, reproducibly.
- `python scripts/run_analysis.py` produces `reports/analysis.json` and `report.html`.
- `python scripts/evaluate.py` prints a scorecard with **all five metrics passing**.
- Pipeline runs end-to-end with `LLM_PROVIDER=none` (fallbacks only) and still passes metrics.
- `pytest` is green, including graph-traversal and scoring golden tests.
