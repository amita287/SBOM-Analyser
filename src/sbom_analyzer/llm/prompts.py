"""Prompt templates for the reasoners.

Every prompt is **fully grounded**: the model is handed the exact facts the
deterministic pipeline already established — the matched CVE, the resolved
dependency path, the version, the fixed version, the licence outcome. It is never
asked to *discover* anything, only to narrate or phrase what it is given. That is
what keeps hallucination out of the report.

Both remaining reasoners produce prose. Neither can move a number.

Note the ``confirmed`` flag threaded through both prompts. When a CVE matched only
on library name — the version is not in the advisory's affected set — the model is
told so explicitly and instructed not to assert the vulnerability. Handing an LLM
a CVE id and a version *without* that caveat is exactly how a report ends up
confidently telling someone to patch something that was never affected.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Reasoner C — attack-chain narrative
# --------------------------------------------------------------------------- #
NARRATIVE_SYSTEM = """\
You explain a resolved software-supply-chain dependency path to an engineer.

The path has ALREADY been resolved by graph traversal, and every hop is given to \
you. Do NOT invent hops, packages, CVEs, or versions, and do not speculate about \
paths that were not supplied — describe only what is listed.

If the finding is marked UNCONFIRMED, the library matches the advisory but this \
specific version is NOT in its affected list. Say so plainly. Do not assert that \
the application is vulnerable; say it needs verification.

Write 2-4 plain sentences: how the application reaches the library, what the flaw \
is, and why it matters here. No headings, no bullet points.

Reply with JSON only.\
"""


def narrative_user(
    *,
    app_name: str,
    path_description: str,
    library_name: str,
    version: str,
    cve_id: str,
    cvss_score: float,
    cvss_severity: str,
    description: str,
    hop_distance: int,
    confirmed: bool,
) -> str:
    status = (
        "CONFIRMED — this version is in the advisory's affected list"
        if confirmed
        else (
            "UNCONFIRMED — the library matches, but this version is NOT in the "
            "advisory's affected list"
        )
    )
    return f"""\
Application: {app_name}

Resolved dependency path (app -> ... -> library), {hop_distance} hop(s):
{path_description}

Library     : {library_name} {version}
CVE         : {cve_id} ({cvss_severity}, CVSS {cvss_score})
Match status: {status}
Description : {description or "(none)"}

Return JSON: {{"narrative": "<2-4 sentences>"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner D — remediation playbook
# --------------------------------------------------------------------------- #
REMEDIATION_SYSTEM = """\
You write a short, concrete remediation playbook for one dependency finding.

Ground every step in the facts supplied — name the real versions and licences. \
Never invent a fixed version that was not given; if there is no patch, say so and \
recommend mitigation (pin, isolate, or replace the library).

If the CVE match is UNCONFIRMED, the FIRST step must be to verify whether the \
advisory actually applies to this version. Do not open with "upgrade".

Priority: P1 = fix now (confirmed, high severity, business-critical application), \
P2 = fix this sprint, P3 = plan it in.

Reply with JSON only.\
"""


def remediation_user(
    *,
    library_name: str,
    version: str,
    app_name: str,
    environment: str,
    criticality: str,
    license_model: str,
    risk_score: float,
    severity: str,
    risk_types: list[str],
    cve_id: str | None,
    fixed_version: str | None,
    license_id: str,
    license_outcome: str,
    is_stale: bool,
    age_years: float,
    confidence: str,
) -> str:
    return f"""\
Finding
  Dependency  : {library_name} {version}
  Application : {app_name} (environment={environment}, criticality={criticality}, \
license_model={license_model})
  Risk score  : {risk_score:.1f} ({severity})
  Risk types  : {", ".join(risk_types) or "none"}

Vulnerability : {cve_id or "(none matched)"}
Match status  : {confidence.upper()}
Fixed version : {fixed_version or "(no patch available)"}
Licence       : {license_id or "(undeclared)"} -> {license_outcome}
Maintenance   : last updated {age_years:.1f} years ago{" (stale)" if is_stale else ""}

Return JSON: {{"steps": ["<step>", "..."], "priority": "P1"|"P2"|"P3"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner B — false-positive adjudication (POTENTIAL matches only)
# --------------------------------------------------------------------------- #
FALSE_POSITIVE_SYSTEM = """\
You adjudicate one ambiguous vulnerability match for a software supply-chain scanner.

The situation: a CVE is filed against a library, and the application uses that \
library — but the specific version in use is NOT in the advisory's affected_versions \
list.

That does NOT automatically make it safe. Advisories commonly enumerate only the \
versions the vendor tested. Backported fixes, distribution rebuilds and vendor patch \
levels routinely fall outside the list while still carrying the flaw. Equally, a \
version far outside the affected line (a different major release, or one predating \
the vulnerable code entirely) is usually genuinely unaffected.

Judge THIS case on the evidence given. Use the affected versions, the fixed version \
and the nature of the flaw described.

Answer true only if you are satisfied this version is genuinely NOT at risk. When the \
evidence does not settle it, answer false and keep the finding — a missed \
vulnerability costs more than a reviewed one.

Reply with JSON only.\
"""


def false_positive_user(
    *,
    library_name: str,
    version: str,
    cve_id: str,
    affected_versions: list[str],
    fixed_version: str | None,
    description: str,
    cvss_score: float,
) -> str:
    return f"""\
Library in use : {library_name} {version}

Advisory       : {cve_id} (CVSS {cvss_score})
Affects        : {", ".join(affected_versions) or "(none listed)"}
Fixed in       : {fixed_version or "(no patch published)"}
Description    : {description or "(none)"}

The version in use is NOT in the affected list. Is it genuinely not at risk?

Return JSON: {{"is_false_positive": <bool>, "confidence": <0.0-1.0>,
               "reasoning": "<one sentence>"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner B (v2) — dependency-level vulnerability assessment
#
# Deliberately tells the model to IGNORE `affected_versions`. That field is the
# broken one: in this dataset not a single dependency version appears in its own
# library's affected list, yet the ground truth marks 176 of them vulnerable. A
# model handed that field would anchor on it and dismiss everything, so the flaw
# is named explicitly and the model is asked to reason from evidence that is not
# corrupted — the description, the component, chronology, CVSS, exploitability.
#
# Batched: one request carries many dependencies. The free-tier key permits a
# couple of dozen requests a day and there are 301 dependencies to judge, so a
# call-per-dependency design simply cannot run. The reasoning contract per
# dependency is unchanged; only the envelope is.
# --------------------------------------------------------------------------- #
VULN_ASSESSMENT_SYSTEM = """\
You are a software vulnerability analyst.

Your task is to determine whether each given dependency version is LIKELY affected \
by the CVEs listed against its library.

Important:
- The affected_versions field may be incorrect or missing.
- Do NOT rely on affected_versions.
- Instead reason from:
    - dependency version
    - CVE description
    - affected component
    - release chronology
    - API changes
    - CVSS
    - exploit information

For each CVE decide: likely affected, unlikely affected, or uncertain.
Then give an overall decision for the dependency.

Be decisive. "possible" is for genuine uncertainty, not for avoiding a judgement.

Return ONLY valid JSON.\
"""


def vuln_assessment_user(items: list[dict]) -> str:
    """One block per dependency: library, version, and every CVE filed on it."""
    blocks = []
    for it in items:
        cves = "\n".join(
            f"    - {c['cve_id']} | CVSS {c['cvss_score']} {c['severity']} | "
            f"exploitability {c['exploitability']} | "
            f"published {c['published_date']} | "
            f"fixed_version {c['fixed_version'] or 'none published'}\n"
            f"      {c['description'] or '(no description)'}"
            for c in it["cves"]
        )
        blocks.append(
            f"""\
- id: {it['dep_id']}
  library: {it['library']}
  version: {it['version']}
  released: {it['last_updated']}
  cves:
{cves}"""
        )

    body = "\n".join(blocks)
    return f"""\
Assess each dependency below.

{body}

Return JSON with one entry per dependency id, exactly:
{{"assessments": [
  {{"dep_id": "<id>",
    "decision": "vulnerable" | "possible" | "not_vulnerable",
    "confidence": <0-100>,
    "reason": "<short explanation>",
    "likely_cves": ["CVE-..."],
    "unlikely_cves": ["CVE-..."]}}
]}}\
"""
