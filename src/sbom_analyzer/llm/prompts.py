"""Prompt templates for the four reasoners (Phase 6, Section 8).

Every prompt is **fully grounded**: the model is handed the exact facts the
deterministic pipeline already established — the matched CVE, the resolved
attack path, the version, the fixed version, the license outcome. It is never
asked to *discover* anything, only to judge or narrate what it is given. That is
what keeps hallucination risk near zero and keeps the LLM out of the metric path.

Each builder returns the user prompt; the paired system prompt is the module
constant above it.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Reasoner A — exploitability adjudication (Section 8.2)
# --------------------------------------------------------------------------- #
EXPLOITABILITY_SYSTEM = """\
You are an application-security analyst adjudicating how *exploitable* a known \
vulnerable dependency is inside one specific application.

You must answer with exactly one of three buckets — no others exist:
  "calls_vulnerable_function" — the app reaches the vulnerable code path.
  "imports_only"              — the library is imported, but the vulnerable function is not called.
  "not_referenced"            — the library ships but is not referenced in code.

A static usage signal is supplied. Trust it unless the CVE description clearly \
contradicts it — for example, the signal says "imports_only" but the flaw triggers \
at import or deserialisation time, which means the import path *is* the exploit. \
Only override on clear evidence; when in doubt, keep the given signal.

Reply with JSON only.\
"""


def exploitability_user(
    *,
    library_name: str,
    version: str,
    app_name: str,
    environment: str,
    internet_facing: bool,
    usage_signal: str,
    cve_id: str,
    cvss_score: float,
    vulnerable_function: str,
    description: str,
) -> str:
    return f"""\
Dependency : {library_name} {version}
Application: {app_name} (environment={environment}, internet_facing={internet_facing})
Static usage signal (from the SBOM): {usage_signal}

Matched vulnerability
  CVE                : {cve_id}
  CVSS               : {cvss_score}
  Vulnerable function: {vulnerable_function or "(not specified)"}
  Description        : {description or "(none)"}

Return JSON: {{"exploitability": "<one of the three buckets>", "confidence": <0.0-1.0>, "reasoning": "<one or two sentences>"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner B — false-positive adjudication (Section 8.3)
# --------------------------------------------------------------------------- #
FALSE_POSITIVE_SYSTEM = """\
You are adjudicating whether a version-range CVE match is a genuine hit or a \
false positive.

A match can be a false positive even though the version sits inside the affected \
range — most often because the fix was backported into that exact build, or the \
version is at or after the fixed version and the published range is simply stale.

The obvious case (the version is explicitly listed as a backported patched build) \
has ALREADY been decided deterministically before you were called; you only see \
genuinely ambiguous ones. Default to "not a false positive" unless the evidence is \
clear — wrongly dismissing a real vulnerability is far more costly than keeping a \
borderline finding.

Reply with JSON only.\
"""


def false_positive_user(
    *,
    library_name: str,
    version: str,
    cve_id: str,
    affected_versions: str,
    fixed_version: str | None,
    backported_patch_builds: list[str],
    description: str,
) -> str:
    return f"""\
Dependency : {library_name} {version}

CVE                    : {cve_id}
Affected range         : {affected_versions}
Fixed version          : {fixed_version or "(no patch published)"}
Backported safe builds : {backported_patch_builds or "(none listed)"}
Description            : {description or "(none)"}

The installed version IS inside the affected range and is NOT one of the listed \
backported builds. Is this nevertheless a false positive?

Return JSON: {{"is_false_positive": <true|false>, "confidence": <0.0-1.0>, "reasoning": "<one or two sentences>"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner C — attack-chain narrative (Section 8.4)
# --------------------------------------------------------------------------- #
NARRATIVE_SYSTEM = """\
You explain a resolved software-supply-chain attack path to an engineer.

The path has ALREADY been resolved by graph traversal, and every hop is given to \
you. Do NOT invent hops, packages, CVEs, or versions, and do not speculate about \
paths that were not supplied — describe only what is listed.

Write 2-4 plain sentences: how the application reaches the vulnerable library, what \
the flaw is, and why it matters here. No headings, no bullet points.

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
) -> str:
    return f"""\
Application: {app_name}

Resolved dependency path (app -> ... -> vulnerable library), {hop_distance} hop(s):
{path_description}

Vulnerable library: {library_name} {version}
CVE               : {cve_id} ({cvss_severity}, CVSS {cvss_score})
Description       : {description or "(none)"}

Return JSON: {{"narrative": "<2-4 sentences>"}}\
"""


# --------------------------------------------------------------------------- #
# Reasoner D — remediation playbook (Section 8.5)
# --------------------------------------------------------------------------- #
REMEDIATION_SYSTEM = """\
You write a short, concrete remediation playbook for one dependency finding.

Ground every step in the facts supplied — name the real versions and licenses. Never \
invent a fixed version that was not given; if there is no patch, say so and recommend \
mitigation (pin, isolate, or replace the library).

Priority: P1 = fix now (exploitable, high severity, production or internet-facing), \
P2 = fix this sprint, P3 = plan it in.

Reply with JSON only.\
"""


def remediation_user(
    *,
    library_name: str,
    version: str,
    app_name: str,
    environment: str,
    internet_facing: bool,
    risk_score: float,
    severity: str,
    risk_types: list[str],
    cve_id: str | None,
    fixed_version: str | None,
    license_id: str,
    license_outcome: str,
    is_stale: bool,
    age_years: float,
) -> str:
    return f"""\
Finding
  Dependency  : {library_name} {version}
  Application : {app_name} (environment={environment}, internet_facing={internet_facing})
  Risk score  : {risk_score:.1f} ({severity})
  Risk types  : {", ".join(risk_types) or "clean"}

Vulnerability : {cve_id or "(none matched)"}
Fixed version : {fixed_version or "(no patch available)"}
License       : {license_id or "(unknown)"} -> {license_outcome}
Maintenance   : last updated {age_years:.1f} years ago{" (stale)" if is_stale else ""}

Return JSON: {{"steps": ["<step>", "..."], "priority": "P1"|"P2"|"P3"}}\
"""
