"""Version-range vulnerability matching (Phase 4).

The analyzer's *independent* vulnerability detector. It answers "does this exact
occurrence match a real CVE?" with the same rule the generator used to build the
ground truth, but implemented separately here — so the eval measures detection,
not a shared shortcut.

Two hard rules (Section 4 / brief item 4):

- **Ranges are matched with ``packaging``**, never raw-string comparison.
  ``"2.9" > "2.14"`` is ``True`` as strings and ``False`` as versions; only
  ``Version(...) in SpecifierSet(...)`` gets this right.
- **``backported_patch_builds`` are false-positive traps.** A build can be
  *inside* the affected range yet actually patched. Those exact build strings
  are excluded — a naive matcher that skips this check is caught by the FP-rate
  metric.
"""

from __future__ import annotations

from typing import Iterable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sbom_analyzer.models.entities import Dependency, Vulnerability
from sbom_analyzer.models.findings import MatchedVulnerability
from sbom_analyzer.scoring.risk import CveScoreInput, vulnerability_component


# --------------------------------------------------------------------------- #
# Primitive matchers (the two things the brief insists on)
# --------------------------------------------------------------------------- #
def version_matches(version: str, affected_versions: str) -> bool:
    """True iff ``version`` falls inside the CVE's SpecifierSet range.

    Uses ``packaging`` exclusively. Unparseable version *or* specifier is treated
    as "no match" (never a crash), mirroring the generator's detector.
    """
    try:
        return Version(version) in SpecifierSet(affected_versions)
    except (InvalidVersion, InvalidSpecifier):
        return False


def is_backported_safe(version: str, backported_patch_builds: Iterable[str]) -> bool:
    """True iff ``version`` is an explicitly patched/safe build (an FP trap).

    Exact membership of the listed build strings — *not* a range test. A version
    can be in-range yet safe because the fix was backported into that build.
    Membership is a set lookup, not an ordering comparison, so the
    never-string-compare rule still holds.
    """
    return version in set(backported_patch_builds)


# --------------------------------------------------------------------------- #
# Matcher — index once, match many
# --------------------------------------------------------------------------- #
class VulnerabilityMatcher:
    """Indexes the CVE database by ``library_name`` for per-dependency matching."""

    def __init__(self, vulnerabilities: Iterable[Vulnerability]) -> None:
        self._by_library: dict[str, list[Vulnerability]] = {}
        for vuln in vulnerabilities:
            self._by_library.setdefault(vuln.library_name, []).append(vuln)

    def candidates(self, library_name: str) -> list[Vulnerability]:
        """Every CVE advisory filed against this library name (any version)."""
        return self._by_library.get(library_name, [])

    def match(self, dep: Dependency) -> list[MatchedVulnerability]:
        """All CVEs whose range covers ``dep.version``.

        Backported/safe builds are still returned but flagged
        ``is_false_positive=True`` with ``cve_score=0`` — the report and LLM
        Reasoner B want to see the near-miss; only real hits feed the score.
        Sorted worst-first for deterministic output.
        """
        matched: list[MatchedVulnerability] = []
        for cve in self.candidates(dep.library_name):
            if not version_matches(dep.version, cve.affected_versions):
                continue
            fp = is_backported_safe(dep.version, cve.backported_patch_builds)
            cve_score = (
                0.0
                if fp
                else vulnerability_component(
                    [CveScoreInput(cve.cvss_score, cve.patch_available)],
                    dep.usage_signal,
                )
            )
            matched.append(
                MatchedVulnerability(
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    cvss_severity=cve.cvss_severity,
                    affected_versions=cve.affected_versions,
                    patch_available=cve.patch_available,
                    fixed_version=cve.fixed_version,
                    vulnerable_function=cve.vulnerable_function,
                    is_false_positive=fp,
                    exploitability=dep.usage_signal,
                    cve_score=cve_score,
                )
            )
        matched.sort(key=lambda m: (-m.cve_score, m.cve_id))
        return matched


# --------------------------------------------------------------------------- #
# Convenience reductions over a match list
# --------------------------------------------------------------------------- #
def real_hits(matched: Iterable[MatchedVulnerability]) -> list[MatchedVulnerability]:
    """Matched CVEs that are genuine (backported FP traps removed)."""
    return [m for m in matched if not m.is_false_positive]


def is_vulnerable(matched: Iterable[MatchedVulnerability]) -> bool:
    """True iff at least one real (non-FP) CVE matched."""
    return any(not m.is_false_positive for m in matched)


def base_vuln_score(matched: Iterable[MatchedVulnerability]) -> float:
    """``base_vuln`` for the dependency — worst real CVE wins (Section 7.1)."""
    return max((m.cve_score for m in matched if not m.is_false_positive), default=0.0)
