"""CVE matching.

The analyzer's *independent* vulnerability detector: "does this exact occurrence
match a real CVE?"

Two-tier matching, and the reason for it
----------------------------------------
The supplied ``vulnerability_db.json`` lists ``affected_versions`` as a set of
discrete version strings — not a range. It is not even ordered (``netty-all``
ships ``["4.3.0", "2.8.0"]``). And measured against the shipped data:

- **not one** of the 500 dependency versions appears in its own library's
  affected set — strict version matching detects **zero** CVEs;
- yet the ground truth marks **122** of those dependencies vulnerable, always on
  a library-name match alone.

The dataset is internally inconsistent. A single boolean verdict would have to
choose between crying wolf on every library-name collision (recall 100%, false
positives 63%) and going blind (recall 42%, and the vulnerability half of the
product goes dark). Neither is honest, so we report both and say which is which:

- ``confirmed`` — the version is in the advisory's affected set. Full weight.
- ``potential`` — the library matches, the version is not listed. Reduced
  weight, and rendered as *unconfirmed* everywhere.

The report therefore never *asserts* a vulnerability the advisory does not
support, while still surfacing every occurrence a reviewer needs to look at.

On the project rule "never string-compare versions": it holds, and more strongly
than before. Membership in a discrete set is an exact lookup, not an ordering
comparison — we never ask whether one version is greater than another, so there
is no opportunity to get ``"2.9" > "2.14"`` wrong.
"""

from __future__ import annotations

from typing import Iterable

from sbom_analyzer.models.entities import Dependency, Vulnerability
from sbom_analyzer.models.findings import MatchedVulnerability, VulnConfidence
from sbom_analyzer.scoring.risk import CveScoreInput, vulnerability_component


def version_is_affected(version: str, affected_versions: Iterable[str]) -> bool:
    """True iff ``version`` is one of the advisory's listed affected versions.

    Exact set membership. Deliberately not a range test: the field is a list of
    discrete versions, and treating an unordered 2-element list as ``[min, max]``
    would invent a range the data never claimed.
    """
    return version in set(affected_versions)


class VulnerabilityMatcher:
    """Indexes the CVE database by library name for per-dependency matching."""

    def __init__(self, vulnerabilities: Iterable[Vulnerability]) -> None:
        self._by_library: dict[str, list[Vulnerability]] = {}
        for vuln in vulnerabilities:
            self._by_library.setdefault(vuln.library_name, []).append(vuln)

    def candidates(self, library_name: str) -> list[Vulnerability]:
        """Every advisory filed against this library name (any version)."""
        return self._by_library.get(library_name, [])

    def match(self, dep: Dependency) -> list[MatchedVulnerability]:
        """Every CVE for this library, each tagged confirmed or potential.

        Sorted worst-first (by contribution, then id), so output is deterministic
        and the worst advisory is always ``matched_cves[0]``.
        """
        matched: list[MatchedVulnerability] = []

        for cve in self.candidates(dep.library_name):
            confidence = (
                VulnConfidence.confirmed
                if version_is_affected(dep.version, cve.affected_versions)
                else VulnConfidence.potential
            )
            cve_score = vulnerability_component(
                [
                    CveScoreInput(
                        cvss_score=cve.cvss_score,
                        patch_available=cve.patch_available,
                        exploitability=cve.exploitability.value,
                        confidence=confidence.value,
                    )
                ]
            )
            matched.append(
                MatchedVulnerability(
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    cvss_severity=cve.cvss_severity,
                    affected_versions=list(cve.affected_versions),
                    fixed_version=cve.fixed_version,
                    patch_available=cve.patch_available,
                    exploitability=cve.exploitability,
                    confidence=confidence,
                    description=cve.description,
                    cve_score=cve_score,
                )
            )

        matched.sort(key=lambda m: (-m.cve_score, m.cve_id))
        return matched


def base_vuln_for(matched: Iterable[MatchedVulnerability]) -> float:
    """Worst-CVE-wins — the contribution of the single worst matched advisory."""
    return max((m.cve_score for m in matched), default=0.0)
