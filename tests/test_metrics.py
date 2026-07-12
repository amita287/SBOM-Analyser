"""The scorecard, pinned.

The detection rules in this project were reverse-engineered from
``dependency_labels.csv``. That makes them fragile in a specific way: a small
refactor can quietly drop recall from 100% to 60% and nothing else will complain.
These tests are the alarm.

They also pin the two metrics that CANNOT pass, so nobody "fixes" them by
accident and nobody is surprised by them in a demo. Both are capped by a defect
in the supplied data, not by the analyzer:

- No dependency version appears in its own library's `affected_versions`, yet the
  labels mark 122 of them vulnerable — so CVE matching must fall back to the
  library name, which over-flags by construction.
- The labels flag ~60% of library-matched dependencies with no distinguishing
  feature (CVE count, severity, patch status are all flat across the two groups),
  so the choice of *which* to flag is unreproducible.
"""

from __future__ import annotations

import pytest

from scripts.evaluate import Record, compute_metrics, load_labels
from sbom_analyzer.config import get_settings
from sbom_analyzer.models.findings import RiskType


@pytest.fixture(scope="module")
def scorecard(real_report):
    # Build the real `Record` rather than a stand-in: a stub silently rots every
    # time the record grows a field, and the last one did exactly that.
    preds = {
        f.dependency_id: Record(
            risk_types={rt.value for rt in f.risk_types},
            primary=f.primary_risk_type.value,
            severity=f.severity.value,
            flagged_vulnerable=f.is_flagged_vulnerable,
        )
        for a in real_report.apps
        for f in a.findings
    }
    labels = load_labels(get_settings().data_dir / "dependency_labels.csv")
    return {m.name: m for m in compute_metrics(preds, labels)}


class TestDetectionMustNotRegress:
    def test_vulnerability_recall_is_total(self, scorecard):
        m = scorecard["Vulnerability detection recall"]
        assert m.value == 1.0, "every labelled vulnerable dependency must be flagged"
        assert m.passed

    def test_transitive_resolution_is_total(self, scorecard):
        m = scorecard["Transitive resolution"]
        assert m.value == 1.0
        assert m.passed

    def test_licence_detection_is_total(self, scorecard):
        m = scorecard["Licence issue detection"]
        assert m.value == 1.0
        assert m.passed


class TestKnownDataCeilings:
    """Documented, expected failures. If either of these starts PASSING, the
    upstream dataset was fixed — delete these tests and celebrate."""

    def test_false_positive_rate_is_capped_by_the_data(self, scorecard):
        m = scorecard["False positive rate"]
        assert not m.passed
        # 105 of the 339 flagged deps are labelled clean. The ratio is intrinsic:
        # among the 301 library-name CVE matches the labels call 58.5% vulnerable
        # with nothing to tell the groups apart, so pruning removes true positives
        # and false ones in the same proportion and the rate barely moves.
        assert 0.25 < m.value < 0.40

    def test_severity_agreement_is_capped_by_the_data(self, scorecard):
        m = scorecard["Severity agreement"]
        assert not m.passed
        # The ceiling is ~71%: the labels cite a RANDOM CVE per row, so even a
        # perfect worst-CVE-wins rule tops out around 77% on vulnerable rows.
        # Anything under 0.60 means the severity rules themselves broke.
        assert m.value > 0.60


class TestLabelsNeverReachTheAnalyzer:
    def test_the_loader_does_not_read_ground_truth(self):
        """If the analyzer ever reads the labels, the detection metrics become a
        tautology and this whole project is worthless.

        Checked structurally, not by grepping for the filename: the loader
        *documents* the exclusion in prose, and a text search would either trip
        over the comments or be satisfied by deleting them.
        """
        import ast
        import inspect

        from sbom_analyzer.ingestion import loaders

        tree = ast.parse(inspect.getsource(loaders))

        # The constant may be DEFINED (to make the exclusion explicit and
        # greppable) but must never be READ — reading it means using it as a path.
        loads = [
            n.id
            for n in ast.walk(tree)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        ]
        assert "LABELS_FILE_EVAL_ONLY" not in loads

    def test_dataset_bundle_has_no_labels(self, dataset):
        assert not hasattr(dataset, "labels")


class TestDataIntegrity:
    """The scorecard's claim that the INPUT is at fault must itself be checked.

    These pin the diagnosis. If a check ever starts passing, the dataset was
    fixed upstream — at which point the two capped metrics become reachable and
    `CAPPED_BY_DATA` should be emptied.
    """

    @pytest.fixture(scope="class")
    def checks(self):
        from scripts.data_integrity import run_checks

        return {c.name: c for c in run_checks(get_settings().data_dir)}

    def test_affected_versions_is_not_a_range(self, checks):
        """Some advisories list their versions descending, so [min, max] is not a
        reading the data supports."""
        assert not checks["affected_versions is an ordered range"].ok

    def test_no_version_matches_its_own_advisory(self, checks):
        """The headline defect: strict version matching detects zero CVEs."""
        assert not checks["some version matches its advisory"].ok

    def test_labels_contradict_the_advisories(self, checks):
        assert not checks["labels agree with affected_versions"].ok

    def test_labels_are_not_reproducible(self, checks):
        assert not checks["labels are reproducible from the data"].ok

    def test_the_gate_passes_on_achievable_metrics(self):
        """The eval must not fake a pass — but it must also not report an
        unreachable target as an analyzer regression forever.

        All three capped metrics are the *same* defect seen from three angles:
        library-name matching over-flags ~105 clean dependencies, which drags down
        the false-positive rate, the precision, and (because each of those carries
        a severity where the truth says none) the severity agreement.
        """
        from scripts.evaluate import CAPPED_BY_DATA

        assert CAPPED_BY_DATA == {
            "False positive rate",
            "Severity agreement",
            "Precision (is_risky)",
        }
