"""Phase 1 — synthetic SBOM data generator (Section 5). RUN FIRST.

Deterministic and seeded. Writes the five data files into ``data/`` with ground
truth injected *and labeled together* — the generator KNOWS the truth because it
CREATES it. There is deliberately no ``detect_issues()`` anywhere in here.

The ONLY code shared with the analyzer is ``scoring.risk.score_dependency`` (the
formula). Every *detector* here (version matching, license resolution, nearest
vulnerable descendant) is implemented independently, so the eval measures the
analyzer's detection rather than a tautology.

Design choices that keep Section 5's invariants exact:

* **Disjoint library pools.** Non-vulnerable slots draw from a "safe" pool; only
  vulnerability injection draws from a "vulnerable" pool. No CVE references a
  safe-pool library, so a slot that should be clean can never accidentally match
  a CVE. Labels stay true by construction.
* **Class-swap rebalancing.** Section 5.4b/5.6 allow *moving/swapping* a class so
  license conflicts land in distributed apps, and Step 6 permits attaching a leaf
  only "if none exists". Because the verifier demands EXACTLY 500 rows, we instead
  guarantee reuse works by swapping primary classes (which preserves the exact
  90/50/60/75/225 counts) so that every transitive intermediate is a non-leaf and
  every license conflict sits in a distributed app. ``attach_new_child_leaf`` is
  therefore never needed.
"""

from __future__ import annotations

import csv
import json
import random
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    DependencyScore,
    age_in_years,
    score_dependency,
    vulnerability_component,
)

# --------------------------------------------------------------------------- #
# 5.2 Constants (define once)
# --------------------------------------------------------------------------- #
SEED = 42
TODAY = date(2026, 4, 15)  # frozen "now" — NEVER datetime.now()
N_APPS = 10
DEPS_PER_APP = 50  # => 500 occurrences total
N_LIBRARIES = 150  # size of the library universe

CLASS_COUNTS = {
    "vulnerable": 90,
    "transitive_vulnerable": 50,
    "license_conflict": 60,
    "unmaintained": 75,
    "clean": 225,
}

ECOSYSTEMS = ["npm", "pypi", "maven"]
PERMISSIVE_LICENSES = ["MIT", "Apache-2.0", "BSD-3-Clause"]

# --- generator-internal knobs -------------------------------------------------
N_VULN_LIBS = 45  # vulnerable-capable pool
N_SAFE_LIBS = N_LIBRARIES - N_VULN_LIBS  # 105 safe pool
N_VULNERABILITIES = 200  # pad vulnerability_db.json to here with noise
N_FP_TRAPS = 3  # >= 2 required by the brief
USAGE_SIGNALS = ["calls_vulnerable_function", "imports_only", "not_referenced"]
STRONG_COPYLEFT = ["GPL-3.0", "AGPL-3.0"]

CVSS_BANDS = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
}
CVSS_BAND_NAMES = ["critical", "high", "medium", "low"]
CVSS_BAND_WEIGHTS = [15, 35, 35, 15]

VULN_FUNC_POOL = [
    "deserialize", "parseObject", "lookup", "loadClass", "render",
    "evaluate", "readValue", "decompress", "execCommand", "resolveEntity",
]

# Realistic names lend legibility; the rest are synthetic.
REALISTIC_VULN_NAMES = [
    "log4j-core", "openssl", "lodash", "jackson-databind", "commons-collections",
    "struts2-core", "spring-core", "netty", "bouncycastle", "xstream",
    "fastjson", "shiro", "dom4j", "snakeyaml", "protobuf-java",
    "tomcat-embed-core", "jetty-server", "httpclient", "zlib", "libxml2",
]
REALISTIC_SAFE_NAMES = [
    "requests", "numpy", "pandas", "flask", "django", "react", "express",
    "axios", "moment", "chalk", "typescript", "webpack", "eslint", "jest",
    "sqlalchemy", "pillow", "scipy", "boto3", "urllib3", "certifi", "six",
    "pyyaml", "click", "werkzeug", "cryptography", "redis", "psycopg2",
    "lxml", "markupsafe", "pytz",
]

# --------------------------------------------------------------------------- #
# License rules (Section 4.4). This IS the generator's independent license
# detector; the analyzer reads the JSON we emit and must reach the same verdicts.
# --------------------------------------------------------------------------- #
LICENSE_DEFINITIONS = {
    "MIT": ("permissive", "low"),
    "Apache-2.0": ("permissive", "low"),
    "BSD-3-Clause": ("permissive", "low"),
    "ISC": ("permissive", "low"),
    "MPL-2.0": ("copyleft-weak", "medium"),
    "LGPL-2.1": ("copyleft-weak", "medium"),
    "GPL-2.0": ("copyleft-strong", "high"),
    "GPL-3.0": ("copyleft-strong", "high"),
    "AGPL-3.0": ("copyleft-network", "high"),
    "": ("unknown", "medium"),
}
COMPAT_DEFINITIONS = {
    "copyleft-strong": ("conflict", "review"),
    "copyleft-network": ("conflict", "review"),
    "copyleft-weak": ("review", "ok"),
    "permissive": ("ok", "ok"),
    "unknown": ("review", "review"),
}
_LICENSE_CATEGORY = {name: cat for name, (cat, _risk) in LICENSE_DEFINITIONS.items()}


def resolve_license(license_id: str, distributed: bool) -> str:
    """Independent license detector: (license, distribution) -> outcome."""
    category = _LICENSE_CATEGORY.get(license_id, "unknown")
    dist_out, int_out = COMPAT_DEFINITIONS[category]
    return dist_out if distributed else int_out


# 10 applications (fixed, legible). >=3 distributed, >=3 internal; criticality
# spread across all four levels; distributed apps hold ample room for 60 conflicts.
APP_DEFINITIONS = [
    # app_id, name, criticality, owner, environment, internet_facing, distributed
    ("APP-001", "customer-portal", "critical", "team-payments", "production", True, True),
    ("APP-002", "billing-service", "critical", "team-billing", "production", True, False),
    ("APP-003", "mobile-backend", "high", "team-mobile", "production", True, True),
    ("APP-004", "internal-dashboard", "medium", "team-ops", "internal", False, False),
    ("APP-005", "partner-api", "high", "team-integrations", "production", True, True),
    ("APP-006", "data-pipeline", "medium", "team-data", "staging", False, False),
    ("APP-007", "marketing-site", "low", "team-web", "production", True, True),
    ("APP-008", "admin-tools", "medium", "team-ops", "internal", False, False),
    ("APP-009", "auth-service", "critical", "team-security", "production", True, False),
    ("APP-010", "analytics-engine", "low", "team-data", "production", False, True),
]

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


# --------------------------------------------------------------------------- #
# Value objects
# --------------------------------------------------------------------------- #
@dataclass
class SafeLib:
    name: str
    ecosystem: str
    versions: list[str]
    base_license: str


@dataclass
class VulnLib:
    name: str
    ecosystem: str
    vuln_version: str
    fp_version: str
    affected_versions: str
    fixed_version: str | None
    cvss_score: float
    cvss_severity: str
    patch_available: bool
    vulnerable_function: str
    cve_id: str
    description: str


@dataclass
class App:
    app_id: str
    name: str
    business_criticality: str
    owner: str
    environment: str
    internet_facing: bool
    distributed: bool
    slots: list["Slot"] = field(default_factory=list)


@dataclass
class Slot:
    dependency_id: str
    app_id: str
    depth: int
    parent_dependency_id: str
    dependency_type: str
    library_name: str
    ecosystem: str
    version: str
    license: str
    last_updated: date
    usage_signal: str = "not_referenced"
    # assignment / injection state
    primary_class: str = ""
    needs_transitive_wiring: bool = False
    is_vulnerable: bool = False  # genuinely vulnerable (not FP trap)
    is_fp_trap: bool = False
    risk_types: set = field(default_factory=set)
    explanation_parts: list = field(default_factory=list)
    # finalized label fields
    is_risk: bool = False
    severity: str = "none"
    risk_score: float = 0.0
    # scratch (computed during finalize)
    _matched: dict | None = None
    _base_vuln: float = 0.0
    _nearest_base: float = 0.0
    _nearest_hop: int = 0
    _license_outcome: str = "ok"
    _score: DependencyScore | None = None


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #
class SBOMGenerator:
    def __init__(self) -> None:
        self.safe_libs: list[SafeLib] = []
        self.vuln_libs: list[VulnLib] = []
        self.apps: list[App] = []
        self.all_slots: list[Slot] = []
        self.slot_by_id: dict[str, Slot] = {}
        self.app_by_id: dict[str, App] = {}
        self.children_map: dict[str, list[str]] = {}
        self.cve_by_library: dict[str, dict] = {}
        self.cve_records: list[dict] = []
        self.used_victims: set[str] = set()
        self.fp_trap_ids: set[str] = set()
        self.injected_chains: list[dict] = []
        self.injected_fp_traps: list[dict] = []
        self._dep_counter = 0

    # ---- Step 1: library universe ----------------------------------------- #
    def build_universe(self) -> None:
        for i in range(N_VULN_LIBS):
            name = REALISTIC_VULN_NAMES[i] if i < len(REALISTIC_VULN_NAMES) else f"vuln-lib-{i:04d}"
            ecosystem = random.choice(ECOSYSTEMS)
            maj = random.randint(1, 3)
            minr = random.randint(0, 8)
            vuln_version = f"{maj}.{minr}.1"
            fp_version = f"{maj}.{minr}.0"
            affected = f">={maj}.0.0,<{maj}.{minr + 1}.0"
            band = random.choices(CVSS_BAND_NAMES, weights=CVSS_BAND_WEIGHTS, k=1)[0]
            lo, hi = CVSS_BANDS[band]
            cvss = round(random.uniform(lo, hi), 1)
            patch = random.random() < 0.7
            fixed = f"{maj}.{minr + 1}.0" if patch else None
            vfunc = f"{_symbol_prefix(name)}.{random.choice(VULN_FUNC_POOL)}"
            year = random.randint(2018, 2024)
            cve_id = f"CVE-{year}-{44000 + i}"
            desc = (
                f"A vulnerability in {name} allows an attacker to trigger unsafe "
                f"behavior via {vfunc}. Affected: {affected}."
            )
            self.vuln_libs.append(
                VulnLib(name, ecosystem, vuln_version, fp_version, affected, fixed,
                        cvss, band, patch, vfunc, cve_id, desc)
            )

        for i in range(N_SAFE_LIBS):
            name = REALISTIC_SAFE_NAMES[i] if i < len(REALISTIC_SAFE_NAMES) else f"lib-{i:04d}"
            ecosystem = random.choice(ECOSYSTEMS)
            n_versions = random.randint(1, 3)
            versions = [
                f"{random.randint(0, 4)}.{random.randint(0, 9)}.{random.randint(0, 9)}"
                for _ in range(n_versions)
            ]
            base_license = random.choice(PERMISSIVE_LICENSES)
            self.safe_libs.append(SafeLib(name, ecosystem, versions, base_license))

    # ---- Step 2: applications --------------------------------------------- #
    def build_apps(self) -> None:
        for app_id, name, crit, owner, env, facing, dist in APP_DEFINITIONS:
            app = App(app_id, name, crit, owner, env, facing, dist)
            self.apps.append(app)
            self.app_by_id[app_id] = app

    # ---- Step 3: dependency skeleton -------------------------------------- #
    def _new_slot(self, app: App, parent: Slot | None, depth: int) -> Slot:
        self._dep_counter += 1
        dep_id = f"DEP-{self._dep_counter:05d}"
        lib = random.choice(self.safe_libs)
        version = random.choice(lib.versions)
        last_updated = TODAY - timedelta(days=random.randint(0, 365))  # recent default
        return Slot(
            dependency_id=dep_id,
            app_id=app.app_id,
            depth=depth,
            parent_dependency_id=(parent.dependency_id if parent else ""),
            dependency_type=("transitive" if parent else "direct"),
            library_name=lib.name,
            ecosystem=lib.ecosystem,
            version=version,
            license=lib.base_license,
            last_updated=last_updated,
        )

    def build_skeleton(self) -> None:
        for app in self.apps:
            slots: list[Slot] = []
            n_direct = random.randint(15, 20)
            for _ in range(n_direct):
                slots.append(self._new_slot(app, parent=None, depth=0))
            while len(slots) < DEPS_PER_APP:
                parent = random.choice([s for s in slots if s.depth < 3])
                slots.append(self._new_slot(app, parent=parent, depth=parent.depth + 1))
            assert len(slots) == DEPS_PER_APP
            app.slots = slots

        self.all_slots = [s for app in self.apps for s in app.slots]
        self.slot_by_id = {s.dependency_id: s for s in self.all_slots}
        self.children_map = {}
        for s in self.all_slots:
            if s.parent_dependency_id:
                self.children_map.setdefault(s.parent_dependency_id, []).append(s.dependency_id)
        for kids in self.children_map.values():
            kids.sort()  # deterministic child order

    # ---- Step 4: primary-class assignment + structural rebalance ---------- #
    def assign_classes(self) -> None:
        random.shuffle(self.all_slots)
        cursor = 0
        for cls, count in CLASS_COUNTS.items():
            for s in self.all_slots[cursor:cursor + count]:
                s.primary_class = cls
            cursor += count
        assert cursor == 500

    def _is_leaf(self, slot: Slot) -> bool:
        return not self.children_map.get(slot.dependency_id)

    def rebalance(self) -> None:
        """Swap primary classes (count-preserving) to satisfy structural needs.

        1. Every transitive_vulnerable intermediate must be a non-leaf (so Step 6
           can reuse an existing descendant as the vulnerable victim).
        2. Every license_conflict slot must sit in a distributed app (only there
           does GPL/AGPL resolve to 'conflict').
        """
        # 1. transitive intermediates -> non-leaf
        leaf_intermediates = sorted(
            (s for s in self.all_slots if s.primary_class == "transitive_vulnerable" and self._is_leaf(s)),
            key=lambda s: s.dependency_id,
        )
        clean_nonleaf = sorted(
            (s for s in self.all_slots if s.primary_class == "clean" and not self._is_leaf(s)),
            key=lambda s: s.dependency_id,
        )
        assert len(leaf_intermediates) <= len(clean_nonleaf), "not enough non-leaf clean hosts"
        for s, host in zip(leaf_intermediates, clean_nonleaf):
            s.primary_class, host.primary_class = host.primary_class, s.primary_class

        # 2. license conflicts -> distributed apps
        distributed_ids = {a.app_id for a in self.apps if a.distributed}
        conflict_internal = sorted(
            (s for s in self.all_slots
             if s.primary_class == "license_conflict" and s.app_id not in distributed_ids),
            key=lambda s: s.dependency_id,
        )
        clean_distributed = sorted(
            (s for s in self.all_slots
             if s.primary_class == "clean" and s.app_id in distributed_ids),
            key=lambda s: s.dependency_id,
        )
        assert len(conflict_internal) <= len(clean_distributed), "not enough distributed clean hosts"
        for s, host in zip(conflict_internal, clean_distributed):
            s.primary_class, host.primary_class = host.primary_class, s.primary_class

    def _has_transitive_ancestor(self, slot: Slot) -> bool:
        cur = slot
        while cur.parent_dependency_id:
            cur = self.slot_by_id[cur.parent_dependency_id]
            if cur.primary_class == "transitive_vulnerable":
                return True
        return False

    def select_fp_traps(self) -> None:
        """Pick FP-trap slots: leaf, vulnerable-primary, and NOT inside any
        transitive intermediate's subtree.

        Leaves can't be transitive, and excluding slots with a transitive ancestor
        guarantees an FP trap is never the *only* non-transitive descendant of an
        intermediate — otherwise Step 6 could find no injectable victim.
        """
        candidates = sorted(
            (s for s in self.all_slots
             if s.primary_class == "vulnerable"
             and self._is_leaf(s)
             and not self._has_transitive_ancestor(s)),
            key=lambda s: s.dependency_id,
        )
        self.fp_trap_ids = {s.dependency_id for s in candidates[:N_FP_TRAPS]}
        assert len(self.fp_trap_ids) >= 2, "need at least 2 FP traps"

    # ---- injection helpers (Section 5.4) ---------------------------------- #
    def _new_cve_from_lib(self, lib: VulnLib) -> dict:
        return {
            "cve_id": lib.cve_id,
            "library_name": lib.name,
            "affected_versions": lib.affected_versions,
            "cvss_score": lib.cvss_score,
            "cvss_severity": lib.cvss_severity,
            "patch_available": lib.patch_available,
            "fixed_version": lib.fixed_version,
            "vulnerable_function": lib.vulnerable_function,
            "backported_patch_builds": [],
            "description": lib.description,
        }

    def make_slot_vulnerable(self, slot: Slot, fp_trap: bool = False) -> tuple[dict, VulnLib]:
        lib = random.choice(self.vuln_libs)
        slot.library_name = lib.name
        slot.ecosystem = lib.ecosystem
        cve = self.cve_by_library.get(lib.name)
        if cve is None:
            cve = self._new_cve_from_lib(lib)
            self.cve_by_library[lib.name] = cve
            self.cve_records.append(cve)
        if fp_trap:
            slot.version = lib.fp_version
            if lib.fp_version not in cve["backported_patch_builds"]:
                cve["backported_patch_builds"].append(lib.fp_version)
            slot.usage_signal = "not_referenced"
        else:
            slot.version = lib.vuln_version
            slot.usage_signal = random.choice(USAGE_SIGNALS)
            slot.is_vulnerable = True
        return cve, lib

    def make_slot_license_conflict(self, slot: Slot) -> None:
        # app is guaranteed distributed by rebalance()
        slot.license = random.choice(STRONG_COPYLEFT)

    def make_slot_unmaintained(self, slot: Slot) -> None:
        # 750..2190 days => age 2.05..5.99 years, always > 2
        slot.last_updated = TODAY - timedelta(days=random.randint(750, 2190))

    # ---- Step 5: inject issues + record labels together ------------------- #
    def inject_issues(self) -> None:
        for s in self.all_slots:
            rt: set = set()
            why: list[str] = []
            pc = s.primary_class

            if pc == "vulnerable":
                is_fp = s.dependency_id in self.fp_trap_ids
                cve, lib = self.make_slot_vulnerable(s, fp_trap=is_fp)
                if is_fp:
                    s.is_fp_trap = True
                    self.injected_fp_traps.append({
                        "dependency_id": s.dependency_id,
                        "library_name": lib.name,
                        "version": s.version,
                        "cve_id": cve["cve_id"],
                    })
                    # labeled clean for the vulnerable dimension (bait)
                else:
                    rt.add("vulnerable")
                    why.append(
                        f"{lib.name} {s.version} matches {cve['cve_id']} "
                        f"({cve['cvss_severity']}, CVSS {cve['cvss_score']})."
                    )

            elif pc == "transitive_vulnerable":
                s.needs_transitive_wiring = True  # resolved in Step 6

            elif pc == "license_conflict":
                self.make_slot_license_conflict(s)
                why.append(
                    f"{s.license} is copyleft in a distributed app — license conflict."
                )
                rt.add("license_conflict")

            elif pc == "unmaintained":
                self.make_slot_unmaintained(s)
                why.append("Not updated in over 2 years — unmaintained.")
                rt.add("unmaintained")

            # optional secondary staleness (never on clean, never on an FP trap)
            if pc != "clean" and not s.is_fp_trap and "unmaintained" not in rt:
                if random.random() < 0.15:
                    self.make_slot_unmaintained(s)
                    why.append("Also not updated in over 2 years.")
                    rt.add("unmaintained")

            s.risk_types = rt
            s.explanation_parts = why

    # ---- Step 6: wire transitive-vulnerable chains ------------------------ #
    def _descendants(self, slot: Slot) -> list[tuple[Slot, int]]:
        """All descendants with hop distance, sorted by (hop, dependency_id)."""
        out: list[tuple[Slot, int]] = []
        seen: set[str] = set()
        q: deque[tuple[str, int]] = deque(
            (cid, 1) for cid in self.children_map.get(slot.dependency_id, [])
        )
        while q:
            cid, hop = q.popleft()
            if cid in seen:
                continue
            seen.add(cid)
            child = self.slot_by_id[cid]
            out.append((child, hop))
            for gcid in self.children_map.get(cid, []):
                q.append((gcid, hop + 1))
        out.sort(key=lambda x: (x[1], x[0].dependency_id))
        return out

    def _pick_victim(self, s: Slot) -> tuple[Slot | None, int, bool]:
        """Choose a descendant to be the vulnerable leaf. Prefer a fresh clean one."""
        desc = self._descendants(s)
        fresh = [
            (d, h) for d, h in desc
            if d.primary_class != "transitive_vulnerable"
            and not d.is_fp_trap
            and not d.is_vulnerable
            and d.dependency_id not in self.used_victims
        ]
        if fresh:
            clean = [(d, h) for d, h in fresh if d.primary_class == "clean"]
            pool = clean if clean else fresh
            d, h = min(pool, key=lambda x: (x[1], x[0].dependency_id))
            return d, h, True
        # fallback: any already-vulnerable descendant satisfies the chain as-is
        # (the intermediate is genuinely on a path to it — sharing a deeper victim
        # that another chain injected is correct, so do NOT exclude used victims).
        already = [(d, h) for d, h in desc if d.is_vulnerable]
        if already:
            d, h = min(already, key=lambda x: (x[1], x[0].dependency_id))
            return d, h, False
        return None, 0, False

    def _path_from_app(self, victim: Slot) -> list[str]:
        """[app_id, direct_dep, ..., victim] following parent pointers upward."""
        chain: list[str] = []
        cur: Slot | None = victim
        guard = 0
        while cur is not None:
            chain.append(cur.dependency_id)
            if not cur.parent_dependency_id:
                break
            cur = self.slot_by_id[cur.parent_dependency_id]
            guard += 1
            if guard > 1000:
                raise AssertionError(f"cycle while pathing from {victim.dependency_id}")
        chain.reverse()
        return [victim.app_id, *chain]

    def wire_transitive(self) -> None:
        for s in [sl for sl in self.all_slots if sl.needs_transitive_wiring]:
            victim, hop, need_inject = self._pick_victim(s)
            if victim is None:
                raise AssertionError(f"no vulnerable-victim descendant for {s.dependency_id}")
            if need_inject:
                cve, lib = self.make_slot_vulnerable(victim, fp_trap=False)
                victim.risk_types.add("vulnerable")
                victim.explanation_parts.append(
                    f"{lib.name} {victim.version} matches {cve['cve_id']} "
                    f"({cve['cvss_severity']}) — inherited-chain vulnerability."
                )
            s.risk_types.add("transitive_vulnerable")
            s.explanation_parts.append(
                f"On a dependency path to vulnerable {victim.library_name} "
                f"{victim.version} ({hop} hop(s) below)."
            )
            self.used_victims.add(victim.dependency_id)
            self.injected_chains.append({
                "app_id": s.app_id,
                "intermediate_id": s.dependency_id,
                "victim_id": victim.dependency_id,
                "hop_distance": hop,
                "path": self._path_from_app(victim),
            })

    # ---- Step 7 (+ structural transitive labeling): finalize labels ------- #
    def matched_cve(self, slot: Slot) -> dict | None:
        """Independent vuln detector: real version match, excluding backports."""
        cve = self.cve_by_library.get(slot.library_name)
        if cve is None:
            return None
        if slot.version in cve["backported_patch_builds"]:
            return None
        try:
            if Version(slot.version) in SpecifierSet(cve["affected_versions"]):
                return cve
        except (InvalidVersion, InvalidSpecifier):
            return None
        return None

    def _nearest_vuln_descendant(self, slot: Slot) -> tuple[float, int]:
        vulns = [(d, h) for d, h in self._descendants(slot) if d._base_vuln > 0.0]
        if not vulns:
            return 0.0, 0
        nearest_hop = min(h for _d, h in vulns)
        base = max(d._base_vuln for d, h in vulns if h == nearest_hop)
        return base, nearest_hop

    def _compute_score(self, slot: Slot) -> DependencyScore:
        cves = (
            [CveScoreInput(slot._matched["cvss_score"], slot._matched["patch_available"])]
            if slot._matched else []
        )
        return score_dependency(
            cves=cves,
            usage_signal=slot.usage_signal,
            license_outcome=slot._license_outcome,
            last_updated=slot.last_updated,
            today=TODAY,
            nearest_descendant_base_vuln=slot._nearest_base,
            transitive_hop_distance=slot._nearest_hop,
        )

    def finalize_labels(self) -> None:
        # 1. per-slot vulnerability facts (final after Steps 5-6)
        for s in self.all_slots:
            s._matched = self.matched_cve(s)
            cves = (
                [CveScoreInput(s._matched["cvss_score"], s._matched["patch_available"])]
                if s._matched else []
            )
            s._base_vuln = vulnerability_component(cves, s.usage_signal)
        # 2. nearest vulnerable descendant (structural, from the graph)
        for s in self.all_slots:
            s._nearest_base, s._nearest_hop = self._nearest_vuln_descendant(s)
        # 3. structural transitive labels + license outcome + score
        for s in self.all_slots:
            if s._base_vuln == 0.0 and s._nearest_base > 0.0:
                if "transitive_vulnerable" not in s.risk_types:
                    s.risk_types.add("transitive_vulnerable")
                    s.explanation_parts.append(
                        "On a dependency path to a vulnerable descendant."
                    )
            s._license_outcome = resolve_license(s.license, self.app_by_id[s.app_id].distributed)
            s._score = self._compute_score(s)

            if not (s.risk_types - {"clean"}):
                s.risk_types = {"clean"}
            s.is_risk = bool(s.risk_types - {"clean"})
            s.severity = s._score.severity
            s.risk_score = s._score.risk_score
            if not s.explanation_parts:
                s.explanation_parts = ["No issues detected."]

    # ---- Step 8: write the five files ------------------------------------- #
    def _build_noise_cves(self) -> list[dict]:
        noise: list[dict] = []
        j = 0
        while len(self.cve_records) + len(noise) < N_VULNERABILITIES:
            maj = random.randint(1, 5)
            minr = random.randint(0, 9)
            band = random.choices(CVSS_BAND_NAMES, weights=CVSS_BAND_WEIGHTS, k=1)[0]
            lo, hi = CVSS_BANDS[band]
            cvss = round(random.uniform(lo, hi), 1)
            patch = random.random() < 0.7
            year = random.randint(2016, 2024)
            name = f"unused-lib-{j:04d}"  # references nothing any occurrence uses
            noise.append({
                "cve_id": f"CVE-{year}-{50000 + j}",
                "library_name": name,
                "affected_versions": f">={maj}.0.0,<{maj}.{minr + 1}.0",
                "cvss_score": cvss,
                "cvss_severity": band,
                "patch_available": patch,
                "fixed_version": f"{maj}.{minr + 1}.0" if patch else None,
                "vulnerable_function": f"{_symbol_prefix(name)}.{random.choice(VULN_FUNC_POOL)}",
                "backported_patch_builds": [],
                "description": f"Unrelated advisory for {name} (noise the analyzer must ignore).",
            })
            j += 1
        return noise

    def write_files(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # applications.json
        apps_out = [{
            "app_id": a.app_id,
            "name": a.name,
            "business_criticality": a.business_criticality,
            "owner": a.owner,
            "environment": a.environment,
            "internet_facing": a.internet_facing,
            "distributed": a.distributed,
        } for a in sorted(self.apps, key=lambda a: a.app_id)]
        _write_json(DATA_DIR / "applications.json", apps_out)

        # sbom_dependencies.csv
        dep_cols = [
            "dependency_id", "app_id", "library_name", "version", "license",
            "dependency_type", "parent_dependency_id", "last_updated", "ecosystem",
            "usage_signal",
        ]
        dep_rows = [{
            "dependency_id": s.dependency_id,
            "app_id": s.app_id,
            "library_name": s.library_name,
            "version": s.version,
            "license": s.license,
            "dependency_type": s.dependency_type,
            "parent_dependency_id": s.parent_dependency_id,
            "last_updated": s.last_updated.isoformat(),
            "ecosystem": s.ecosystem,
            "usage_signal": s.usage_signal,
        } for s in sorted(self.all_slots, key=lambda s: s.dependency_id)]
        _write_csv(DATA_DIR / "sbom_dependencies.csv", dep_cols, dep_rows)

        # vulnerability_db.json (accumulated + noise, deduped by cve_id)
        all_cves = self.cve_records + self._build_noise_cves()
        for cve in all_cves:
            cve["backported_patch_builds"] = sorted(cve["backported_patch_builds"])
        seen_ids: set[str] = set()
        deduped: list[dict] = []
        for cve in sorted(all_cves, key=lambda c: c["cve_id"]):
            if cve["cve_id"] in seen_ids:
                continue
            seen_ids.add(cve["cve_id"])
            deduped.append(cve)
        _write_json(DATA_DIR / "vulnerability_db.json", deduped)
        self._written_vulns = deduped  # kept for the verifier

        # license_rules.json
        license_rules = {
            "licenses": {
                name: {"category": cat, "base_risk": risk}
                for name, (cat, risk) in LICENSE_DEFINITIONS.items()
            },
            "compatibility": {
                cat: {"distributed": dist, "internal": intern}
                for cat, (dist, intern) in COMPAT_DEFINITIONS.items()
            },
        }
        _write_json(DATA_DIR / "license_rules.json", license_rules)

        # dependency_labels.csv (GROUND TRUTH)
        label_cols = ["dependency_id", "is_risk", "risk_types", "severity", "risk_score", "explanation"]
        label_rows = [{
            "dependency_id": s.dependency_id,
            "is_risk": "true" if s.is_risk else "false",
            "risk_types": "|".join(sorted(s.risk_types)),
            "severity": s.severity,
            "risk_score": f"{round(s.risk_score, 4)}",
            "explanation": " ".join(s.explanation_parts),
        } for s in sorted(self.all_slots, key=lambda s: s.dependency_id)]
        _write_csv(DATA_DIR / "dependency_labels.csv", label_cols, label_rows)

        # debug ground-truth extras (not one of the five; consumed by Phases 3/8)
        debug = {
            "injected_chains": sorted(self.injected_chains, key=lambda c: c["victim_id"]),
            "injected_fp_traps": sorted(self.injected_fp_traps, key=lambda t: t["dependency_id"]),
        }
        _write_json(DATA_DIR / "_ground_truth_debug.json", debug)

    # ---- Step 9: self-verifier (Section 5.5) ------------------------------ #
    def verify(self) -> None:
        errors: list[str] = []

        def check(cond: bool, msg: str) -> None:
            if not cond:
                errors.append(msg)

        # 1. row counts
        check(len(self.apps) == 10, f"apps == {len(self.apps)}, expected 10")
        check(len(self.all_slots) == 500, f"deps == {len(self.all_slots)}, expected 500")
        labels = [s for s in self.all_slots if s.risk_types]
        check(len(labels) == 500, f"labels == {len(labels)}, expected 500")
        n_rules = len(LICENSE_DEFINITIONS) + len(COMPAT_DEFINITIONS)
        check(n_rules == 15, f"license rules == {n_rules}, expected 15")
        n_vulns = len(getattr(self, "_written_vulns", self.cve_records))
        check(n_vulns >= 180, f"vulnerabilities == {n_vulns}, expected >= 180")

        # 2. primary-class counts exact
        counts = Counter(s.primary_class for s in self.all_slots)
        for cls, expected in CLASS_COUNTS.items():
            check(counts[cls] == expected, f"primary '{cls}' == {counts[cls]}, expected {expected}")

        # 3. parent references valid, same app
        for s in self.all_slots:
            if s.parent_dependency_id:
                parent = self.slot_by_id.get(s.parent_dependency_id)
                check(parent is not None, f"{s.dependency_id}: dangling parent {s.parent_dependency_id}")
                if parent is not None:
                    check(parent.app_id == s.app_id, f"{s.dependency_id}: cross-app parent edge")

        # 4. no cycles (parent chain terminates at a direct dep)
        for s in self.all_slots:
            cur, guard = s, 0
            while cur.parent_dependency_id:
                cur = self.slot_by_id[cur.parent_dependency_id]
                guard += 1
                if guard > 500:
                    check(False, f"{s.dependency_id}: cycle in parent chain")
                    break

        # 5. injected transitive chains
        check(len(self.injected_chains) == CLASS_COUNTS["transitive_vulnerable"],
              f"injected chains == {len(self.injected_chains)}, expected 50")
        for ch in self.injected_chains:
            inter = self.slot_by_id[ch["intermediate_id"]]
            victim = self.slot_by_id[ch["victim_id"]]
            # walk victim -> ... -> intermediate via parent pointers
            cur, found, guard = victim, False, 0
            while True:
                if cur.dependency_id == inter.dependency_id:
                    found = True
                    break
                if not cur.parent_dependency_id:
                    break
                cur = self.slot_by_id[cur.parent_dependency_id]
                guard += 1
                if guard > 500:
                    break
            check(found, f"chain {ch['intermediate_id']}->{ch['victim_id']}: not reachable")
            check(inter._base_vuln == 0.0 and "vulnerable" not in inter.risk_types,
                  f"chain intermediate {inter.dependency_id} is vulnerable (must be transitive)")
            check("transitive_vulnerable" in inter.risk_types,
                  f"chain intermediate {inter.dependency_id} missing transitive_vulnerable label")
            check(victim._base_vuln > 0.0 and "vulnerable" in victim.risk_types,
                  f"chain victim {victim.dependency_id} is not vulnerable")

        # 6. every vulnerable slot (except FP traps) really matches a CVE
        for s in self.all_slots:
            if "vulnerable" in s.risk_types:
                check(not s.is_fp_trap, f"{s.dependency_id}: FP trap labeled vulnerable")
                check(self.matched_cve(s) is not None,
                      f"{s.dependency_id}: 'vulnerable' label without a real version match")
            # tie the label to the facts, both directions
            check((s._base_vuln > 0.0) == ("vulnerable" in s.risk_types),
                  f"{s.dependency_id}: base_vuln/label mismatch")

        # 7. FP traps
        check(len(self.injected_fp_traps) >= 2, f"FP traps == {len(self.injected_fp_traps)}, expected >= 2")
        for trap in self.injected_fp_traps:
            s = self.slot_by_id[trap["dependency_id"]]
            cve = self.cve_by_library[s.library_name]
            in_range = Version(s.version) in SpecifierSet(cve["affected_versions"])
            check(in_range, f"FP trap {s.dependency_id}: version not in affected range")
            check(s.version in cve["backported_patch_builds"],
                  f"FP trap {s.dependency_id}: version not in backported_patch_builds")
            check("vulnerable" not in s.risk_types, f"FP trap {s.dependency_id}: labeled vulnerable")

        # 8. license conflicts: outcome==conflict AND app distributed
        for s in self.all_slots:
            if "license_conflict" in s.risk_types:
                app = self.app_by_id[s.app_id]
                check(app.distributed, f"{s.dependency_id}: license_conflict in non-distributed app")
                check(resolve_license(s.license, app.distributed) == "conflict",
                      f"{s.dependency_id}: license '{s.license}' does not resolve to conflict")

        # 9. every unmaintained label is genuinely old
        for s in self.all_slots:
            if "unmaintained" in s.risk_types:
                check(age_in_years(s.last_updated, TODAY) > 2.0,
                      f"{s.dependency_id}: unmaintained label but age <= 2 years")

        # 10. label numbers == score_dependency() recomputed
        for s in self.all_slots:
            recomputed = self._compute_score(s)
            check(recomputed == s._score,
                  f"{s.dependency_id}: stored score != recomputed score")
            check(s.severity == recomputed.severity and abs(s.risk_score - recomputed.risk_score) < 1e-9,
                  f"{s.dependency_id}: severity/risk_score disagree with scorer")

        if errors:
            raise AssertionError(
                "Self-verifier FAILED with %d error(s):\n  - %s"
                % (len(errors), "\n  - ".join(errors[:25]))
            )

    # ---- orchestration ---------------------------------------------------- #
    def run(self) -> None:
        random.seed(SEED)  # Step 0
        self.build_universe()       # Step 1
        self.build_apps()           # Step 2
        self.build_skeleton()       # Step 3
        self.assign_classes()       # Step 4
        self.rebalance()            # Step 4 (structural fix-up)
        self.select_fp_traps()
        self.inject_issues()        # Step 5
        self.wire_transitive()      # Step 6
        self.finalize_labels()      # Step 7 (+ structural transitive labels)
        self.write_files()          # Step 8
        self.verify()               # Step 9
        self._print_summary()

    def _print_summary(self) -> None:
        counts = Counter(s.primary_class for s in self.all_slots)
        n_vuln_labeled = sum(1 for s in self.all_slots if "vulnerable" in s.risk_types)
        n_trans = sum(1 for s in self.all_slots if "transitive_vulnerable" in s.risk_types)
        n_conf = sum(1 for s in self.all_slots if "license_conflict" in s.risk_types)
        n_unmaint = sum(1 for s in self.all_slots if "unmaintained" in s.risk_types)
        n_risk = sum(1 for s in self.all_slots if s.is_risk)
        print("SBOM sample data generated in", DATA_DIR)
        print(f"  apps={len(self.apps)}  deps={len(self.all_slots)}  "
              f"vulnerabilities={len(self._written_vulns)}")
        print(f"  primary classes: {dict(counts)}")
        print(f"  labeled: vulnerable={n_vuln_labeled}  transitive_vulnerable={n_trans}  "
              f"license_conflict={n_conf}  unmaintained={n_unmaint}  is_risk={n_risk}")
        print(f"  injected chains={len(self.injected_chains)}  FP traps={len(self.injected_fp_traps)}")
        print("Self-verifier: PASS")


# --------------------------------------------------------------------------- #
# I/O helpers (deterministic, byte-stable)
# --------------------------------------------------------------------------- #
def _symbol_prefix(name: str) -> str:
    parts = name.replace("_", "-").split("-")
    return "".join(p.capitalize() for p in parts if p) or "Lib"


def _write_json(path: Path, obj) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    SBOMGenerator().run()


if __name__ == "__main__":
    main()
