# Problem 10 — Software Supply Chain Risk Scorer (SBOM Analyzer)

## Sample Data Overview

This directory contains **6 files** that together form a complete software supply chain risk dataset for 10 enterprise applications with 500 dependencies.

---

## File Inventory

| File | Format | Records | Description |
|---|---|---|---|
| `applications.json` | JSON | 10 | Application inventory with metadata |
| `sbom_dependencies.csv` | CSV | 500 | Library dependencies (50 per app) |
| `vulnerability_db.json` | JSON | ~200 | Simulated CVE/NVD vulnerability database |
| `license_rules.json` | JSON | 15 | License compatibility matrix |
| `transitive_dependencies.json` | JSON | ~200+ | Parent → child dependency resolution |
| `dependency_labels.csv` | CSV | 500 | **Ground truth** labels for evaluation |

---

## File Descriptions

### 1. `applications.json`

The 10 enterprise applications your SBOM analyzer must assess.

| Field | Type | Description | Example Values |
|---|---|---|---|
| `app_id` | string | Unique app identifier | `APP-001` … `APP-010` |
| `name` | string | Application name | `CustomerPortal`, `PaymentService` |
| `language` | string | Primary language | `Java`, `Python`, `JavaScript`, `Go` |
| `criticality` | string | Business criticality | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `license_model` | string | App's own license model | `proprietary`, `internal-only` |
| `business_owner` | string | Responsible person | `Sarah Chen` |
| `department` | string | Owning department | `Engineering`, `Finance`, `HR`, `DevOps` |
| `deployment` | string | Deployment target | `cloud`, `on-prem` |

**Sample record:**
```json
{
  "app_id": "APP-001",
  "name": "CustomerPortal",
  "language": "Java",
  "criticality": "HIGH",
  "license_model": "proprietary",
  "business_owner": "Sarah Chen",
  "department": "Engineering",
  "deployment": "cloud"
}
```

---

### 2. `sbom_dependencies.csv`

The core SBOM data — 500 library dependencies across all 10 applications (~50 per app).

| Column | Type | Description |
|---|---|---|
| `dep_id` | string | Unique dependency ID (`DEP-0001` … `DEP-0500`) |
| `application_id` | string | FK → `applications.json` |
| `application_name` | string | App name (denormalized) |
| `library` | string | Library/package name |
| `version` | string | Semver version |
| `license` | string | SPDX license identifier (`MIT`, `Apache-2.0`, `GPL-3.0`, `UNKNOWN`, etc.) |
| `dependency_type` | string | `direct` or `transitive` |
| `last_updated` | date | Last release/update date (YYYY-MM-DD) |
| `transitive_deps` | string | Semicolon-delimited child dependencies (`lib:version;lib:version`), or empty |

**Sample row:**
```
DEP-0001,APP-001,CustomerPortal,micrometer-core,3.0.10,Apache-2.0,direct,2025-08-15,tomcat-embed-core:2.4.0;jackson-databind:2.15.0
```

---

### 3. `vulnerability_db.json`

Simulated National Vulnerability Database (NVD) with ~200 CVE entries.

| Field | Type | Description |
|---|---|---|
| `cve_id` | string | CVE identifier (`CVE-YYYY-NNNN`) |
| `library` | string | Affected library name |
| `affected_versions` | array | List of vulnerable version strings |
| `fixed_version` | string \| null | Patched version (`null` if no fix exists) |
| `cvss_score` | float | CVSS v3 score (0.0–10.0) |
| `severity` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `exploitability` | string | `LOW`, `MEDIUM`, `HIGH` |
| `description` | string | Vulnerability description |
| `patch_available` | boolean | Whether a fix is available |
| `published_date` | date | CVE publication date (YYYY-MM-DD) |

**Sample record:**
```json
{
  "cve_id": "CVE-2021-44228",
  "library": "log4j-core",
  "affected_versions": ["2.0-beta9", "2.14.1"],
  "fixed_version": "2.17.0",
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "exploitability": "HIGH",
  "description": "Remote code execution via JNDI lookup in log messages",
  "patch_available": true,
  "published_date": "2021-12-10"
}
```

---

### 4. `license_rules.json`

License compatibility matrix with 15 license types and their risk profiles.

| Field | Type | Description |
|---|---|---|
| `license` | string | License name |
| `spdx` | string | SPDX identifier |
| `risk_level` | string | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `compatible_with_proprietary` | boolean | Can be used in proprietary/commercial software |
| `viral` | boolean | Copyleft — requires derivative works to use same license |
| `notes` | string | Human-readable explanation |

**Risk level guide:**

| Risk Level | License Types | Key Concern |
|---|---|---|
| `LOW` | MIT, Apache-2.0, BSD, ISC, Unlicense | Permissive — safe for any use |
| `MEDIUM` | MPL-2.0, LGPL-2.1, LGPL-3.0 | Weak copyleft — linking OK, modifications must be shared |
| `HIGH` | SSPL, UNKNOWN | Unclear terms or restrictive; legal review needed |
| `CRITICAL` | GPL-3.0, AGPL-3.0 | Strong copyleft + viral — incompatible with proprietary distribution |

---

### 5. `transitive_dependencies.json`

Resolves the parent → child dependency chains (~200+ edges). Use this to build dependency graphs and trace transitive vulnerability paths.

| Field | Type | Description |
|---|---|---|
| `parent_library` | string | Direct dependency (parent) |
| `parent_version` | string | Parent version |
| `child_library` | string | Transitive dependency (child) |
| `child_version` | string | Child version |
| `application_id` | string | FK → `applications.json` |

**Sample record:**
```json
{
  "parent_library": "micrometer-core",
  "parent_version": "3.0.10",
  "child_library": "tomcat-embed-core",
  "child_version": "2.4.0",
  "application_id": "APP-001"
}
```

**Usage:** Build a directed graph `App → direct dep → transitive dep` to find all paths to vulnerable libraries.

---

### 6. `dependency_labels.csv` ⭐ Ground Truth

Evaluation labels for all 500 dependencies. **Use this to measure your solution's accuracy.**

| Column | Type | Description |
|---|---|---|
| `dep_id` | string | FK → `sbom_dependencies.csv` (1:1 mapping) |
| `application_id` | string | FK → `applications.json` |
| `library` | string | Library name |
| `version` | string | Version |
| `is_risky` | boolean | `True` = flagged, `False` = clean |
| `risk_type` | string | Category of risk detected |
| `severity` | string | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `explanation` | string | Human-readable rationale |

**Risk type distribution:**

| `risk_type` | Approx % | Description |
|---|---|---|
| `NONE` | ~45% | No issues detected |
| `VULNERABLE_DEPENDENCY` | ~18% | Direct dependency with known CVE |
| `TRANSITIVE_VULNERABILITY` | ~10% | Inherited CVE via dependency chain |
| `LICENSE_CONFLICT` | ~8% | Incompatible license (e.g., GPL in proprietary app) |
| `TRANSITIVE_LICENSE_CONFLICT` | ~4% | Inherited license conflict via dependency chain |
| `UNMAINTAINED` | ~15% | No updates in 2+ years |

---

## Entity Relationships

```
applications.json (10 apps)
    │
    ├──→ sbom_dependencies.csv (500 deps, ~50 per app)
    │       │
    │       ├──↔ dependency_labels.csv (1:1 on dep_id) ← GROUND TRUTH
    │       │
    │       └──→ transitive_dependencies.json (parent → child edges)
    │
    ├── vulnerability_db.json (lookup by library + version)
    │
    └── license_rules.json (lookup by license SPDX id)
```

## How to Use This Data

### Step 1: Load the SBOM
```python
import pandas as pd
import json

apps = json.load(open('applications.json'))
deps = pd.read_csv('sbom_dependencies.csv')
vulns = json.load(open('vulnerability_db.json'))
licenses = json.load(open('license_rules.json'))
transitive = json.load(open('transitive_dependencies.json'))
labels = pd.read_csv('dependency_labels.csv')
```

### Step 2: Cross-reference vulnerabilities
For each dependency in `sbom_dependencies.csv`, check if its `library` + `version` appears in `vulnerability_db.json`'s `affected_versions`.

### Step 3: Resolve transitive chains
Use `transitive_dependencies.json` to build a dependency graph. A vulnerability in a child library makes the parent (and its application) transitively vulnerable.

### Step 4: Check license compatibility
Look up each dependency's `license` in `license_rules.json`. Flag `GPL-3.0` / `AGPL-3.0` dependencies in apps with `license_model: "proprietary"`.

### Step 5: Flag unmaintained libraries
Check `last_updated` in `sbom_dependencies.csv`. Libraries not updated in 2+ years (before April 2024) are maintenance risks.

### Step 6: Evaluate your solution
```python
from sklearn.metrics import precision_score, recall_score, f1_score

y_true = labels['is_risky'].astype(int)
y_pred = labels['predicted_risky'].astype(int)  # your predictions

print(f"Precision: {precision_score(y_true, y_pred):.2%}")
print(f"Recall:    {recall_score(y_true, y_pred):.2%}")
print(f"F1 Score:  {f1_score(y_true, y_pred):.2f}")
# Target: Precision > 75%, Recall > 70%
```

---

## Evaluation Targets

| Metric | Target |
|---|---|
| Vulnerability Detection | > 85% recall on CVE-flagged dependencies |
| Transitive Resolution | 100% of transitive chains resolved |
| License Conflict Detection | > 90% recall |
| False Positive Rate | < 20% |
| Risk Score Accuracy | ±10% of labeled ground truth severity |
