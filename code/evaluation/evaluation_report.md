# Preliminary Evaluation Report: Ghost Data Still Exists

**Phase:** Phase 4 - Public Benchmark Evaluation and Regression Testing  
**Public Evaluation Dataset:** `dataset/sample_deletion_requests.csv` (32 cases)  
**Ground Truth Reference:** `dataset/sample_output.csv`  
**Custom Fixtures:** `code/evaluation/custom_cases.py` (3 cases)  

---

## 1. Executive Summary & Measured Benchmark Metrics

| Metric | Measured Score | Passed / Total | Notes |
|---|---|---|---|
| **Case-Level Deletion-Status Accuracy** | **100.00%** | 32 / 32 | Agreement across COMPLETE, INCOMPLETE, and NOT_APPLICABLE |
| **Structural Validity & Numbering** | **100.00%** | 32 / 32 | 1-indexed consecutive numbering, phase ordering, exact 7 keys |
| **Sequence Accuracy** | **100.00%** | 32 / 32 | Monotonic dependency ordering and relative phase sequence |
| **Exact Step-Array Match Accuracy** | **100.00%** | 32 / 32 | Exact match of all steps, operations, states, and evidence |
| **Overall Field-Level Accuracy** | **100.00%** | 1351 / 1351 | Key-aligned evaluation across all 7 mandatory step keys |

### Field-Level Accuracy Breakdown

| Step Field | Accuracy | Matches / Total Step Comparisons |
|---|---|---|
| `step_no` | 100.00% | 193 / 193 |
| `phase` | 100.00% | 193 / 193 |
| `system_id` | 100.00% | 193 / 193 |
| `resource_id` | 100.00% | 193 / 193 |
| `operation` | 100.00% | 193 / 193 |
| `state` | 100.00% | 193 / 193 |
| `evidence_id` | 100.00% | 193 / 193 |

---

## 2. Independent Custom Evaluation Cases

Three independent evaluation scenarios were created to validate edge-case behaviors without shortcuts:

| Case ID | Scenario | Expected Status | Predicted Status | Status Match | Steps Match |
|---|---|---|---|---|---|
| `custom_case_01` | Temporal email alias reuse: decoy account with same historical email must not cause false merge or false incomplete. | `COMPLETE` | `COMPLETE` | PASS | PASS |
| `custom_case_02` | Downstream remaining export combined with active connector and backup restore risk. | `INCOMPLETE` | `INCOMPLETE` | PASS | PASS |
| `custom_case_03` | Lawful retention of security audit record paired with tombstone failing PII redaction. | `INCOMPLETE` | `INCOMPLETE` | PASS | PASS |

**Custom Fixture Summary:** Status Accuracy: **100.0%**, Exact Step Sequence Accuracy: **100.0%**.

---

## 3. GitHub Issue 19 Investigation (Cases 18, 20, 23)

Public GitHub Issue 19 reported perceived discrepancies in expected steps and evidence references for `case_18`, `case_20`, and `case_23`.

### Findings from Grounded Local Inspection:
1. **`case_18` (Email: `mori.ren@gmail.com`):**
   - The golden output specifies 4 findings (`search_4013`, `analytics_037`, `support_5569`, `data_flow_4890`), all citing `evidence_94`.
   - Physical inspection of `evidence/logs/resource_lookup_trace_20260926_103856.log` (`evidence_94`) confirms that lines specifically query `mori.ren@gmail.com` and expose remaining entries for `search_4013`, `support_5569`, `analytics_037`, and `data_flow_4890` (`enabled=true`).
   - **Conclusion:** Grounded and valid in participant-visible evidence.

2. **`case_20` (Email: `akosua.gyasi@gmail.com`):**
   - The golden output specifies findings for `search_4262` and `data_flow_1770` citing `evidence_94`.
   - Log inspection of `evidence_94` confirms `trace_id=rb-075713-004` lookup for `akosua.gyasi@gmail.com` with `result=hit`, `resource_id=search_4262`, and `trace_id=rb-095254-020` with `resource_id=data_flow_1770` (`enabled=true`).
   - **Conclusion:** Verified and fully grounded.

3. **`case_23` (Email: `thandiwe.m6866@zoho.com`):**
   - The golden output specifies findings for `export_7364` and `search_898` citing `evidence_92`.
   - Structured JSON inspection of `evidence/records/service_resource_export_20260915_114455.json` (`evidence_92`) confirms entries under `service_exports` for `export_service` (`export_7364`) and `search_service` (`search_898`).
   - Post-remediation verification steps (`account_410`, `audit_record_4128`) have `evidence_id = ""`, in strict accordance with §6.6 of `AGENTS.md` (post-remediation verification describes future checks, not existing evidence).
   - **Conclusion:** The issue was caused by participants misinterpreting future verification steps as missing evidence references, whereas the contract mandates an empty string.

---

## 4. Failures Found, Root Causes, and Improvements Made

During Phase 4 benchmark evaluation, the following key engineering insights and fixes were implemented:

1. **Pre-Request vs Post-Request Temporal Partitioning:**
   - *Defect:* Initially, `case_21`, `case_26`, and `case_28` were incorrectly classified as `INCOMPLETE` (90.6% status accuracy).
   - *Root Cause:* Historical snapshots captured *before* `requested_at` showed active records. Applying pre-request active state as post-deletion violations violated the fundamental temporal contract.
   - *Fix:* Enforced that evidence proving a remaining record violation must be captured on or after `requested_at`. This improved status accuracy to **100.0%**.

2. **Nested JSON Export Unpacking:**
   - *Defect:* Service exports in `evidence_92` nested resources inside `service_exports -> {service_name} -> {resource_type}` arrays.
   - *Fix:* Added recursive sub-dictionary unpacking in `EvidenceEngine.parse_json_records`.

3. **Multi-Line Log Correlation by Trace ID:**
   - *Defect:* In structured observability logs (e.g. `evidence_94`), query parameters (`lookup_key`) and query results (`resource_id`, `result=hit`) are split across paired DEBUG/INFO lines sharing a `trace_id`.
   - *Fix:* Implemented trace-level dictionary aggregation in `EvidenceEngine.parse_log_file`.

---

## 5. Full Evaluation Dataset Execution & Unverified Predictions

In Phase 5, the production deletion-audit engine was executed across all 518 evaluation requests in `dataset/deletion_requests.csv`, writing the official predictions to root-level `output.csv`.

### Full Dataset Status Distribution
- **Total Input Requests:** 518 cases (`case_33` through `case_550`)
- **Total Output Records:** 518 rows (100% coverage, 0 missing, 0 duplicates)
- **Status Distribution:**
  - `INCOMPLETE`: 333 cases (64.29%)
  - `COMPLETE`: 175 cases (33.78%)
  - `NOT_APPLICABLE`: 10 cases (1.93%)

*Note on Unverified Predictions:* Ground truth labels for the 518 evaluation cases in `dataset/deletion_requests.csv` are organizer-held and withheld from participants. Unlike the 32 public sample cases and 3 custom evaluation cases (which are verified against known truth at 100.0% accuracy), the full 518-case predictions are unverified by design.

### Structural & Schema Validation (100% Pass)
The final `output.csv` was subjected to automated validation:
1. **Row Count:** Exactly 518 rows.
2. **Column Headers:** Exact match `['case_id', 'deletion_status', 'steps_json']`.
3. **Ordering:** Strict ascending alphanumeric sort by `case_id`.
4. **JSON Serialization:** All 518 `steps_json` values parse as valid JSON arrays with 1-indexed consecutive numbering.
5. **Phase & Operation Contract:** Strict phase monotonicity (`FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION`), valid canonical operations, and mapped states.
6. **Evidence Citations:** `COMPLETE` verifications cite grounding evidence; `INCOMPLETE` post-remediation and verification steps use empty `evidence_id = ""`.
7. **Non-Deletion Handling:** All 10 `NOT_APPLICABLE` cases have `steps_json = []`.

---

## 6. Submission Artifacts and Compliance

| Artifact | Location | Status |
|---|---|---|
| `output.csv` | Repository Root | Generated (518 rows, validated) |
| `evaluation_report.md` | `code/evaluation/` & `evaluation/` | Updated with full evaluation details |
| `usage_report.md` | `code/evaluation/` & `evaluation/` | Completed ($0.00 cost, 0 API tokens) |
| `code.zip` | Repository Root | Prepared (excluding dataset, git, pycache) |
| `log.txt` | Repository Root | Appended with complete turn history |
| `agent-trace.zip` | Repository Root | Packaged transcript and session data |

