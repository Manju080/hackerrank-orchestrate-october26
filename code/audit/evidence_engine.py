"""Evidence engine for ingestion, format parsing, and multi-source artifact correlation.

Reconciles evidence_files.csv against disk, extracts structured records,
executes SQLite snapshot comparisons, and enforces temporal cutoff filtering.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
import json
import os
import re
import sqlite3
import pandas as pd

from code.config import REPO_ROOT, DATASET_DIR, EVIDENCE_DIR, EVIDENCE_FILES_PATH


@dataclass
class EvidenceFileMeta:
    """Metadata entry for an evidence file in evidence_files.csv."""
    file_id: str
    file_path: str
    origin: str
    captured_at: str
    absolute_path: Path
    exists_on_disk: bool
    category: str


@dataclass
class ExtractedRecord:
    """Standardized record extracted from evidence."""
    evidence_id: str
    system_id: str
    resource_id: str
    user_id: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    record_state: str  # e.g. "PRESENT", "ACTIVE", "DELETED"
    event_timestamp: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    source_origin: Optional[str] = None

def normalize_system(system_id: str, resource_id: str) -> str:
    """Normalize system_id based on deterministic resource prefix rules."""
    r = resource_id.lower()
    if r.startswith("account_"):
        return "account_service"
    if r.startswith("audit_record_"):
        return "security_service"
    if r.startswith("analytics_") or r.startswith("telemetry_"):
        return "analytics_platform"
    if r.startswith("search_"):
        return "search_service"
    if r.startswith("support_"):
        return "support_platform"
    if r.startswith("export_"):
        return "export_service"
    if r.startswith("backup_"):
        return "backup_service"
    if r.startswith("data_flow_"):
        return "integration_service"
    if r.startswith("tombstone_"):
        return "identity_service"
    if r.startswith("marketing_"):
        return "marketing_platform"
    return system_id


class EvidenceEngine:
    """Manages evidence files, parsing, and query execution."""

    def __init__(
        self,
        manifest_path: Path = EVIDENCE_FILES_PATH,
        evidence_dir: Path = EVIDENCE_DIR,
    ):
        self.manifest_path = manifest_path
        self.evidence_dir = evidence_dir
        self.inventory: Dict[str, EvidenceFileMeta] = {}
        self.inventory_by_path: Dict[str, EvidenceFileMeta] = {}
        self._load_inventory()

    def _load_inventory(self) -> None:
        """Load and verify evidence manifest against disk."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Missing evidence_files.csv at {self.manifest_path}")

        df = pd.read_csv(self.manifest_path)
        for _, row in df.iterrows():
            fid = str(row["file_id"]).strip()
            fpath = str(row["file_path"]).strip()
            origin = str(row.get("origin", "")).strip()
            captured_at = str(row.get("captured_at", "")).strip()

            abs_path = DATASET_DIR / fpath
            exists = abs_path.exists()
            category = fpath.split("/")[1] if "/" in fpath else "root"

            meta = EvidenceFileMeta(
                file_id=fid,
                file_path=fpath,
                origin=origin,
                captured_at=captured_at,
                absolute_path=abs_path,
                exists_on_disk=exists,
                category=category,
            )
            self.inventory[fid] = meta
            self.inventory_by_path[fpath] = meta

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Return audit counts and category breakdown."""
        total = len(self.inventory)
        on_disk = sum(1 for m in self.inventory.values() if m.exists_on_disk)
        categories: Dict[str, int] = {}
        for m in self.inventory.values():
            categories[m.category] = categories.get(m.category, 0) + 1
        return {
            "total_manifest_entries": total,
            "total_files_on_disk": on_disk,
            "is_consistent": total == on_disk,
            "category_counts": categories,
        }

    def get_valid_evidence_files(self, audit_at: str) -> List[EvidenceFileMeta]:
        """Return all evidence files whose captured_at is <= audit_at."""
        valid = []
        for meta in self.inventory.values():
            if meta.captured_at <= audit_at and meta.exists_on_disk:
                valid.append(meta)
        return valid

    def parse_sql_snapshot(
        self, file_path: Path
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Execute SQLite script in an in-memory DB and extract all table contents."""
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        tables_data: Dict[str, List[Dict[str, Any]]] = {}

        try:
            sql_text = file_path.read_text(encoding="utf-8", errors="replace")
            # Execute script
            cursor.executescript(sql_text)

            # Discover all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]

            for t in tables:
                cursor.execute(f"PRAGMA table_info({t});")
                col_names = [col[1] for col in cursor.fetchall()]
                cursor.execute(f"SELECT * FROM {t};")
                rows = cursor.fetchall()
                tables_data[t] = [dict(zip(col_names, row)) for row in rows]
        except Exception as e:
            # Malformed SQL guard
            tables_data["_error"] = [{"error": str(e)}]
        finally:
            conn.close()

        return tables_data

    def parse_json_records(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse structured JSON evidence files."""
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(text)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # 1. Unpack service_exports if present
                if "service_exports" in data and isinstance(data["service_exports"], dict):
                    records = []
                    for srv, sdata in data["service_exports"].items():
                        if isinstance(sdata, dict):
                            for k, v in sdata.items():
                                if isinstance(v, list):
                                    for item in v:
                                        if isinstance(item, dict):
                                            item_copy = dict(item)
                                            item_copy["_inferred_system_id"] = srv
                                            if "hits" in item_copy and isinstance(item_copy["hits"], dict):
                                                docs = item_copy["hits"].get("documents", [])
                                                for doc in docs:
                                                    d_copy = dict(doc)
                                                    d_copy["_inferred_system_id"] = srv
                                                    records.append(d_copy)
                                            records.append(item_copy)
                    return records

                # 2. Unpack snapshot bundles if present
                if "snapshots" in data and isinstance(data["snapshots"], list):
                    records = []
                    for snap in data["snapshots"]:
                        if isinstance(snap, dict):
                            srv = snap.get("data_store", snap.get("collection", ""))
                            for r in snap.get("records", []):
                                if isinstance(r, dict):
                                    r_copy = dict(r)
                                    r_copy["_inferred_system_id"] = srv
                                    records.append(r_copy)
                    return records

                # 3. Standard wrapped records list
                for k in ["records", "items", "users", "profiles", "exports"]:
                    if k in data and isinstance(data[k], list):
                        return data[k]
                return [data]
            return []
        except Exception:
            return []

    def parse_log_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse structured logs (JSON lines or key=value logs), correlating multi-line events by trace_id."""
        records = []
        traces = {}
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Check JSON line (which may have an ISO-8601 timestamp prefix)
                    idx = line.find("{")
                    if idx != -1 and line.endswith("}"):
                        try:
                            d = json.loads(line[idx:])
                            ts = line[:idx].strip()
                            if ts and "timestamp" not in d:
                                d["timestamp"] = ts
                            tid = d.get("trace_id")
                            if tid:
                                if tid not in traces:
                                    traces[tid] = {}
                                traces[tid].update(d)
                            else:
                                records.append(d)
                            continue
                        except Exception:
                            pass
                    # Key=value regex parser
                    kv_pairs = re.findall(r'(\w+)=("[^"]*"|\S+)', line)
                    if kv_pairs:
                        d = {}
                        first_sp = line.find(" ")
                        if first_sp != -1 and "T" in line[:first_sp] and "Z" in line[:first_sp]:
                            d["timestamp"] = line[:first_sp].strip()
                        for k, v in kv_pairs:
                            d[k] = v.strip('"')
                        tid = d.get("trace_id")
                        if tid:
                            if tid not in traces:
                                traces[tid] = {}
                            traces[tid].update(d)
                        else:
                            records.append(d)
            for tid, d in traces.items():
                records.append(d)
        except Exception:
            pass
        return records

    def parse_pdf_text_streams(self, file_path: Path) -> Dict[str, Any]:
        """Pure-Python extraction of PDF text streams supporting ASCII85 and FlateDecode.

        Extracts text across all page content streams, handles font CMaps and literal strings.
        """
        import base64
        import zlib

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj\s*(.*?)\s*endobj", re.DOTALL)
            objs = {int(m.group(1)): m.group(3) for m in pattern.finditer(content)}

            pages = []
            has_custom_cmap = b"/CIDInit" in content or b"AAAAAA+" in content

            for obj_num, obj_data in sorted(objs.items()):
                if b"/Filter" in obj_data and (b"/Contents" not in obj_data) and b"stream" in obj_data:
                    s_idx = obj_data.find(b"stream")
                    e_idx = obj_data.find(b"endstream", s_idx)
                    header = obj_data[:s_idx]
                    s_data = obj_data[s_idx + 6 : e_idx].strip()

                    filters = []
                    if b"/ASCII85Decode" in header:
                        filters.append("/ASCII85Decode")
                    if b"/FlateDecode" in header:
                        filters.append("/FlateDecode")

                    try:
                        dec = s_data
                        for flt in filters:
                            if flt == "/ASCII85Decode":
                                dec = base64.a85decode(dec, adobe=True)
                            elif flt == "/FlateDecode":
                                dec = zlib.decompress(dec)

                        if b"BT" in dec:
                            tj_matches = re.findall(rb"\((.*?)\)\s*Tj", dec)
                            page_text = " ".join(m.decode("latin1", errors="replace") for m in tj_matches)
                            if page_text:
                                pages.append(page_text)
                    except Exception:
                        pass

            full_text = " ".join(pages)
            is_incomplete = len(full_text.strip()) == 0

            return {
                "file_path": str(file_path),
                "extracted_text": full_text,
                "token_count": len(full_text.split()),
                "has_custom_font_cmap": has_custom_cmap,
                "is_potentially_incomplete": is_incomplete,
                "pages_extracted": len(pages),
            }
        except Exception as e:
            return {
                "file_path": str(file_path),
                "extracted_text": "",
                "token_count": 0,
                "has_custom_font_cmap": False,
                "is_potentially_incomplete": True,
                "pages_extracted": 0,
                "error": str(e),
            }

    def correlate_evidence_for_user(
        self,
        user_id: str,
        identifiers: Dict[str, Set[str]],
        audit_at: str,
    ) -> List[ExtractedRecord]:
        """Search all evidence captured on or before audit_at for mentions of the user."""
        valid_files = self.get_valid_evidence_files(audit_at)
        user_emails = {e.lower() for e in (identifiers.get("emails") or set()) if e}
        user_phones = {p for p in (identifiers.get("phones") or set()) if p}
        user_ids = {u for u in (identifiers.get("user_ids") or {user_id}) if u}
        user_hashes = {h.lower() for h in (identifiers.get("hashes") or identifiers.get("email_hashes") or set()) if h}

        found_records: List[ExtractedRecord] = []

        for meta in valid_files:
            # 1. SQL Snapshot processing
            if meta.category == "databases":
                tables = self.parse_sql_snapshot(meta.absolute_path)
                for tname, rows in tables.items():
                    if tname.startswith("_") or tname == "snapshot_scope":
                        continue
                    for r in rows:
                        row_uid = str(r.get("user_id", r.get("customer_reference", r.get("subject_reference", "")))).strip()
                        row_email = str(r.get("email", r.get("requester_email", r.get("owner_email", r.get("customer_email", ""))))).strip().lower()
                        row_phone = str(r.get("phone", r.get("requester_phone", r.get("owner_phone", "")))).strip()
                        row_hash = str(r.get("email_hash", "")).strip().lower()

                        if "record_json" in r and r["record_json"]:
                            try:
                                parsed_json = json.loads(r["record_json"]) if isinstance(r["record_json"], str) else r["record_json"]
                                if isinstance(parsed_json, dict):
                                    doc = parsed_json.get("document", {}) if isinstance(parsed_json.get("document"), dict) else {}
                                    row_uid = row_uid or str(parsed_json.get("user_id", parsed_json.get("customer_reference", parsed_json.get("subject_reference", doc.get("customer_reference", doc.get("user_id", "")))))).strip()
                                    row_email = row_email or str(parsed_json.get("email", doc.get("email", ""))).strip().lower()
                                    row_phone = row_phone or str(parsed_json.get("phone", doc.get("phone", ""))).strip()
                                    row_hash = row_hash or str(parsed_json.get("email_hash", doc.get("email_hash", ""))).strip().lower()
                                    if "resource_id" in parsed_json and not r.get("resource_id"):
                                        r["resource_id"] = parsed_json["resource_id"]
                            except Exception:
                                pass

                        matched = (
                            (row_uid and row_uid in user_ids)
                            or (row_email and row_email in user_emails)
                            or (row_phone and row_phone in user_phones)
                            or (row_hash and row_hash in user_hashes)
                        )
                        if matched:
                            res_id = str(r.get("resource_id", f"{tname}_{row_uid}"))
                            status = str(r.get("account_status", "PRESENT")).upper()
                            raw_sys = r.get("origin_system", r.get("system_id", r.get("service", "")))
                            system_id = normalize_system(raw_sys or "account_service", res_id)
                            if "audit_record" in res_id or system_id == "security_service":
                                state = "PRESENT"
                            elif "tombstone" in res_id or system_id == "identity_service":
                                state = "REDACTED"
                            elif "analytics" in res_id or system_id == "analytics_platform":
                                has_pii = bool(row_email or row_phone or row_hash)
                                state = "PRESENT" if has_pii else "ANONYMIZED"
                            else:
                                state = "PRESENT" if status in ["ACTIVE", "PRESENT"] else status

                            found_records.append(
                                ExtractedRecord(
                                    evidence_id=meta.file_id,
                                    system_id=system_id,
                                    resource_id=res_id,
                                    user_id=row_uid or user_id,
                                    email=row_email or (list(user_emails)[0] if user_emails else None),
                                    phone=row_phone,
                                    record_state=state,
                                    event_timestamp=str(r.get("updated_at", meta.captured_at)),
                                    details=r,
                                    source_origin=meta.origin,
                                )
                            )

            # 2. Text and JSON Records processing
            elif meta.category == "records":
                if meta.absolute_path.suffix == ".txt":
                    try:
                        with open(meta.absolute_path, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line.startswith("-"):
                                    continue
                                parts = [p.strip() for p in line.lstrip("-").split("|")]
                                if len(parts) >= 6:
                                    ts, srv, res, cat, raw_st, lookup = parts[:6]
                                    lookup_lower = lookup.lower()
                                    matched = bool(
                                        lookup and (
                                            (lookup in user_ids)
                                            or (lookup_lower in user_emails)
                                            or (lookup in user_phones)
                                            or (lookup_lower in user_hashes)
                                        )
                                    )
                                    if matched:
                                        if raw_st in ["NOT_FOUND"]:
                                            st = "ABSENT"
                                        elif raw_st in ["FOUND", "IDENTIFIABLE"]:
                                            st = "PRESENT"
                                        elif raw_st in ["ACTIVE"]:
                                            st = "ACTIVE"
                                        elif raw_st in ["BLOCKED"]:
                                            st = "BLOCKED"
                                        elif raw_st in ["DISABLED"]:
                                            st = "DISABLED"
                                        elif raw_st in ["REDACTED"]:
                                            st = "REDACTED"
                                        elif raw_st in ["ANONYMIZED"]:
                                            st = "ANONYMIZED"
                                        else:
                                            st = "PRESENT"

                                        system_id = normalize_system(srv, res)
                                        found_records.append(
                                            ExtractedRecord(
                                                evidence_id=meta.file_id,
                                                system_id=system_id,
                                                resource_id=res,
                                                user_id=lookup if lookup in user_ids else user_id,
                                                email=lookup_lower if "@" in lookup_lower else None,
                                                phone=lookup if lookup in user_phones else None,
                                                record_state=st,
                                                event_timestamp=ts,
                                                details={"raw_status": raw_st, "category": cat},
                                                source_origin=meta.origin,
                                            )
                                        )
                    except Exception:
                        pass
                else:
                    records = self.parse_json_records(meta.absolute_path)
                    for rec in records:
                        rec_profile = rec.get("profile") if isinstance(rec.get("profile"), dict) else {}
                        rec_uid = str(rec.get("user_id", rec.get("customer_id", rec.get("customer_reference", rec.get("subject_reference", rec_profile.get("customer_reference", rec_profile.get("user_id", ""))))))).strip()
                        rec_email = str(rec.get("email", rec.get("customer_email", rec.get("owner_email", rec.get("requester_email", rec.get("query", rec_profile.get("email", ""))))))).strip().lower()
                        rec_phone = str(rec.get("phone", rec.get("owner_phone", rec.get("requester_phone", rec_profile.get("phone", ""))))).strip()
                        rec_hash = str(rec.get("email_hash", rec_profile.get("email_hash", ""))).strip().lower()
                        rec_res_id = str(rec.get("resource_id", rec.get("id", ""))).strip()

                        matched = False
                        if rec_uid and rec_uid in user_ids:
                            matched = True
                        elif rec_email and rec_email in user_emails:
                            matched = True
                        elif rec_phone and rec_phone in user_phones:
                            matched = True
                        elif rec_hash and rec_hash in user_hashes:
                            matched = True

                        if matched and rec_res_id:
                            raw_sys = rec.get("_inferred_system_id") or rec.get("origin_system", "")
                            sys_id = normalize_system(raw_sys or "account_service", rec_res_id)
                            status = str(rec.get("account_status", "PRESENT")).upper()
                            status_code = rec.get("status_code")
                            if status_code == 404:
                                rec_state = "ABSENT"
                            elif status_code == 200:
                                rec_state = "PRESENT"
                            elif "tombstone" in rec_res_id.lower() or status == "DELETED":
                                rec_state = "REDACTED" if not rec.get("email") else "PRESENT"
                            elif "audit_record" in rec_res_id.lower() or sys_id == "security_service":
                                rec_state = "PRESENT"
                            elif rec.get("restore_allowed") is False or str(rec.get("restore_allowed", "")).lower() == "false":
                                rec_state = "BLOCKED"
                            elif rec.get("enabled") is False or str(rec.get("enabled", "")).lower() == "false":
                                rec_state = "DISABLED"
                            elif "support" in sys_id.lower() or "support" in rec_res_id.lower():
                                has_pii = (
                                    bool(rec.get("requester_email"))
                                    or bool(rec.get("requester_phone"))
                                    or bool(rec.get("requester_name"))
                                    or bool(rec.get("email"))
                                    or bool(rec.get("phone"))
                                )
                                rec_state = "PRESENT" if has_pii else "REDACTED"
                            elif "analytics" in sys_id.lower() or "analytics" in rec_res_id.lower():
                                has_pii = (
                                    bool(rec.get("email"))
                                    or bool(rec.get("phone"))
                                    or bool(rec.get("correlation_key"))
                                    or bool(rec.get("email_hash"))
                                )
                                rec_state = "PRESENT" if has_pii else "ANONYMIZED"
                            else:
                                rec_state = "PRESENT" if status in ["ACTIVE", "PRESENT"] else status

                            found_records.append(
                                ExtractedRecord(
                                    evidence_id=meta.file_id,
                                    system_id=sys_id,
                                    resource_id=rec_res_id,
                                    user_id=rec_uid or user_id,
                                    email=rec_email or (list(user_emails)[0] if user_emails else None),
                                    phone=rec_phone,
                                    record_state=rec_state,
                                    event_timestamp=str(rec.get("timestamp", rec.get("updated_at", rec.get("observed_at", meta.captured_at)))),
                                    details=rec,
                                    source_origin=meta.origin,
                                )
                            )

            # 3. Log processing
            elif meta.category == "logs":
                logs = self.parse_log_file(meta.absolute_path)
                for entry in logs:
                    line_text = str(entry).lower()
                    matched_email = any(re.search(r'\b' + re.escape(e) + r'\b', line_text) for e in user_emails if e)
                    matched_uid = any(re.search(r'\b' + re.escape(u.lower()) + r'\b', line_text) for u in user_ids if u)
                    matched_hash = any(re.search(r'\b' + re.escape(h) + r'\b', line_text) for h in user_hashes if h)

                    if matched_email or matched_uid or matched_hash:
                        res_id = str(entry.get("resource_id", ""))
                        if res_id:
                            srv = normalize_system(str(entry.get("service", "account_service")), res_id)
                            rows = str(entry.get("rows", "")).strip()
                            http_status = str(entry.get("http_status", "")).strip()
                            result = str(entry.get("result", "")).strip()
                            enabled = str(entry.get("enabled", "")).strip().lower()

                            if rows == "0" or http_status == "404" or result == "miss":
                                state = "ABSENT"
                            elif enabled == "true":
                                state = "ACTIVE"
                            elif enabled == "false":
                                state = "DISABLED"
                            elif "data_flow" in res_id.lower():
                                state = "DISABLED" if enabled == "false" else "ACTIVE"
                            elif "analytics" in srv or "analytics" in res_id.lower():
                                e_val = entry.get("email")
                                p_val = entry.get("phone")
                                c_key = entry.get("correlation_key")
                                h_val = entry.get("email_hash")
                                has_id = (
                                    (e_val and e_val != "null")
                                    or (p_val and p_val != "null")
                                    or (c_key and c_key != "null")
                                    or (h_val and h_val != "null")
                                )
                                state = "PRESENT" if has_id else "ANONYMIZED"
                            elif "tombstone" in res_id.lower():
                                state = "REDACTED"
                            else:
                                state = "PRESENT"

                            found_records.append(
                                ExtractedRecord(
                                    evidence_id=meta.file_id,
                                    system_id=srv,
                                    resource_id=res_id,
                                    user_id=user_id,
                                    email=str(entry.get("email", entry.get("lookup_key", ""))),
                                    phone=str(entry.get("phone", "")),
                                    record_state=state,
                                    event_timestamp=str(entry.get("timestamp", meta.captured_at)),
                                    details=entry,
                                    source_origin=meta.origin,
                                )
                            )

            # 4. Document / PDF processing
            elif meta.category == "documents":
                pdf_res = self.parse_pdf_text_streams(meta.absolute_path)
                extracted_text = pdf_res.get("extracted_text", "").lower()
                for e in user_emails:
                    if e and e in extracted_text:
                        # Extract support reference or ID from surrounding text
                        res_match = re.search(r'(support_\d+|account_\d+|order_\d+|audit_record_\d+)', extracted_text)
                        res_id = res_match.group(1) if res_match else f"doc_{meta.file_id}"
                        srv = normalize_system("support_platform", res_id)
                        found_records.append(
                            ExtractedRecord(
                                evidence_id=meta.file_id,
                                system_id=srv,
                                resource_id=res_id,
                                user_id=user_id,
                                email=e,
                                phone=None,
                                record_state="PRESENT",
                                event_timestamp=meta.captured_at,
                                details={"source_file": meta.file_path, "is_attachment": True, "category": "SUPPORT_ATTACHMENT"},
                                source_origin=meta.origin,
                            )
                        )

            # 5. Image evidence processing via grounded catalog
            elif meta.category == "images":
                from code.audit.image_metadata import lookup_image_evidence_for_user
                image_facts = lookup_image_evidence_for_user(user_id, user_emails, audit_at)
                for fact in image_facts:
                    if fact.evidence_id == meta.file_id:
                        found_records.append(
                            ExtractedRecord(
                                evidence_id=fact.evidence_id,
                                system_id=fact.system_id,
                                resource_id=fact.resource_id,
                                user_id=fact.user_id or user_id,
                                email=fact.email,
                                phone=fact.phone,
                                record_state=fact.observed_state,
                                event_timestamp=fact.captured_at,
                                details={"supporting_snippet": fact.supporting_snippet, "title": fact.title_text},
                                source_origin=fact.origin,
                            )
                        )

        return found_records
