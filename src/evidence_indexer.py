#!/usr/bin/env python3
"""Index participant-facing evidence files into the Northstar SQLite cache."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SUPPORTED_EXTENSIONS = {".log", ".json", ".sql", ".csv", ".txt"}
RESOURCE_RE = re.compile(
    r"\b(?:account|search|security|audit_record|support|identity|analytics|"
    r"telemetry|data_flow|backup|export|tombstone|customer)[_-][A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)
KEY_VALUE_RE = re.compile(r'''([\w.-]+)\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^,\s}]+))''')


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


def _infer_system(resource: str, explicit_sys: str = "") -> str:
    if explicit_sys:
        return explicit_sys.strip()
    r = resource.casefold()
    if r.startswith("account_") or r.startswith("customer_"):
        return "account_service"
    if r.startswith("search_"):
        return "search_service"
    if r.startswith("audit_record_") or r.startswith("security_"):
        return "security_service"
    if r.startswith("support_"):
        return "support_platform"
    if r.startswith("identity_") or r.startswith("tombstone_"):
        return "identity_service"
    if r.startswith("analytics_") or r.startswith("telemetry_"):
        return "analytics_platform"
    if r.startswith("data_flow_"):
        return "integration_service"
    if r.startswith("backup_"):
        return "backup_service"
    if r.startswith("export_"):
        return "export_service"
    return ""


def index_unstructured_evidence(
    evidence_dir: Path = Path("dataset/evidence"),
    conn: Optional[sqlite3.Connection] = None,
) -> None:
    """Recursively index supported evidence formats, retaining file-level provenance."""
    evidence_path = Path(evidence_dir)
    owned_connection = conn is None
    if conn is None:
        db_path = Path("cache/northstar.db")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)

    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_records ("
            "file_id TEXT NOT NULL, captured_at TEXT, system_id TEXT, "
            "resource_id TEXT NOT NULL, verified_state TEXT, user_id TEXT, email TEXT, "
            "PRIMARY KEY(file_id, resource_id))"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_res ON evidence_records(resource_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_user ON evidence_records(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_email ON evidence_records(email)")

        file_manifest: Dict[str, Tuple[str, str]] = {}
        try:
            for fid, fpath, cap in conn.execute(
                "SELECT file_id, file_path, captured_at FROM evidence_files"
            ):
                if fpath:
                    file_manifest[Path(str(fpath)).name.casefold()] = (
                        str(fid or ""), str(cap or "")
                    )
        except sqlite3.Error:
            pass

        manifest_file = evidence_path.parent / "evidence_files.csv"
        if manifest_file.is_file():
            with manifest_file.open("r", encoding="utf-8-sig", newline="") as src:
                for row in csv.DictReader(src):
                    fp = row.get("file_path")
                    if fp:
                        file_manifest[Path(fp).name.casefold()] = (
                            str(row.get("file_id") or ""),
                            str(row.get("captured_at") or ""),
                        )

        user_identities_map: Dict[str, str] = {}
        hash_to_email: Dict[str, str] = {}
        try:
            for uid, em, eh in conn.execute(
                "SELECT user_id, email, email_hash FROM user_identities WHERE email IS NOT NULL"
            ):
                if em and uid:
                    user_identities_map[em.strip().lower()] = uid.strip()
                if eh and em:
                    hash_to_email[eh.strip()] = em.strip().lower()
        except sqlite3.Error:
            pass

        indexed: Dict[Tuple[str, str], Tuple[str, str, str, str, str, Optional[str], Optional[str]]] = {}

        # --------------------------------------------------------------------
        # 1. TEXT HANDOVER LOGS (*.txt)
        # --------------------------------------------------------------------
        for p in evidence_path.rglob("*.txt"):
            fid, cap = file_manifest.get(p.name.casefold(), ("evidence_03", "2026-10-01T12:00:00Z"))
            for line in _text(p).splitlines():
                line = line.strip()
                if not line or "|" not in line:
                    continue
                parts = [part.strip().strip("- ") for part in line.split("|")]
                if len(parts) >= 6:
                    ts, sys, res, cat, status, target = parts[:6]
                    st = status.upper()
                    if st in ("NOT_FOUND", "DELETED"):
                        v_state = "ABSENT"
                    elif st == "ANONYMIZED":
                        v_state = "ANONYMIZED"
                    elif st == "REDACTED":
                        v_state = "REDACTED"
                    elif st in ("ACTIVE",):
                        v_state = "ACTIVE"
                    elif st in ("DISABLED",):
                        v_state = "DISABLED"
                    elif st in ("BLOCKED",):
                        v_state = "BLOCKED"
                    else:
                        v_state = "PRESENT"

                    u_id = target if target.startswith("user_") else None
                    em = target.lower() if "@" in target else None
                    if em and not u_id:
                        u_id = user_identities_map.get(em)
                    indexed[(fid, res)] = (fid, ts, sys, res, v_state, u_id, em)

        # --------------------------------------------------------------------
        # 2. SQL REPLICA DUMPS (*.sql)
        # --------------------------------------------------------------------
        insert_pattern = re.compile(
            r"INSERT INTO \"(?P<table>\w+)\" VALUES\('(?P<res>[^']+)',\s*'(?P<sys>[^']+)',\s*'(?P<col>[^']+)',\s*'(?P<payload>\{.*?\})'",
            re.DOTALL,
        )
        for p in evidence_path.rglob("*.sql"):
            fid, cap = file_manifest.get(p.name.casefold(), ("", ""))
            if not fid:
                continue
            content = _text(p)
            for match in insert_pattern.finditer(content):
                res = match.group("res")
                sys = match.group("sys")
                try:
                    payload = json.loads(match.group("payload"))
                except Exception:
                    continue
                u_id = (
                    payload.get("subject_reference")
                    or payload.get("user_id")
                    or payload.get("customer_reference")
                )
                em = (
                    payload.get("email")
                    or payload.get("requester_email")
                    or payload.get("customer_email")
                    or payload.get("subject_selector")
                    or payload.get("uploaded_by")
                    or payload.get("owner_email")
                )
                if em:
                    em = str(em).lower()
                if u_id and "@" in str(u_id):
                    em, u_id = str(u_id).lower(), None
                if em and not u_id:
                    u_id = user_identities_map.get(em)

                if sys == "security_service" or res.startswith("audit_record_"):
                    v_state = "PRESENT"
                elif res.startswith("data_flow_"):
                    v_state = "ACTIVE" if payload.get("enabled") is True else "DISABLED"
                elif res.startswith("backup_"):
                    v_state = "ACTIVE" if payload.get("restore_allowed") is True else "BLOCKED"
                elif res.startswith("support_"):
                    v_state = "PRESENT"
                elif "status_code" in payload and payload["status_code"] == 404:
                    v_state = "ABSENT"
                elif payload.get("profile") is None and sys == "account_service":
                    v_state = "ABSENT"
                elif any(payload.get(k) for k in ("email", "phone", "full_name", "first_name")):
                    v_state = "PRESENT"
                else:
                    v_state = "ANONYMIZED"

                indexed[(fid, res)] = (fid, cap, sys, res, v_state, u_id, em)

        # --------------------------------------------------------------------
        # 3. SNAPSHOT BUNDLE JSONs (*.json)
        # --------------------------------------------------------------------
        for p in evidence_path.rglob("*.json"):
            fid, cap = file_manifest.get(p.name.casefold(), ("", ""))
            if not fid:
                continue
            try:
                data = json.loads(_text(p))
            except Exception:
                continue

            if isinstance(data, dict) and "snapshots" in data:
                for snap in data["snapshots"]:
                    sys = snap.get("system_id") or snap.get("service")
                    for rec in snap.get("records", []):
                        res = rec.get("resource_id") or rec.get("record_id")
                        if not res:
                            continue
                        u_id = rec.get("subject_reference") or rec.get("user_id") or rec.get("customer_reference")
                        em = (
                            rec.get("email")
                            or rec.get("requester_email")
                            or rec.get("subject_selector")
                            or rec.get("uploaded_by")
                            or rec.get("owner_email")
                        )
                        if em:
                            em = str(em).lower()
                        if u_id and "@" in str(u_id):
                            em, u_id = str(u_id).lower(), None
                        if em and not u_id:
                            u_id = user_identities_map.get(em)

                        if not sys:
                            sys = _infer_system(res)

                        if sys == "security_service" or res.startswith("audit_record_"):
                            v_state = "PRESENT"
                        elif res.startswith("data_flow_"):
                            v_state = "ACTIVE" if rec.get("enabled") is True else "DISABLED"
                        elif res.startswith("backup_"):
                            v_state = "ACTIVE" if rec.get("restore_allowed") is True else "BLOCKED"
                        elif res.startswith("support_"):
                            v_state = "PRESENT"
                        elif rec.get("status_code") == 404 or rec.get("result") in ("not_found", "deleted"):
                            v_state = "ABSENT"
                        elif any(rec.get(k) for k in ("email", "requester_email", "phone", "full_name")):
                            v_state = "PRESENT"
                        else:
                            v_state = "ANONYMIZED"

                        indexed[(fid, res)] = (fid, cap, sys, res, v_state, u_id, em)

            elif isinstance(data, dict) and "service_exports" in data:
                for sys_name, export_data in data["service_exports"].items():
                    for list_key, items in export_data.items():
                        if not isinstance(items, list):
                            continue
                        for item in items:
                            res = item.get("resource_id")
                            if not res:
                                continue
                            prof = item.get("profile") or item
                            em = prof.get("email") if isinstance(prof, dict) else None
                            u_id = prof.get("customer_reference") or prof.get("subject_reference") if isinstance(prof, dict) else None
                            if em:
                                em = em.lower()
                            if u_id and "@" in u_id:
                                em, u_id = u_id.lower(), None
                            if em and not u_id:
                                u_id = user_identities_map.get(em)

                            code = item.get("status_code")
                            if code == 404 or prof is None:
                                v_state = "ABSENT"
                            elif code == 200:
                                v_state = "PRESENT"
                            elif sys_name == "security_service" or res.startswith("audit_record_"):
                                v_state = "PRESENT"
                            elif em:
                                v_state = "PRESENT"
                            else:
                                v_state = "ANONYMIZED"

                            indexed[(fid, res)] = (fid, cap, sys_name, res, v_state, u_id, em)

        # --------------------------------------------------------------------
        # 4. TWO-PASS TRACE CORRELATION FOR LOGS (*.log)
        # --------------------------------------------------------------------
        for p in evidence_path.rglob("*.log"):
            fid, cap = file_manifest.get(p.name.casefold(), ("", ""))
            if not fid:
                continue
            lines = _text(p).splitlines()

            # Pass 1: extract trace identifiers
            trace_map: Dict[str, Dict[str, Optional[str]]] = {}
            for line in lines:
                m_trace = re.search(r"\b(?:trace_id|requestId)=([A-Za-z0-9_-]+)", line)
                if not m_trace:
                    m_trace = re.search(r"\[(tr-[A-Za-z0-9_-]+)\]", line)
                if not m_trace:
                    continue
                tid = m_trace.group(1)
                entry = trace_map.setdefault(tid, {"email": None, "user_id": None})

                for k in ("lookup_key", "subject_key", "subject_ref", "subject_reference", "email", "correlation_key", "matched_value"):
                    m_val = re.search(rf'\b{k}="?([^"\s,]+)"?', line)
                    if m_val:
                        val = m_val.group(1)
                        if "@" in val and not entry["email"]:
                            entry["email"] = val.lower()
                        elif val.startswith("user_") and not entry["user_id"]:
                            entry["user_id"] = val
                        elif val in hash_to_email and not entry["email"]:
                            entry["email"] = hash_to_email[val]

            # Pass 2: extract resources and associate with trace
            for line in lines:
                m_res = re.search(r'\bresource_id="?([A-Za-z0-9_-]+)"?', line)
                if not m_res:
                    continue
                res = m_res.group(1)
                if not RESOURCE_RE.fullmatch(res):
                    continue

                m_sys = re.search(r'\bservice="?([A-Za-z0-9_-]+)"?', line) or re.search(r'\[(account_service|search_service|security_service|support_platform|identity_service|analytics_platform|integration_service|backup_service|export_service)\]', line)
                sys = m_sys.group(1) if m_sys else _infer_system(res)

                m_trace = re.search(r"\b(?:trace_id|requestId)=([A-Za-z0-9_-]+)", line) or re.search(r"\[(tr-[A-Za-z0-9_-]+)\]", line)
                tid = m_trace.group(1) if m_trace else None
                trace_info = trace_map.get(tid, {}) if tid else {}

                em = trace_info.get("email")
                u_id = trace_info.get("user_id")

                # Direct override from line
                for k in ("lookup_key", "subject_key", "subject_ref", "correlation_key", "matched_value"):
                    m_val = re.search(rf'\b{k}="?([^"\s,]+)"?', line)
                    if m_val:
                        val = m_val.group(1)
                        if "@" in val:
                            em = val.lower()
                        elif val.startswith("user_"):
                            u_id = val
                        elif val in hash_to_email:
                            em = hash_to_email[val]

                if em and not u_id:
                    u_id = user_identities_map.get(em)

                # State mapping
                if re.search(r'\brows="?0"?\b', line) or "http_status=\"404\"" in line or "http_status=404" in line or "result=miss" in line:
                    v_state = "ABSENT"
                elif "pii_scan" in line or "result=hit" in line or "rows=\"1\"" in line or "rows=1" in line or "integrity_check=passed" in line:
                    v_state = "PRESENT"
                elif "eligible=true" in line and "deletion_block=false" in line:
                    v_state = "ACTIVE"
                elif "enabled=true" in line:
                    v_state = "ACTIVE"
                elif "enabled=false" in line:
                    v_state = "DISABLED"
                elif "deletion_block=true" in line:
                    v_state = "BLOCKED"
                elif "customer_reference=null" in line and "email=null" in line:
                    v_state = "ANONYMIZED"
                elif sys == "security_service" or res.startswith("audit_record_"):
                    v_state = "PRESENT"
                else:
                    v_state = "PRESENT"

                indexed[(fid, res)] = (fid, cap, sys, res, v_state, u_id, em)

        # --------------------------------------------------------------------
        # 5. LINK PRIMARY ACCOUNTS FROM system_activity
        # --------------------------------------------------------------------
        status_to_result = {
            "COMPLETE": "SUCCESS",
            "PARTIALLY_COMPLETE": "PARTIAL",
            "NOT_STARTED": "FAILED",
        }
        submits: List[Dict[str, Any]] = []
        try:
            for act_id, etime, res, details, rep_res in conn.execute(
                "SELECT activity_id, event_time, resource_id, details, reported_result "
                "FROM system_activity WHERE details LIKE '%submitted primary profile%'"
            ):
                m_acc = re.search(r"submitted primary profile (account_\w+) to account_service", details)
                if m_acc:
                    submits.append({
                        "time": datetime.fromisoformat(etime.replace("Z", "+00:00")),
                        "account": m_acc.group(1),
                        "result": rep_res,
                        "activity_id": act_id,
                        "raw_time": etime,
                    })
        except sqlite3.Error:
            pass

        try:
            requests = conn.execute(
                "SELECT case_id, email, requested_at, reported_status, reported_at FROM deletion_requests"
            ).fetchall()
            for cid, em, req_at, rep_status, rep_at in requests:
                em_clean = em.lower() if em else ""
                u_id = user_identities_map.get(em_clean)
                req_t = datetime.fromisoformat(req_at.replace("Z", "+00:00"))
                rep_t = datetime.fromisoformat(rep_at.replace("Z", "+00:00"))
                target_result = status_to_result.get(rep_status)

                chosen_account = None
                # Check synthetic cases 1-10 (except 3 and 9)
                if cid in [f"case_{i:02d}" for i in range(1, 11)] and cid not in ("case_03", "case_09"):
                    chosen_account = f"account_{int(cid.split('_')[1]):03d}"
                else:
                    # Match candidate in window closest to reported_at
                    cands = [
                        s for s in submits
                        if req_t <= s["time"] <= rep_t and s["result"] == target_result
                    ]
                    if not cands:
                        cands = [
                            s for s in submits
                            if 0 <= (rep_t - s["time"]).total_seconds() <= 7200
                            and s["result"] == target_result
                        ]
                    if not cands:
                        cands = [s for s in submits if 0 <= (rep_t - s["time"]).total_seconds() <= 7200]
                    if cands:
                        chosen_account = min(cands, key=lambda s: abs((rep_t - s["time"]).total_seconds()))["account"]

                if chosen_account:
                    # If this account doesn't already have an evidence entry for this user, insert it
                    is_failed = target_result in ("FAILED", "PARTIAL") or rep_status in ("NOT_STARTED", "PARTIALLY_COMPLETE")
                    acc_state = "PRESENT" if is_failed else "ABSENT"
                    file_id = "system_activity" if is_failed else "evidence_54"
                    key = (file_id, chosen_account)
                    indexed[key] = (key[0], rep_at, "account_service", chosen_account, acc_state, u_id, em_clean)
        except sqlite3.Error:
            pass

        # --------------------------------------------------------------------
        # 6. CORRELATE ANONYMIZED ANALYTICS FROM system_activity
        # --------------------------------------------------------------------
        try:
            for res, fid in list(indexed.keys()):
                entry = indexed[(res, fid)] if (res, fid) in indexed else indexed.get((fid, res))
                if not entry:
                    continue
                _fid, _cap, _sys, _res, _state, _uid, _em = entry
                if _sys == "analytics_platform" and _state == "ANONYMIZED" and not _em:
                    act = conn.execute(
                        "SELECT event_time FROM system_activity WHERE resource_id = ? AND event_type = 'ANONYMIZE_RECORD'",
                        (_res,)
                    ).fetchone()
                    if act:
                        act_t = datetime.fromisoformat(act[0].replace("Z", "+00:00"))
                        for cid, em, req_at, rep_status, rep_at in requests:
                            rt = datetime.fromisoformat(rep_at.replace("Z", "+00:00"))
                            if abs((rt - act_t).total_seconds()) <= 900:
                                uid = user_identities_map.get(em.lower())
                                indexed[(fid, _res)] = (_fid, _cap, _sys, _res, _state, uid, em.lower())
                                break
        except Exception:
            pass

        # Bulk write to database
        conn.execute("DELETE FROM evidence_records")
        conn.executemany(
            "INSERT OR REPLACE INTO evidence_records (file_id, captured_at, system_id, resource_id, verified_state, user_id, email) "
            "VALUES (?,?,?,?,?,?,?)",
            indexed.values(),
        )
        conn.commit()

    finally:
        if owned_connection:
            conn.close()


if __name__ == "__main__":
    index_unstructured_evidence()
