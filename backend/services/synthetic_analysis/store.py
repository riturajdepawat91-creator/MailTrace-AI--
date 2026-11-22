"""Durable, tenant-scoped storage for sanitized synthetic analysis reports."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from database.database import get_connection


_FORBIDDEN_KEYS = {
    "subject", "body", "body_text", "raw_email", "raw_eml", "headers",
    "attachments", "attachment_bytes", "attachment_names", "mime_payload",
}


def _report_json(report: dict[str, Any]) -> str:
    def validate(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).casefold() in _FORBIDDEN_KEYS:
                    raise ValueError("Report contains a prohibited content field.")
                validate(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                validate(child)
    validate(report)
    if report.get("synthetic_test_analysis") is not True:
        raise ValueError("Only synthetic analysis reports can be persisted.")
    return json.dumps(report, separators=(",", ":"), ensure_ascii=True)


def initialize_synthetic_analysis_reports() -> None:
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS synthetic_analysis_reports (
                analysis_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                owner_subject TEXT NOT NULL,
                idempotency_hash TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
                policy_version TEXT NOT NULL,
                report_json TEXT NOT NULL,
                delivery_status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK(delivery_status IN ('PENDING','IN_PROGRESS','RETRY_PENDING','DELIVERED','FAILED')),
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                investigation_id TEXT,
                alert_id TEXT,
                case_id TEXT,
                delivery_error_code TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, idempotency_hash)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_synthetic_report_owner ON synthetic_analysis_reports(tenant_id, owner_subject, created_at DESC)")
        connection.commit()
    finally:
        connection.close()


def make_idempotency_hash(tenant_id: str, key: str) -> str:
    return hashlib.sha256((tenant_id + "\0" + key).encode("utf-8")).hexdigest()


def create_or_get_report(tenant_id: str, owner_subject: str, idempotency_hash: str, report: dict) -> tuple[dict, bool]:
    serialized = _report_json(report)
    risk = report["risk"]
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute(
            "SELECT * FROM synthetic_analysis_reports WHERE tenant_id=? AND idempotency_hash=?",
            (tenant_id, idempotency_hash),
        ).fetchone()
        if prior:
            connection.commit()
            return _decode(prior), False
        connection.execute("""
            INSERT INTO synthetic_analysis_reports (
                analysis_id, tenant_id, owner_subject, idempotency_hash,
                verdict, score, policy_version, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report["analysis_id"], tenant_id, owner_subject, idempotency_hash,
            risk["verdict"], int(risk["score"]), risk["policy_version"], serialized,
        ))
        row = connection.execute("SELECT * FROM synthetic_analysis_reports WHERE analysis_id=?", (report["analysis_id"],)).fetchone()
        connection.commit()
        return _decode(row), True
    finally:
        connection.close()


def _decode(row) -> dict:
    result = dict(row)
    result["report"] = json.loads(result.pop("report_json"))
    return result


def get_report(analysis_id: str, tenant_id: str, owner_subject: str | None = None) -> dict | None:
    connection = get_connection()
    try:
        query = "SELECT * FROM synthetic_analysis_reports WHERE analysis_id=? AND tenant_id=?"
        args: tuple = (analysis_id, tenant_id)
        if owner_subject is not None:
            query += " AND owner_subject=?"
            args += (owner_subject,)
        row = connection.execute(query, args).fetchone()
        return _decode(row) if row else None
    finally:
        connection.close()


def claim_delivery(analysis_id: str, tenant_id: str, *, max_attempts: int = 5) -> tuple[dict | None, str]:
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM synthetic_analysis_reports WHERE analysis_id=? AND tenant_id=?",
            (analysis_id, tenant_id),
        ).fetchone()
        if row is None:
            connection.rollback()
            return None, "NOT_FOUND"
        if row["delivery_status"] == "DELIVERED":
            connection.commit()
            return _decode(row), "DELIVERED"
        if row["delivery_status"] == "IN_PROGRESS":
            stale = connection.execute("SELECT datetime(?) < datetime('now','-5 minutes')", (row["updated_at"],)).fetchone()[0]
            if not stale:
                connection.commit()
                return _decode(row), "IN_PROGRESS"
        if int(row["delivery_attempts"]) >= max_attempts:
            connection.execute("UPDATE synthetic_analysis_reports SET delivery_status='FAILED', updated_at=CURRENT_TIMESTAMP WHERE analysis_id=?", (analysis_id,))
            connection.commit()
            return _decode(connection.execute("SELECT * FROM synthetic_analysis_reports WHERE analysis_id=?", (analysis_id,)).fetchone()), "RETRY_LIMIT"
        connection.execute("""
            UPDATE synthetic_analysis_reports SET delivery_status='IN_PROGRESS',
                delivery_attempts=delivery_attempts+1, delivery_error_code=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE analysis_id=? AND tenant_id=?
        """, (analysis_id, tenant_id))
        claimed = connection.execute("SELECT * FROM synthetic_analysis_reports WHERE analysis_id=?", (analysis_id,)).fetchone()
        connection.commit()
        return _decode(claimed), "CLAIMED"
    finally:
        connection.close()


def finish_delivery(analysis_id: str, tenant_id: str, *, investigation_id: str, alert_id: str, case_id: str | None) -> None:
    connection = get_connection()
    try:
        connection.execute("""
            UPDATE synthetic_analysis_reports SET delivery_status='DELIVERED',
                investigation_id=?, alert_id=?, case_id=?, delivery_error_code=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE analysis_id=? AND tenant_id=? AND delivery_status='IN_PROGRESS'
        """, (investigation_id, alert_id, case_id, analysis_id, tenant_id))
        connection.commit()
    finally:
        connection.close()


def fail_delivery(analysis_id: str, tenant_id: str, error_code: str, *, max_attempts: int = 5) -> None:
    connection = get_connection()
    try:
        connection.execute("""
            UPDATE synthetic_analysis_reports SET delivery_status=?, delivery_error_code=?, updated_at=CURRENT_TIMESTAMP
            WHERE analysis_id=? AND tenant_id=? AND delivery_status='IN_PROGRESS'
        """, ("FAILED" if _attempts(connection, analysis_id) >= max_attempts else "RETRY_PENDING", error_code[:80], analysis_id, tenant_id))
        connection.commit()
    finally:
        connection.close()


def _attempts(connection, analysis_id: str) -> int:
    row = connection.execute("SELECT delivery_attempts FROM synthetic_analysis_reports WHERE analysis_id=?", (analysis_id,)).fetchone()
    return int(row[0]) if row else 0
