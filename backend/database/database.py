import sqlite3
import secrets
import json
import os
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timezone
from services.data_protection import (
    is_production,
    protect_investigation_row,
    protect_sensitive_value,
    reveal_sensitive_value,
    require_data_encryption_key,
)


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "mailtrace.db"


def _scope_tenant(tenant_id: str | None, *, allow_missing: bool = True) -> str | None:
    """Apply the production single-tenant boundary again at the DB layer."""
    supplied = str(tenant_id or "").strip() or None
    if not is_production():
        return supplied
    allowed = os.getenv("MAILTRACE_SINGLE_TENANT_ID", "").strip()
    if not allowed:
        raise RuntimeError("MAILTRACE_SINGLE_TENANT_ID is required for production database access.")
    if supplied is None:
        if allow_missing:
            return allowed
        raise ValueError("A verified tenant_id is required for production database writes.")
    if supplied != allowed:
        raise ValueError("The requested tenant does not match MAILTRACE_SINGLE_TENANT_ID.")
    return allowed


def _employee_email_lookup_hmac(email_address: str | None) -> str | None:
    normalized = str(email_address or "").strip().casefold()
    if not normalized:
        return None
    key = os.getenv("MAILTRACE_ROUTING_EMAIL_HMAC_KEY", "").strip()
    if len(key) < 32:
        raise ValueError("MAILTRACE_ROUTING_EMAIL_HMAC_KEY must be at least 32 characters to configure recipient-based routing.")
    return hmac.new(key.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def recipient_routing_key_configured() -> bool:
    return len(os.getenv("MAILTRACE_ROUTING_EMAIL_HMAC_KEY", "").strip()) >= 32


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# INITIALIZE DATABASE
# ==========================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            investigation_id TEXT UNIQUE NOT NULL,

            filename TEXT NOT NULL,

            subject TEXT,

            sender TEXT,

            recipient TEXT,

            smtp_recipient TEXT,

            threat_score INTEGER DEFAULT 0,

            threat_verdict TEXT,

            threat_confidence TEXT,

            analysis_json TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
    """)

    # ==========================================
    # CASES
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT '__legacy_unassigned__',
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT DEFAULT 'LOW',
            status TEXT DEFAULT 'OPEN',
            threat_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # ==========================================
    # CAMPAIGNS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            severity TEXT DEFAULT 'LOW',
            status TEXT DEFAULT 'ACTIVE',
            threat_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # ==========================================
    # CASE ↔ INVESTIGATION
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, investigation_id)
        )
    """)


    # ==========================================
    # CAMPAIGN ↔ INVESTIGATION
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS campaign_investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(campaign_id, investigation_id)
        )
    """)


    # ==========================================
    # CASE NOTES
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            note TEXT NOT NULL,
            author TEXT DEFAULT 'Analyst',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # ==========================================
    # EVIDENCE
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            investigation_id TEXT,
            evidence_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Tenant migration is deliberately fail-closed for existing production rows.
    # Development data is assigned to the local-only principal; production legacy
    # rows remain quarantined until an administrator maps them to a verified tenant.
    case_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(cases)")
    }
    if "tenant_id" not in case_columns:
        cursor.execute(
            "ALTER TABLE cases ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '__legacy_unassigned__'"
        )
    if os.getenv("MAILTRACE_ENV", "development").strip().lower() not in {"prod", "production"}:
        cursor.execute(
            "UPDATE cases SET tenant_id='local' WHERE tenant_id='__legacy_unassigned__'"
        )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_cases_tenant_status_created ON cases(tenant_id, status, created_at DESC)"
    )

    investigation_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(investigations)")
    }
    if "smtp_recipient" not in investigation_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN smtp_recipient TEXT")
    if "tenant_id" not in investigation_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN tenant_id TEXT")
    retention_columns = {
        "retention_classification": "TEXT",
        "retention_policy_id": "TEXT",
        "retention_expires_at": "TEXT",
        "retention_purge_derived": "INTEGER NOT NULL DEFAULT 0",
        "retention_purge_raw": "INTEGER NOT NULL DEFAULT 0",
        "legal_hold": "INTEGER NOT NULL DEFAULT 0",
        "forensic_hold": "INTEGER NOT NULL DEFAULT 0",
        "retention_purged_at": "TEXT",
    }
    for column, definition in retention_columns.items():
        if column not in investigation_columns:
            cursor.execute(f"ALTER TABLE investigations ADD COLUMN {column} {definition}")
    # Keep legacy records inaccessible to hosted tenants until explicitly
    # mapped. In local development they belong to the local development tenant.
    if os.getenv("MAILTRACE_ENV", "development").strip().lower() not in {"prod", "production"}:
        cursor.execute("UPDATE investigations SET tenant_id='local' WHERE tenant_id IS NULL OR tenant_id=''")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_investigations_tenant_created ON investigations(tenant_id, created_at DESC, id DESC)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_investigations_retention_due ON investigations(tenant_id, retention_expires_at, retention_purged_at)"
    )
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_retention_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            actor_subject TEXT NOT NULL,
            action TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            previous_hash TEXT,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_retention_events_tenant_investigation
        ON evidence_retention_events(tenant_id, investigation_id, id)
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_retention_events_no_update
        BEFORE UPDATE ON evidence_retention_events BEGIN
            SELECT RAISE(ABORT, 'retention events are append-only');
        END
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_retention_events_no_delete
        BEFORE DELETE ON evidence_retention_events BEGIN
            SELECT RAISE(ABORT, 'retention events are append-only');
        END
    """)
    _migrate_sensitive_investigation_fields(connection)
    connection.commit()

    connection.close()


def _migrate_sensitive_investigation_fields(connection):
    """Encrypt any legacy plaintext investigation fields before serving data."""
    configured_key = bool(
        os.getenv("MAILTRACE_DATA_ENCRYPTION_KEY", "").strip()
        or os.getenv("MAILTRACE_DATA_ENCRYPTION_KEYS_JSON", "").strip()
    )
    if is_production():
        require_data_encryption_key()
    if not configured_key:
        return

    fields = ("filename", "subject", "sender", "recipient", "smtp_recipient", "analysis_json")
    rows = connection.execute(
        "SELECT id, filename, subject, sender, recipient, smtp_recipient, analysis_json FROM investigations"
    ).fetchall()
    for row in rows:
        updates = {}
        for field in fields:
            if row[field] is None:
                continue
            protected = protect_sensitive_value(row[field], field)
            if protected != row[field]:
                updates[field] = protected
        if updates:
            assignments = ", ".join(f"{field}=?" for field in updates)
            connection.execute(
                f"UPDATE investigations SET {assignments} WHERE id=?",
                (*updates.values(), row["id"]),
            )


def _append_retention_event(connection, tenant_id, investigation_id, actor, action, details):
    previous = connection.execute(
        "SELECT event_hash FROM evidence_retention_events WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    created_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "tenant_id": tenant_id,
        "investigation_id": investigation_id,
        "actor_subject": actor,
        "action": action,
        "details": details,
        "previous_hash": previous_hash,
        "created_at": created_at,
    }
    event_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    connection.execute(
        """INSERT INTO evidence_retention_events
        (tenant_id, investigation_id, actor_subject, action, details_json, previous_hash, event_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (tenant_id, investigation_id, actor, action,
         json.dumps(details, sort_keys=True, separators=(",", ":")), previous_hash, event_hash, created_at),
    )


def get_evidence_retention_state(tenant_id: str, investigation_id: str) -> dict | None:
    connection = get_connection()
    try:
        row = connection.execute(
            """SELECT investigation_id, tenant_id, retention_classification,
               retention_policy_id, retention_expires_at, retention_purge_derived,
               retention_purge_raw, legal_hold, forensic_hold, retention_purged_at
               FROM investigations WHERE tenant_id=? AND investigation_id=?""",
            (tenant_id, investigation_id),
        ).fetchone()
        if row is None:
            return None
        events = connection.execute(
            """SELECT id, actor_subject, action, details_json, previous_hash,
               event_hash, created_at FROM evidence_retention_events
               WHERE tenant_id=? AND investigation_id=? ORDER BY id""",
            (tenant_id, investigation_id),
        ).fetchall()
        return {
            **dict(row),
            "events": [dict(event) for event in events],
            "tenant_chain_integrity": verify_evidence_retention_chain(tenant_id),
        }
    finally:
        connection.close()


def verify_evidence_retention_chain(tenant_id: str) -> dict:
    connection = get_connection()
    try:
        events = connection.execute(
            """SELECT tenant_id, investigation_id, actor_subject, action,
               details_json, previous_hash, event_hash, created_at
               FROM evidence_retention_events WHERE tenant_id=? ORDER BY id""",
            (tenant_id,),
        ).fetchall()
        previous_hash = None
        for index, row in enumerate(events, start=1):
            try:
                details = json.loads(row["details_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                return {"valid": False, "event_count": len(events), "first_invalid_event": index}
            payload = {
                "tenant_id": row["tenant_id"],
                "investigation_id": row["investigation_id"],
                "actor_subject": row["actor_subject"],
                "action": row["action"],
                "details": details,
                "previous_hash": previous_hash,
                "created_at": row["created_at"],
            }
            calculated = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                return {"valid": False, "event_count": len(events), "first_invalid_event": index}
            previous_hash = calculated
        return {"valid": True, "event_count": len(events), "first_invalid_event": None}
    finally:
        connection.close()


def set_evidence_retention_holds(
    tenant_id: str, investigation_id: str, actor: str,
    legal_hold: bool, forensic_hold: bool,
) -> dict | None:
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """SELECT legal_hold, forensic_hold, retention_purged_at FROM investigations
               WHERE tenant_id=? AND investigation_id=?""",
            (tenant_id, investigation_id),
        ).fetchone()
        if row is None:
            connection.rollback()
            return None
        if row["retention_purged_at"]:
            connection.rollback()
            raise ValueError("Retention data has already been purged; holds cannot be changed afterward.")
        prior = (bool(row["legal_hold"]), bool(row["forensic_hold"]))
        requested = (bool(legal_hold), bool(forensic_hold))
        if prior != requested:
            connection.execute(
                """UPDATE investigations SET legal_hold=?, forensic_hold=?
                   WHERE tenant_id=? AND investigation_id=? AND retention_purged_at IS NULL""",
                (int(requested[0]), int(requested[1]), tenant_id, investigation_id),
            )
            _append_retention_event(
                connection, tenant_id, investigation_id, actor,
                "HOLDS_UPDATED",
                {"legal_hold": requested[0], "forensic_hold": requested[1]},
            )
        connection.commit()
        return get_evidence_retention_state(tenant_id, investigation_id)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_retention_tenant_ids() -> list[str]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT DISTINCT tenant_id FROM investigations WHERE tenant_id IS NOT NULL AND tenant_id<>''"
        ).fetchall()
        return [str(row[0]) for row in rows]
    finally:
        connection.close()


def process_expired_derived_retention(tenant_id: str, *, purge_raw_evidence=None) -> int:
    """Apply due tenant retention actions, except held, claimed, or active-case evidence."""
    connection = get_connection()
    purged = 0
    try:
        connection.execute("BEGIN IMMEDIATE")
        due = connection.execute(
            """SELECT i.investigation_id, i.analysis_json, i.retention_policy_id,
                      i.retention_classification, i.retention_purge_derived,
                      i.retention_purge_raw, i.retention_expires_at
               FROM investigations i
               WHERE i.tenant_id=?
                 AND (i.retention_purge_derived=1 OR i.retention_purge_raw=1)
                 AND i.retention_expires_at IS NOT NULL
                 AND julianday(i.retention_expires_at)<=julianday('now')
                 AND i.legal_hold=0 AND i.forensic_hold=0
                 AND i.retention_purged_at IS NULL
                 AND NOT EXISTS (
                     SELECT 1 FROM case_investigations ci
                     JOIN cases c ON c.case_id=ci.case_id
                     WHERE ci.investigation_id=i.investigation_id
                       AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM case_investigations ci
                     JOIN case_claims cc ON cc.case_id=ci.case_id
                     WHERE ci.investigation_id=i.investigation_id
                       AND cc.tenant_id=i.tenant_id AND cc.status='ACTIVE'
                       AND datetime(cc.lease_expires_at)>datetime('now')
                 )
               ORDER BY i.retention_expires_at LIMIT 250""",
            (tenant_id,),
        ).fetchall()
        for item in due:
            investigation_id = item["investigation_id"]
            if item["retention_purge_raw"]:
                if purge_raw_evidence is None:
                    raise RuntimeError("Raw evidence purge is enabled but no custody-ledger purger is configured.")
                evidence_id = "EV-" + str(investigation_id).replace("INV-", "")
                try:
                    purge_raw_evidence(
                        evidence_id,
                        policy_id=item["retention_policy_id"],
                        reason="Configured retention period elapsed; no legal hold, forensic hold, active case, or active claim applies.",
                        expires_at_utc=item["retention_expires_at"],
                    )
                except Exception as error:
                    _append_retention_event(
                        connection, tenant_id, investigation_id, "system:retention",
                        "RAW_EVIDENCE_PURGE_FAILED",
                        {
                            "policy_id": item["retention_policy_id"],
                            "failure_type": type(error).__name__,
                            "retry_scheduled": True,
                        },
                    )
                    continue
            purged_derived = bool(item["retention_purge_derived"])
            purged_raw = bool(item["retention_purge_raw"])
            analysis = reveal_sensitive_value(item["analysis_json"], "analysis_json") or "{}"
            original_digest = hashlib.sha256(str(analysis).encode("utf-8")).hexdigest()
            purged_at = datetime.now(timezone.utc).isoformat()
            tombstone = json.dumps({
                "retention_tombstone": True,
                "purged_at_utc": purged_at,
                "policy_id": item["retention_policy_id"],
                "classification": item["retention_classification"],
                "derived_payload_sha256": original_digest,
            }, sort_keys=True, separators=(",", ":"))
            case_rows = connection.execute(
                "SELECT case_id FROM case_investigations WHERE investigation_id=?",
                (investigation_id,),
            ).fetchall()
            case_ids = [row["case_id"] for row in case_rows]
            if purged_derived:
                connection.execute(
                    """UPDATE investigations SET filename='[PURGED]', subject=NULL,
                       sender=NULL, recipient=NULL, smtp_recipient=NULL,
                       analysis_json=?, retention_purged_at=?
                       WHERE tenant_id=? AND investigation_id=?""",
                    (protect_sensitive_value(tombstone, "analysis_json"), purged_at, tenant_id, investigation_id),
                )
                connection.execute(
                    "UPDATE employee_email_reports SET reporter_email='[PURGED]', employee_note='', updated_at=CURRENT_TIMESTAMP WHERE tenant_id=? AND investigation_id=?",
                    (tenant_id, investigation_id),
                )
                connection.execute(
                    "UPDATE email_webhook_events SET policy_decision_json=NULL, last_error=NULL WHERE investigation_id=?",
                    (investigation_id,),
                )
                connection.execute("DELETE FROM evidence WHERE investigation_id=?", (investigation_id,))
                connection.execute("DELETE FROM campaign_investigations WHERE investigation_id=?", (investigation_id,))
                for case_id in case_ids:
                    connection.execute("DELETE FROM case_notes WHERE case_id=?", (case_id,))
                    connection.execute(
                        "UPDATE cases SET title=?, description='Email-derived details removed under the configured retention policy.', updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
                        (f"Retention record {case_id}", case_id, tenant_id),
                    )
            else:
                connection.execute(
                    "UPDATE investigations SET retention_purged_at=? WHERE tenant_id=? AND investigation_id=?",
                    (purged_at, tenant_id, investigation_id),
                )
            _append_retention_event(
                connection, tenant_id, investigation_id, "system:retention",
                "RETENTION_PURGE_COMPLETED",
                {
                    "purged_at_utc": purged_at,
                    "policy_id": item["retention_policy_id"],
                    "classification": item["retention_classification"],
                    "derived_payload_sha256": original_digest,
                    "derived_data_purged": purged_derived,
                    "raw_evidence_purged": purged_raw,
                    "raw_evidence_retained": not purged_raw,
                },
            )
            purged += 1
        connection.commit()
        return purged
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_email_webhook_events():
    """Create the delivery ledger used for webhook idempotency and retries."""
    connection = get_connection()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS email_webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            payload_fingerprint TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('processing', 'completed', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 1,
            lease_token TEXT,
            investigation_id TEXT,
            policy_decision_json TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(email_webhook_events)")
    }
    if "lease_token" not in columns:
        connection.execute("ALTER TABLE email_webhook_events ADD COLUMN lease_token TEXT")
    if "policy_decision_json" not in columns:
        connection.execute("ALTER TABLE email_webhook_events ADD COLUMN policy_decision_json TEXT")
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_email_webhook_events_status
        ON email_webhook_events(status, updated_at)
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS email_gateway_action_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('ALLOW', 'REVIEW', 'QUARANTINE')),
            outcome TEXT NOT NULL CHECK(outcome IN ('APPLIED', 'FAILED', 'OBSERVED')),
            gateway_message_id TEXT,
            reason_code TEXT,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(event_id, idempotency_key)
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_gateway_action_receipts_event
        ON email_gateway_action_receipts(event_id, id)
    """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_gateway_action_receipts_no_update
        BEFORE UPDATE ON email_gateway_action_receipts
        BEGIN SELECT RAISE(ABORT, 'gateway action receipts are append-only'); END
    """)
    connection.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_gateway_action_receipts_no_delete
        BEFORE DELETE ON email_gateway_action_receipts
        BEGIN SELECT RAISE(ABORT, 'gateway action receipts are append-only'); END
    """)
    connection.commit()
    connection.close()


def record_email_gateway_action(
    event_id: str,
    idempotency_key: str,
    action: str,
    outcome: str,
    gateway_message_id: str | None = None,
    reason_code: str | None = None,
) -> dict:
    """Persist a signed gateway result as an idempotent, append-only hash chain event."""
    import hashlib

    action = str(action).upper()
    outcome = str(outcome).upper()
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        delivery = connection.execute(
            "SELECT status, policy_decision_json FROM email_webhook_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if delivery is None or delivery["status"] != "completed":
            connection.rollback()
            return {"status": "not_ready"}
        try:
            decision = json.loads(delivery["policy_decision_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            connection.rollback()
            return {"status": "invalid_decision"}
        if action != decision.get("recommended_action"):
            connection.rollback()
            return {"status": "action_mismatch"}
        mode = str(decision.get("enforcement_mode", "")).upper()
        allowed_outcomes = {"APPLIED", "FAILED"} if mode == "ENFORCE" else {"OBSERVED", "FAILED"}
        if outcome not in allowed_outcomes:
            connection.rollback()
            return {"status": "outcome_mismatch"}

        prior = connection.execute(
            "SELECT * FROM email_gateway_action_receipts WHERE event_id=? AND idempotency_key=?",
            (event_id, idempotency_key),
        ).fetchone()
        comparable = (action, outcome, gateway_message_id, reason_code)
        if prior:
            stored = (prior["action"], prior["outcome"], prior["gateway_message_id"], prior["reason_code"])
            connection.rollback()
            return {"status": "duplicate" if stored == comparable else "idempotency_conflict", "receipt": dict(prior)}

        latest = connection.execute(
            "SELECT * FROM email_gateway_action_receipts WHERE event_id=? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
        if latest and latest["outcome"] == "APPLIED" and outcome != "APPLIED":
            connection.rollback()
            return {"status": "already_applied", "receipt": dict(latest)}
        previous_hash = latest["event_hash"] if latest else "0" * 64
        created_at = connection.execute("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')").fetchone()[0]
        record = {
            "event_id": event_id,
            "idempotency_key": idempotency_key,
            "action": action,
            "outcome": outcome,
            "gateway_message_id": gateway_message_id,
            "reason_code": reason_code,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        event_hash = hashlib.sha256((previous_hash + "\n" + canonical).encode("utf-8")).hexdigest()
        connection.execute(
            """INSERT INTO email_gateway_action_receipts
               (event_id, idempotency_key, action, outcome, gateway_message_id, reason_code,
                previous_hash, event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_id, idempotency_key, action, outcome, gateway_message_id, reason_code,
             previous_hash, event_hash, created_at),
        )
        row = connection.execute(
            "SELECT * FROM email_gateway_action_receipts WHERE event_id=? AND idempotency_key=?",
            (event_id, idempotency_key),
        ).fetchone()
        connection.commit()
        return {"status": "recorded", "receipt": dict(row)}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_email_gateway_action_state(event_id: str) -> dict:
    connection = get_connection()
    try:
        delivery = connection.execute(
            "SELECT policy_decision_json FROM email_webhook_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if delivery is None:
            return {"status": "not_found"}
        try:
            decision = json.loads(delivery["policy_decision_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            decision = {}
        row = connection.execute(
            "SELECT * FROM email_gateway_action_receipts WHERE event_id=? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
        if row:
            receipt = dict(row)
            return {"status": receipt["outcome"], "receipt": receipt}
        if decision.get("enforcement_mode") == "ENFORCE":
            return {"status": "PENDING_CONFIRMATION", "action": decision.get("recommended_action")}
        return {"status": "MONITOR_ONLY", "action": decision.get("recommended_action")}
    finally:
        connection.close()


def verify_email_gateway_action_chain(event_id: str) -> dict:
    """Verify receipt linkage and content hashes; reports tampering without rewriting evidence."""
    import hashlib

    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM email_gateway_action_receipts WHERE event_id=? ORDER BY id",
            (event_id,),
        ).fetchall()
        previous_hash = "0" * 64
        for index, row in enumerate(rows):
            record = {
                "event_id": row["event_id"],
                "idempotency_key": row["idempotency_key"],
                "action": row["action"],
                "outcome": row["outcome"],
                "gateway_message_id": row["gateway_message_id"],
                "reason_code": row["reason_code"],
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            expected_hash = hashlib.sha256((previous_hash + "\n" + canonical).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "event_count": len(rows),
                    "verified_count": index,
                    "first_invalid_receipt_id": row["id"],
                    "head_hash": previous_hash,
                }
            previous_hash = row["event_hash"]
        return {
            "valid": True,
            "event_count": len(rows),
            "verified_count": len(rows),
            "first_invalid_receipt_id": None,
            "head_hash": previous_hash,
        }
    finally:
        connection.close()


def begin_email_webhook_event(event_id: str, payload_fingerprint: str) -> dict:
    """Atomically claim a webhook delivery or return its existing state.

    Every active attempt owns a fresh lease token. A reclaimed or retried worker
    cannot complete or fail a delivery after a newer attempt has taken over.
    """
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        lease_token = secrets.token_urlsafe(32)
        # Keep event identifiers long enough to make ordinary provider retries
        # idempotent without turning this metadata ledger into permanent history.
        connection.execute(
            "DELETE FROM email_webhook_events WHERE created_at < datetime('now', '-30 days')"
        )
        row = connection.execute(
            "SELECT * FROM email_webhook_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()

        if row is None:
            connection.execute(
                "INSERT INTO email_webhook_events (event_id, payload_fingerprint, status, attempts, lease_token) VALUES (?, ?, 'processing', 1, ?)",
                (event_id, payload_fingerprint, lease_token),
            )
            state = {
                "event_id": event_id,
                "status": "processing",
                "attempts": 1,
                "investigation_id": None,
                "policy_decision_json": None,
                "duplicate": False,
                "retry": False,
                "lease_token": lease_token,
            }
        elif row["payload_fingerprint"] != payload_fingerprint:
            connection.rollback()
            return {"event_id": event_id, "status": "conflict", "attempts": row["attempts"]}
        elif row["status"] == "failed":
            connection.execute(
                "UPDATE email_webhook_events SET status='processing', attempts=attempts+1, lease_token=?, last_error=NULL, updated_at=CURRENT_TIMESTAMP WHERE event_id=?",
                (lease_token, event_id),
            )
            state = {
                "event_id": event_id,
                "status": "processing",
                "attempts": row["attempts"] + 1,
                "investigation_id": None,
                "policy_decision_json": None,
                "duplicate": True,
                "retry": True,
                "lease_token": lease_token,
            }
        elif row["status"] == "processing":
            is_stale = connection.execute(
                "SELECT datetime(?) < datetime('now', '-10 minutes')",
                (row["updated_at"],),
            ).fetchone()[0]
            if is_stale:
                connection.execute(
                    "UPDATE email_webhook_events SET attempts=attempts+1, lease_token=?, updated_at=CURRENT_TIMESTAMP WHERE event_id=?",
                    (lease_token, event_id),
                )
                state = {
                    "event_id": event_id,
                    "status": "processing",
                    "attempts": row["attempts"] + 1,
                    "investigation_id": None,
                    "policy_decision_json": None,
                    "duplicate": True,
                    "retry": True,
                    "lease_token": lease_token,
                }
            else:
                state = {
                    "event_id": event_id,
                    "status": row["status"],
                    "attempts": row["attempts"],
                    "investigation_id": row["investigation_id"],
                    "policy_decision_json": row["policy_decision_json"],
                    "duplicate": True,
                    "retry": False,
                }
        else:
            state = {
                "event_id": event_id,
                "status": row["status"],
                "attempts": row["attempts"],
                "investigation_id": row["investigation_id"],
                "policy_decision_json": row["policy_decision_json"],
                "duplicate": True,
                "retry": False,
            }

        connection.commit()
        return state
    finally:
        connection.close()


def initialize_email_alerts():
    """Create the durable alert ledger linked to webhook investigations."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS email_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                event_id TEXT UNIQUE NOT NULL,
                investigation_id TEXT NOT NULL,
                case_id TEXT,
                severity TEXT NOT NULL CHECK(severity IN ('MEDIUM', 'HIGH', 'CRITICAL')),
                threat_score INTEGER NOT NULL,
                confidence TEXT NOT NULL,
                policy_version TEXT NOT NULL DEFAULT 'unknown',
                recommended_action TEXT NOT NULL,
                user_notice_json TEXT,
                status TEXT NOT NULL DEFAULT 'NEW'
                    CHECK(status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED')),
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                resolved_by TEXT,
                resolved_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS email_alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_email_alert_events_alert
            ON email_alert_events(alert_id, id)
        """)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(email_alerts)")
        }
        if "case_id" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN case_id TEXT")
        if "user_notice_json" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN user_notice_json TEXT")
        if "resolved_by" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN resolved_by TEXT")
        if "resolved_at" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN resolved_at TEXT")
        if "policy_version" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN policy_version TEXT NOT NULL DEFAULT 'unknown'")
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_email_alerts_status_created
            ON email_alerts(status, created_at DESC)
        """)
        connection.commit()
    finally:
        connection.close()


def initialize_employee_email_reports():
    """Create employee-scoped report records and append-only report events."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS employee_email_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                reporter_subject TEXT NOT NULL,
                reporter_email TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                employee_note TEXT NOT NULL DEFAULT '',
                incident_type TEXT NOT NULL CHECK(incident_type IN (
                    'suspicious', 'clicked_link', 'opened_attachment',
                    'shared_credentials', 'made_payment'
                )),
                priority TEXT NOT NULL CHECK(priority IN ('NORMAL', 'HIGH', 'CRITICAL')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, reporter_subject, investigation_id)
            )
        """)
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(employee_email_reports)")
        }
        if "employee_note" not in columns:
            connection.execute(
                "ALTER TABLE employee_email_reports ADD COLUMN employee_note TEXT NOT NULL DEFAULT ''"
            )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS employee_email_report_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_employee_reports_owner_created
            ON employee_email_reports(tenant_id, reporter_subject, created_at DESC)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_employee_report_events_report
            ON employee_email_report_events(tenant_id, report_id, id)
        """)
        connection.commit()
    finally:
        connection.close()


def initialize_case_claims():
    """Create single-owner, expiring SOC case claims and their audit history."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_claims (
                case_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                assigned_analyst TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'RELEASED', 'EXPIRED')),
                claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                lease_expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_claim_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_claim_rate_limits (
                tenant_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                window_bucket INTEGER NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(tenant_id, actor_subject, action)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_claim_idempotency (
                tenant_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                operation TEXT NOT NULL CHECK(operation IN ('CLAIM', 'RENEW', 'RELEASE')),
                idempotency_key TEXT NOT NULL,
                succeeded INTEGER NOT NULL CHECK(succeeded IN (0, 1)),
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(tenant_id, case_id, actor_subject, operation, idempotency_key)
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_case_claims_owner_status
            ON case_claims(tenant_id, assigned_analyst, status, lease_expires_at)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_case_claim_events_case
            ON case_claim_events(tenant_id, case_id, id)
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_claim_events_no_update
            BEFORE UPDATE ON case_claim_events
            BEGIN SELECT RAISE(ABORT, 'case claim audit events are append-only'); END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_claim_events_no_delete
            BEFORE DELETE ON case_claim_events
            BEGIN SELECT RAISE(ABORT, 'case claim audit events are append-only'); END
        """)
        connection.commit()
    finally:
        connection.close()


def initialize_case_audit():
    """Create an append-only hash-chained audit ledger for SOC case changes."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT,
                changed_fields_json TEXT NOT NULL DEFAULT '[]',
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_case_audit_tenant_case
            ON case_audit_events(tenant_id, case_id, id)
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_audit_events_no_update
            BEFORE UPDATE ON case_audit_events
            BEGIN SELECT RAISE(ABORT, 'case audit events are append-only'); END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_audit_events_no_delete
            BEFORE DELETE ON case_audit_events
            BEGIN SELECT RAISE(ABORT, 'case audit events are append-only'); END
        """)
        connection.commit()
    finally:
        connection.close()


def append_case_audit_event(
    connection,
    tenant_id: str,
    case_id: str,
    actor_subject: str,
    action: str,
    *,
    from_status: str | None = None,
    to_status: str | None = None,
    changed_fields: list[str] | None = None,
) -> dict:
    """Append an actor-attributed case event in the caller's transaction."""
    import hashlib

    prior = connection.execute(
        "SELECT event_hash FROM case_audit_events WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    previous_hash = prior["event_hash"] if prior else "0" * 64
    created_at = connection.execute("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')").fetchone()[0]
    fields_json = json.dumps(sorted(set(changed_fields or [])), separators=(",", ":"))
    record = {
        "tenant_id": tenant_id,
        "case_id": case_id,
        "actor_subject": actor_subject,
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "changed_fields_json": fields_json,
        "previous_hash": previous_hash,
        "created_at": created_at,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    event_hash = hashlib.sha256((previous_hash + "\n" + canonical).encode("utf-8")).hexdigest()
    cursor = connection.execute(
        """INSERT INTO case_audit_events
           (tenant_id, case_id, actor_subject, action, from_status, to_status,
            changed_fields_json, previous_hash, event_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (tenant_id, case_id, actor_subject, action, from_status, to_status,
         fields_json, previous_hash, event_hash, created_at),
    )
    return {**record, "id": cursor.lastrowid, "event_hash": event_hash}


def verify_case_audit_chain(tenant_id: str) -> dict:
    """Verify the tenant's complete case-change hash chain."""
    import hashlib

    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM case_audit_events WHERE tenant_id=? ORDER BY id",
            (tenant_id,),
        ).fetchall()
        previous_hash = "0" * 64
        for index, row in enumerate(rows):
            record = {
                "tenant_id": row["tenant_id"],
                "case_id": row["case_id"],
                "actor_subject": row["actor_subject"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "changed_fields_json": row["changed_fields_json"],
                "previous_hash": row["previous_hash"],
                "created_at": row["created_at"],
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            expected_hash = hashlib.sha256((previous_hash + "\n" + canonical).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "event_count": len(rows),
                    "verified_count": index,
                    "first_invalid_event_id": row["id"],
                    "head_hash": previous_hash,
                }
            previous_hash = row["event_hash"]
        return {
            "valid": True,
            "event_count": len(rows),
            "verified_count": len(rows),
            "first_invalid_event_id": None,
            "head_hash": previous_hash,
        }
    finally:
        connection.close()


def get_case_audit_events(tenant_id: str, case_id: str) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """SELECT id, tenant_id, case_id, actor_subject, action, from_status,
                      to_status, changed_fields_json, previous_hash, event_hash, created_at
               FROM case_audit_events WHERE tenant_id=? AND case_id=? ORDER BY id""",
            (tenant_id, case_id),
        ).fetchall()
        events = [dict(row) for row in rows]
        for event in events:
            try:
                event["changed_fields"] = json.loads(event.pop("changed_fields_json") or "[]")
            except (TypeError, json.JSONDecodeError):
                event["changed_fields"] = []
        return events
    finally:
        connection.close()


def allow_soc_action(tenant_id: str, actor_subject: str, action: str, *, limit: int = 30, window_seconds: int = 60) -> bool:
    """Atomic SQLite-backed per-tenant/actor/action rate limiter shared by workers."""
    limit = max(1, min(int(limit), 10000))
    window_seconds = max(1, min(int(window_seconds), 3600))
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        bucket = int(connection.execute(
            "SELECT CAST(strftime('%s','now') AS INTEGER) / ?", (window_seconds,)
        ).fetchone()[0])
        connection.execute("""
            INSERT INTO case_claim_rate_limits(tenant_id, actor_subject, action, window_bucket, request_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(tenant_id, actor_subject, action) DO UPDATE SET
                request_count=CASE WHEN case_claim_rate_limits.window_bucket=excluded.window_bucket
                    THEN case_claim_rate_limits.request_count+1 ELSE 1 END,
                window_bucket=excluded.window_bucket, updated_at=CURRENT_TIMESTAMP
        """, (tenant_id, actor_subject, action, bucket))
        count = connection.execute(
            "SELECT request_count FROM case_claim_rate_limits WHERE tenant_id=? AND actor_subject=? AND action=?",
            (tenant_id, actor_subject, action),
        ).fetchone()[0]
        connection.commit()
        return int(count) <= limit
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _touch_case_routing(connection, tenant_id: str, case_id: str):
    """Keep routing ownership aligned with the authoritative claim lease.

    Claims and routing are separate records for audit and queueing, but the UI
    consumes both. Update them in the same transaction as claim/release/renew so
    a successful claim cannot continue to appear unassigned in the SOC queue.
    """
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_routing'"
    ).fetchone()
    if not exists:
        return
    claim = connection.execute(
        """SELECT assigned_analyst FROM case_claims
           WHERE tenant_id=? AND case_id=? AND status='ACTIVE'
             AND datetime(lease_expires_at)>datetime('now')""",
        (tenant_id, case_id),
    ).fetchone()
    owner = claim["assigned_analyst"] if claim else None
    if owner:
        connection.execute(
            """UPDATE case_routing
               SET assigned_analyst=?, status='ASSIGNED',
                   routing_reason=CASE WHEN routing_reason LIKE '%preserved_active_claim_owner%'
                                       THEN routing_reason ELSE routing_reason || ';active_claim_owner' END,
                   assigned_at=COALESCE(assigned_at,CURRENT_TIMESTAMP),
                   last_activity_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
               WHERE tenant_id=? AND case_id=?""",
            (owner, tenant_id, case_id),
        )
    else:
        connection.execute(
            """UPDATE case_routing
               SET assigned_analyst=NULL,
                   status=CASE WHEN status='UNROUTED' THEN status ELSE 'QUEUED' END,
                   routing_reason=CASE WHEN routing_reason LIKE '%active_claim_owner%'
                                       THEN replace(routing_reason, ';active_claim_owner', '')
                                       ELSE routing_reason END,
                   last_activity_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
               WHERE tenant_id=? AND case_id=?
                 AND (assigned_analyst IS NULL OR assigned_analyst IN
                      (SELECT assigned_analyst FROM case_claims WHERE tenant_id=? AND case_id=?))""",
            (tenant_id, case_id, tenant_id, case_id),
        )


def _replay_case_claim_request(connection, tenant_id, case_id, actor_subject, operation, idempotency_key):
    key = str(idempotency_key or "").strip()
    if not key:
        return None
    row = connection.execute("""
        SELECT succeeded, result_json FROM case_claim_idempotency
        WHERE tenant_id=? AND case_id=? AND actor_subject=? AND operation=? AND idempotency_key=?
    """, (tenant_id, case_id, actor_subject, operation, key)).fetchone()
    if row is None:
        return None
    return json.loads(row["result_json"]), bool(row["succeeded"])


def _remember_case_claim_request(connection, tenant_id, case_id, actor_subject, operation, idempotency_key, result, succeeded):
    key = str(idempotency_key or "").strip()
    if not key:
        return
    if len(key) > 128:
        raise ValueError("Idempotency-Key must be 128 characters or fewer.")
    connection.execute("""
        INSERT OR IGNORE INTO case_claim_idempotency
            (tenant_id, case_id, actor_subject, operation, idempotency_key, succeeded, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tenant_id, case_id, actor_subject, operation, key, int(bool(succeeded)),
          json.dumps(result, separators=(",", ":"))))


def claim_case_for_analyst(
    case_id: str,
    tenant_id: str,
    analyst_subject: str,
    lease_minutes: int | None = None,
    reason: str = "not_provided",
    idempotency_key: str | None = None,
) -> tuple[dict | None, bool]:
    """Atomically claim/renew a case; at most one analyst owns an unexpired lease."""
    configured_lease = os.getenv("MAILTRACE_CASE_CLAIM_LEASE_MINUTES", "20")
    try:
        configured_lease = int(configured_lease)
    except (TypeError, ValueError):
        configured_lease = 20
    lease_minutes = max(5, min(60, int(lease_minutes if lease_minutes is not None else configured_lease)))
    reason = str(reason or "not_provided").strip()[:300] or "not_provided"
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not connection.execute(
            "SELECT 1 FROM cases WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)
        ).fetchone():
            connection.rollback()
            return None, False

        replay = _replay_case_claim_request(
            connection, tenant_id, case_id, analyst_subject, "CLAIM", idempotency_key
        )
        if replay is not None:
            connection.commit()
            return replay
        current = connection.execute("""
            SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?
        """, (case_id, tenant_id)).fetchone()
        route_table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_routing'").fetchone()
        if route_table:
            route = connection.execute(
                "SELECT assigned_analyst FROM case_routing WHERE case_id=? AND tenant_id=?",
                (case_id, tenant_id),
            ).fetchone()
            if route and route["assigned_analyst"] and route["assigned_analyst"] != analyst_subject:
                claim_live = bool(current and current["status"] == "ACTIVE" and connection.execute(
                    "SELECT datetime(?) > datetime('now')", (current["lease_expires_at"],)
                ).fetchone()[0])
                # The current owner may renew their own claim. An expired lease can
                # be reclaimed by any eligible analyst; otherwise routing is authoritative.
                if not claim_live and not (current and current["status"] == "ACTIVE"):
                    raise PermissionError(f"Case is assigned to {route['assigned_analyst']}; an authorized SOC lead must reassign it first.")
        if current and current["status"] == "ACTIVE":
            lease_valid = connection.execute(
                "SELECT datetime(?) > datetime('now')",
                (current["lease_expires_at"],),
            ).fetchone()[0]
            if lease_valid and current["assigned_analyst"] != analyst_subject:
                conflict = dict(current)
                _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "CLAIM", idempotency_key, conflict, False)
                connection.commit()
                return conflict, False
            if lease_valid:
                connection.execute("""
                    UPDATE case_claims
                    SET lease_expires_at=datetime('now', ?), updated_at=CURRENT_TIMESTAMP
                    WHERE case_id=? AND tenant_id=? AND assigned_analyst=? AND status='ACTIVE'
                """, (f"+{lease_minutes} minutes", case_id, tenant_id, analyst_subject))
                action = "RENEWED"
            else:
                connection.execute("""
                    UPDATE case_claims
                    SET assigned_analyst=?, status='ACTIVE', claimed_at=CURRENT_TIMESTAMP,
                        lease_expires_at=datetime('now', ?), updated_at=CURRENT_TIMESTAMP
                    WHERE case_id=? AND tenant_id=?
                """, (analyst_subject, f"+{lease_minutes} minutes", case_id, tenant_id))
                action = "RECLAIMED_EXPIRED"
        else:
            connection.execute("""
                INSERT INTO case_claims (
                    case_id, tenant_id, assigned_analyst, status, claimed_at, lease_expires_at
                ) VALUES (?, ?, ?, 'ACTIVE', CURRENT_TIMESTAMP, datetime('now', ?))
                ON CONFLICT(case_id) DO UPDATE SET
                    tenant_id=excluded.tenant_id,
                    assigned_analyst=excluded.assigned_analyst,
                    status='ACTIVE',
                    claimed_at=CURRENT_TIMESTAMP,
                    lease_expires_at=excluded.lease_expires_at,
                    updated_at=CURRENT_TIMESTAMP
            """, (case_id, tenant_id, analyst_subject, f"+{lease_minutes} minutes"))
            action = "CLAIMED"

        connection.execute("""
            INSERT INTO case_claim_events (case_id, tenant_id, actor_subject, action, details_json)
            VALUES (?, ?, ?, ?, ?)
        """, (
            case_id, tenant_id, analyst_subject, action,
            json.dumps({"lease_minutes": lease_minutes, "reason": reason}, separators=(",", ":")),
        ))
        assignment = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        assignment_result = dict(assignment)
        _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "CLAIM", idempotency_key, assignment_result, True)
        _touch_case_routing(connection, tenant_id, case_id)
        connection.commit()
        return assignment_result, True
    finally:
        connection.close()


def renew_case_claim(
    case_id: str,
    tenant_id: str,
    analyst_subject: str,
    lease_minutes: int | None = None,
    reason: str = "not_provided",
    idempotency_key: str | None = None,
) -> tuple[dict | None, bool]:
    """Renew only an existing, unexpired claim owned by the caller."""
    configured_lease = os.getenv("MAILTRACE_CASE_CLAIM_LEASE_MINUTES", "20")
    try:
        configured_lease = int(configured_lease)
    except (TypeError, ValueError):
        configured_lease = 20
    lease_minutes = max(5, min(60, int(lease_minutes if lease_minutes is not None else configured_lease)))
    reason = str(reason or "not_provided").strip()[:300] or "not_provided"
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        replay = _replay_case_claim_request(
            connection, tenant_id, case_id, analyst_subject, "RENEW", idempotency_key
        )
        if replay is not None:
            connection.commit()
            return replay
        current = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        if current is None:
            connection.rollback()
            return None, False
        valid = connection.execute(
            "SELECT datetime(?) > datetime('now')",
            (current["lease_expires_at"],),
        ).fetchone()[0]
        if current["status"] != "ACTIVE" or not valid or current["assigned_analyst"] != analyst_subject:
            result = dict(current)
            _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "RENEW", idempotency_key, result, False)
            connection.commit()
            return result, False
        connection.execute("""
            UPDATE case_claims
            SET lease_expires_at=datetime('now', ?), updated_at=CURRENT_TIMESTAMP
            WHERE case_id=? AND tenant_id=? AND assigned_analyst=? AND status='ACTIVE'
              AND datetime(lease_expires_at) > datetime('now')
        """, (f"+{lease_minutes} minutes", case_id, tenant_id, analyst_subject))
        connection.execute("""
            INSERT INTO case_claim_events (case_id, tenant_id, actor_subject, action, details_json)
            VALUES (?, ?, ?, 'RENEWED', ?)
        """, (case_id, tenant_id, analyst_subject,
              json.dumps({"lease_minutes": lease_minutes, "reason": reason}, separators=(",", ":"))))
        renewed = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        result = dict(renewed)
        _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "RENEW", idempotency_key, result, True)
        _touch_case_routing(connection, tenant_id, case_id)
        connection.commit()
        return result, True
    finally:
        connection.close()


def release_case_claim(
    case_id: str, tenant_id: str, analyst_subject: str, reason: str = "not_provided",
    idempotency_key: str | None = None,
) -> tuple[dict | None, bool]:
    """Release only the caller's unexpired claim and preserve a release audit event."""
    reason = str(reason or "not_provided").strip()[:300] or "not_provided"
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        replay = _replay_case_claim_request(
            connection, tenant_id, case_id, analyst_subject, "RELEASE", idempotency_key
        )
        if replay is not None:
            connection.commit()
            return replay
        current = connection.execute("""
            SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?
        """, (case_id, tenant_id)).fetchone()
        if current is None:
            connection.rollback()
            return None, False
        lease_valid = connection.execute(
            "SELECT datetime(?) > datetime('now')",
            (current["lease_expires_at"],),
        ).fetchone()[0]
        if current["status"] != "ACTIVE" or not lease_valid or current["assigned_analyst"] != analyst_subject:
            result = dict(current)
            _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "RELEASE", idempotency_key, result, False)
            connection.commit()
            return result, False
        connection.execute("""
            UPDATE case_claims
            SET status='RELEASED', updated_at=CURRENT_TIMESTAMP
            WHERE case_id=? AND tenant_id=? AND assigned_analyst=? AND status='ACTIVE'
        """, (case_id, tenant_id, analyst_subject))
        connection.execute("""
            INSERT INTO case_claim_events (case_id, tenant_id, actor_subject, action, details_json)
            VALUES (?, ?, ?, 'RELEASED', ?)
        """, (
            case_id, tenant_id, analyst_subject,
            json.dumps({"reason": reason}, separators=(",", ":")),
        ))
        released = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        result = dict(released)
        _remember_case_claim_request(connection, tenant_id, case_id, analyst_subject, "RELEASE", idempotency_key, result, True)
        _touch_case_routing(connection, tenant_id, case_id)
        connection.commit()
        return result, True
    finally:
        connection.close()


def submit_employee_email_report(
    tenant_id: str,
    reporter_subject: str,
    reporter_email: str,
    investigation_id: str,
    incident_type: str,
    employee_note: str = "",
    hourly_limit: int = 10,
) -> tuple[dict, bool] | None:
    """Create or safely deduplicate an employee report and linked SOC case.

    Returns ``None`` when the reporter exceeded the hourly new-report limit.
    Re-reporting an existing email is idempotent and may only raise its priority.
    """
    priorities = {
        "suspicious": ("NORMAL", "LOW"),
        "clicked_link": ("HIGH", "HIGH"),
        "opened_attachment": ("HIGH", "HIGH"),
        "shared_credentials": ("CRITICAL", "CRITICAL"),
        "made_payment": ("CRITICAL", "CRITICAL"),
    }
    if incident_type not in priorities:
        raise ValueError("Unsupported employee incident type.")
    priority, case_severity = priorities[incident_type]
    employee_note = str(employee_note or "").strip()[:1000]
    priority_rank = {"NORMAL": 1, "HIGH": 2, "CRITICAL": 3}
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute("""
            SELECT * FROM employee_email_reports
            WHERE tenant_id=? AND reporter_subject=? AND investigation_id=?
        """, (tenant_id, reporter_subject, investigation_id)).fetchone()
        recent_activity = connection.execute("""
            SELECT COUNT(*) FROM employee_email_report_events
            WHERE tenant_id=? AND actor_subject=?
              AND created_at >= datetime('now', '-1 hour')
        """, (tenant_id, reporter_subject)).fetchone()[0]
        if int(recent_activity) >= max(1, min(100, int(hourly_limit) * 3)):
            connection.rollback()
            return None
        if existing:
            previous_priority = existing["priority"]
            escalated = priority_rank[priority] > priority_rank.get(previous_priority, 0)
            case_row = connection.execute(
                "SELECT severity, status, description FROM cases WHERE case_id=? AND tenant_id=?",
                (existing["case_id"], tenant_id),
            ).fetchone()
            if escalated:
                connection.execute("""
                    UPDATE employee_email_reports
                    SET incident_type=?, priority=?, updated_at=CURRENT_TIMESTAMP
                    WHERE report_id=? AND tenant_id=?
                """, (incident_type, priority, existing["report_id"], tenant_id))
            if case_row:
                case_severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                case_updates = []
                if case_severity_rank.get(case_severity, 0) > case_severity_rank.get(str(case_row["severity"]).upper(), 0):
                    case_updates.append("severity=?")
                if str(case_row["status"]).upper() in {"CLOSED", "RESOLVED"}:
                    case_updates.append("status='OPEN'")
                if case_updates:
                    update_values = ([case_severity] if "severity=?" in case_updates else [])
                    update_values.extend([existing["case_id"], tenant_id])
                    connection.execute(
                        f"UPDATE cases SET {', '.join(case_updates)}, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
                        tuple(update_values),
                    )
                changed_case_fields = []
                if "severity=?" in case_updates:
                    changed_case_fields.append("severity")
                if "status='OPEN'" in case_updates:
                    changed_case_fields.append("status")
                if changed_case_fields:
                    append_case_audit_event(
                        connection, tenant_id, existing["case_id"], reporter_subject,
                        "EMPLOYEE_REPORT_ESCALATION",
                        from_status=str(case_row["status"] or "OPEN").upper(),
                        to_status=("OPEN" if "status='OPEN'" in case_updates else str(case_row["status"] or "OPEN").upper()),
                        changed_fields=changed_case_fields,
                    )
            report_summary = f"Employee report: {reporter_email} reported {incident_type}."
            if employee_note:
                report_summary += f" Employee context: {employee_note}"
            prior_description = str(case_row["description"] or "") if case_row else ""
            if report_summary not in prior_description:
                connection.execute("""
                    UPDATE cases
                    SET description=?, updated_at=CURRENT_TIMESTAMP
                    WHERE case_id=? AND tenant_id=?
                """, (
                    (prior_description + "\n\n" + report_summary).strip(),
                    existing["case_id"],
                    tenant_id,
                ))
                if employee_note:
                    prior_notes = str(existing["employee_note"] or "")
                    combined_notes = (prior_notes + "\n\n" + employee_note).strip()
                    connection.execute("""
                        UPDATE employee_email_reports
                        SET employee_note=?, updated_at=CURRENT_TIMESTAMP
                        WHERE report_id=? AND tenant_id=?
                    """, (combined_notes[:2000], existing["report_id"], tenant_id))
                append_case_audit_event(
                    connection, tenant_id, existing["case_id"], reporter_subject,
                    "EMPLOYEE_REPORT_UPDATED",
                    from_status=str(case_row["status"] or "OPEN") if case_row else None,
                    to_status=str(case_row["status"] or "OPEN") if case_row else None,
                    changed_fields=["employee_report"] + (["employee_context"] if employee_note else []),
                )
            connection.execute("""
                INSERT INTO employee_email_report_events
                    (report_id, tenant_id, actor_subject, action, details_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                existing["report_id"], tenant_id, reporter_subject,
                "ESCALATED_BY_REPEAT_REPORT" if escalated else "DUPLICATE_REPORT",
                json.dumps({"incident_type": incident_type, "priority": priority, "has_note": bool(employee_note)}, separators=(",", ":")),
            ))
            row = connection.execute("""
                SELECT r.report_id, r.investigation_id, r.case_id, r.incident_type,
                       r.priority, c.status, r.created_at, r.updated_at
                FROM employee_email_reports r
                JOIN cases c ON c.case_id = r.case_id
                WHERE r.report_id=? AND r.tenant_id=?
            """, (existing["report_id"], tenant_id)).fetchone()
            connection.commit()
            return dict(row), False

        recent_count = connection.execute("""
            SELECT COUNT(*) FROM employee_email_reports
            WHERE tenant_id=? AND reporter_subject=?
              AND created_at >= datetime('now', '-1 hour')
        """, (tenant_id, reporter_subject)).fetchone()[0]
        if int(recent_count) >= max(1, min(100, int(hourly_limit))):
            connection.rollback()
            return None

        report_id = "RPT-" + secrets.token_hex(6).upper()
        linked_case = connection.execute("""
            SELECT c.case_id, c.severity, c.status
            FROM cases c
            JOIN case_investigations ci ON ci.case_id = c.case_id
            WHERE ci.investigation_id = ? AND c.tenant_id=?
            ORDER BY c.created_at ASC, c.id ASC
            LIMIT 1
        """, (investigation_id, tenant_id)).fetchone()
        case_id = linked_case["case_id"] if linked_case else "CASE-" + secrets.token_hex(5).upper()
        connection.execute("""
            INSERT OR IGNORE INTO cases (case_id, tenant_id, title, description, severity, status, threat_score)
            VALUES (?, ?, ?, ?, ?, 'OPEN', 0)
        """, (
            case_id,
            tenant_id,
            f"Employee reported email incident — {investigation_id}",
            f"Employee {reporter_email} reported {incident_type} for investigation {investigation_id}."
            + (f"\n\nEmployee context: {employee_note}" if employee_note else ""),
            case_severity,
        ))
        case_updates = []
        if linked_case:
            case_severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if case_severity_rank.get(case_severity, 0) > case_severity_rank.get(str(linked_case["severity"]).upper(), 0):
                case_updates.append("severity=?")
            if str(linked_case["status"]).upper() in {"CLOSED", "RESOLVED"}:
                case_updates.append("status='OPEN'")
            if case_updates:
                update_values = ([case_severity] if "severity=?" in case_updates else [])
                update_values.extend([case_id, tenant_id])
                connection.execute(
                    f"UPDATE cases SET {', '.join(case_updates)}, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
                    tuple(update_values),
                )
        current_description = connection.execute(
            "SELECT description FROM cases WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)
        ).fetchone()
        report_summary = f"Employee report: {reporter_email} reported {incident_type}."
        if employee_note:
            report_summary += f" Employee context: {employee_note}"
        prior_description = str(current_description["description"] or "") if current_description else ""
        if report_summary not in prior_description:
            connection.execute("""
                UPDATE cases
                SET description=?, updated_at=CURRENT_TIMESTAMP
                WHERE case_id=? AND tenant_id=?
            """, ((prior_description + "\n\n" + report_summary).strip(), case_id, tenant_id))
        connection.execute("""
            INSERT OR IGNORE INTO case_investigations (case_id, investigation_id)
            VALUES (?, ?)
        """, (case_id, investigation_id))
        connection.execute("""
            INSERT INTO employee_email_reports (
                report_id, tenant_id, reporter_subject, reporter_email,
                investigation_id, case_id, employee_note, incident_type, priority
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_id, tenant_id, reporter_subject, reporter_email.lower(),
            investigation_id, case_id, employee_note, incident_type, priority,
        ))
        connection.execute("""
            INSERT INTO employee_email_report_events
                (report_id, tenant_id, actor_subject, action, details_json)
            VALUES (?, ?, ?, 'SUBMITTED', ?)
        """, (
            report_id, tenant_id, reporter_subject,
            json.dumps({"incident_type": incident_type, "priority": priority, "has_note": bool(employee_note)}, separators=(",", ":")),
        ))
        audit_action = "EMPLOYEE_REPORT_CASE_CREATED" if not linked_case else "EMPLOYEE_REPORT_LINKED_TO_CASE"
        audit_fields = ["employee_report", "investigation_link"]
        if linked_case and case_updates:
            audit_fields.extend(
                field for field, changed in (("severity", "severity=?" in case_updates), ("status", "status='OPEN'" in case_updates))
                if changed
            )
        prior_case_status = str(linked_case["status"] or "OPEN").upper() if linked_case else None
        resulting_case_status = (
            "OPEN"
            if linked_case and "status='OPEN'" in case_updates
            else prior_case_status if linked_case else "OPEN"
        )
        append_case_audit_event(
            connection, tenant_id, case_id, reporter_subject, audit_action,
            from_status=prior_case_status,
            to_status=resulting_case_status,
            changed_fields=audit_fields,
        )
        row = connection.execute("""
            SELECT r.report_id, r.investigation_id, r.case_id, r.incident_type,
                   r.priority, c.status, r.created_at, r.updated_at
            FROM employee_email_reports r
            JOIN cases c ON c.case_id = r.case_id
            WHERE r.report_id=? AND r.tenant_id=?
        """, (report_id, tenant_id)).fetchone()
        connection.commit()
        return dict(row), True
    finally:
        connection.close()


def get_employee_email_reports(
    tenant_id: str, reporter_subject: str, limit: int = 50
) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT r.report_id, r.investigation_id, r.case_id, r.incident_type,
                   r.priority, c.status, r.created_at, r.updated_at
            FROM employee_email_reports r
            JOIN cases c ON c.case_id = r.case_id
            WHERE r.tenant_id=? AND r.reporter_subject=?
            ORDER BY r.created_at DESC, r.id DESC LIMIT ?
        """, (tenant_id, reporter_subject, max(1, min(100, int(limit))))).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_employee_email_report(
    tenant_id: str, reporter_subject: str, report_id: str
) -> dict | None:
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT r.report_id, r.investigation_id, r.case_id, r.incident_type,
                   r.priority, c.status, r.created_at, r.updated_at
            FROM employee_email_reports r
            JOIN cases c ON c.case_id = r.case_id
            WHERE r.tenant_id=? AND r.reporter_subject=? AND r.report_id=?
        """, (tenant_id, reporter_subject, report_id)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def create_email_alert(
    event_id: str,
    investigation_id: str,
    severity: str,
    threat_score: int,
    confidence: str,
    recommended_action: str,
    policy_version: str = "mailtrace-gateway-policy-v2",
    user_notice: dict | None = None,
    tenant_id: str | None = None,
    lease_token: str | None = None,
) -> dict | None:
    """Idempotently create an alert without duplicating email content."""
    tenant_id = str(tenant_id or os.getenv("MAILTRACE_WEBHOOK_TENANT_ID", "")).strip()
    production = os.getenv("MAILTRACE_ENV", "development").strip().lower() in {"prod", "production"}
    if not tenant_id and not production:
        tenant_id = "local"
    if not tenant_id:
        raise RuntimeError("MAILTRACE_WEBHOOK_TENANT_ID is required for production email alerts.")
    if production:
        single_tenant = os.getenv("MAILTRACE_SINGLE_TENANT_ID", "").strip()
        if not single_tenant or tenant_id != single_tenant:
            raise RuntimeError("Production email alerts must use MAILTRACE_SINGLE_TENANT_ID.")
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if lease_token is not None:
            # The delivery lease and alert/case commit must be serialized. A
            # worker whose lease was reclaimed may finish expensive analysis,
            # but it must not create the authoritative SOC side effect.
            owner = connection.execute(
                "SELECT 1 FROM email_webhook_events WHERE event_id=? AND status='processing' AND lease_token=?",
                (event_id, lease_token),
            ).fetchone()
            if owner is None:
                connection.rollback()
                return None
        prior = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id=?", (event_id,)
        ).fetchone()
        if prior:
            connection.commit()
            return dict(prior)

        case_id = "CASE-" + secrets.token_hex(5).upper()
        severity = severity.upper()
        connection.execute(
            """
            INSERT INTO cases (
                case_id, tenant_id, title, description, severity, status, threat_score
            ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?)
            """,
            (
                case_id,
                tenant_id,
                f"Automated {severity.lower()} email review — {investigation_id}",
                f"Created from trusted mail-gateway event {event_id}.",
                severity,
                max(0, min(100, int(threat_score))),
            ),
        )
        connection.execute(
            "INSERT OR IGNORE INTO case_investigations (case_id, investigation_id) VALUES (?, ?)",
            (case_id, investigation_id),
        )
        append_case_audit_event(
            connection,
            tenant_id,
            case_id,
            "system:mail-gateway",
            "AUTOMATED_HIGH_RISK_CASE_CREATED",
            to_status="OPEN",
            changed_fields=["title", "severity", "threat_score", "investigation_link"],
        )
        alert_id = "ALT-" + secrets.token_hex(6).upper()
        connection.execute(
            """
            INSERT OR IGNORE INTO email_alerts (
                alert_id, event_id, investigation_id, case_id, severity, threat_score,
                confidence, policy_version, recommended_action, user_notice_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id, event_id, investigation_id, case_id, severity,
                max(0, min(100, int(threat_score))), confidence,
                policy_version[:80], recommended_action,
                json.dumps(user_notice, separators=(",", ":")) if user_notice else None,
            ),
        )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id = ?", (event_id,)
        ).fetchone()
        connection.execute(
            "INSERT INTO email_alert_events (alert_id, action, actor, details_json) VALUES (?, 'CREATED', 'mailtrace-policy', ?)",
            (
                alert_id,
                json.dumps({
                    "event_id": event_id,
                    "investigation_id": investigation_id,
                    "case_id": case_id,
                    "severity": severity,
                    "threat_score": max(0, min(100, int(threat_score))),
                    "policy_version": policy_version,
                    "recommended_action": recommended_action,
                }, separators=(",", ":")),
            ),
        )
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def get_email_alerts(limit: int = 100, status: str | None = None, tenant_id: str | None = None) -> list[dict]:
    """List alert metadata with safe investigation summary fields."""
    connection = get_connection()
    try:
        query = """
            SELECT a.alert_id, a.event_id, a.investigation_id, a.case_id, a.severity,
                   a.threat_score, a.confidence, a.policy_version, a.recommended_action,
                   a.user_notice_json,
                   a.status, a.acknowledged_by, a.acknowledged_at,
                   a.created_at, a.updated_at,
                   i.subject, i.sender, i.recipient,
                   w.policy_decision_json,
                   (SELECT r.outcome FROM email_gateway_action_receipts r
                    WHERE r.event_id=a.event_id ORDER BY r.id DESC LIMIT 1) AS gateway_action_outcome,
                   (SELECT r.reason_code FROM email_gateway_action_receipts r
                    WHERE r.event_id=a.event_id ORDER BY r.id DESC LIMIT 1) AS gateway_action_reason
            FROM email_alerts a
            LEFT JOIN investigations i ON i.investigation_id = a.investigation_id
            LEFT JOIN email_webhook_events w ON w.event_id = a.event_id
            WHERE a.recommended_action = 'QUARANTINE' AND a.confidence = 'HIGH'
        """
        params: tuple = ()
        if tenant_id is not None:
            query += " AND i.tenant_id = ?"
            params = (*params, tenant_id)
        if status:
            query += " AND a.status = ?"
            params = (*params, status)
        query += " ORDER BY a.created_at DESC, a.id DESC LIMIT ?"
        rows = connection.execute(
            query, (*params, max(1, min(500, int(limit))))
        ).fetchall()
        alerts = [protect_investigation_row(dict(row)) for row in rows]
        for alert in alerts:
            try:
                policy = json.loads(alert.pop("policy_decision_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                policy = {}
            alert["gateway_action_status"] = alert.get("gateway_action_outcome") or (
                "PENDING_CONFIRMATION"
                if str(policy.get("enforcement_mode", "")).upper() == "ENFORCE"
                else "MONITOR_ONLY"
            )
        return alerts
    finally:
        connection.close()


def get_email_alert_by_event(event_id: str) -> dict | None:
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id=?", (event_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def acknowledge_email_alert(alert_id: str, actor: str, tenant_id: str | None = None) -> dict | None:
    """Persist an analyst acknowledgement; repeated acknowledgement is safe."""
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE email_alerts
            SET status='ACKNOWLEDGED', acknowledged_by=?,
                acknowledged_at=COALESCE(acknowledged_at, CURRENT_TIMESTAMP),
                updated_at=CURRENT_TIMESTAMP
            WHERE alert_id=? AND status='NEW'
              AND (? IS NULL OR EXISTS (SELECT 1 FROM investigations i WHERE i.investigation_id=email_alerts.investigation_id AND i.tenant_id=?))
            """,
            (actor[:128], alert_id, tenant_id, tenant_id),
        )
        if cursor.rowcount:
            connection.execute(
                "INSERT INTO email_alert_events (alert_id, action, actor, details_json) VALUES (?, 'ACKNOWLEDGED', ?, '{}')",
                (alert_id, actor[:128]),
            )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE alert_id=? AND (? IS NULL OR EXISTS (SELECT 1 FROM investigations i WHERE i.investigation_id=email_alerts.investigation_id AND i.tenant_id=?))",
            (alert_id, tenant_id, tenant_id),
        ).fetchone()
        connection.commit()
        return dict(row) if row else None
    finally:
        connection.close()


def resolve_email_alert(alert_id: str, actor: str, tenant_id: str | None = None) -> dict | None:
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE email_alerts
            SET status='RESOLVED', resolved_by=?,
                resolved_at=COALESCE(resolved_at, CURRENT_TIMESTAMP),
                updated_at=CURRENT_TIMESTAMP
            WHERE alert_id=? AND status IN ('NEW', 'ACKNOWLEDGED')
              AND (? IS NULL OR EXISTS (SELECT 1 FROM investigations i WHERE i.investigation_id=email_alerts.investigation_id AND i.tenant_id=?))
            """,
            (actor[:128], alert_id, tenant_id, tenant_id),
        )
        if cursor.rowcount:
            connection.execute(
                "INSERT INTO email_alert_events (alert_id, action, actor, details_json) VALUES (?, 'RESOLVED', ?, '{}')",
                (alert_id, actor[:128]),
            )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE alert_id=? AND (? IS NULL OR EXISTS (SELECT 1 FROM investigations i WHERE i.investigation_id=email_alerts.investigation_id AND i.tenant_id=?))",
            (alert_id, tenant_id, tenant_id),
        ).fetchone()
        connection.commit()
        return dict(row) if row else None
    finally:
        connection.close()


def get_email_alert_history(alert_id: str, tenant_id: str | None = None) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """SELECT e.action, e.actor, e.details_json, e.created_at FROM email_alert_events e
               JOIN email_alerts a ON a.alert_id=e.alert_id
               JOIN investigations i ON i.investigation_id=a.investigation_id
               WHERE e.alert_id=? AND (? IS NULL OR i.tenant_id=?) ORDER BY e.id ASC""",
            (alert_id, tenant_id, tenant_id),
        ).fetchall()
        history = [dict(row) for row in rows]
        for event in history:
            try:
                event["details"] = json.loads(event.pop("details_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                event["details"] = {}
        return history
    finally:
        connection.close()


def complete_email_webhook_event(
    event_id: str,
    investigation_id: str,
    lease_token: str,
    policy_decision: dict | None = None,
) -> bool:
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET status='completed', investigation_id=?, policy_decision_json=?, lease_token=NULL, last_error=NULL, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND status='processing' AND lease_token=?",
            (
                investigation_id,
                json.dumps(policy_decision, separators=(",", ":")) if policy_decision else None,
                event_id,
                lease_token,
            ),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


def renew_email_webhook_event_lease(event_id: str, lease_token: str) -> bool:
    """Keep an active worker claim fresh; return false after ownership is lost."""
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND status='processing' AND lease_token=?",
            (event_id, lease_token),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


def fail_email_webhook_event(event_id: str, error: str, lease_token: str) -> bool:
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET status='failed', lease_token=NULL, last_error=?, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND status='processing' AND lease_token=?",
            (error[:500], event_id, lease_token),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


# ==========================================
# SAVE INVESTIGATION
# ==========================================

def save_investigation(
    investigation_id,
    filename,
    subject,
    sender,
    recipient,
    threat_score,
    threat_verdict,
    threat_confidence,
    analysis_json,
    smtp_recipient=None,
    tenant_id=None,
    retention_classification=None,
    retention_policy_id=None,
    retention_expires_at=None,
    retention_purge_derived=False,
    retention_purge_raw=False,
):
    tenant_id = _scope_tenant(tenant_id, allow_missing=False)
    if not tenant_id:
        tenant_id = "local"

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO investigations (

            investigation_id,
            filename,
            subject,
            sender,
            recipient,
            smtp_recipient,
            threat_score,
            threat_verdict,
            threat_confidence,
            analysis_json,
            tenant_id,
            retention_classification,
            retention_policy_id,
            retention_expires_at,
            retention_purge_derived,
            retention_purge_raw

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        investigation_id,
        protect_sensitive_value(filename, "filename"),
        protect_sensitive_value(subject, "subject"),
        protect_sensitive_value(sender, "sender"),
        protect_sensitive_value(recipient, "recipient"),
        protect_sensitive_value(smtp_recipient, "smtp_recipient"),
        threat_score,
        threat_verdict,
        threat_confidence,
        protect_sensitive_value(analysis_json, "analysis_json"),
        tenant_id,
        retention_classification,
        retention_policy_id,
        retention_expires_at,
        int(bool(retention_purge_derived)),
        int(bool(retention_purge_raw))

    ))

    if retention_policy_id:
        _append_retention_event(
            connection,
            tenant_id,
            investigation_id,
            "system:retention-policy",
            "RETENTION_REGISTERED",
            {
                "policy_id": retention_policy_id,
                "classification": retention_classification,
                "expires_at_utc": retention_expires_at,
                "purge_derived_views": bool(retention_purge_derived),
                "purge_raw_evidence": bool(retention_purge_raw),
            },
        )

    connection.commit()

    connection.close()


# ==========================================
# GET ALL INVESTIGATIONS
# ==========================================

def get_all_investigations(tenant_id=None):
    tenant_id = _scope_tenant(tenant_id)

    connection = get_connection()

    cursor = connection.cursor()

    if tenant_id is None:
        cursor.execute("""
        SELECT
            investigation_id,
            filename,
            subject,
            sender,
            recipient,
            threat_score,
            threat_verdict,
            threat_confidence,
            analysis_json,
            created_at

        FROM investigations
        ORDER BY created_at DESC
        """)
    else:
        cursor.execute("""
        SELECT investigation_id, filename, subject, sender, recipient,
               threat_score, threat_verdict, threat_confidence, analysis_json,
               created_at, tenant_id
        FROM investigations WHERE tenant_id = ?
        ORDER BY created_at DESC, id DESC
        """, (tenant_id,))

    rows = cursor.fetchall()

    connection.close()

    return [protect_investigation_row(dict(row)) for row in rows]


def get_all_investigation_summaries(tenant_id=None):
    """Return list-view fields without loading full forensic analysis documents."""
    tenant_id = _scope_tenant(tenant_id)
    connection = get_connection()
    try:
        query = """
            SELECT
                investigation_id,
                filename,
                subject,
                sender,
                recipient,
                threat_score,
                threat_verdict,
                threat_confidence,
                CASE
                    WHEN json_valid(COALESCE(analysis_json, '')) = 1
                     AND json_type(analysis_json) = 'object' THEN 'PASS'
                    ELSE 'ERROR'
                END AS analysis_document_status,
                created_at
            FROM investigations
            {where}
            ORDER BY created_at DESC, id DESC
        """.format(where="WHERE tenant_id = ?" if tenant_id is not None else "")
        rows = connection.execute(query, (tenant_id,) if tenant_id is not None else ()).fetchall()
        summaries = [protect_investigation_row(dict(row)) for row in rows]
        for item in summaries:
            if item.get("analysis_document_status") == "ERROR":
                item["threat_score"] = None
                item["threat_verdict"] = "REPORT DATA UNAVAILABLE"
                item["threat_confidence"] = "UNKNOWN"
        return summaries
    finally:
        connection.close()


def get_investigation_snapshot_marker(tenant_id=None) -> tuple[int, int]:
    """Cheap cursor for checking whether the investigation snapshot changed."""
    tenant_id = _scope_tenant(tenant_id)
    connection = get_connection()
    try:
        if tenant_id is None:
            row = connection.execute("SELECT COUNT(*) AS item_count, COALESCE(MAX(id), 0) AS latest_id FROM investigations").fetchone()
        else:
            row = connection.execute("SELECT COUNT(*) AS item_count, COALESCE(MAX(id), 0) AS latest_id FROM investigations WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return int(row["item_count"]), int(row["latest_id"])
    finally:
        connection.close()


# ==========================================
# GET SINGLE INVESTIGATION
# ==========================================

def get_investigation(
    investigation_id, tenant_id=None
):
    tenant_id = _scope_tenant(tenant_id)

    connection = get_connection()

    cursor = connection.cursor()

    if tenant_id is None:
        cursor.execute("""
        SELECT *

        FROM investigations

        WHERE investigation_id = ?
        """, (investigation_id,))
    else:
        cursor.execute("SELECT * FROM investigations WHERE investigation_id = ? AND tenant_id = ?", (investigation_id, tenant_id))

    row = cursor.fetchone()

    connection.close()

    if row is None:

        return None

    return protect_investigation_row(dict(row))

# =========================================================
# THREAT INTELLIGENCE STORAGE
# =========================================================

def initialize_threat_intelligence_table():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source TEXT NOT NULL,

            external_id TEXT,

            ioc TEXT NOT NULL,

            ioc_type TEXT,

            threat_type TEXT,

            malware TEXT,

            confidence INTEGER DEFAULT 0,

            first_seen TEXT,

            last_seen TEXT,

            reference TEXT,

            raw_json TEXT,

            created_at TEXT DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(source, external_id, ioc)
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_ioc
        ON threat_intelligence(ioc)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_source
        ON threat_intelligence(source)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence_sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            configured INTEGER NOT NULL,
            success INTEGER NOT NULL,
            provider_status TEXT NOT NULL,
            fetched_count INTEGER NOT NULL DEFAULT 0,
            inserted_count INTEGER NOT NULL DEFAULT 0,
            error_type TEXT,
            synced_by TEXT,
            checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_ti_sync_provider_checked
        ON threat_intelligence_sync_runs(provider, checked_at DESC, id DESC)
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_ti_sync_runs_no_update
        BEFORE UPDATE ON threat_intelligence_sync_runs
        BEGIN SELECT RAISE(ABORT, 'threat intelligence sync runs are append-only'); END
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_ti_sync_runs_no_delete
        BEFORE DELETE ON threat_intelligence_sync_runs
        BEGIN SELECT RAISE(ABORT, 'threat intelligence sync runs are append-only'); END
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intelligence_sync_lease (
            lease_name TEXT PRIMARY KEY,
            owner_token TEXT,
            expires_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO threat_intelligence_sync_lease(lease_name, owner_token, expires_at)
        VALUES ('scheduled', NULL, '1970-01-01T00:00:00Z')
    """)

    connection.commit()

    connection.close()


def record_threat_intelligence_sync(
    provider_results: dict,
    inserted_counts: dict[str, int],
    *,
    synced_by: str | None = None,
) -> str:
    """Append provider outcomes without persisting remote response bodies or secrets."""
    import re

    sync_id = secrets.token_hex(16)
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        for provider, result in provider_results.items():
            if not isinstance(result, dict):
                result = {}
            provider_name = re.sub(r"[^a-z0-9_.-]", "_", str(provider).lower())[:64] or "unknown"
            provider_status = re.sub(
                r"[^A-Za-z0-9_.:-]", "_", str(result.get("status") or "unknown")
            )[:64] or "unknown"
            error_type = result.get("error_type")
            if error_type is not None:
                error_type = re.sub(r"[^A-Za-z0-9_.-]", "_", str(error_type))[:80]
            try:
                fetched_count = max(0, min(10_000_000, int(result.get("count", 0) or 0)))
            except (TypeError, ValueError):
                fetched_count = 0
            try:
                inserted_count = max(0, min(10_000_000, int(inserted_counts.get(provider, 0) or 0)))
            except (TypeError, ValueError):
                inserted_count = 0
            connection.execute(
                """INSERT INTO threat_intelligence_sync_runs
                   (sync_id, provider, configured, success, provider_status,
                    fetched_count, inserted_count, error_type, synced_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sync_id,
                    provider_name,
                    int(bool(result.get("configured"))),
                    int(bool(result.get("success"))),
                    provider_status,
                    fetched_count,
                    inserted_count,
                    error_type,
                    str(synced_by)[:256] if synced_by else None,
                ),
            )
        connection.commit()
        return sync_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_threat_intelligence_source_status(max_age_hours: int = 24) -> dict:
    """Report feed configuration, latest attempt/success, local coverage, and freshness."""
    max_age_hours = max(1, min(168, int(max_age_hours)))
    providers = ("threatfox", "urlhaus")
    connection = get_connection()
    try:
        result = {}
        for provider in providers:
            latest = connection.execute(
                """SELECT configured, success, provider_status, fetched_count,
                          inserted_count, error_type, synced_by, checked_at
                   FROM threat_intelligence_sync_runs WHERE provider=?
                   ORDER BY checked_at DESC, id DESC LIMIT 1""",
                (provider,),
            ).fetchone()
            latest_success = connection.execute(
                """SELECT checked_at FROM threat_intelligence_sync_runs
                   WHERE provider=? AND configured=1 AND success=1
                   ORDER BY checked_at DESC, id DESC LIMIT 1""",
                (provider,),
            ).fetchone()
            record_count = connection.execute(
                "SELECT COUNT(*) FROM threat_intelligence WHERE LOWER(source)=?",
                (provider,),
            ).fetchone()[0]
            if latest is None:
                freshness = "NEVER_SYNCED"
            elif not latest["configured"]:
                freshness = "NOT_CONFIGURED"
            elif latest_success is None:
                freshness = "UNAVAILABLE"
            else:
                fresh = connection.execute(
                    "SELECT CASE WHEN julianday(?) >= julianday('now', ?) THEN 1 ELSE 0 END",
                    (latest_success["checked_at"], f"-{max_age_hours} hours"),
                ).fetchone()[0]
                if fresh and latest["success"]:
                    freshness = "FRESH"
                elif fresh:
                    freshness = "FRESH_WITH_REFRESH_FAILURE"
                else:
                    freshness = "STALE" if latest["success"] else "STALE_AFTER_FAILURE"
            result[provider] = {
                "configured": bool(latest["configured"]) if latest else None,
                "status": latest["provider_status"] if latest else "never_synced",
                "last_attempt_at_utc": latest["checked_at"] if latest else None,
                "last_success_at_utc": latest_success["checked_at"] if latest_success else None,
                "last_fetched_count": int(latest["fetched_count"]) if latest else 0,
                "last_inserted_count": int(latest["inserted_count"]) if latest else 0,
                "error_type": latest["error_type"] if latest else None,
                "synced_by": latest["synced_by"] if latest else None,
                "local_indicator_count": int(record_count),
                "freshness": freshness,
            }
        configured = [item for item in result.values() if item["configured"] is True]
        fresh_count = sum(item["freshness"] == "FRESH" for item in configured)
        if not configured:
            coverage = (
                "NO_FEEDS_CONFIGURED"
                if all(item["configured"] is False for item in result.values())
                else "NEVER_SYNCED"
            )
        elif fresh_count == len(configured):
            coverage = "FRESH"
        elif fresh_count:
            coverage = "PARTIAL"
        elif any(item["freshness"] == "FRESH_WITH_REFRESH_FAILURE" for item in configured):
            coverage = "DEGRADED"
        elif any(item["freshness"] in {"STALE", "STALE_AFTER_FAILURE", "UNAVAILABLE"} for item in configured):
            coverage = "STALE_OR_UNAVAILABLE"
        else:
            coverage = "NEVER_SYNCED"
        return {
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "freshness_window_hours": max_age_hours,
            "coverage_status": coverage,
            "providers": result,
        }
    finally:
        connection.close()


def claim_threat_intelligence_sync_lease(lease_seconds: int = 600) -> str | None:
    """Acquire the shared scheduler lease so multiple API workers do not sync in parallel."""
    lease_seconds = max(60, min(3600, int(lease_seconds)))
    token = secrets.token_hex(16)
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """UPDATE threat_intelligence_sync_lease
               SET owner_token=?, expires_at=datetime('now', ?)
               WHERE lease_name='scheduled'
                 AND (owner_token IS NULL OR julianday(expires_at)<=julianday('now'))""",
            (token, f"+{lease_seconds} seconds"),
        )
        connection.commit()
        return token if cursor.rowcount == 1 else None
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def release_threat_intelligence_sync_lease(owner_token: str) -> bool:
    connection = get_connection()
    try:
        cursor = connection.execute(
            """UPDATE threat_intelligence_sync_lease
               SET owner_token=NULL, expires_at='1970-01-01T00:00:00Z'
               WHERE lease_name='scheduled' AND owner_token=?""",
            (owner_token,),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def save_threat_intelligence(
    indicators
):
    """
    Persist normalized threat-intelligence evidence with SOC-grade fields.
    """

    if not indicators:
        return 0

    connection = get_connection()
    cursor = connection.cursor()
    saved = 0

    try:
        for indicator in indicators:
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO threat_intelligence (
                        source,
                        external_id,
                        ioc,
                        ioc_type,
                        threat_type,
                        malware,
                        confidence,
                        first_seen,
                        last_seen,
                        reference,
                        raw_json,
                        severity,
                        risk_score,
                        mitre_attack,
                        tags,
                        campaign,
                        actor,
                        kill_chain,
                        enrichment_json,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator.get("source"),
                    indicator.get("external_id"),
                    indicator.get("ioc"),
                    indicator.get("ioc_type"),
                    indicator.get("threat_type"),
                    indicator.get("malware"),
                    indicator.get("confidence", 0),
                    indicator.get("first_seen"),
                    indicator.get("last_seen"),
                    indicator.get("reference"),
                    indicator.get("raw_json"),
                    indicator.get("severity"),
                    indicator.get("risk_score"),
                    indicator.get("mitre_attack"),
                    indicator.get("tags"),
                    indicator.get("campaign"),
                    indicator.get("actor"),
                    indicator.get("kill_chain"),
                    indicator.get("enrichment_json"),
                    indicator.get("updated_at"),
                ))

                if cursor.rowcount > 0:
                    saved += 1

            except Exception:
                continue

        connection.commit()
        return saved

    finally:
        connection.close()

def get_threat_intelligence(
    limit=100
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            source,
            external_id,
            ioc,
            ioc_type,
            threat_type,
            malware,
            confidence,
            first_seen,
            last_seen,
            reference,
            created_at

        FROM threat_intelligence

        ORDER BY
            COALESCE(last_seen, first_seen, created_at)
            DESC

        LIMIT ?
    """, (
        int(limit),
    ))

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def lookup_threat_intelligence(ioc, limit=20):
    """
    Exact IOC lookup against locally stored threat-intelligence indicators,
    including advanced SOC evidence fields.
    """

    if not ioc:
        return []

    normalized_ioc = str(ioc).strip()

    if not normalized_ioc:
        return []

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            SELECT
                id,
                source,
                external_id,
                ioc,
                ioc_type,
                threat_type,
                malware,
                confidence,
                first_seen,
                last_seen,
                reference,
                raw_json,
                created_at,
                severity,
                risk_score,
                mitre_attack,
                tags,
                campaign,
                actor,
                kill_chain,
                enrichment_json,
                updated_at
            FROM threat_intelligence
            WHERE LOWER(TRIM(ioc)) = LOWER(TRIM(?))
            ORDER BY
                COALESCE(risk_score, 0) DESC,
                confidence DESC,
                COALESCE(
                    last_seen,
                    first_seen,
                    updated_at,
                    created_at
                ) DESC
            LIMIT ?
        """, (
            normalized_ioc,
            int(limit),
        ))

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()

def lookup_threat_intelligence_batch(iocs, limit_per_ioc=20):
    """
    Lookup multiple IOC values against the
    local threat-intelligence database.
    """

    results = {}

    if not iocs:
        return results

    seen = set()

    for value in iocs:

        if value is None:
            continue

        normalized = str(value).strip()

        if not normalized:
            continue

        key = normalized.lower()

        if key in seen:
            continue

        seen.add(key)

        matches = lookup_threat_intelligence(
            normalized,
            limit=limit_per_ioc
        )

        if matches:
            results[normalized] = matches

    return results


def upgrade_threat_intelligence_schema():

    connection = get_connection()

    cursor = connection.cursor()

    columns = {
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(threat_intelligence)"
        ).fetchall()
    }

    new_columns = {
        "severity": "TEXT",
        "risk_score": "REAL DEFAULT 0",
        "mitre_attack": "TEXT",
        "tags": "TEXT",
        "campaign": "TEXT",
        "actor": "TEXT",
        "kill_chain": "TEXT",
        "enrichment_json": "TEXT",
        "updated_at": "TEXT"
    }

    for column, definition in new_columns.items():

        if column not in columns:

            cursor.execute(
                f"ALTER TABLE threat_intelligence "
                f"ADD COLUMN {column} {definition}"
            )

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_type
        ON threat_intelligence(ioc_type)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_severity
        ON threat_intelligence(severity)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_risk
        ON threat_intelligence(risk_score DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_threat_intelligence_confidence
        ON threat_intelligence(confidence DESC)
    """)

    connection.commit()

    connection.close()




# ---------------------------------------------------------------------------
# Tenant-scoped SOC routing, workload balancing, and SLA escalation
# ---------------------------------------------------------------------------

def initialize_soc_routing():
    """Create/upgrade SOC queues, analyst eligibility, routing, and audit records."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_queues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queue_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                region_key TEXT NOT NULL,
                team_key TEXT NOT NULL DEFAULT '',
                is_central INTEGER NOT NULL DEFAULT 0 CHECK(is_central IN (0,1)),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, queue_id), UNIQUE(tenant_id, name)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS employee_region_assignments (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                email_lookup_hmac TEXT,
                region_key TEXT NOT NULL,
                team_key TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'admin_config',
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(tenant_id, subject_id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_analysts (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                region_key TEXT NOT NULL,
                team_key TEXT NOT NULL DEFAULT '',
                skills_json TEXT NOT NULL DEFAULT '[]',
                availability TEXT NOT NULL DEFAULT 'AVAILABLE'
                    CHECK(availability IN ('AVAILABLE','BUSY','AWAY')),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                max_open_cases INTEGER NOT NULL DEFAULT 20 CHECK(max_open_cases > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(tenant_id, subject_id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_routing (
                case_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                region_key TEXT NOT NULL,
                team_key TEXT NOT NULL DEFAULT '',
                queue_id TEXT NOT NULL,
                assigned_analyst TEXT,
                status TEXT NOT NULL DEFAULT 'UNASSIGNED'
                    CHECK(status IN ('QUEUED','ASSIGNED','FALLBACK','UNASSIGNED','IN_PROGRESS','CLOSED','UNROUTED')),
                priority TEXT NOT NULL DEFAULT 'P3',
                sla_deadline TEXT,
                required_skills_json TEXT NOT NULL DEFAULT '[]',
                routing_reason TEXT NOT NULL DEFAULT '',
                assigned_at TEXT,
                last_activity_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_escalated_at TEXT,
                escalation_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_sla_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                alert_type TEXT NOT NULL DEFAULT 'SLA_OVERDUE',
                priority TEXT NOT NULL,
                sla_deadline TEXT NOT NULL,
                assigned_analyst TEXT,
                routing_status TEXT NOT NULL,
                escalation_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, case_id, alert_type)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_sla_alerts_active ON soc_sla_alerts(tenant_id, status, last_seen_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_sla_alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                tenant_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('ACKNOWLEDGED','RESOLVED')),
                from_status TEXT NOT NULL CHECK(from_status IN ('OPEN','ACKNOWLEDGED')),
                to_status TEXT NOT NULL CHECK(to_status IN ('ACKNOWLEDGED','RESOLVED')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_sla_alert_events_tenant_alert ON soc_sla_alert_events(tenant_id, alert_id, id)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_routing_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_subject TEXT,
                action TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_routing_config_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_subject TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Upgrade early regional-routing package schemas without replacing existing rows.
        upgrades = {
            "soc_queues": {"team_key": "TEXT NOT NULL DEFAULT ''"},
            "employee_region_assignments": {
                "team_key": "TEXT NOT NULL DEFAULT ''",
                "email_lookup_hmac": "TEXT",
            },
            "soc_analysts": {
                "team_key": "TEXT NOT NULL DEFAULT ''",
                "skills_json": "TEXT NOT NULL DEFAULT '[]'",
                "availability": "TEXT NOT NULL DEFAULT 'AVAILABLE'",
            },
            "case_routing": {
                "team_key": "TEXT NOT NULL DEFAULT ''",
                "priority": "TEXT NOT NULL DEFAULT 'P3'",
                "sla_deadline": "TEXT",
                "required_skills_json": "TEXT NOT NULL DEFAULT '[]'",
                "last_activity_at": "TEXT",
                "last_escalated_at": "TEXT",
                "escalation_count": "INTEGER NOT NULL DEFAULT 0",
            },
            "case_routing_events": {"reason": "TEXT NOT NULL DEFAULT ''"},
        }
        for table, columns in upgrades.items():
            existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        connection.execute("UPDATE case_routing SET last_activity_at=COALESCE(last_activity_at, updated_at, created_at, CURRENT_TIMESTAMP)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_queues_region ON soc_queues(tenant_id, region_key, team_key, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_employee_region ON employee_region_assignments(tenant_id, region_key, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_employee_region_email ON employee_region_assignments(tenant_id, email_lookup_hmac, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_analysts_load ON soc_analysts(tenant_id, region_key, active, availability)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_case_routing_queue ON case_routing(tenant_id, queue_id, status, priority, sla_deadline)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_case_routing_assignee ON case_routing(tenant_id, assigned_analyst, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_case_routing_events_case ON case_routing_events(tenant_id, case_id, id)")
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_routing_events_no_update
            BEFORE UPDATE ON case_routing_events
            BEGIN SELECT RAISE(ABORT, 'case routing audit events are append-only'); END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_case_routing_events_no_delete
            BEFORE DELETE ON case_routing_events
            BEGIN SELECT RAISE(ABORT, 'case routing audit events are append-only'); END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_soc_routing_config_events_no_update
            BEFORE UPDATE ON soc_routing_config_events
            BEGIN SELECT RAISE(ABORT, 'SOC routing configuration audit events are append-only'); END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_soc_routing_config_events_no_delete
            BEFORE DELETE ON soc_routing_config_events
            BEGIN SELECT RAISE(ABORT, 'SOC routing configuration audit events are append-only'); END
        """)
        connection.commit()
    finally:
        connection.close()


def _routing_config_event(connection, tenant_id, actor_subject, action, reason, details):
    connection.execute("""
        INSERT INTO soc_routing_config_events(tenant_id, actor_subject, action, reason, details_json)
        VALUES (?, ?, ?, ?, ?)
    """, (tenant_id, actor_subject, action, str(reason or "configuration update").strip()[:300],
          json.dumps(details, separators=(",", ":"))))


def configure_soc_queue(tenant_id: str, queue_id: str, name: str, region_key: str, *, team_key="", is_central=False, active=True, actor_subject="system", reason="configuration update") -> dict:
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            INSERT INTO soc_queues(queue_id, tenant_id, name, region_key, team_key, is_central, active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, queue_id) DO UPDATE SET
                name=excluded.name, region_key=excluded.region_key, team_key=excluded.team_key,
                is_central=excluded.is_central, active=excluded.active, updated_at=CURRENT_TIMESTAMP
        """, (queue_id, tenant_id, name, region_key, team_key, int(is_central), int(active)))
        row = connection.execute("SELECT * FROM soc_queues WHERE tenant_id=? AND queue_id=?", (tenant_id, queue_id)).fetchone()
        _routing_config_event(connection, tenant_id, actor_subject, "QUEUE_CONFIGURED", reason,
                              {"queue_id": queue_id, "region_key": region_key, "team_key": team_key, "active": bool(active)})
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def configure_employee_region(tenant_id: str, subject_id: str, region_key: str, *, team_key="", email_address=None, source="admin_config", active=True, actor_subject="system", reason="organization mapping update") -> dict:
    email_lookup_hmac = _employee_email_lookup_hmac(email_address)
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            INSERT INTO employee_region_assignments(tenant_id, subject_id, email_lookup_hmac, region_key, team_key, source, active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, subject_id) DO UPDATE SET
                email_lookup_hmac=COALESCE(excluded.email_lookup_hmac, employee_region_assignments.email_lookup_hmac),
                region_key=excluded.region_key, team_key=excluded.team_key, source=excluded.source,
                active=excluded.active, updated_at=CURRENT_TIMESTAMP
        """, (tenant_id, subject_id, email_lookup_hmac, region_key, team_key, source, int(active)))
        row = connection.execute("SELECT * FROM employee_region_assignments WHERE tenant_id=? AND subject_id=?", (tenant_id, subject_id)).fetchone()
        _routing_config_event(connection, tenant_id, actor_subject, "EMPLOYEE_REGION_CONFIGURED", reason,
                              {"subject_id": subject_id, "region_key": region_key, "team_key": team_key, "active": bool(active)})
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def configure_soc_analyst(tenant_id: str, subject_id: str, region_key: str, *, team_key="", skills=None, availability="AVAILABLE", max_open_cases=20, active=True, actor_subject="system", reason="analyst roster update") -> dict:
    skills = sorted({str(skill).strip().lower() for skill in (skills or []) if str(skill).strip()})
    availability = str(availability or "AVAILABLE").upper()
    if availability not in {"AVAILABLE", "BUSY", "AWAY"}:
        raise ValueError("availability must be AVAILABLE, BUSY, or AWAY")
    max_open_cases = max(1, min(int(max_open_cases), 1000))
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            INSERT INTO soc_analysts(tenant_id, subject_id, region_key, team_key, skills_json, availability, active, max_open_cases)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, subject_id) DO UPDATE SET
                region_key=excluded.region_key, team_key=excluded.team_key, skills_json=excluded.skills_json,
                availability=excluded.availability, active=excluded.active,
                max_open_cases=excluded.max_open_cases, updated_at=CURRENT_TIMESTAMP
        """, (tenant_id, subject_id, region_key, team_key, json.dumps(skills), availability, int(active), max_open_cases))
        row = connection.execute("SELECT * FROM soc_analysts WHERE tenant_id=? AND subject_id=?", (tenant_id, subject_id)).fetchone()
        _routing_config_event(connection, tenant_id, actor_subject, "ANALYST_CONFIGURED", reason,
                              {"subject_id": subject_id, "region_key": region_key, "team_key": team_key,
                               "skills": skills, "availability": availability, "active": bool(active), "max_open_cases": max_open_cases})
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def _case_priority_and_sla(severity, threat_score):
    severity = str(severity or "LOW").upper()
    score = int(threat_score or 0)
    if severity == "CRITICAL" or score >= 90:
        priority, env_name, default_minutes = "P1", "MAILTRACE_SLA_CRITICAL_MINUTES", 15
    elif severity == "HIGH" or score >= 70:
        priority, env_name, default_minutes = "P2", "MAILTRACE_SLA_HIGH_MINUTES", 60
    elif severity == "MEDIUM" or score >= 40:
        priority, env_name, default_minutes = "P3", "MAILTRACE_SLA_MEDIUM_MINUTES", 240
    else:
        priority, env_name, default_minutes = "P4", "MAILTRACE_SLA_LOW_MINUTES", 1440
    try:
        minutes = max(1, min(10080, int(os.getenv(env_name, str(default_minutes)))))
    except (TypeError, ValueError):
        minutes = default_minutes
    return priority, minutes


def route_case_to_soc(case_id: str, tenant_id: str, reporter_subject: str, *, recipient_email=None, actor_subject=None, required_skills=None, force=False) -> dict:
    """Route by verified organization region; keep assigned ownership stable unless explicitly rerouted."""
    required = sorted({str(skill).strip().lower() for skill in (required_skills or []) if str(skill).strip()})
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        case = connection.execute("SELECT case_id, severity, threat_score, status FROM cases WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        if case is None:
            connection.rollback()
            raise ValueError("Case not found for this tenant")
        prior = connection.execute("SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        if prior and prior["assigned_analyst"] and not force:
            # Scheduler races, queue refreshes, and duplicate employee reports must
            # not silently move an already-owned case to another analyst.
            current_priority, sla_minutes = _case_priority_and_sla(
                case["severity"], case["threat_score"]
            )
            priority_rank = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
            if priority_rank.get(current_priority, 4) < priority_rank.get(prior["priority"], 4):
                new_deadline = connection.execute(
                    "SELECT datetime('now', ?)", (f"+{sla_minutes} minutes",)
                ).fetchone()[0]
                deadline = min(str(prior["sla_deadline"] or new_deadline), new_deadline)
                connection.execute(
                    "UPDATE case_routing SET priority=?, sla_deadline=?, "
                    "last_activity_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP "
                    "WHERE case_id=? AND tenant_id=?",
                    (current_priority, deadline, case_id, tenant_id),
                )
                reason = "risk_priority_escalated_without_reassignment"
                details = {
                    "previous_priority": prior["priority"],
                    "priority": current_priority,
                    "sla_deadline": deadline,
                    "assigned_analyst": prior["assigned_analyst"],
                }
                connection.execute(
                    "INSERT INTO case_routing_events "
                    "(case_id, tenant_id, actor_subject, action, reason, details_json) "
                    "VALUES (?, ?, ?, 'PRIORITY_ESCALATED', ?, ?)",
                    (case_id, tenant_id, actor_subject, reason,
                     json.dumps(details, separators=(",", ":"))),
                )
            connection.commit()
            refreshed = connection.execute(
                "SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?",
                (case_id, tenant_id),
            ).fetchone()
            return dict(refreshed)
        active_claim = connection.execute("""
            SELECT assigned_analyst FROM case_claims
            WHERE case_id=? AND tenant_id=? AND status='ACTIVE'
              AND datetime(lease_expires_at)>datetime('now')
        """, (case_id, tenant_id)).fetchone()
        employee = connection.execute("SELECT region_key, team_key FROM employee_region_assignments WHERE tenant_id=? AND subject_id=? AND active=1", (tenant_id, reporter_subject)).fetchone() if reporter_subject else None
        try:
            recipient_hmac = _employee_email_lookup_hmac(recipient_email) if recipient_email else None
        except ValueError:
            recipient_hmac = None
        if employee is None and recipient_hmac:
            matching_recipients = connection.execute(
                "SELECT subject_id, region_key, team_key FROM employee_region_assignments WHERE tenant_id=? AND email_lookup_hmac=? AND active=1 ORDER BY subject_id LIMIT 2",
                (tenant_id, recipient_hmac),
            ).fetchall()
            # A recipient address maps to a region only when one active identity
            # owns it. Ambiguous addresses safely use the central SOC fallback.
            employee = matching_recipients[0] if len(matching_recipients) == 1 else None
        requested_region = str(employee["region_key"]).strip() if employee else ""
        requested_team = str(employee["team_key"] or "").strip() if employee else ""
        fallback = False
        reason = "verified_employee_region"
        queue = None
        if requested_region:
            queue = connection.execute("""
                SELECT * FROM soc_queues WHERE tenant_id=? AND region_key=? AND active=1 AND is_central=0
                  AND (?='' OR team_key='' OR team_key=?) ORDER BY id LIMIT 1
            """, (tenant_id, requested_region, requested_team, requested_team)).fetchone()
        if queue is None:
            fallback = True
            reason = "central_fallback:no_active_regional_queue" if requested_region else "central_fallback:no_unique_verified_recipient_region" if recipient_email else "central_fallback:no_verified_employee_region"
            connection.execute("""
                INSERT INTO soc_queues(queue_id, tenant_id, name, region_key, team_key, is_central, active)
                VALUES ('CENTRAL', ?, 'Central SOC', 'CENTRAL', '', 1, 1)
                ON CONFLICT(tenant_id, queue_id) DO UPDATE SET active=1, is_central=1, region_key='CENTRAL', updated_at=CURRENT_TIMESTAMP
            """, (tenant_id,))
            queue = connection.execute("SELECT * FROM soc_queues WHERE tenant_id=? AND queue_id='CENTRAL'", (tenant_id,)).fetchone()
        region = str(queue["region_key"])
        team = str(queue["team_key"] or (requested_team if not fallback else "") or "")
        priority, sla_minutes = _case_priority_and_sla(case["severity"], case["threat_score"])
        # Keep an existing deadline if it is earlier; duplicate employee reports must not reset SLA.
        candidates = connection.execute("""
            SELECT a.subject_id, a.max_open_cases, a.skills_json, a.team_key,
                   (SELECT COUNT(*) FROM case_routing r
                    JOIN cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
                    WHERE r.tenant_id=a.tenant_id AND r.assigned_analyst=a.subject_id
                      AND r.status IN ('ASSIGNED','IN_PROGRESS')
                      AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')) AS open_load
            FROM soc_analysts a
            WHERE a.tenant_id=? AND a.active=1 AND a.availability='AVAILABLE'
              AND ((?=1 AND a.region_key='CENTRAL') OR (?=0 AND (a.region_key=? OR a.region_key='CENTRAL')))
              AND (?='' OR a.team_key='' OR a.team_key=?)
            ORDER BY open_load ASC, a.subject_id ASC
        """, (tenant_id, int(bool(queue["is_central"])), int(bool(queue["is_central"])), region, team, team)).fetchall()
        eligible = []
        for analyst in candidates:
            try:
                analyst_skills = {str(v).lower() for v in json.loads(analyst["skills_json"] or "[]")}
            except (TypeError, json.JSONDecodeError):
                analyst_skills = set()
            if int(analyst["open_load"]) < int(analyst["max_open_cases"]) and set(required).issubset(analyst_skills):
                eligible.append(analyst)
        chosen = eligible[0] if eligible else None
        assigned = chosen["subject_id"] if chosen else None
        if active_claim:
            # Routing reconciliation must never silently replace a live claim owner.
            assigned = active_claim["assigned_analyst"]
            reason += ";preserved_active_claim_owner"
        # QUEUED + a NULL assignee represents the explicit unassigned queue and
        # remains compatible with the earlier regional-routing schema constraint.
        status = "ASSIGNED" if assigned else "QUEUED"
        if not assigned:
            reason += ";no_eligible_analyst"
        deadline_expr = f"+{sla_minutes} minutes"
        new_deadline = connection.execute("SELECT datetime('now', ?)", (deadline_expr,)).fetchone()[0]
        if prior and prior["sla_deadline"]:
            # Never extend an existing deadline on duplicate reports or severity changes.
            deadline = min(str(prior["sla_deadline"]), str(new_deadline))
        else:
            deadline = new_deadline
        connection.execute("""
            INSERT INTO case_routing(case_id, tenant_id, region_key, team_key, queue_id, assigned_analyst,
                status, priority, sla_deadline, required_skills_json, routing_reason, assigned_at, last_activity_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE CURRENT_TIMESTAMP END, CURRENT_TIMESTAMP)
            ON CONFLICT(case_id) DO UPDATE SET
                tenant_id=excluded.tenant_id, region_key=excluded.region_key, team_key=excluded.team_key,
                queue_id=excluded.queue_id, assigned_analyst=excluded.assigned_analyst, status=excluded.status,
                priority=excluded.priority, sla_deadline=excluded.sla_deadline,
                required_skills_json=excluded.required_skills_json, routing_reason=excluded.routing_reason,
                assigned_at=COALESCE(case_routing.assigned_at, excluded.assigned_at),
                last_activity_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
        """, (case_id, tenant_id, region, team, queue["queue_id"], assigned, status, priority, deadline,
              json.dumps(required), reason, assigned))
        action = "ROUTED" if assigned else "NO_ELIGIBLE_ANALYST"
        details = {"region": region, "team": team, "queue_id": queue["queue_id"], "assigned_analyst": assigned,
                   "priority": priority, "sla_deadline": deadline, "required_skills": required,
                   "fallback": fallback, "reason": reason}
        connection.execute("INSERT INTO case_routing_events(case_id, tenant_id, actor_subject, action, reason, details_json) VALUES (?, ?, ?, ?, ?, ?)",
                           (case_id, tenant_id, actor_subject, action, reason, json.dumps(details, separators=(",", ":"))))
        connection.commit()
        row = connection.execute("SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        return dict(row)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_case_routing(case_id: str, tenant_id: str) -> dict | None:
    connection = get_connection()
    try:
        row = connection.execute("SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def get_soc_queue(tenant_id: str, region_key: str | None = None, limit: int = 200) -> list[dict]:
    connection = get_connection()
    try:
        params = [tenant_id]
        where = "r.tenant_id=? AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')"
        if region_key:
            where += " AND r.region_key=?"
            params.append(region_key)
        params.append(max(1, min(int(limit), 500)))
        rows = connection.execute(f"""
            SELECT r.case_id, c.title, c.severity, c.threat_score, c.status AS case_status,
                   c.created_at, c.updated_at, r.tenant_id, r.region_key, r.team_key, r.queue_id, r.assigned_analyst,
                   r.status AS routing_status, r.priority, r.sla_deadline, r.routing_reason,
                   r.required_skills_json, r.last_activity_at, r.escalation_count,
                   cc.assigned_analyst AS claim_owner, cc.lease_expires_at AS claim_expires_at,
                   CASE WHEN cc.status='ACTIVE' AND datetime(cc.lease_expires_at)<=datetime('now') THEN 1 ELSE 0 END AS claim_expired,
                   CASE WHEN r.sla_deadline IS NOT NULL AND datetime(r.sla_deadline)<=datetime('now') THEN 1 ELSE 0 END AS overdue
            FROM case_routing r JOIN cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
            LEFT JOIN case_claims cc ON cc.case_id=r.case_id AND cc.tenant_id=r.tenant_id
                AND cc.status='ACTIVE'
            WHERE {where}
            ORDER BY CASE r.priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
                     overdue DESC, r.sla_deadline ASC, r.last_activity_at DESC LIMIT ?
        """, tuple(params)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["required_skills"] = json.loads(item.pop("required_skills_json") or "[]")
            except (TypeError, json.JSONDecodeError):
                item["required_skills"] = []
            result.append(item)
        return result
    finally:
        connection.close()


def get_case_routing_events(case_id: str, tenant_id: str) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute("SELECT id, case_id, tenant_id, actor_subject, action, reason, details_json, created_at FROM case_routing_events WHERE case_id=? AND tenant_id=? ORDER BY id ASC", (case_id, tenant_id)).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def assign_case_manually(case_id: str, tenant_id: str, analyst_subject: str, actor_subject: str, reason: str) -> dict | None:
    reason = str(reason or "").strip()[:300]
    if len(reason) < 5:
        raise ValueError("A manual assignment reason of at least 5 characters is required.")
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        case = connection.execute("SELECT case_id FROM cases WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        analyst = connection.execute("SELECT subject_id, region_key, team_key, active FROM soc_analysts WHERE tenant_id=? AND subject_id=?", (tenant_id, analyst_subject)).fetchone()
        if case is None or analyst is None or not analyst["active"]:
            connection.rollback()
            return None
        routing = connection.execute("SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        if routing is None:
            connection.rollback()
            raise ValueError("Case must be routed before manual reassignment.")
        previous_claim = connection.execute(
            "SELECT assigned_analyst, status, lease_expires_at FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        active_claim = bool(previous_claim and previous_claim["status"] == "ACTIVE" and connection.execute(
            "SELECT datetime(?) > datetime('now')", (previous_claim["lease_expires_at"],)
        ).fetchone()[0])
        connection.execute("""
            UPDATE case_routing SET assigned_analyst=?, status='ASSIGNED', region_key=?, team_key=?,
                routing_reason='manual_override', assigned_at=CURRENT_TIMESTAMP, last_activity_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?
        """, (analyst_subject, analyst["region_key"], analyst["team_key"], case_id, tenant_id))
        if active_claim and previous_claim["assigned_analyst"] != analyst_subject:
            configured_lease = os.getenv("MAILTRACE_CASE_CLAIM_LEASE_MINUTES", "20")
            try:
                configured_lease = max(5, min(60, int(configured_lease)))
            except (TypeError, ValueError):
                configured_lease = 20
            connection.execute("""
                UPDATE case_claims SET assigned_analyst=?, lease_expires_at=datetime('now', ?), updated_at=CURRENT_TIMESTAMP
                WHERE case_id=? AND tenant_id=? AND status='ACTIVE'
            """, (analyst_subject, f"+{configured_lease} minutes", case_id, tenant_id))
            connection.execute("""
                INSERT INTO case_claim_events(case_id, tenant_id, actor_subject, action, details_json)
                VALUES (?, ?, ?, 'MANUAL_REASSIGN', ?)
            """, (case_id, tenant_id, actor_subject, json.dumps({
                "previous_owner": previous_claim["assigned_analyst"],
                "new_owner": analyst_subject,
                "reason": reason,
            }, separators=(",", ":"))))
        details = {"assigned_analyst": analyst_subject, "previous_assignee": routing["assigned_analyst"],
                   "region_key": analyst["region_key"], "team_key": analyst["team_key"]}
        connection.execute("INSERT INTO case_routing_events(case_id, tenant_id, actor_subject, action, reason, details_json) VALUES (?, ?, ?, 'MANUAL_OVERRIDE', ?, ?)",
                           (case_id, tenant_id, actor_subject, reason, json.dumps(details, separators=(",", ":"))))
        connection.commit()
        row = connection.execute("SELECT * FROM case_routing WHERE case_id=? AND tenant_id=?", (case_id, tenant_id)).fetchone()
        return dict(row)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_routing_tenant_ids() -> list[str]:
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT tenant_id FROM case_routing
            UNION SELECT tenant_id FROM cases WHERE tenant_id <> '__legacy_unassigned__'
            UNION SELECT tenant_id FROM employee_email_reports
        """).fetchall()
        return [str(row[0]) for row in rows if row[0]]
    finally:
        connection.close()


def get_pending_cases_for_routing(tenant_id: str, limit: int = 100) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT c.case_id, c.severity, c.threat_score,
                   r.reporter_subject, r.incident_type
            FROM cases c
            LEFT JOIN case_routing cr ON cr.case_id=c.case_id AND cr.tenant_id=c.tenant_id
            LEFT JOIN employee_email_reports r ON r.case_id=c.case_id AND r.tenant_id=c.tenant_id
            WHERE c.tenant_id=? AND cr.case_id IS NULL
              AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')
            ORDER BY CASE UPPER(c.severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                     c.created_at ASC LIMIT ?
        """, (tenant_id, max(1, min(int(limit), 500)))).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def process_sla_escalations(tenant_id: str) -> int:
    """Persist escalation events for overdue cases; safe to run from multiple workers."""
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        due = connection.execute("""
            SELECT r.case_id, r.priority, r.sla_deadline, r.assigned_analyst, r.status, r.escalation_count
            FROM case_routing r JOIN cases c ON c.case_id=r.case_id AND c.tenant_id=r.tenant_id
            WHERE r.tenant_id=? AND r.sla_deadline IS NOT NULL AND datetime(r.sla_deadline)<=datetime('now')
              AND r.status IN ('ASSIGNED','FALLBACK','QUEUED','UNROUTED')
              AND UPPER(COALESCE(c.status,'OPEN')) NOT IN ('CLOSED','RESOLVED')
              AND (r.last_escalated_at IS NULL OR datetime(r.last_escalated_at)<=datetime('now', CASE WHEN r.priority='P1' THEN '-15 minutes' ELSE '-60 minutes' END))
            ORDER BY CASE r.priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, r.sla_deadline
        """, (tenant_id,)).fetchall()
        for row in due:
            count = int(row["escalation_count"] or 0) + 1
            reason = "critical_sla_overdue" if row["priority"] == "P1" else "sla_overdue"
            details = {"priority": row["priority"], "sla_deadline": row["sla_deadline"],
                       "assigned_analyst": row["assigned_analyst"], "routing_status": row["status"],
                       "escalation_count": count, "unassigned": row["assigned_analyst"] is None}
            connection.execute("UPDATE case_routing SET last_escalated_at=CURRENT_TIMESTAMP, escalation_count=?, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?", (count, row["case_id"], tenant_id))
            connection.execute("INSERT INTO case_routing_events(case_id, tenant_id, actor_subject, action, reason, details_json) VALUES (?, ?, 'system:sla', 'SLA_ESCALATED', ?, ?)",
                               (row["case_id"], tenant_id, reason, json.dumps(details, separators=(",", ":"))))
            connection.execute("""
                INSERT INTO soc_sla_alerts(tenant_id, case_id, alert_type, priority, sla_deadline,
                    assigned_analyst, routing_status, escalation_count, status, last_seen_at)
                VALUES (?, ?, 'SLA_OVERDUE', ?, ?, ?, ?, ?, 'OPEN', CURRENT_TIMESTAMP)
                ON CONFLICT(tenant_id, case_id, alert_type) DO UPDATE SET
                    priority=excluded.priority, sla_deadline=excluded.sla_deadline,
                    assigned_analyst=excluded.assigned_analyst, routing_status=excluded.routing_status,
                    escalation_count=excluded.escalation_count, status='OPEN', last_seen_at=CURRENT_TIMESTAMP
            """, (tenant_id, row["case_id"], row["priority"], row["sla_deadline"],
                  row["assigned_analyst"], row["status"], count))
        connection.commit()
        return len(due)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
