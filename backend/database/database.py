import sqlite3
import secrets
import json
from pathlib import Path


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "mailtrace.db"


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
            tenant_id TEXT,

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
    # CASE â†” INVESTIGATION
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
    # CAMPAIGN â†” INVESTIGATION
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
    investigation_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(investigations)")
    }
    if "smtp_recipient" not in investigation_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN smtp_recipient TEXT")
    if "tenant_id" not in investigation_columns:
        cursor.execute("ALTER TABLE investigations ADD COLUMN tenant_id TEXT")
    for table in ("cases", "campaigns", "case_investigations", "campaign_investigations", "case_notes", "evidence"):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "tenant_id" not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT")
    connection.commit()

    initialize_email_alerts()

    connection.close()


def initialize_email_webhook_events():
    """Create the delivery ledger used for webhook idempotency and retries."""
    connection = get_connection()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS email_webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            tenant_id TEXT,
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
    # Older deployments created event_id as globally UNIQUE. Rebuild the small
    # delivery ledger once so the idempotency boundary is tenant-scoped.
    indexes = connection.execute("PRAGMA index_list(email_webhook_events)").fetchall()
    has_global_event_unique = False
    for idx in indexes:
        if int(idx[2]) != 1:
            continue
        idx_name = idx[1]
        indexed_cols = [row[2] for row in connection.execute(f"PRAGMA index_info([{idx_name}])").fetchall()]
        if indexed_cols == ["event_id"]:
            has_global_event_unique = True
            break
    if has_global_event_unique:
        connection.execute("ALTER TABLE email_webhook_events RENAME TO email_webhook_events_legacy")
        connection.execute("""
            CREATE TABLE email_webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                tenant_id TEXT,
                payload_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('processing', 'completed', 'failed')),
                attempts INTEGER NOT NULL DEFAULT 1,
                lease_token TEXT,
                investigation_id TEXT,
                policy_decision_json TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(event_id, tenant_id)
            )
        """)
        connection.execute("""
            INSERT INTO email_webhook_events (
                id, event_id, tenant_id, payload_fingerprint, status, attempts,
                lease_token, investigation_id, policy_decision_json, last_error,
                created_at, updated_at
            )
            SELECT id, event_id, tenant_id, payload_fingerprint, status, attempts,
                   lease_token, investigation_id, policy_decision_json, last_error,
                   created_at, updated_at
            FROM email_webhook_events_legacy
        """)
        connection.execute("DROP TABLE email_webhook_events_legacy")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(email_webhook_events)")}
    if "tenant_id" not in columns:
        connection.execute("ALTER TABLE email_webhook_events ADD COLUMN tenant_id TEXT")
    if "lease_token" not in columns:
        connection.execute("ALTER TABLE email_webhook_events ADD COLUMN lease_token TEXT")
    if "policy_decision_json" not in columns:
        connection.execute("ALTER TABLE email_webhook_events ADD COLUMN policy_decision_json TEXT")
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_email_webhook_events_status
        ON email_webhook_events(status, updated_at)
    """)
    connection.commit()
    connection.close()


def begin_email_webhook_event(event_id: str, payload_fingerprint: str, tenant_id: str | None = None) -> dict:
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
            "SELECT * FROM email_webhook_events WHERE event_id = ? AND tenant_id IS ?",
            (event_id, tenant_id),
        ).fetchone()

        if row is None:
            connection.execute(
                "INSERT INTO email_webhook_events (event_id, tenant_id, payload_fingerprint, status, attempts, lease_token) VALUES (?, ?, ?, 'processing', 1, ?)",
                (event_id, tenant_id, payload_fingerprint, lease_token),
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
        elif row["tenant_id"] != tenant_id or row["payload_fingerprint"] != payload_fingerprint:
            connection.rollback()
            return {"event_id": event_id, "status": "conflict", "attempts": row["attempts"]}
        elif row["status"] == "failed":
            connection.execute(
                "UPDATE email_webhook_events SET status='processing', attempts=attempts+1, lease_token=?, last_error=NULL, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND tenant_id IS ?",
                (lease_token, event_id, tenant_id),
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
                    "UPDATE email_webhook_events SET attempts=attempts+1, lease_token=?, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND tenant_id IS ?",
                    (lease_token, event_id, tenant_id),
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
                tenant_id TEXT,
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
        if "tenant_id" not in columns:
            connection.execute("ALTER TABLE email_alerts ADD COLUMN tenant_id TEXT")
        event_columns = {row["name"] for row in connection.execute("PRAGMA table_info(email_alert_events)")}
        if "tenant_id" not in event_columns:
            connection.execute("ALTER TABLE email_alert_events ADD COLUMN tenant_id TEXT")
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



def initialize_soc_routing():
    """Create tenant-scoped SOC routing configuration, assignments and audit tables."""
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS soc_queues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queue_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                region_key TEXT NOT NULL,
                is_central INTEGER NOT NULL DEFAULT 0 CHECK(is_central IN (0,1)),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, queue_id),
                UNIQUE(tenant_id, name)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS employee_region_assignments (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                region_key TEXT NOT NULL,
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
                queue_id TEXT NOT NULL,
                assigned_analyst TEXT,
                status TEXT NOT NULL CHECK(status IN ('QUEUED','ASSIGNED','FALLBACK','UNROUTED')),
                routing_reason TEXT NOT NULL DEFAULT '',
                assigned_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS case_routing_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_subject TEXT,
                action TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_queues_region ON soc_queues(tenant_id, region_key, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_employee_region ON employee_region_assignments(tenant_id, region_key, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_soc_analysts_load ON soc_analysts(tenant_id, region_key, active)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_case_routing_queue ON case_routing(tenant_id, queue_id, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_case_routing_events_case ON case_routing_events(tenant_id, case_id, id)")
        connection.commit()
    finally:
        connection.close()


def ensure_central_soc_queue(tenant_id: str) -> dict:
    """Create/get a safe tenant-local central fallback queue."""
    tenant_id = str(tenant_id).strip()
    if not tenant_id:
        raise ValueError("tenant_id is required")
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO soc_queues (queue_id, tenant_id, name, region_key, is_central, active)
            VALUES ('CENTRAL', ?, 'Central SOC', 'CENTRAL', 1, 1)
            ON CONFLICT(tenant_id, queue_id) DO UPDATE SET
                active=1, is_central=1, region_key='CENTRAL', updated_at=CURRENT_TIMESTAMP
        """, (tenant_id,))
        row = connection.execute(
            "SELECT * FROM soc_queues WHERE tenant_id=? AND queue_id='CENTRAL'",
            (tenant_id,),
        ).fetchone()
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def configure_soc_queue(tenant_id: str, queue_id: str, name: str, region_key: str, *, is_central=False, active=True) -> dict:
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO soc_queues (queue_id, tenant_id, name, region_key, is_central, active)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, queue_id) DO UPDATE SET
                name=excluded.name, region_key=excluded.region_key,
                is_central=excluded.is_central, active=excluded.active,
                updated_at=CURRENT_TIMESTAMP
        """, (queue_id, tenant_id, name, region_key, int(is_central), int(active)))
        row = connection.execute(
            "SELECT * FROM soc_queues WHERE tenant_id=? AND queue_id=?",
            (tenant_id, queue_id),
        ).fetchone()
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def configure_employee_region(tenant_id: str, subject_id: str, region_key: str, *, source='admin_config', active=True) -> dict:
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO employee_region_assignments (tenant_id, subject_id, region_key, source, active)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, subject_id) DO UPDATE SET
                region_key=excluded.region_key, source=excluded.source,
                active=excluded.active, updated_at=CURRENT_TIMESTAMP
        """, (tenant_id, subject_id, region_key, source, int(active)))
        row = connection.execute(
            "SELECT * FROM employee_region_assignments WHERE tenant_id=? AND subject_id=?",
            (tenant_id, subject_id),
        ).fetchone()
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def configure_soc_analyst(tenant_id: str, subject_id: str, region_key: str, *, max_open_cases=20, active=True) -> dict:
    max_open_cases = max(1, min(int(max_open_cases), 1000))
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO soc_analysts (tenant_id, subject_id, region_key, active, max_open_cases)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, subject_id) DO UPDATE SET
                region_key=excluded.region_key, active=excluded.active,
                max_open_cases=excluded.max_open_cases, updated_at=CURRENT_TIMESTAMP
        """, (tenant_id, subject_id, region_key, int(active), max_open_cases))
        row = connection.execute(
            "SELECT * FROM soc_analysts WHERE tenant_id=? AND subject_id=?",
            (tenant_id, subject_id),
        ).fetchone()
        connection.commit()
        return dict(row)
    finally:
        connection.close()


def route_case_to_soc(case_id: str, tenant_id: str, reporter_subject: str, *, actor_subject=None) -> dict:
    """Route a case by registered employee region; never uses IP geolocation for routing.

    If the employee has no active regional mapping or the regional queue is unavailable,
    the case is routed to the tenant's central SOC queue. Analyst assignment is capacity-aware.
    """
    initialize_soc_routing()
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        employee = connection.execute("""
            SELECT region_key FROM employee_region_assignments
            WHERE tenant_id=? AND subject_id=? AND active=1
        """, (tenant_id, reporter_subject)).fetchone()
        requested_region = str(employee["region_key"]).strip() if employee else ""
        queue = None
        reason = "regional_mapping"
        fallback = False
        if requested_region:
            queue = connection.execute("""
                SELECT * FROM soc_queues
                WHERE tenant_id=? AND region_key=? AND active=1 AND is_central=0
                ORDER BY id LIMIT 1
            """, (tenant_id, requested_region)).fetchone()
        if queue is None:
            fallback = True
            reason = "central_fallback:no_active_regional_queue" if requested_region else "central_fallback:no_employee_region"
            connection.execute("""
                INSERT INTO soc_queues (queue_id, tenant_id, name, region_key, is_central, active)
                VALUES ('CENTRAL', ?, 'Central SOC', 'CENTRAL', 1, 1)
                ON CONFLICT(tenant_id, queue_id) DO UPDATE SET active=1, is_central=1, region_key='CENTRAL', updated_at=CURRENT_TIMESTAMP
            """, (tenant_id,))
            queue = connection.execute("SELECT * FROM soc_queues WHERE tenant_id=? AND queue_id='CENTRAL'", (tenant_id,)).fetchone()

        region_for_assignment = str(queue["region_key"])
        analysts = connection.execute("""
            SELECT a.subject_id, a.max_open_cases,
                   COALESCE((
                     SELECT COUNT(*)
                     FROM case_routing cr
                     JOIN cases c ON c.case_id=cr.case_id
                     WHERE cr.tenant_id=a.tenant_id
                       AND cr.assigned_analyst=a.subject_id
                       AND cr.status='ASSIGNED'
                       AND UPPER(COALESCE(c.status, 'OPEN')) NOT IN ('CLOSED', 'RESOLVED')
                   ), 0) AS open_load
            FROM soc_analysts a
            WHERE a.tenant_id=? AND a.region_key=? AND a.active=1
            ORDER BY open_load ASC, a.subject_id ASC
        """, (tenant_id, region_for_assignment)).fetchall()
        analyst = next((row for row in analysts if int(row["open_load"]) < int(row["max_open_cases"])), None)
        assigned_analyst = analyst["subject_id"] if analyst else None
        status = "ASSIGNED" if assigned_analyst else ("FALLBACK" if fallback else "QUEUED")
        if fallback and assigned_analyst is None:
            reason += ";no_available_central_analyst"
        elif assigned_analyst is None:
            reason += ";no_available_regional_analyst"

        connection.execute("""
            INSERT INTO case_routing (case_id, tenant_id, region_key, queue_id, assigned_analyst, status, routing_reason, assigned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE CURRENT_TIMESTAMP END)
            ON CONFLICT(case_id) DO UPDATE SET
                tenant_id=excluded.tenant_id, region_key=excluded.region_key,
                queue_id=excluded.queue_id, assigned_analyst=excluded.assigned_analyst,
                status=excluded.status, routing_reason=excluded.routing_reason,
                assigned_at=excluded.assigned_at, updated_at=CURRENT_TIMESTAMP
        """, (case_id, tenant_id, region_for_assignment, queue["queue_id"], assigned_analyst, status, reason, assigned_analyst))
        connection.execute("""
            INSERT INTO case_routing_events (case_id, tenant_id, actor_subject, action, details_json)
            VALUES (?, ?, ?, ?, ?)
        """, (case_id, tenant_id, actor_subject, "ROUTED", json.dumps({
            "region": region_for_assignment, "queue_id": queue["queue_id"],
            "assigned_analyst": assigned_analyst, "fallback": fallback, "reason": reason,
        }, separators=(",", ":"))))
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
            CREATE INDEX IF NOT EXISTS idx_case_claims_owner_status
            ON case_claims(tenant_id, assigned_analyst, status, lease_expires_at)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_case_claim_events_case
            ON case_claim_events(tenant_id, case_id, id)
        """)
        connection.commit()
    finally:
        connection.close()


def claim_case_for_analyst(
    case_id: str,
    tenant_id: str,
    analyst_subject: str,
    lease_minutes: int = 20,
) -> tuple[dict | None, bool]:
    """Atomically claim a case; at most one analyst owns an unexpired lease."""
    lease_minutes = max(5, min(60, int(lease_minutes)))
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if not connection.execute(
            "SELECT 1 FROM cases WHERE case_id=?", (case_id,)
        ).fetchone():
            connection.rollback()
            return None, False

        current = connection.execute("""
            SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?
        """, (case_id, tenant_id)).fetchone()
        if current and current["status"] == "ACTIVE":
            lease_valid = connection.execute(
                "SELECT datetime(?) > datetime('now')",
                (current["lease_expires_at"],),
            ).fetchone()[0]
            if lease_valid and current["assigned_analyst"] != analyst_subject:
                connection.commit()
                return dict(current), False
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
            json.dumps({"lease_minutes": lease_minutes}, separators=(",", ":")),
        ))
        assignment = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        connection.commit()
        return dict(assignment), True
    finally:
        connection.close()


def release_case_claim(
    case_id: str, tenant_id: str, analyst_subject: str
) -> tuple[dict | None, bool]:
    """Release only the caller's claim and preserve a release audit event."""
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute("""
            SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?
        """, (case_id, tenant_id)).fetchone()
        if current is None:
            connection.rollback()
            return None, False
        if current["status"] != "ACTIVE" or current["assigned_analyst"] != analyst_subject:
            connection.commit()
            return dict(current), False
        connection.execute("""
            UPDATE case_claims
            SET status='RELEASED', updated_at=CURRENT_TIMESTAMP
            WHERE case_id=? AND tenant_id=? AND assigned_analyst=? AND status='ACTIVE'
        """, (case_id, tenant_id, analyst_subject))
        connection.execute("""
            INSERT INTO case_claim_events (case_id, tenant_id, actor_subject, action)
            VALUES (?, ?, ?, 'RELEASED')
        """, (case_id, tenant_id, analyst_subject))
        released = connection.execute(
            "SELECT * FROM case_claims WHERE case_id=? AND tenant_id=?",
            (case_id, tenant_id),
        ).fetchone()
        connection.commit()
        return dict(released), True
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
                    update_values.append(existing["case_id"])
                    connection.execute(
                        f"UPDATE cases SET {', '.join(case_updates)}, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
                        tuple(update_values) + (tenant_id,),
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
            WHERE ci.investigation_id = ? AND ci.tenant_id = ? AND c.tenant_id = ?
            ORDER BY c.created_at ASC, c.id ASC
            LIMIT 1
        """, (investigation_id, tenant_id, tenant_id)).fetchone()
        case_id = linked_case["case_id"] if linked_case else "CASE-" + secrets.token_hex(5).upper()
        connection.execute("""
            INSERT OR IGNORE INTO cases (case_id, tenant_id, title, description, severity, status, threat_score)
            VALUES (?, ?, ?, ?, ?, 'OPEN', 0)
        """, (
            case_id,
            tenant_id,
            f"Employee reported email incident â€” {investigation_id}",
            f"Employee {reporter_email} reported {incident_type} for investigation {investigation_id}."
            + (f"\n\nEmployee context: {employee_note}" if employee_note else ""),
            case_severity,
        ))
        if linked_case:
            case_severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            case_updates = []
            if case_severity_rank.get(case_severity, 0) > case_severity_rank.get(str(linked_case["severity"]).upper(), 0):
                case_updates.append("severity=?")
            if str(linked_case["status"]).upper() in {"CLOSED", "RESOLVED"}:
                case_updates.append("status='OPEN'")
            if case_updates:
                update_values = ([case_severity] if "severity=?" in case_updates else [])
                update_values.append(case_id)
                connection.execute(
                    f"UPDATE cases SET {', '.join(case_updates)}, updated_at=CURRENT_TIMESTAMP WHERE case_id=? AND tenant_id=?",
                    tuple(update_values) + (tenant_id,),
                )
        current_description = connection.execute(
            "SELECT description FROM cases WHERE case_id=?", (case_id,)
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
            INSERT OR IGNORE INTO case_investigations (case_id, tenant_id, investigation_id)
            VALUES (?, ?, ?)
        """, (case_id, tenant_id, investigation_id))
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
) -> dict:
    """Idempotently create an alert without duplicating email content."""
    connection = get_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id=? AND tenant_id IS ?", (event_id, tenant_id)
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
                f"Automated {severity.lower()} email review â€” {investigation_id}",
                f"Created from trusted mail-gateway event {event_id}.",
                severity,
                max(0, min(100, int(threat_score))),
            ),
        )
        connection.execute(
            "INSERT OR IGNORE INTO case_investigations (case_id, investigation_id, tenant_id) VALUES (?, ?, ?)",
            (case_id, investigation_id, tenant_id),
        )
        alert_id = "ALT-" + secrets.token_hex(6).upper()
        connection.execute(
            """
            INSERT OR IGNORE INTO email_alerts (
                alert_id, event_id, investigation_id, case_id, tenant_id, severity, threat_score,
                confidence, policy_version, recommended_action, user_notice_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id, event_id, investigation_id, case_id, tenant_id, severity,
                max(0, min(100, int(threat_score))), confidence,
                policy_version[:80], recommended_action,
                json.dumps(user_notice, separators=(",", ":")) if user_notice else None,
            ),
        )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id = ? AND tenant_id IS ?", (event_id, tenant_id)
        ).fetchone()
        connection.execute(
            "INSERT INTO email_alert_events (alert_id, tenant_id, action, actor, details_json) VALUES (?, ?, 'CREATED', 'mailtrace-policy', ?)",
            (
                alert_id, tenant_id,
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
                   i.subject, i.sender, i.recipient
            FROM email_alerts a
            LEFT JOIN investigations i ON i.investigation_id = a.investigation_id
            WHERE a.recommended_action = 'QUARANTINE' AND a.confidence = 'HIGH'
              AND a.tenant_id IS ?
        """
        params: tuple = (tenant_id,)
        if status:
            query += " AND a.status = ?"
            params = (status,)
        query += " ORDER BY a.created_at DESC, a.id DESC LIMIT ?"
        rows = connection.execute(
            query, (*params, max(1, min(500, int(limit))))
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_email_alert_by_event(event_id: str, tenant_id: str | None = None) -> dict | None:
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE event_id=? AND tenant_id IS ?", (event_id, tenant_id)
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
            WHERE alert_id=? AND tenant_id IS ? AND status='NEW'
            """,
            (actor[:128], alert_id, tenant_id),
        )
        if cursor.rowcount:
            connection.execute(
                "INSERT INTO email_alert_events (alert_id, tenant_id, action, actor, details_json) VALUES (?, ?, 'ACKNOWLEDGED', ?, '{}')",
                (alert_id, tenant_id, actor[:128]),
            )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE alert_id=? AND tenant_id IS ?", (alert_id, tenant_id)
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
            WHERE alert_id=? AND tenant_id IS ? AND status IN ('NEW', 'ACKNOWLEDGED')
            """,
            (actor[:128], alert_id, tenant_id),
        )
        if cursor.rowcount:
            connection.execute(
                "INSERT INTO email_alert_events (alert_id, tenant_id, action, actor, details_json) VALUES (?, ?, 'RESOLVED', ?, '{}')",
                (alert_id, tenant_id, actor[:128]),
            )
        row = connection.execute(
            "SELECT * FROM email_alerts WHERE alert_id=? AND tenant_id IS ?", (alert_id, tenant_id)
        ).fetchone()
        connection.commit()
        return dict(row) if row else None
    finally:
        connection.close()


def get_email_alert_history(alert_id: str) -> list[dict]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT action, actor, details_json, created_at FROM email_alert_events WHERE alert_id=? ORDER BY id ASC",
            (alert_id,),
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
    tenant_id: str | None = None,
) -> bool:
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET status='completed', investigation_id=?, policy_decision_json=?, lease_token=NULL, last_error=NULL, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND tenant_id IS ? AND status='processing' AND lease_token=?",
            (
                investigation_id,
                json.dumps(policy_decision, separators=(",", ":")) if policy_decision else None,
                event_id,
                tenant_id,
                lease_token,
            ),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


def renew_email_webhook_event_lease(event_id: str, lease_token: str, tenant_id: str | None = None) -> bool:
    """Keep an active worker claim fresh; return false after ownership is lost."""
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND tenant_id IS ? AND status='processing' AND lease_token=?",
            (event_id, tenant_id, lease_token),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


def fail_email_webhook_event(event_id: str, error: str, lease_token: str, tenant_id: str | None = None) -> bool:
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE email_webhook_events SET status='failed', lease_token=NULL, last_error=?, updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND tenant_id IS ? AND status='processing' AND lease_token=?",
            (error[:500], event_id, tenant_id, lease_token),
        )
        connection.commit()
        return connection.total_changes > 0
    finally:
        connection.close()


# ==========================================
# SAVE INVESTIGATION
# ==========================================

def save_investigation(
    investigation_id, filename, subject, sender, recipient,
    threat_score, threat_verdict, threat_confidence, analysis_json,
    smtp_recipient=None, tenant_id=None,
):
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO investigations (
                investigation_id, tenant_id, filename, subject, sender, recipient,
                smtp_recipient, threat_score, threat_verdict, threat_confidence, analysis_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            investigation_id, tenant_id, filename, subject, sender, recipient,
            smtp_recipient, threat_score, threat_verdict, threat_confidence, analysis_json
        ))
        connection.commit()
    finally:
        connection.close()


# ==========================================
# GET ALL INVESTIGATIONS
# ==========================================

def get_all_investigations(tenant_id=None):

    connection = get_connection()

    cursor = connection.cursor()

    if tenant_id is None:
        cursor.execute("""
            SELECT investigation_id, filename, subject, sender, recipient, threat_score,
                   threat_verdict, threat_confidence, analysis_json, created_at, tenant_id
            FROM investigations ORDER BY created_at DESC
        """)
    else:
        cursor.execute("""
            SELECT investigation_id, filename, subject, sender, recipient, threat_score,
                   threat_verdict, threat_confidence, analysis_json, created_at, tenant_id
            FROM investigations WHERE tenant_id = ? ORDER BY created_at DESC
        """, (tenant_id,))

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_all_investigation_summaries(tenant_id=None):
    """Return list-view fields without loading full forensic analysis documents."""
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT
                investigation_id,
                filename,
                subject,
                sender,
                recipient,
                threat_score,
                threat_verdict,
                threat_confidence,
                created_at
            FROM investigations
            {where}
            ORDER BY created_at DESC, id DESC
        """.format(where="WHERE tenant_id = ?" if tenant_id is not None else ""), (tenant_id,) if tenant_id is not None else ()).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_investigation_snapshot_marker(tenant_id=None) -> tuple[int, int]:
    """Cheap cursor for checking whether the investigation snapshot changed."""
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

    connection = get_connection()

    cursor = connection.cursor()

    if tenant_id is None:
        cursor.execute("SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,))
    else:
        cursor.execute("SELECT * FROM investigations WHERE investigation_id = ? AND tenant_id = ?", (investigation_id, tenant_id))

    row = cursor.fetchone()

    connection.close()

    if row is None:

        return None

    return dict(row)

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
            tenant_id TEXT,

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

    ti_columns = {row["name"] for row in cursor.execute("PRAGMA table_info(threat_intelligence)").fetchall()}
    if "tenant_id" not in ti_columns:
        cursor.execute("ALTER TABLE threat_intelligence ADD COLUMN tenant_id TEXT")

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

    connection.commit()

    connection.close()


def save_threat_intelligence(
    indicators,
    tenant_id: str | None = None,
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
                        tenant_id,
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator.get("source"),
                    tenant_id,
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
    limit=100,
    tenant_id: str | None = None,
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
        WHERE tenant_id IS ? OR tenant_id IS NULL

        ORDER BY
            COALESCE(last_seen, first_seen, created_at)
            DESC

        LIMIT ?
    """, (
        int(limit),
        tenant_id,
    ))

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def lookup_threat_intelligence(ioc, limit=20, tenant_id: str | None = None):
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
              AND (tenant_id IS ? OR tenant_id IS NULL)
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
            tenant_id,
            int(limit),
        ))

        rows = cursor.fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()

def lookup_threat_intelligence_batch(iocs, limit_per_ioc=20, tenant_id: str | None = None):
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
            limit=limit_per_ioc,
            tenant_id=tenant_id,
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
