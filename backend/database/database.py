import sqlite3
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

            filename TEXT NOT NULL,

            subject TEXT,

            sender TEXT,

            recipient TEXT,

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
    connection.commit()

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
    analysis_json
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO investigations (

            investigation_id,
            filename,
            subject,
            sender,
            recipient,
            threat_score,
            threat_verdict,
            threat_confidence,
            analysis_json

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        investigation_id,
        filename,
        subject,
        sender,
        recipient,
        threat_score,
        threat_verdict,
        threat_confidence,
        analysis_json

    ))

    connection.commit()

    connection.close()


# ==========================================
# GET ALL INVESTIGATIONS
# ==========================================

def get_all_investigations():

    connection = get_connection()

    cursor = connection.cursor()

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
            created_at

        FROM investigations

        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [dict(row) for row in rows]


# ==========================================
# GET SINGLE INVESTIGATION
# ==========================================

def get_investigation(
    investigation_id
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *

        FROM investigations

        WHERE investigation_id = ?
    """, (
        investigation_id,
    ))

    row = cursor.fetchone()

    connection.close()

    if row is None:

        return None

    return dict(row)
