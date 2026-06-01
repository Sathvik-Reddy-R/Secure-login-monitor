import sqlite3

DB = "security.db"


def get_connection():
    return sqlite3.connect(DB)


def init_db():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips(
        ip TEXT UNIQUE,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts(
        ip TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS detections(
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        ip TEXT,
        country TEXT,
        region TEXT,
        city TEXT,

        organization TEXT,

        provider_type TEXT,

        risk_score INTEGER,

        threat_level TEXT,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_requests(
        ip TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices(

        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        device_hash TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes(
        email TEXT PRIMARY KEY,
        otp TEXT,
        expires_at DATETIME
    )
    """)
    conn.commit()
    conn.close()
