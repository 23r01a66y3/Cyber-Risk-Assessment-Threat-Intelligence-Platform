import sqlite3

DB_NAME = "cyber_risk.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        port INTEGER,
        issue TEXT,
        risk_score INTEGER
    )
    """)

    conn.commit()
    conn.close()
