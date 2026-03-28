from .db import get_connection

def insert_result(port, issue, risk_score):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_results (port, issue, risk_score) VALUES (?, ?, ?)",
                   (port, issue, risk_score))
    conn.commit()
    conn.close()

def fetch_results():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_results ORDER BY timestamp DESC")
    data = cursor.fetchall()
    conn.close()
    return data
