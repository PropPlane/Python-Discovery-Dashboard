import sqlite3
from datetime import datetime


DB_PATH = "database/logs.db"


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        ip TEXT PRIMARY KEY,
        status TEXT,
        mac TEXT,
        manufacturer TEXT,
        last_seen TEXT
    )
    """)

    con.commit()
    con.close()


def save_devices(devices):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # Get list of current IPs from scan
    current_ips = [ip for _, ip, _, _ in devices]
    
    # Mark devices not in current scan as OFFLINE (but keep the row)
    if current_ips:
        placeholders = ",".join("?" * len(current_ips))
        cur.execute(f"UPDATE logs SET status='OFFLINE' WHERE ip NOT IN ({placeholders})", current_ips)

    last_seen = datetime.now().isoformat()

    for status, ip, mac, manufacturer in devices:
        cur.execute("""
            INSERT INTO logs (status, ip, mac, manufacturer, last_seen) VALUES (?, ?, ?, ?, ?)

            ON CONFLICT(ip) 
            DO UPDATE SET status=excluded.status, mac=excluded.mac, manufacturer=excluded.manufacturer, last_seen=excluded.last_seen
            """, (status, ip, mac, manufacturer, last_seen)
        )

    con.commit()
    con.close()


def get_all_devices():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    rows = cur.execute("SELECT * FROM logs").fetchall()

    con.close()
    return rows