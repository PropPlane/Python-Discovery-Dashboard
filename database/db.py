import sqlite3
from datetime import datetime


DB_PATH = "database/logs.db"


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        ip TEXT PRIMARY KEY,
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

    last_seen = datetime.now().isoformat()

    for ip, mac, manufacturer in devices:
        cur.execute("""
            INSERT INTO logs (ip, mac, manufacturer, last_seen) VALUES (?, ?, ?, ?)

            ON CONFLICT(ip) 
            DO UPDATE SET mac=excluded.mac, manufacturer=excluded.manufacturer, last_seen=excluded.last_seen
            """, (ip, mac, manufacturer, last_seen)
        )

    con.commit()
    con.close()


def get_all_devices():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    rows = cur.execute("SELECT * FROM logs").fetchall()

    con.close()
    return rows