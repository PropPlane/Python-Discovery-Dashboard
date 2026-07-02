from utils.startup_text import module_startup_text

module_startup_text(__file__)

import os
import sqlite3
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "logs.db")
ARCHIVE_PATH = os.path.join(BASE_DIR, "device_archive.db")

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        ip TEXT PRIMARY KEY,
        status TEXT,
        mac TEXT,
        manufacturer TEXT,
        last_seen TEXT,
        hidden INTEGER DEFAULT 0,
        total_seconds INTEGER DEFAULT 0
    )
    """)

    cur.execute("PRAGMA table_info(logs)")
    existing_columns = [row[1] for row in cur.fetchall()]
    if "hidden" not in existing_columns:
        cur.execute("ALTER TABLE logs ADD COLUMN hidden INTEGER DEFAULT 0")
    if "total_seconds" not in existing_columns:
        cur.execute("ALTER TABLE logs ADD COLUMN total_seconds INTEGER DEFAULT 0")

    con.commit()
    con.close()

def init_archive_db():
    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS device_archive (
        ip TEXT PRIMARY KEY,
        status TEXT,
        mac TEXT,
        manufacturer TEXT,
        last_seen TEXT,
        hidden INTEGER DEFAULT 0,
        total_seconds INTEGER DEFAULT 0
    )
    """)

    cur.execute("PRAGMA table_info(device_archive)")
    archive_columns = [row[1] for row in cur.fetchall()]
    if "hidden" not in archive_columns:
        cur.execute("ALTER TABLE device_archive ADD COLUMN hidden INTEGER DEFAULT 0")
    if "total_seconds" not in archive_columns:
        cur.execute("ALTER TABLE device_archive ADD COLUMN total_seconds INTEGER DEFAULT 0")

    con.commit()
    con.close()

#live device saving start
def save_devices(devices, elapsed_seconds=0):
    init_archive_db()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()

    current_ips = [ip for _, ip, _, _ in devices]

    if current_ips:
        placeholders = ",".join("?" * len(current_ips))
        cur.execute(
            f"UPDATE logs SET status='OFFLINE' WHERE ip NOT IN ({placeholders})",
            current_ips,
        )

    last_seen = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")

    for status, ip, mac, manufacturer in devices:
        seconds_to_add = elapsed_seconds if status and status.lower() == "online" else 0

        cur.execute(
            """
            INSERT INTO logs (status, ip, mac, manufacturer, last_seen, hidden, total_seconds)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                hidden = hidden,
                total_seconds = total_seconds + excluded.total_seconds
            """,
            (status, ip, mac, manufacturer, last_seen, seconds_to_add),
        )

        archive_cur.execute(
            """
            INSERT INTO device_archive (ip, status, mac, manufacturer, last_seen, hidden, total_seconds)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                hidden = hidden,
                total_seconds = total_seconds + excluded.total_seconds
            """,
            (ip, status, mac, manufacturer, last_seen, seconds_to_add),
        )

    con.commit()
    con.close()
    archive_con.commit()
    archive_con.close()

#live device saving end

#device archive start
def archive_devices():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("SELECT * FROM logs")
    rows = cur.fetchall()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()

    for row in rows:
        archive_cur.execute(
            """
            INSERT OR REPLACE INTO device_archive (ip, status, mac, manufacturer, last_seen, hidden, total_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    archive_con.commit()
    archive_con.close()
    con.close()
#device archive end

def get_all_devices(include_hidden=False):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    if include_hidden:
        rows = cur.execute("SELECT * FROM logs").fetchall()
    else:
        rows = cur.execute("SELECT * FROM logs WHERE hidden=0").fetchall()

    con.close()
    return [
        {
            "ip": row[0],
            "status": row[1],
            "mac": row[2],
            "manufacturer": row[3],
            "last_seen": row[4],
            "hidden": bool(row[5]),
            "total_seconds": row[6],
        }
        for row in rows
    ]


def set_device_hidden(ip, hidden):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("UPDATE logs SET hidden=? WHERE ip=?", (1 if hidden else 0, ip))
    con.commit()
    con.close()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()
    archive_cur.execute("UPDATE device_archive SET hidden=? WHERE ip=?", (1 if hidden else 0, ip))
    archive_con.commit()
    archive_con.close()


def get_network_usage():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    row = cur.execute("SELECT SUM(total_seconds) FROM logs").fetchone()
    con.close()
    return int(row[0] or 0)

def get_device_archive():
    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()

    rows = cur.execute("SELECT * FROM device_archive").fetchall()

    con.close()
    return rows