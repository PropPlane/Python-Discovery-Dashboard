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
        last_seen TEXT
    )
    """)

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
        last_seen TEXT
    )
    """)

    con.commit()
    con.close()

#live device saving start
def save_devices(devices):
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
        cur.execute(
            """
            INSERT INTO logs (status, ip, mac, manufacturer, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen
            """,
            (status, ip, mac, manufacturer, last_seen),
        )

        archive_cur.execute(
            """
            INSERT INTO device_archive (ip, status, mac, manufacturer, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen
            """,
            (ip, status, mac, manufacturer, last_seen),
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
            INSERT OR REPLACE INTO device_archive (ip, mac, manufacturer, last_seen)
            VALUES (?, ?, ?, ?)
            """,
            row,
        )

    archive_con.commit()
    archive_con.close()
    con.close()
#device archive end

def get_all_devices():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    rows = cur.execute("SELECT * FROM logs").fetchall()

    con.close()
    return rows

def get_device_archive():
    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()

    rows = cur.execute("SELECT * FROM device_archive").fetchall()

    con.close()
    return rows