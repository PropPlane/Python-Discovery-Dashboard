from utils.startup_text import module_startup_text

module_startup_text(__file__)

import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "logs.db")
ARCHIVE_PATH = os.path.join(BASE_DIR, "device_archive.db")
UNIQUE_PATH = os.path.join(BASE_DIR, "unique_devices.db")

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
        first_seen TEXT       
    )
    """)
    
    cur.execute("PRAGMA table_info(logs)")
    existing_columns = [row[1] for row in cur.fetchall()]
    if "hidden" not in existing_columns:
        cur.execute("ALTER TABLE logs ADD COLUMN hidden INTEGER DEFAULT 0")
    if "first_seen" not in existing_columns:
        cur.execute("ALTER TABLE logs ADD COLUMN first_seen TEXT")

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

def init_unique_db():
    con = sqlite3.connect(UNIQUE_PATH)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS unique_devices (
        ip TEXT PRIMARY KEY,
        status TEXT,
        mac TEXT,
        manufacturer TEXT,
        last_seen TEXT,
        hidden INTEGER DEFAULT 0,
        first_seen TEXT
    )
    """)

    cur.execute("PRAGMA table_info(unique_devices)")
    unique_columns = [row[1] for row in cur.fetchall()]
    if "hidden" not in unique_columns:
        cur.execute("ALTER TABLE unique_devices ADD COLUMN hidden INTEGER DEFAULT 0")
    if "first_seen" not in unique_columns:
        cur.execute("ALTER TABLE unique_devices ADD COLUMN first_seen TEXT")

    con.commit()
    con.close()


def save_devices(devices, elapsed_seconds=0):
    init_db()
    init_archive_db()
    init_unique_db()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()

    unique_con = sqlite3.connect(UNIQUE_PATH)
    unique_cur = unique_con.cursor()

    current_ips = [ip for _, ip, _, _ in devices]

    if current_ips:
        placeholders = ",".join("?" * len(current_ips))
        cur.execute(
            f"UPDATE logs SET status='OFFLINE' WHERE ip NOT IN ({placeholders})",
            current_ips,
        )

    # Standard ISO format allows SQLite time math to work correctly
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for status, ip, mac, manufacturer in devices:
        is_online = status and status.lower() == "online"
        seconds_to_add = elapsed_seconds if is_online else 0

        # 1. Save to Logs
        cur.execute(
            """
            INSERT INTO logs (ip, status, mac, manufacturer, last_seen, hidden, first_seen)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                first_seen = COALESCE(logs.first_seen, excluded.first_seen)
            """,
            (ip, status, mac, manufacturer, now_str, now_str),
        )

        # 2. Save to Archive (Tracks accumulated active time)
        archive_cur.execute(
            """
            INSERT INTO device_archive (ip, status, mac, manufacturer, last_seen, hidden, total_seconds)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                total_seconds = total_seconds + excluded.total_seconds
            """,
            (ip, status, mac, manufacturer, now_str, seconds_to_add),
        )

        # 3. Save to Unique Devices (Added missing 'hidden' column so 7 parameters match 7 columns)
        unique_cur.execute(
            """
            INSERT INTO unique_devices (ip, status, mac, manufacturer, last_seen, hidden, first_seen)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                first_seen = COALESCE(unique_devices.first_seen, excluded.first_seen)
            """,
            (ip, status, mac, manufacturer, now_str, now_str),
        )

    # Run cleanup once outside the loop using correct modifier syntax
    unique_cur.execute(
        """
        DELETE FROM unique_devices
        WHERE (strftime('%s', 'now') - strftime('%s', first_seen)) >= 86400
        """
    )

    con.commit()
    con.close()
    archive_con.commit()
    archive_con.close()
    unique_con.commit()
    unique_con.close()


def archive_devices():
    """Copies current log stats safely over to the archive file."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT ip, status, mac, manufacturer, last_seen, hidden FROM logs")
    rows = cur.fetchall()
    con.close()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()

    for row in rows:
        archive_cur.execute(
            """
            INSERT INTO device_archive (ip, status, mac, manufacturer, last_seen, hidden, total_seconds)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(ip) DO UPDATE SET
                status = excluded.status,
                mac = excluded.mac,
                manufacturer = excluded.manufacturer,
                last_seen = excluded.last_seen,
                hidden = excluded.hidden
            """,
            row,
        )

    archive_con.commit()
    archive_con.close()


def get_all_devices(include_hidden=False):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    if include_hidden:
        rows = cur.execute("SELECT ip, status, mac, manufacturer, last_seen, hidden, first_seen FROM logs").fetchall()
    else:
        rows = cur.execute("SELECT ip, status, mac, manufacturer, last_seen, hidden, first_seen FROM logs WHERE hidden=0").fetchall()

    con.close()
    return [
        {
            "ip": row[0],
            "status": row[1],
            "mac": row[2],
            "manufacturer": row[3],
            "last_seen": row[4],
            "hidden": bool(row[5]),
            "first_seen": row[6],
        }
        for row in rows
    ]


def set_device_hidden(ip, hidden):
    val = 1 if hidden else 0
    
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("UPDATE logs SET hidden=? WHERE ip=?", (val, ip))
    con.commit()
    con.close()

    archive_con = sqlite3.connect(ARCHIVE_PATH)
    archive_cur = archive_con.cursor()
    archive_cur.execute("UPDATE device_archive SET hidden=? WHERE ip=?", (val, ip))
    archive_con.commit()
    archive_con.close()


def get_total_logged_seconds():
    """Returns the total network active time tracked inside the archive."""
    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()
    row = cur.execute("SELECT SUM(total_seconds) FROM device_archive").fetchone()
    con.close()
    return int(row[0] or 0)


def get_device_archive():
    """Safely retrieves all archive entries (Fixes the cut-off bug)."""
    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()
    rows = cur.execute("SELECT ip, status, mac, manufacturer, last_seen, hidden, total_seconds FROM device_archive").fetchall()
    con.close()
    return rows
