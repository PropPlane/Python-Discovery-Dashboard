from utils.startup_text import module_startup_text

module_startup_text(__file__)

import os
import sqlite3
import ipaddress
import json
import re
from datetime import datetime
import time

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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ids_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        rule_type TEXT NOT NULL,
        threshold INTEGER NOT NULL,
        window_seconds INTEGER NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        protocol TEXT NOT NULL DEFAULT 'ANY',
        metric TEXT NOT NULL DEFAULT 'count',
        group_by TEXT NOT NULL DEFAULT 'source_ip',
        destination_ip TEXT,
        min_sources INTEGER NOT NULL DEFAULT 1,
        mitre_id TEXT,
        excluded_ips TEXT NOT NULL DEFAULT '[]',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ids_alert_exemptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(device_ip, alert_type)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS traffic_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at_ms INTEGER NOT NULL,
        packet_count INTEGER NOT NULL,
        interval_seconds REAL NOT NULL,
        packets_per_second REAL NOT NULL
    )
    """)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_traffic_samples_recorded_at "
        "ON traffic_samples(recorded_at_ms)"
    )

    alert_columns = {row[1] for row in cur.execute("PRAGMA table_info(ids_alerts)")}
    if "destination_ip" not in alert_columns:
        cur.execute("ALTER TABLE ids_alerts ADD COLUMN destination_ip TEXT")
    if "mitre_id" not in alert_columns:
        cur.execute("ALTER TABLE ids_alerts ADD COLUMN mitre_id TEXT")

    rule_columns = {row[1] for row in cur.execute("PRAGMA table_info(ids_rules)")}
    rule_migrations = {
        "metric": "TEXT NOT NULL DEFAULT 'count'",
        "group_by": "TEXT NOT NULL DEFAULT 'source_ip'",
        "destination_ip": "TEXT",
        "min_sources": "INTEGER NOT NULL DEFAULT 1",
        "mitre_id": "TEXT",
        "excluded_ips": "TEXT NOT NULL DEFAULT '[]'",
    }
    for column, definition in rule_migrations.items():
        if column not in rule_columns:
            cur.execute(f"ALTER TABLE ids_rules ADD COLUMN {column} {definition}")
    if "metric" not in rule_columns:
        cur.execute("UPDATE ids_rules SET metric='unique_ports' WHERE rule_type='port_scan'")
        cur.execute("UPDATE ids_rules SET metric='event' WHERE rule_type='new_device'")
    cur.execute(
        "UPDATE ids_rules SET mitre_id='T1046' "
        "WHERE rule_type='port_scan' AND mitre_id IS NULL"
    )
    
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
        for connection_cursor, table in (
            (cur, "logs"),
            (archive_cur, "device_archive"),
            (unique_cur, "unique_devices"),
        ):
            connection_cursor.execute(
                f"UPDATE {table} SET status='OFFLINE' WHERE ip NOT IN ({placeholders})",
                current_ips,
            )
    else:
        for connection_cursor, table in (
            (cur, "logs"),
            (archive_cur, "device_archive"),
            (unique_cur, "unique_devices"),
        ):
            connection_cursor.execute(f"UPDATE {table} SET status='OFFLINE'")

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
    init_db()
    init_archive_db()

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
    init_db()

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
    init_db()
    init_archive_db()

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
    init_archive_db()

    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()
    row = cur.execute("SELECT SUM(total_seconds) FROM device_archive").fetchone()
    con.close()
    return int(row[0] or 0)


def get_unique_device_count():
    """Returns the number of devices currently tracked in the unique devices DB."""
    init_unique_db()

    con = sqlite3.connect(UNIQUE_PATH)
    cur = con.cursor()
    row = cur.execute("SELECT COUNT(*) FROM unique_devices").fetchone()
    con.close()
    return int(row[0] or 0)


def get_device_archive():
    """Safely retrieves all archive entries (Fixes the cut-off bug)."""
    init_archive_db()

    con = sqlite3.connect(ARCHIVE_PATH)
    cur = con.cursor()
    rows = cur.execute("SELECT ip, status, mac, manufacturer, last_seen, hidden, total_seconds FROM device_archive").fetchall()
    con.close()
    return rows


def save_ids_alert(alert):
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO ids_alerts
            (alert_type, severity, source_ip, destination_ip, description, created_at, mitre_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (alert["alert_type"], alert["severity"], alert.get("source_ip"),
         alert.get("destination_ip"), alert["description"], alert["created_at"],
         alert.get("mitre_id")),
    )
    cur.execute(
        "DELETE FROM ids_alerts WHERE id NOT IN "
        "(SELECT id FROM ids_alerts ORDER BY id DESC LIMIT 1000)"
    )
    con.commit()
    con.close()


def get_recent_ids_alerts(limit=100):
    init_db()
    limit = max(1, min(int(limit), 500))
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT id, alert_type, severity, source_ip, destination_ip, description, created_at, mitre_id "
        "FROM ids_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    con.close()
    return [dict(row) for row in rows]


def delete_ids_alert(alert_id):
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM ids_alerts WHERE id = ?", (int(alert_id),))
    con.commit()
    deleted = cur.rowcount > 0
    con.close()
    return deleted


def delete_all_ids_alerts():
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM ids_alerts")
    con.commit()
    deleted_count = cur.rowcount
    con.close()
    return deleted_count

def is_ids_alert_exempt(alert, exemptions):
    alert_type = alert.get("alert_type", "")
    if alert_type.startswith("Custom rule: "):
        return False
    device_ips = {alert.get("source_ip"), alert.get("destination_ip")}
    return any(
        exemption["device_ip"] in device_ips
        and (
            exemption["alert_type"] == "*"
            or exemption["alert_type"] == alert_type
        )
        for exemption in exemptions
    )


def get_ids_alert_exemptions():
    """Return all configured IDS alert exemptions."""
    init_db()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    rows = con.execute(
        """
        SELECT id, device_ip, alert_type, created_at
        FROM ids_alert_exemptions
        ORDER BY id DESC
        """
    ).fetchall()

    con.close()
    return [dict(row) for row in rows]


def add_ids_alert_exemption(device_ip, alert_type="*"):
    """Add an exemption for a device and alert type."""
    device_ip = str(device_ip or "").strip()
    alert_type = str(alert_type or "*").strip()

    if not device_ip:
        raise ValueError("Device IP is required.")

    try:
        if ipaddress.ip_address(device_ip).version != 4:
            raise ValueError
    except ValueError as error:
        raise ValueError("Device IP must be a valid IPv4 address.") from error

    if not alert_type:
        alert_type = "*"

    if len(alert_type) > 100:
        raise ValueError("Alert type must be 100 characters or fewer.")

    init_db()
    created_at = datetime.now().astimezone().isoformat(timespec="seconds")

    con = sqlite3.connect(DB_PATH)

    try:
        cur = con.execute(
            """
            INSERT INTO ids_alert_exemptions
                (device_ip, alert_type, created_at)
            VALUES (?, ?, ?)
            """,
            (device_ip, alert_type, created_at),
        )
        exemption_id = cur.lastrowid
        con.commit()

        row = con.execute(
            """
            SELECT id, device_ip, alert_type, created_at
            FROM ids_alert_exemptions
            WHERE id = ?
            """,
            (exemption_id,),
        ).fetchone()

        return {
            "id": row[0],
            "device_ip": row[1],
            "alert_type": row[2],
            "created_at": row[3],
        }

    except sqlite3.IntegrityError as error:
        con.rollback()
        raise ValueError(
            "An exemption for this device and alert type already exists."
        ) from error

    finally:
        con.close()


def delete_ids_alert_exemption(exemption_id):
    """Delete an exemption by its database ID."""
    init_db()

    con = sqlite3.connect(DB_PATH)

    try:
        cur = con.execute(
            "DELETE FROM ids_alert_exemptions WHERE id = ?",
            (int(exemption_id),),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def _validate_ids_rule(data):
    if not isinstance(data, dict):
        raise ValueError("Rule data must be a JSON object.")

    name = str(data.get("name", "")).strip()
    if not name or len(name) > 60:
        raise ValueError("Rule name must be between 1 and 60 characters.")

    rule_type = str(data.get("rule_type", "")).strip().lower()
    allowed_types = (
        "packet_burst", "port_scan", "ping_activity", "ping_sweep",
        "arp_sweep", "syn_scan", "target_flood", "new_device",
    )
    if rule_type not in allowed_types:
        raise ValueError("Choose a supported network event type.")

    default_metrics = {
        "packet_burst": "count",
        "port_scan": "unique_ports",
        "ping_activity": "count",
        "ping_sweep": "unique_destinations",
        "arp_sweep": "unique_destinations",
        "syn_scan": "unique_ports",
        "target_flood": "count",
        "new_device": "event",
    }
    allowed_metrics = {
        "packet_burst": ("count", "unique_destinations", "unique_ports", "unique_sources"),
        "port_scan": ("count", "unique_ports"),
        "ping_activity": ("count", "unique_destinations"),
        "ping_sweep": ("unique_destinations",),
        "arp_sweep": ("unique_destinations",),
        "syn_scan": ("count", "unique_ports"),
        "target_flood": ("count", "unique_sources"),
        "new_device": ("event",),
    }
    metric = str(data.get("metric") or default_metrics[rule_type]).strip().lower()
    if metric not in allowed_metrics[rule_type]:
        raise ValueError("Metric is not supported for this event type.")

    default_group = "destination_ip" if rule_type == "target_flood" else "source_ip"
    group_by = str(data.get("group_by") or default_group).strip().lower()
    if rule_type == "new_device":
        group_by = "source_ip"
        destination_ip = None
    if group_by not in ("source_ip", "destination_ip"):
        raise ValueError("Group by must be source_ip or destination_ip.")
    if metric == "unique_destinations" and group_by != "source_ip":
        raise ValueError("Distinct destination counts must be grouped by source IP.")
    if metric == "unique_sources" and group_by != "destination_ip":
        raise ValueError("Unique source counts must be grouped by destination IP.")

    if rule_type == "new_device":
        threshold, window_seconds = 1, 60
    else:
        try:
            threshold = int(data.get("threshold"))
            window_seconds = int(data.get("window_seconds"))
        except (TypeError, ValueError) as error:
            raise ValueError("Threshold and window must be whole numbers.") from error

        max_threshold = 65536 if metric.startswith("unique_") else 10000000
        if threshold < 2 or threshold > max_threshold:
            raise ValueError(f"Threshold must be between 2 and {max_threshold}.")
        if window_seconds < 1 or window_seconds > 3600:
            raise ValueError("Window must be between 1 and 3600 seconds.")

    severity = str(data.get("severity", "")).strip().lower()
    if severity not in ("low", "medium", "high"):
        raise ValueError("Severity must be low, medium, or high.")

    def validate_ip_filter(field_name):
        ip_filter = str(data.get(field_name) or "").strip() or None
        if not ip_filter:
            return None
        try:
            if ipaddress.ip_address(ip_filter).version != 4:
                raise ValueError(f"{field_name} filter must be an IPv4 address.")
        except ValueError as error:
            raise ValueError(f"{field_name} filter must be a valid IPv4 address.") from error
        return ip_filter

    source_ip = validate_ip_filter("source_ip")
    destination_ip = validate_ip_filter("destination_ip")

    protocol = str(data.get("protocol", "ANY")).strip().upper()
    fixed_protocols = {
        "ping_activity": "ICMP",
        "ping_sweep": "ICMP",
        "arp_sweep": "ARP",
        "syn_scan": "TCP",
        "new_device": "ANY",
    }
    protocol_options = {
        "packet_burst": ("ANY", "TCP", "UDP", "ICMP"),
        "port_scan": ("ANY", "TCP", "UDP"),
        "target_flood": ("ANY", "TCP", "UDP", "ICMP"),
    }
    if rule_type in fixed_protocols:
        protocol = fixed_protocols[rule_type]
    elif protocol not in protocol_options[rule_type]:
        raise ValueError("Protocol is not supported for this event type.")

    default_mitre = {
        "port_scan": "T1046",
        "ping_sweep": "T1018",
        "arp_sweep": "T1018",
        "syn_scan": "T1046",
        "target_flood": "T1498.001",
    }
    mitre_id = str(data.get("mitre_id") or default_mitre.get(rule_type) or "").strip().upper() or None
    if mitre_id and not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", mitre_id):
        raise ValueError("MITRE ID must look like T1018 or T1498.001.")

    raw_excluded_ips = data.get("excluded_ips", [])
    if isinstance(raw_excluded_ips, str):
        raw_excluded_ips = re.split(r"[,\n\r]+", raw_excluded_ips)
    if not isinstance(raw_excluded_ips, (list, tuple)):
        raise ValueError("Excluded devices must be a list of IPv4 addresses.")
    excluded_ips = []
    for raw_ip in raw_excluded_ips:
        excluded_ip = str(raw_ip or "").strip()
        if not excluded_ip:
            continue
        try:
            if ipaddress.ip_address(excluded_ip).version != 4:
                raise ValueError
        except ValueError as error:
            raise ValueError(f"Excluded device is not a valid IPv4 address: {excluded_ip}") from error
        if excluded_ip not in excluded_ips:
            excluded_ips.append(excluded_ip)
    if len(excluded_ips) > 100:
        raise ValueError("A rule can exclude at most 100 device IPs.")

    default_min_sources = 3 if rule_type == "target_flood" else 1
    try:
        min_sources = int(data.get("min_sources", default_min_sources))
    except (TypeError, ValueError) as error:
        raise ValueError("Minimum source count must be a whole number.") from error
    if not 1 <= min_sources <= 10000:
        raise ValueError("Minimum source count must be between 1 and 10000.")
    if min_sources > 1 and group_by != "destination_ip":
        raise ValueError("Multiple-source thresholds require grouping by destination IP.")
    if rule_type == "new_device":
        min_sources = 1

    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("Enabled must be a boolean.")

    return {
        "name": name,
        "rule_type": rule_type,
        "threshold": threshold,
        "window_seconds": window_seconds,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "metric": metric,
        "group_by": group_by,
        "min_sources": min_sources,
        "mitre_id": mitre_id,
        "excluded_ips": excluded_ips,
        "enabled": enabled,
    }


def create_ids_rule(data):
    init_db()
    rule = _validate_ids_rule(data)
    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.execute(
            """
            INSERT INTO ids_rules
                 (name, rule_type, threshold, window_seconds, severity, source_ip,
                  protocol, metric, group_by, destination_ip, min_sources, mitre_id,
                                    excluded_ips, enabled, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rule["name"], rule["rule_type"], rule["threshold"],
             rule["window_seconds"], rule["severity"], rule["source_ip"],
               rule["protocol"], rule["metric"], rule["group_by"],
               rule["destination_ip"], rule["min_sources"], rule["mitre_id"],
               json.dumps(rule["excluded_ips"]), int(rule["enabled"]),
             datetime.now().astimezone().isoformat(timespec="seconds")),
        )
        rule_id = cur.lastrowid
        con.commit()
    except sqlite3.IntegrityError as error:
        raise ValueError("A rule with that name already exists.") from error
    finally:
        con.close()
    return get_ids_rule(rule_id)


def get_ids_rule(rule_id):
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM ids_rules WHERE id = ?", (int(rule_id),)).fetchone()
    con.close()
    return _ids_rule_dict(row) if row else None


def _ids_rule_dict(row):
    rule = dict(row)
    rule["enabled"] = bool(rule["enabled"])
    try:
        rule["excluded_ips"] = json.loads(rule.get("excluded_ips") or "[]")
    except (TypeError, json.JSONDecodeError):
        rule["excluded_ips"] = []
    return rule


def get_ids_rules(enabled_only=False):
    init_db()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    query = "SELECT * FROM ids_rules"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY id DESC"
    rows = con.execute(query).fetchall()
    con.close()
    return [_ids_rule_dict(row) for row in rows]


def set_ids_rule_enabled(rule_id, enabled):
    if not isinstance(enabled, bool):
        raise ValueError("Enabled must be a boolean.")
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "UPDATE ids_rules SET enabled = ? WHERE id = ?",
        (int(enabled), int(rule_id)),
    )
    con.commit()
    updated = cur.rowcount > 0
    con.close()
    return get_ids_rule(rule_id) if updated else None


def delete_ids_rule(rule_id):
    init_db()
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM ids_rules WHERE id = ?", (int(rule_id),))
    con.commit()
    deleted = cur.rowcount > 0
    con.close()
    return deleted


def get_new_devices(devices, exclude_ips=None):
    """Return newly observed IP/MAC pairs before the current scan is saved."""
    init_db()
    excluded = set(exclude_ips or ())
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT ip, mac FROM logs").fetchall()
    con.close()

    known_by_ip = {ip: (mac or "").lower() for ip, mac in rows}
    known_macs = {mac for mac in known_by_ip.values() if mac}
    new_devices = []
    for ip, mac in devices:
        if ip in excluded:
            continue
        normalized_mac = (mac or "").lower()
        old_mac = known_by_ip.get(ip)
        is_new_device = False
        if old_mac is None:
            if not normalized_mac or normalized_mac not in known_macs:
                is_new_device = True
        elif normalized_mac and old_mac and normalized_mac != old_mac:
            is_new_device = True

        if is_new_device:
            new_devices.append((ip, mac))
        if normalized_mac:
            known_macs.add(normalized_mac)
        known_by_ip[ip] = normalized_mac
    return new_devices


def record_packet_count(count, interval_seconds=10, recorded_at_ms=None):
    init_db()
    packet_count = max(0, int(count))
    interval_seconds = max(float(interval_seconds), 0.001)
    timestamp = int(recorded_at_ms or time.time() * 1000)

    con = sqlite3.connect(DB_PATH)
    con.execute(
        """
        INSERT INTO traffic_samples
            (recorded_at_ms, packet_count, interval_seconds, packets_per_second)
        VALUES (?, ?, ?, ?)
        """,
        (timestamp, packet_count, interval_seconds, packet_count / interval_seconds),
    )
    retention_cutoff = timestamp - 30 * 24 * 60 * 60 * 1000
    con.execute("DELETE FROM traffic_samples WHERE recorded_at_ms < ?", (retention_cutoff,))
    con.commit()
    con.close()


def get_recent_packet_counts(limit=120):
    init_db()
    limit = max(1, min(int(limit), 1000))
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT recorded_at_ms, packet_count, interval_seconds, packets_per_second
        FROM (
            SELECT recorded_at_ms, packet_count, interval_seconds, packets_per_second, id
            FROM traffic_samples
            ORDER BY recorded_at_ms DESC, id DESC
            LIMIT ?
        )
        ORDER BY recorded_at_ms ASC, id ASC
        """,
        (limit,),
    ).fetchall()
    con.close()
    return [dict(row) for row in rows]
