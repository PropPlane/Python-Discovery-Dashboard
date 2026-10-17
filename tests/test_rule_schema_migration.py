import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database import db


class RuleSchemaMigrationTests(unittest.TestCase):
    def test_legacy_rules_get_generic_fields_without_losing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = os.path.join(directory, "legacy.db")
            with patch("database.db.DB_PATH", db_path):
                con = sqlite3.connect(db_path)
                con.executescript("""
                    CREATE TABLE ids_alerts (
                        id INTEGER PRIMARY KEY, alert_type TEXT, severity TEXT,
                        source_ip TEXT, description TEXT, created_at TEXT
                    );
                    CREATE TABLE ids_rules (
                        id INTEGER PRIMARY KEY, name TEXT UNIQUE, rule_type TEXT,
                        threshold INTEGER, window_seconds INTEGER, severity TEXT,
                        source_ip TEXT, protocol TEXT, enabled INTEGER, created_at TEXT
                    );
                    INSERT INTO ids_rules
                        (name, rule_type, threshold, window_seconds, severity,
                         protocol, enabled, created_at)
                    VALUES ('Legacy scan', 'port_scan', 15, 20, 'medium',
                            'TCP', 1, '2026-10-17T10:00:00+00:00');
                    CREATE TABLE ids_alert_exemptions (
                        id INTEGER PRIMARY KEY, device_ip TEXT, alert_type TEXT, created_at TEXT,
                        UNIQUE(device_ip, alert_type)
                    );
                    INSERT INTO ids_alert_exemptions (device_ip, alert_type, created_at)
                    VALUES ('192.0.2.25', 'Custom rule: Legacy scan', '2026-10-17T10:00:00+00:00');
                """)
                con.commit()
                con.close()

                migrated = db.get_ids_rules()[0]
                remaining_exemptions = db.get_ids_alert_exemptions()

            self.assertEqual(migrated["name"], "Legacy scan")
            self.assertEqual(migrated["metric"], "unique_ports")
            self.assertEqual(migrated["group_by"], "source_ip")
            self.assertEqual(migrated["mitre_id"], "T1046")
            self.assertEqual(migrated["excluded_ips"], ["192.0.2.25"])
            self.assertEqual(remaining_exemptions, [])

    def test_custom_rule_wildcard_exemption_migrates_to_each_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = os.path.join(directory, "legacy-wildcard.db")
            with patch("database.db.DB_PATH", db_path):
                con = sqlite3.connect(db_path)
                con.executescript("""
                    CREATE TABLE ids_rules (
                        id INTEGER PRIMARY KEY, name TEXT UNIQUE, rule_type TEXT,
                        threshold INTEGER, window_seconds INTEGER, severity TEXT,
                        source_ip TEXT, protocol TEXT, enabled INTEGER, created_at TEXT
                    );
                    INSERT INTO ids_rules (name, rule_type, threshold, window_seconds, severity,
                                           protocol, enabled, created_at)
                    VALUES ('Rule A', 'packet_burst', 3, 10, 'high', 'ANY', 1, 'now');
                    INSERT INTO ids_rules (name, rule_type, threshold, window_seconds, severity,
                                           protocol, enabled, created_at)
                    VALUES ('Rule B', 'packet_burst', 3, 10, 'high', 'ANY', 1, 'now');
                    CREATE TABLE ids_alert_exemptions (
                        id INTEGER PRIMARY KEY, device_ip TEXT, alert_type TEXT, created_at TEXT,
                        UNIQUE(device_ip, alert_type)
                    );
                    INSERT INTO ids_alert_exemptions (device_ip, alert_type, created_at)
                    VALUES ('192.0.2.55', 'Custom rule', 'now');
                """)
                con.commit()
                con.close()

                rules = db.get_ids_rules()
                remaining_exemptions = db.get_ids_alert_exemptions()

            self.assertEqual({rule["name"] for rule in rules}, {"Rule A", "Rule B"})
            self.assertTrue(all(rule["excluded_ips"] == ["192.0.2.55"] for rule in rules))
            self.assertEqual(remaining_exemptions, [])


if __name__ == "__main__":
    unittest.main()