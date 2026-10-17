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
                """)
                con.commit()
                con.close()

                migrated = db.get_ids_rules()[0]

            self.assertEqual(migrated["name"], "Legacy scan")
            self.assertEqual(migrated["metric"], "unique_ports")
            self.assertEqual(migrated["group_by"], "source_ip")
            self.assertEqual(migrated["mitre_id"], "T1046")


if __name__ == "__main__":
    unittest.main()