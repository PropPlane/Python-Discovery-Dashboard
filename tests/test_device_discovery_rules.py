import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database import db


class NewDeviceDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path_patch = patch(
            "database.db.DB_PATH", os.path.join(self.temp_dir.name, "devices.db")
        )
        self.db_path_patch.start()
        db.init_db()
        con = sqlite3.connect(db.DB_PATH)
        con.executemany(
            "INSERT INTO logs (ip, mac) VALUES (?, ?)",
            [
                ("192.168.1.10", "aa:bb:cc:00:00:10"),
                ("192.168.1.11", "aa:bb:cc:00:00:11"),
            ],
        )
        con.commit()
        con.close()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def test_only_unseen_macs_or_changed_ip_claims_are_reported(self):
        scan_results = [
            ("192.168.1.10", "aa:bb:cc:00:00:10"),
            ("192.168.1.20", "aa:bb:cc:00:00:10"),
            ("192.168.1.11", "aa:bb:cc:00:00:99"),
            ("192.168.1.30", "aa:bb:cc:00:00:30"),
            ("192.168.1.30", "aa:bb:cc:00:00:30"),
            ("192.168.1.40", "aa:bb:cc:00:00:40"),
        ]

        new_devices = db.get_new_devices(scan_results, exclude_ips={"192.168.1.40"})

        self.assertEqual(new_devices, [
            ("192.168.1.11", "aa:bb:cc:00:00:99"),
            ("192.168.1.30", "aa:bb:cc:00:00:30"),
        ])


if __name__ == "__main__":
    unittest.main()