import os
import tempfile
import unittest
from unittest.mock import patch

from database import db


class EmptyScanStateTests(unittest.TestCase):
    def test_successful_empty_scan_marks_tracked_devices_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {
                "DB_PATH": os.path.join(directory, "logs.db"),
                "ARCHIVE_PATH": os.path.join(directory, "archive.db"),
                "UNIQUE_PATH": os.path.join(directory, "unique.db"),
            }
            with patch.multiple("database.db", **paths):
                db.save_devices([("ONLINE", "192.0.2.10", "aa:bb:cc:00:00:10", "Test")])
                db.save_devices([])

                devices = db.get_all_devices()
                archived_devices = db.get_device_archive()

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["status"], "OFFLINE")
        self.assertEqual(archived_devices[0][1], "OFFLINE")


if __name__ == "__main__":
    unittest.main()