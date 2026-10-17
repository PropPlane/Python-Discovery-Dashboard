import os
import tempfile
import unittest
from unittest.mock import patch

from database import db


class PacketHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "traffic.db")
        self.db_path_patch = patch("database.db.DB_PATH", self.db_path)
        self.db_path_patch.start()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def test_packet_samples_are_persisted_in_time_order_with_rates(self):
        db.record_packet_count(80, interval_seconds=10, recorded_at_ms=2000)
        db.record_packet_count(60, interval_seconds=5, recorded_at_ms=1000)

        samples = db.get_recent_packet_counts()

        self.assertEqual([sample["recorded_at_ms"] for sample in samples], [1000, 2000])
        self.assertEqual([sample["packet_count"] for sample in samples], [60, 80])
        self.assertEqual([sample["packets_per_second"] for sample in samples], [12.0, 8.0])


if __name__ == "__main__":
    unittest.main()