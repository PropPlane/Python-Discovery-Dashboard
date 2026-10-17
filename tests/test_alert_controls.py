import os
import tempfile
import unittest
from unittest.mock import patch

from database import db
from web.app import app


class AlertControlApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path_patch = patch(
            "database.db.DB_PATH", os.path.join(self.temp_dir.name, "alerts.db")
        )
        self.db_path_patch.start()
        db.init_db()
        self.client = app.test_client()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def add_alert(self, source_ip):
        return db.save_ids_alert({
            "alert_type": "Port scan",
            "severity": "medium",
            "source_ip": source_ip,
            "description": "Test alert detail.",
            "created_at": "2026-10-17T10:00:00+00:00",
        })

    def test_delete_single_alert(self):
        self.add_alert("192.0.2.10")
        alert_id = db.get_recent_ids_alerts()[0]["id"]

        response = self.client.delete(f"/api/ids/alerts/{alert_id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(db.get_recent_ids_alerts(), [])

    def test_clear_alerts(self):
        self.add_alert("192.0.2.10")
        self.add_alert("192.0.2.11")

        response = self.client.delete("/api/ids/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 2)
        self.assertEqual(db.get_recent_ids_alerts(), [])

    def test_alert_response_includes_target_and_mitre_metadata(self):
        db.save_ids_alert({
            "alert_type": "Custom rule: Flood watch",
            "severity": "high",
            "source_ip": None,
            "destination_ip": "192.0.2.50",
            "description": "Three sources targeted one host.",
            "created_at": "2026-10-17T10:00:00+00:00",
            "mitre_id": "T1498.001",
        })

        response = self.client.get("/api/ids/alerts")
        alert = response.get_json()[0]

        self.assertEqual(alert["destination_ip"], "192.0.2.50")
        self.assertEqual(alert["mitre_id"], "T1498.001")

    def test_network_endpoint_returns_selected_ssid(self):
        with patch("web.app.detect_interface", return_value=("Wi-Fi", "192.168.1.12")), \
                patch("web.app.get_network_ssid", return_value="Office LAN"):
            response = self.client.get("/api/network")

        self.assertEqual(response.get_json(), {
            "ssid": "Office LAN",
            "interface": "Wi-Fi",
            "ip": "192.168.1.12",
        })

    def test_paused_capture_is_not_reported_as_active(self):
        class PausedSniffer:
            _running = True
            iface = None

        with patch("web.app.get_global_sniffer", return_value=PausedSniffer()):
            response = self.client.get("/api/sniffer/status")

        self.assertFalse(response.get_json()["enabled"])
        self.assertTrue(response.get_json()["running"])
        self.assertIsNone(response.get_json()["interface"])


if __name__ == "__main__":
    unittest.main()