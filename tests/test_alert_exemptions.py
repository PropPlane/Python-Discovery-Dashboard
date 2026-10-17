import os
import tempfile
import unittest
from unittest.mock import patch

from database import db
from web.app import app


class AlertExemptionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path_patch = patch(
            "database.db.DB_PATH", os.path.join(self.temp_dir.name, "exemptions.db")
        )
        self.db_path_patch.start()
        db.init_db()
        self.client = app.test_client()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def test_exemption_matches_only_its_device_and_alert_type(self):
        exemption = db.add_ids_alert_exemption("192.0.2.10", "Port scan")
        exemptions = db.get_ids_alert_exemptions()

        self.assertTrue(db.is_ids_alert_exempt({
            "alert_type": "Port scan", "source_ip": "192.0.2.10",
        }, exemptions))
        self.assertFalse(db.is_ids_alert_exempt({
            "alert_type": "Packet burst", "source_ip": "192.0.2.10",
        }, exemptions))
        self.assertFalse(db.is_ids_alert_exempt({
            "alert_type": "Port scan", "source_ip": "192.0.2.11",
        }, exemptions))
        self.assertEqual(exemption["alert_type"], "Port scan")

    def test_wildcard_exemption_matches_source_or_target(self):
        db.add_ids_alert_exemption("192.0.2.50", "*")
        exemptions = db.get_ids_alert_exemptions()

        self.assertTrue(db.is_ids_alert_exempt({
            "alert_type": "Packet burst", "destination_ip": "192.0.2.50",
        }, exemptions))

    def test_global_exemptions_do_not_suppress_custom_rules(self):
        db.add_ids_alert_exemption("192.0.2.10", "*")
        exemptions = db.get_ids_alert_exemptions()

        self.assertFalse(db.is_ids_alert_exempt({
            "alert_type": "Custom rule: Watch web probes",
            "source_ip": "192.0.2.10",
        }, exemptions))

    def test_custom_rule_categories_are_not_accepted_as_global_exemptions(self):
        with self.assertRaises(ValueError):
            db.add_ids_alert_exemption("192.0.2.10", "Custom rule")

    def test_api_add_list_validate_and_delete_exemption(self):
        response = self.client.post("/api/ids/exemptions", json={
            "device_ip": "192.0.2.10",
            "alert_type": "Conflicting ARP claim",
        })
        self.assertEqual(response.status_code, 201)
        exemption_id = response.get_json()["id"]
        self.assertEqual(len(self.client.get("/api/ids/exemptions").get_json()), 1)

        invalid = self.client.post("/api/ids/exemptions", json={"device_ip": "bad-ip"})
        self.assertEqual(invalid.status_code, 400)

        deleted = self.client.delete(f"/api/ids/exemptions/{exemption_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get("/api/ids/exemptions").get_json(), [])


if __name__ == "__main__":
    unittest.main()