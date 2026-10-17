import os
import tempfile
import unittest
from unittest.mock import patch

from database import db
from web.app import app


class IdsRulesApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path_patch = patch(
            "database.db.DB_PATH", os.path.join(self.temp_dir.name, "rules.db")
        )
        self.db_path_patch.start()
        db.init_db()
        self.client = app.test_client()

    def tearDown(self):
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    def valid_rule(self):
        return {
            "name": "Watch web scan",
            "rule_type": "port_scan",
            "threshold": 12,
            "window_seconds": 30,
            "severity": "high",
            "source_ip": "",
            "protocol": "TCP",
            "enabled": True,
        }

    def test_create_list_disable_and_delete_rule(self):
        created = self.client.post("/api/ids/rules", json=self.valid_rule())
        self.assertEqual(created.status_code, 201)
        rule_id = created.get_json()["id"]
        self.assertEqual(len(self.client.get("/api/ids/rules").get_json()), 1)

        disabled = self.client.patch(
            f"/api/ids/rules/{rule_id}", json={"enabled": False}
        )
        self.assertEqual(disabled.status_code, 200)
        self.assertFalse(disabled.get_json()["enabled"])
        self.assertEqual(db.get_ids_rules(enabled_only=True), [])

        deleted = self.client.delete(f"/api/ids/rules/{rule_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get("/api/ids/rules").get_json(), [])

    def test_invalid_rule_is_rejected(self):
        invalid = self.valid_rule()
        invalid["threshold"] = 1

        response = self.client.post("/api/ids/rules", json=invalid)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Threshold", response.get_json()["error"])

    def test_ping_and_new_device_rules_get_type_specific_defaults(self):
        ping_rule = self.valid_rule()
        ping_rule.update({"name": "Ping watcher", "rule_type": "ping_activity", "protocol": "TCP"})
        ping_response = self.client.post("/api/ids/rules", json=ping_rule)
        self.assertEqual(ping_response.status_code, 201)
        self.assertEqual(ping_response.get_json()["protocol"], "ICMP")

        device_rule = {
            "name": "New device watcher",
            "rule_type": "new_device",
            "severity": "medium",
        }
        device_response = self.client.post("/api/ids/rules", json=device_rule)
        self.assertEqual(device_response.status_code, 201)
        self.assertEqual(device_response.get_json()["threshold"], 1)
        self.assertEqual(device_response.get_json()["window_seconds"], 60)

    def test_target_flood_defaults_to_destination_group_and_mitre_technique(self):
        response = self.client.post("/api/ids/rules", json={
            "name": "Watch destination floods",
            "rule_type": "target_flood",
            "threshold": 500,
            "window_seconds": 10,
            "severity": "high",
        })

        self.assertEqual(response.status_code, 201)
        rule = response.get_json()
        self.assertEqual(rule["group_by"], "destination_ip")
        self.assertEqual(rule["metric"], "count")
        self.assertEqual(rule["min_sources"], 3)
        self.assertEqual(rule["mitre_id"], "T1498.001")

    def test_metric_group_and_mitre_fields_are_validated(self):
        invalid_group = self.valid_rule()
        invalid_group.update({
            "metric": "unique_destinations",
            "group_by": "destination_ip",
        })
        response = self.client.post("/api/ids/rules", json=invalid_group)
        self.assertEqual(response.status_code, 400)

        invalid_mitre = self.valid_rule()
        invalid_mitre.update({"name": "Bad technique", "mitre_id": "ATTACK-1018"})
        response = self.client.post("/api/ids/rules", json=invalid_mitre)
        self.assertEqual(response.status_code, 400)

    def test_custom_rule_persists_excluded_device_ips(self):
        rule_data = self.valid_rule()
        rule_data.update({
            "excluded_ips": ["192.0.2.10", "192.0.2.11", "192.0.2.10"],
        })
        response = self.client.post("/api/ids/rules", json=rule_data)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["excluded_ips"], ["192.0.2.10", "192.0.2.11"])

        invalid = self.valid_rule()
        invalid["name"] = "Invalid excluded address"
        invalid["excluded_ips"] = ["not-an-ip"]
        response = self.client.post("/api/ids/rules", json=invalid)
        self.assertEqual(response.status_code, 400)

    def test_global_exemption_api_rejects_custom_rule_categories(self):
        response = self.client.post("/api/ids/exemptions", json={
            "device_ip": "192.0.2.10",
            "alert_type": "Custom rule",
        })
        self.assertEqual(response.status_code, 400)

    def test_rule_event_types_and_metrics(self):
        cases = [
            ("Ping sweep", "ping_sweep", "unique_destinations", "T1018"),
            ("ARP sweep", "arp_sweep", "unique_destinations", "T1018"),
            ("SYN scan", "syn_scan", "unique_ports", "T1046"),
        ]
        for name, rule_type, metric, mitre_id in cases:
            response = self.client.post("/api/ids/rules", json={
                "name": name,
                "rule_type": rule_type,
                "threshold": 5,
                "window_seconds": 20,
                "severity": "medium",
            })
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.get_json()["metric"], metric)
            self.assertEqual(response.get_json()["mitre_id"], mitre_id)


if __name__ == "__main__":
    unittest.main()