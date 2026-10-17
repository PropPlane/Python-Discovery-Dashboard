
from collections import defaultdict, deque
from datetime import datetime
import threading
import time


class CustomRuleEngine:
    def __init__(
        self,
        rules_provider=None,
        clock=None,
        refresh_seconds=5,
        alert_cooldown=60,
    ):
        self._rules_provider = rules_provider or self._load_enabled_rules
        self._clock = clock or time.monotonic
        self._refresh_seconds = refresh_seconds
        self._alert_cooldown = alert_cooldown
        self._lock = threading.Lock()
        self._rules = []
        self._last_refresh = float("-inf")
        self._events = defaultdict(deque)
        self._last_alert = {}

    @staticmethod
    def _load_enabled_rules():
        from database.db import get_ids_rules
        return get_ids_rules(enabled_only=True)

    def observe(
        self,
        source_ip=None,
        destination_ip=None,
        destination_port=None,
        protocol=None,
        icmp_type=None,
        tcp_syn=False,
        arp_op=None,
        arp_target_ip=None,
    ):
        """Observe a packet and return newly generated custom alerts."""
        now = self._clock()
        protocol = (protocol or "").upper()
        event_destination = arp_target_ip or destination_ip
        alerts = []

        with self._lock:
            rules = self._get_rules(now)

            for rule in rules:
                rule_type = rule["rule_type"]

                if rule_type == "new_device":
                    continue

                excluded_ips = set(rule.get("excluded_ips") or ())

                if (
                    source_ip in excluded_ips
                    or event_destination in excluded_ips
                ):
                    continue

                if (
                    rule.get("source_ip")
                    and rule["source_ip"] != source_ip
                ):
                    continue

                if (
                    rule.get("destination_ip")
                    and rule["destination_ip"] != event_destination
                ):
                    continue

                rule_protocol = rule.get("protocol", "ANY").upper()

                if rule_protocol != "ANY" and rule_protocol != protocol:
                    continue

                if not self._matches_event(
                    rule_type,
                    source_ip,
                    event_destination,
                    destination_port,
                    protocol,
                    icmp_type,
                    tcp_syn,
                    arp_op,
                    arp_target_ip,
                ):
                    continue

                group_by = rule.get("group_by", "source_ip")
                group_value = (
                    event_destination
                    if group_by == "destination_ip"
                    else source_ip
                )

                if not group_value:
                    continue

                metric = rule.get("metric") or self._default_metric(
                    rule_type
                )

                if metric == "count":
                    metric_value = None
                elif metric == "unique_destinations":
                    metric_value = event_destination
                elif metric == "unique_ports":
                    metric_value = destination_port
                elif metric == "unique_sources":
                    metric_value = source_ip
                else:
                    continue

                if metric != "count" and metric_value is None:
                    continue

                events = self._events[
                    (rule["id"], group_by, group_value)
                ]

                events.append((now, metric_value, source_ip))
                self._expire(events, now - rule["window_seconds"])

                observed = (
                    len(events)
                    if metric == "count"
                    else len({value for _, value, _ in events})
                )

                distinct_sources = len(
                    {ip for _, _, ip in events if ip}
                )

                if (
                    observed < rule["threshold"]
                    or distinct_sources < rule.get("min_sources", 1)
                ):
                    continue

                alert_key = (rule["id"], group_by, group_value)
                previous_alert = self._last_alert.get(alert_key)

                if (
                    previous_alert is not None
                    and now - previous_alert < self._alert_cooldown
                ):
                    continue

                self._last_alert[alert_key] = now

                observed_unit = self._metric_label(metric, rule_type)
                grouping_text = (
                    "source"
                    if group_by == "source_ip"
                    else "destination"
                )

                alerts.append({
                    "alert_type": f"Custom rule: {rule['name']}",
                    "severity": rule["severity"],
                    "source_ip": (
                        group_value
                        if group_by == "source_ip"
                        else None
                    ),
                    "destination_ip": (
                        group_value
                        if group_by == "destination_ip"
                        else None
                    ),
                    "mitre_id": rule.get("mitre_id"),
                    "description": (
                        f"Rule '{rule['name']}' matched "
                        f"{observed} {observed_unit} "
                        f"for {grouping_text} {group_value} within "
                        f"{rule['window_seconds']} seconds "
                        f"(threshold: {rule['threshold']}; "
                        f"distinct sources: {distinct_sources}, "
                        f"minimum: {rule.get('min_sources', 1)})."
                    ),
                    "created_at": datetime.now()
                    .astimezone()
                    .isoformat(timespec="seconds"),
                })

        return alerts

    def is_source_excluded_for_rule(self, rule_type, source_ip):
        """Check whether an enabled custom rule excludes a source IP."""
        if not rule_type or not source_ip:
            return False

        now = self._clock()

        with self._lock:
            rules = self._get_rules(now)

            for rule in rules:
                if rule.get("rule_type") != rule_type:
                    continue

                excluded_ips = set(rule.get("excluded_ips") or ())

                if source_ip in excluded_ips:
                    return True

        return False

    @staticmethod
    def _default_metric(rule_type):
        return {
            "packet_burst": "count",
            "port_scan": "unique_ports",
            "ping_activity": "count",
            "ping_sweep": "unique_destinations",
            "arp_sweep": "unique_destinations",
            "syn_scan": "unique_ports",
            "target_flood": "count",
            "new_device": "event",
        }.get(rule_type, "count")

    @staticmethod
    def _metric_label(metric, rule_type):
        if rule_type == "ping_activity" and metric == "count":
            return "ICMP echo requests"

        if metric == "count":
            return "packets"

        return {
            "unique_destinations": "distinct destination IPs",
            "unique_ports": "distinct destination ports",
            "unique_sources": "distinct source IPs",
        }.get(metric, "events")

    @staticmethod
    def _matches_event(
        rule_type,
        source_ip,
        destination_ip,
        destination_port,
        protocol,
        icmp_type,
        tcp_syn,
        arp_op,
        arp_target_ip,
    ):
        if rule_type in ("packet_burst", "target_flood"):
            return bool(
                source_ip
                and destination_ip
                and protocol in ("TCP", "UDP", "ICMP")
            )

        if rule_type == "port_scan":
            return (
                destination_port is not None
                and protocol in ("TCP", "UDP")
            )

        if rule_type == "syn_scan":
            return bool(
                source_ip
                and destination_port is not None
                and protocol == "TCP"
                and tcp_syn
            )

        if rule_type in ("ping_activity", "ping_sweep"):
            return bool(
                source_ip
                and destination_ip
                and protocol == "ICMP"
                and icmp_type == 8
            )

        if rule_type == "arp_sweep":
            return bool(
                source_ip
                and arp_target_ip
                and arp_op == 1
            )

        return False

    def observe_new_device(self, source_ip, mac_address=None):
        if not source_ip:
            return []

        now = self._clock()
        alerts = []

        with self._lock:
            for rule in self._get_rules(now):
                if rule["rule_type"] != "new_device":
                    continue

                if source_ip in set(rule.get("excluded_ips") or ()):
                    continue

                if (
                    rule.get("source_ip")
                    and rule["source_ip"] != source_ip
                ):
                    continue

                alert_key = (rule["id"], source_ip, "new_device")
                previous_alert = self._last_alert.get(alert_key)

                if (
                    previous_alert is not None
                    and now - previous_alert < self._alert_cooldown
                ):
                    continue

                self._last_alert[alert_key] = now
                mac_text = f" ({mac_address})" if mac_address else ""

                alerts.append({
                    "alert_type": f"Custom rule: {rule['name']}",
                    "severity": rule["severity"],
                    "source_ip": source_ip,
                    "destination_ip": None,
                    "mitre_id": rule.get("mitre_id"),
                    "description": (
                        f"Rule '{rule['name']}' matched a newly "
                        f"discovered device at {source_ip}{mac_text}."
                    ),
                    "created_at": datetime.now()
                    .astimezone()
                    .isoformat(timespec="seconds"),
                })

        return alerts

    def _get_rules(self, now):
        if now - self._last_refresh >= self._refresh_seconds:
            try:
                self._rules = list(self._rules_provider())
            except Exception:
                self._rules = []

            self._last_refresh = now

        return self._rules

    @staticmethod
    def _expire(events, cutoff):
        while events:
            if events[0][0] >= cutoff:
                break
            events.popleft()
