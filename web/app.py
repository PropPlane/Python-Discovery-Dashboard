from flask import Flask, render_template, jsonify, Response, request
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db import (
    delete_all_ids_alerts,
    delete_ids_alert,
    create_ids_rule,
    delete_ids_rule,
    get_all_devices,
    get_ids_rules,
    get_recent_ids_alerts,
    get_recent_packet_counts,
    record_packet_count,
    get_unique_device_count,
    set_device_hidden,
    set_ids_rule_enabled,
)
from queue import Queue, Empty
import json
from utils.packet_sniffer import get_global_sniffer
from utils.Lauto_detect import detect_interface
from utils.network_info import get_network_ssid

app = Flask(__name__)

# In-memory queue for pushing live scan updates from the scanner
live_queue = Queue()


def push_live_update(devices):
    """Push a list of device dicts to connected SSE clients.
    The scanner thread can call this to deliver updates immediately."""
    try:
        live_queue.put(devices)
    except Exception:
        # Best-effort: swallow errors so scanner isn't blocked
        pass


def record_packet_usage(count, interval_seconds=10):
    """Persist one captured-packet sample for the dashboard traffic chart."""
    record_packet_count(count, interval_seconds)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/live")
def live_devices():
    def event_stream():
        print("[SSE] client connected")
        while True:
            try:
                # Prefer pushed updates from the scanner if available
                # We pull the item off the queue to clear it, then grab current state
                _ = live_queue.get(timeout=2)
                
                # Fixed: Added parentheses () to call the database function
                devices = get_all_devices()

                print(f"[SSE] sending pushed update ({len(devices)} devices)")
                yield f"event: update\ndata: {json.dumps(devices)}\n\n"
            except Empty:
                # If queue is empty, loop again without crashing
                pass
    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/devices")
def api_devices():
    """Fetches device log data from logs.db."""
    include_hidden = request.args.get("include_hidden", "0").lower() in ("1", "true", "yes")
    devices = get_all_devices(include_hidden=include_hidden)
    return jsonify(devices)


@app.route("/api/device/hidden", methods=["POST"])
def api_toggle_hidden():
    """Hides or unhides any device from the main devices table."""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    hidden = data.get("hidden")

    if not ip or hidden is None:
        return jsonify({"error": "ip and hidden are required"}), 400

    set_device_hidden(ip, bool(hidden))
    return jsonify({"ok": True, "ip": ip, "hidden": bool(hidden)})


@app.route("/api/unique_devices")
def api_unique_devices():
    """Returns the unique device count for the summary metrics table."""
    return jsonify({"count": get_unique_device_count()})


@app.route("/api/packet_usage")
def api_packet_usage():
    return jsonify(get_recent_packet_counts())


@app.route("/api/ids/alerts")
def api_ids_alerts():
    return jsonify(get_recent_ids_alerts())


@app.route("/api/ids/alerts", methods=["DELETE"])
def api_clear_ids_alerts():
    return jsonify({"ok": True, "deleted": delete_all_ids_alerts()})


@app.route("/api/ids/alerts/<int:alert_id>", methods=["DELETE"])
def api_delete_ids_alert(alert_id):
    if not delete_ids_alert(alert_id):
        return jsonify({"error": "alert not found"}), 404
    return jsonify({"ok": True, "id": alert_id})


@app.route("/api/ids/exemptions", methods=["GET"])
def api_ids_alert_exemptions():
    return jsonify(get_ids_alert_exemptions())


@app.route("/api/ids/exemptions", methods=["POST"])
def api_add_ids_alert_exemption():
    data = request.get_json(force=True, silent=True) or {}
    try:
        exemption = add_ids_alert_exemption(
            data.get("device_ip"), data.get("alert_type", "*")
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(exemption), 201


@app.route("/api/ids/exemptions/<int:exemption_id>", methods=["DELETE"])
def api_delete_ids_alert_exemption(exemption_id):
    if not delete_ids_alert_exemption(exemption_id):
        return jsonify({"error": "exemption not found"}), 404
    return jsonify({"ok": True, "id": exemption_id})


@app.route("/api/ids/rules", methods=["GET"])
def api_ids_rules():
    return jsonify(get_ids_rules())


@app.route("/api/ids/rules", methods=["POST"])
def api_create_ids_rule():
    data = request.get_json(force=True, silent=True) or {}
    try:
        rule = create_ids_rule(data)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(rule), 201


@app.route("/api/ids/rules/<int:rule_id>", methods=["PATCH", "DELETE"])
def api_manage_ids_rule(rule_id):
    if request.method == "DELETE":
        if not delete_ids_rule(rule_id):
            return jsonify({"error": "rule not found"}), 404
        return jsonify({"ok": True, "id": rule_id})

    data = request.get_json(force=True, silent=True) or {}
    try:
        rule = set_ids_rule_enabled(rule_id, data.get("enabled"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if not rule:
        return jsonify({"error": "rule not found"}), 404
    return jsonify(rule)


@app.route("/api/network")
def api_network():
    interface, ip_address = detect_interface()
    return jsonify({
        "ssid": get_network_ssid(interface),
        "interface": interface,
        "ip": ip_address,
    })


@app.route('/api/sniffer/status')
def api_sniffer_status():
    try:
        sniffer = get_global_sniffer()
        running = bool(getattr(sniffer, '_running', False))
        interface = getattr(sniffer, 'iface', None)
        enabled = running and bool(interface)
    except Exception:
        running = False
        interface = None
        enabled = False
    return jsonify({'enabled': enabled, 'running': running, 'interface': interface})


@app.route('/api/sniffer', methods=['POST'])
def api_sniffer_control():
    data = request.get_json(force=True, silent=True) or {}
    enable = data.get('enable')
    if enable is None:
        return jsonify({'error': 'enable (true/false) required'}), 400

    try:
        sniffer = get_global_sniffer()
        if enable:  
            sniffer.start()
        else:
            sniffer.stop()  
        running = bool(getattr(sniffer, '_running', False))
        enabled = running and bool(getattr(sniffer, 'iface', None))
        return jsonify({
            'ok': True,
            'enabled': enabled,
            'running': running,
            'interface': getattr(sniffer, 'iface', None),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
