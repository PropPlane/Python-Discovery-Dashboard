from flask import Flask, render_template, jsonify, Response, request
from database.db import get_all_devices, get_network_usage, set_device_hidden
from queue import Queue, Empty
import time
import json
from utils.packet_sniffer import get_global_sniffer

app = Flask(__name__)

# in-memory queue for pushing live scan updates from the scanner
live_queue = Queue()
packet_usage_points = []


def push_live_update(devices):
    """Push a list of device dicts to connected SSE clients.

    The scanner thread can call this to deliver updates immediately
    instead of waiting for the periodic DB poll.
    """
    try:
        live_queue.put(devices)
    except Exception:
        # best-effort: swallow errors so scanner isn't blocked
        pass


def record_packet_usage(count):
    timestamp = int(time.time() * 1000)
    packet_usage_points.append({"x": timestamp, "y": count})
    if len(packet_usage_points) > 50:
        packet_usage_points.pop(0)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/live")
def live_devices():
    def event_stream():
        print("[SSE] client connected")
        while True:
            try:
                # prefer pushed updates from the scanner if available
                devices = live_queue.get(timeout=2)
                print(f"[SSE] sending pushed update ({len(devices)} devices)")
                yield f"event: update\ndata: {json.dumps(devices)}\n\n"
            except Empty:
                # fallback to DB poll when no pushed update available
                devices = get_all_devices()
                print(f"[SSE] sending polled update ({len(devices)} devices)")
                yield f"event: update\ndata: {json.dumps(devices)}\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/devices")
def api_devices():
    include_hidden = request.args.get("include_hidden", "0").lower() in ("1", "true", "yes")
    devices = get_all_devices(include_hidden=include_hidden)
    return jsonify(devices)


@app.route("/api/device/hidden", methods=["POST"])
def api_toggle_hidden():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    hidden = data.get("hidden")

    if not ip or hidden is None:
        return jsonify({"error": "ip and hidden are required"}), 400

    set_device_hidden(ip, bool(hidden))
    return jsonify({"ok": True, "ip": ip, "hidden": bool(hidden)})


@app.route("/api/network_usage")
def api_network_usage():
    total_seconds = get_network_usage()
    return jsonify({"total_seconds": total_seconds})


@app.route("/api/packet_usage")
def api_packet_usage():
    return jsonify(packet_usage_points)


@app.route('/api/sniffer/status')
def api_sniffer_status():
    try:
        sniffer = get_global_sniffer()
        enabled = bool(getattr(sniffer, '_running', False))
    except Exception:
        enabled = False
    return jsonify({'enabled': enabled})


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
        return jsonify({'ok': True, 'enabled': bool(getattr(sniffer, '_running', False))})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
