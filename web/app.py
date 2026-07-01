from flask import Flask, render_template, jsonify, Response
from database.db import get_all_devices
import time
import json

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/live")
def live_devices():
    def event_stream():
        while True:
            devices = get_all_devices()
            yield f"event: update\ndata: {json.dumps(devices)}\n\n"
            time.sleep(2)

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/devices")
def api_devices():
    devices = get_all_devices()
    return jsonify(devices)