from flask import Flask, render_template, jsonify
from database.db import get_all_devices

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    devices = get_all_devices()
    return jsonify(devices)