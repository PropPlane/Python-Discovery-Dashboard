import os
import sys
from datetime import datetime


def _timestamp():
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")


def print_startup_text():
    startup_text = f"""
    {_timestamp()} [BOOT] ==========================================
    {_timestamp()} [BOOT] |       Network Scanner and Logger       |
    {_timestamp()} [BOOT] ==========================================
    {_timestamp()} [BOOT] |  Scans the local network for devices   |
    {_timestamp()} [BOOT] |  and logs their IP, MAC, and status.   |
    {_timestamp()} [BOOT] ==========================================
    """
    print(startup_text)

def print_flask_startup_text(flask_thread):
    flask_startup_text = f"{_timestamp()} [BOOT] Flask server is starting on http://{flask_thread.name}:5000"
    print(flask_startup_text)

def package_startup_text(__package__):
    if __package__:
        print(f"{_timestamp()} [LOAD] Package {__package__} has been loaded successfully.")
    else:
        print(f"{_timestamp()} [LOAD] No package name available for this module.")


def module_startup_text(module_file):
    module_text = os.path.basename(module_file)
    print(f"{_timestamp()} [LOAD] Module {module_text} has been loaded successfully.")