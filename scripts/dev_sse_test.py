import threading
import time
import sys
import os
# ensure project root is on sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import web.app as webapp

app = webapp.app
push = webapp.push_live_update

def server_thread():
    app.run(host='127.0.0.1', port=5001, use_reloader=False, threaded=True)

thr = threading.Thread(target=server_thread, daemon=True)
thr.start()

# give server time to start
time.sleep(1)

# push a few updates
for i in range(3):
    push([
        {"status": "online" if i % 2 == 0 else "offline", "ip": f"10.0.0.{i+5}", "mac": "aa:bb:cc:dd:ee:ff", "manufacturer": "TestCo", "last_seen": "now"}
    ])
    print('pushed', i)
    time.sleep(1)

print('done pushing')
# keep process alive so curl can connect
while True:
    time.sleep(1)
