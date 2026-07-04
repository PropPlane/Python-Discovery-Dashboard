const deviceTable = document.getElementById("deviceTable");
const countEl = document.getElementById("count");
const summaryTotal = document.getElementById("summaryTotal");

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
    }[char]));
}

function setText(element, value) {
    if (element) {
        element.innerText = value;
    }
}

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
        throw new Error(`${url} returned ${response.status}`);
    }
    return response.json();
}

// 1. Setup Scatter Chart for Packet Usage
const packetUsageChartCtx = document.getElementById("packetUsageChart").getContext("2d");
const packetUsageChart = new Chart(packetUsageChartCtx, {
    type: 'scatter',
    data: {
        datasets: [{
            label: 'Packet usage',
            data: [],
            backgroundColor: '#3f51b5',
        }],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                type: 'linear',
                title: { display: true, text: 'Time' },
                ticks: {
                    callback: (value) => new Date(value).toLocaleTimeString(),
                },
            },
            y: {
                title: { display: true, text: 'Packets' },
                beginAtZero: true,
            },
        },
        plugins: {
            legend: { display: false },
        },
    },
});

// 2. Setup Doughnut Chart for Device Status
const statusChartCtx = document.getElementById("statusChart").getContext("2d");
const statusChart = new Chart(statusChartCtx, {
    type: "doughnut",
    data: {
        labels: ["Online", "Offline"],
        datasets: [{
            data:[0, 0],
            backgroundColor: ["#4caf50", "#f44336"],
            borderColor: ["#ffffff", "#ffffff"],
            borderWidth: 2,
        }],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: "bottom", labels: { boxWidth: 12, padding: 16 } },
        },
    },
});

// 3. Render Active Devices Table
function renderDevices(devices) {
    let rows = "";
    let online = 0;
    let offline = 0;

    devices.forEach((device) => {
        const status = (device.status || "").toString();
        const ip = device.ip || "";
        const mac = device.mac || "";
        const manufacturer = device.manufacturer || "";
        const lastSeen = device.last_seen || "";

        if (status.toLowerCase().includes("online")) {
            online += 1;
        } else {
            offline += 1;
        }

        rows += `
            <tr>
                <td>${escapeHtml(ip)}</td>
                <td>${escapeHtml(status)}</td>
                <td>${escapeHtml(mac)}</td>
                <td>${escapeHtml(manufacturer)}</td>
                <td>${escapeHtml(lastSeen)}</td>
                <td><button class="hide-button" data-ip="${escapeHtml(ip)}">Hide</button></td>
            </tr>
        `;
    });

    if (deviceTable.innerHTML !== rows){
        deviceTable.innerHTML = rows;
    }
    
    setText(countEl, devices.length);
    setText(summaryTotal, devices.length);

    const currentChartData = statusChart.data.datasets[0].data;
    if (!currentChartData || currentChartData[0] !== online || currentChartData[1] !== offline){
        statusChart.data.datasets[0].data = [online, offline];
        statusChart.update('none');
    }
}

// 4. Render Hidden Devices Table
function renderHiddenDevices(devices) {
    const hiddenRows = devices.map((device) => {
        const status = (device.status || "").toString();
        const ip = device.ip || "";
        const mac = device.mac || "";
        const manufacturer = device.manufacturer || "";
        const lastSeen = device.last_seen || "";
        return `
            <tr>
                <td>${escapeHtml(ip)}</td>
                <td>${escapeHtml(status)}</td>
                <td>${escapeHtml(mac)}</td>
                <td>${escapeHtml(manufacturer)}</td>
                <td>${escapeHtml(lastSeen)}</td>
                <td><button class="unhide-button" data-ip="${escapeHtml(ip)}">Unhide</button></td>
            </tr>
        `;
    }).join("");

    const hiddenDeviceTable = document.getElementById('hiddenDeviceTable');
    if (hiddenDeviceTable) {
        hiddenDeviceTable.innerHTML = hiddenRows;
    }
}

// 5. Data Fetching Tasks
async function loadDevices() {
    try {
        const devices = await fetchJson('/api/devices');
        renderDevices(devices);
        await Promise.all([
            updateUniqueDevices(),
            updatePacketUsage(),
            loadHiddenDevices(),
        ]);
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

async function loadHiddenDevices() {
    try {
        const devices = await fetchJson('/api/devices?include_hidden=1');
        const hiddenDevices = devices.filter((device) => device.hidden);
        renderHiddenDevices(hiddenDevices);
    } catch (error) {
        console.error('Failed to load hidden devices:', error);
    }
}

function toggleHiddenContent() {
    const card = document.getElementById('hiddenDevicesCard');
    const content = document.getElementById('hiddenDevicesContent');
    const button = document.getElementById('toggleHiddenDevices');

    if (!card || !content || !button) {
        return;
    }

    const isOpen = card.classList.toggle('open');
    button.innerText = isOpen ? 'Hide hidden devices' : 'Show hidden devices';
}

async function updatePacketUsage() {
    try {
        const points = await fetchJson('/api/packet_usage');
        packetUsageChart.data.datasets[0].data = points;
        packetUsageChart.update();
    } catch (error) {
        console.error('Failed to update packet usage:', error);
    }
}

async function updateUniqueDevices() {
    try {
        const data = await fetchJson('/api/unique_devices');
        const usageEl = document.getElementById('uniqueDevices');
        if (usageEl) {
            usageEl.innerText = data.count ?? 0;
        }
    } catch (error) {
        console.error('Failed to update summary metrics:', error);
    }
}

async function setDeviceHidden(ip, hidden) {
    try {
        await fetchJson('/api/device/hidden', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, hidden }),
        });
        await loadDevices();
    } catch (error) {
        console.error(`Failed to ${hidden ? 'hide' : 'unhide'} ${ip}:`, error);
    }
}

// 6. Sniffer Control Operations
async function fetchSnifferStatus() {
    try {
        const resp = await fetch('/api/sniffer/status');
        const data = await resp.json();
        updateSnifferUI(Boolean(data.enabled));
    } catch (err) {
        updateSnifferUI(false);
    }
}

function updateSnifferUI(enabled) {
    const statusEl = document.getElementById('snifferStatus');
    const btn = document.getElementById('snifferToggle');
    if (statusEl) statusEl.innerText = enabled ? 'Running' : 'Stopped';
    if (btn) btn.innerText = enabled ? 'Stop' : 'Start';
    if (btn) {
        if (enabled) btn.classList.add('active'); else btn.classList.remove('active');
    }
}

async function toggleSniffer() {
    const btn = document.getElementById('snifferToggle');
    if (!btn) return;
    const currentlyRunning = btn.innerText === 'Stop';
    try {
        const resp = await fetch('/api/sniffer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: !currentlyRunning }),
        });
        if (resp.ok) {
            const data = await resp.json();
            updateSnifferUI(Boolean(data.enabled));
        }
    } catch (err) {
        console.error('Failed to toggle sniffer', err);
    }
}

// 7. Live Server-Sent Events (SSE) Processing
const eventSource = new EventSource('/api/live');

function handleLiveEvent(event) {
    try {
        const devices = JSON.parse(event.data);
        const dbg = document.getElementById('debugSSE');
        if (dbg) {
            const summary = `Received ${devices.length} device(s) at ${new Date().toLocaleTimeString()}`;
            const preview = JSON.stringify(devices.slice(0, 4), null, 2);
            dbg.textContent = `${summary}\n${preview}${devices.length > 4 ? '\n...more devices omitted...' : ''}`;
        }
        renderDevices(devices);
        updatePacketUsage();
        updateUniqueDevices();
        loadHiddenDevices();
    } catch (error) {
        console.error('Failed to parse SSE payload:', error);
    }
}

// Listen to explicit 'update' events and raw stream fallbacks
eventSource.addEventListener('update', handleLiveEvent);
eventSource.onmessage = handleLiveEvent;

eventSource.onerror = () => {
    console.warn('Live update stream disconnected; polling for dashboard data.');
};

document.addEventListener('click', (event) => {
    const hideButton = event.target.closest('.hide-button');
    if (hideButton) {
        setDeviceHidden(hideButton.dataset.ip, true);
        return;
    }

    const unhideButton = event.target.closest('.unhide-button');
    if (unhideButton) {
        setDeviceHidden(unhideButton.dataset.ip, false);
        return;
    }

    if (event.target.closest('#toggleHiddenDevices')) {
        toggleHiddenContent();
    }
});

const snifferToggle = document.getElementById('snifferToggle');
if (snifferToggle) {
    snifferToggle.addEventListener('click', toggleSniffer);
}

loadDevices();
fetchSnifferStatus();
setInterval(loadDevices, 10000);
setInterval(fetchSnifferStatus, 10000);
