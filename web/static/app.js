const deviceTable = document.getElementById("deviceTable");
const countEl = document.getElementById("count");
const summaryTotal = document.getElementById("summaryTotal");
const networkUsageEl = document.getElementById("networkUsage");

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
                <td>${ip}</td>
                <td>${status}</td>
                <td>${mac}</td>
                <td>${manufacturer}</td>
                <td>${lastSeen}</td>
                <td><button class="hide-button" data-ip="${ip}" data-hidden="0">Hide</button></td>
            </tr>
        `;
    });

    if (deviceTable.innerHTML !== rows){
        deviceTable.innerHTML = rows;
    }
    
    countEl.innerText = devices.length;
    summaryTotal.innerText = devices.length;

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
                <td>${ip}</td>
                <td>${status}</td>
                <td>${mac}</td>
                <td>${manufacturer}</td>
                <td>${lastSeen}</td>
                <td><button class="unhide-button" data-ip="${ip}">Unhide</button></td>
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
    const response = await fetch('/api/devices');
    const devices = await response.json();
    renderDevices(devices);
    await updateUniqueDevices();
    await updatePacketUsage();
    await loadHiddenDevices();
}

async function loadHiddenDevices() {
    const response = await fetch('/api/devices?include_hidden=1');
    const devices = await response.json();
    const hiddenDevices = devices.filter((device) => device.hidden);
    renderHiddenDevices(hiddenDevices);
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
    const response = await fetch('/api/packet_usage');
    const points = await response.json();
    packetUsageChart.data.datasets[0].data = points;
    packetUsageChart.update();
}

function formatDuration(seconds) {
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    const remainingSeconds = seconds % 60;

    if (hours > 0) {
        return `${hours}h ${remainingMinutes}m ${remainingSeconds}s`;
    }
    if (minutes > 0) {
        return `${minutes}m ${remainingSeconds}s`;
    }
    return `${remainingSeconds}s`;
}

async function updateUniqueDevices() {
    // Fixed: Handles counting items safely and updates both cards correctly
    const response = await fetch('/api/unique_devices');
    const data = await response.json();
    
    // Update unique device count card
    const usageEl = document.getElementById('uniqueDevices');
    if (usageEl) {
        // If your API returns an object like { count: X }, use data.count. Otherwise use raw data.
        usageEl.innerText = data.count !== undefined ? data.count : data;
    }

    // Update accumulated total active log time element if provided by your backend
    if (networkUsageEl && data.total_seconds !== undefined) {
        networkUsageEl.innerText = formatDuration(data.total_seconds);
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
    } catch (error) {
        console.error('Failed to parse SSE payload:', error);
    }
}

// Listen to explicit 'update' events and raw stream fallbacks
eventSource.addEventListener('update', handleLiveEvent);
eventSource.onmessage = handleLiveEvent;
