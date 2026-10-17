const deviceTable = document.getElementById("deviceTable");
const countEl = document.getElementById("count");
let currentIdsAlerts = [];
let currentIdsRules = [];
let currentAlertExemptions = [];

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

// 1. Setup packet volume chart
const PACKET_WATCH_RATE = 25;
const packetUsageChartCtx = document.getElementById("packetUsageChart").getContext("2d");
const packetUsageChart = new Chart(packetUsageChartCtx, {
    type: 'bar',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Packets per interval',
                data: [],
                backgroundColor: [],
                borderColor: [],
                borderWidth: 1,
            },
            {
                type: 'line',
                label: 'Watch level (25 packets/sec)',
                data: [],
                borderColor: '#c7794f',
                borderDash: [6, 4],
                borderWidth: 2,
                pointRadius: 0,
                tension: 0,
            },
        ],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                title: { display: true, text: 'Sample time' },
                ticks: { autoSkip: true, maxRotation: 0, maxTicksLimit: 8 },
            },
            y: {
                title: { display: true, text: 'Packets per interval' },
                beginAtZero: true,
                grid: { color: '#e8eee9' },
            },
        },
        plugins: {
            legend: { display: true, position: 'bottom', labels: { boxWidth: 10, usePointStyle: true } },
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
            backgroundColor: ["#428c99", "#c87569"],
            borderColor: ["#ffffff", "#ffffff"],
            borderWidth: 3,
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

    if (!devices.length) {
        rows = '<tr><td class="empty-state" colspan="6">No devices have been discovered yet.</td></tr>';
    }

    if (deviceTable.innerHTML !== rows){
        deviceTable.innerHTML = rows;
    }
    
    setText(countEl, devices.length);

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
        hiddenDeviceTable.innerHTML = hiddenRows || '<tr><td class="empty-state" colspan="6">No devices are hidden.</td></tr>';
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
            loadIdsAlerts(),
            loadHiddenDevices(),
        ]);
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

async function loadNetworkInfo() {
    try {
        const network = await fetchJson('/api/network');
        setText(document.getElementById('networkSsid'), network.ssid || 'SSID unavailable');
        setText(document.getElementById('networkInterface'), network.interface || 'No active interface');
        setText(document.getElementById('networkAddress'), network.ip || 'No address');
    } catch (error) {
        setText(document.getElementById('networkSsid'), 'Network unavailable');
        setText(document.getElementById('networkInterface'), 'Interface unavailable');
        setText(document.getElementById('networkAddress'), '');
        console.error('Failed to load network identity:', error);
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
        const samples = await fetchJson('/api/packet_usage');
        const packetDataset = packetUsageChart.data.datasets[0];
        packetUsageChart.data.labels = samples.map((sample) =>
            new Date(sample.recorded_at_ms).toLocaleTimeString()
        );
        packetDataset.data = samples.map((sample) => sample.packet_count);
        packetDataset.backgroundColor = samples.map((sample) =>
            sample.packets_per_second >= PACKET_WATCH_RATE ? '#b83c32' : '#4d8298'
        );
        packetDataset.borderColor = packetDataset.backgroundColor;
        packetUsageChart.data.datasets[1].data = samples.map((sample) =>
            PACKET_WATCH_RATE * sample.interval_seconds
        );
        packetUsageChart.update('none');
    } catch (error) {
        console.error('Failed to update packet usage:', error);
    }
}

function summarizeAlert(alert) {
    const summaries = {
        'Port scan': 'One host contacted many distinct TCP or UDP ports in a short time.',
        'Packet burst': 'Packet volume from one source exceeded the burst threshold.',
        'Conflicting ARP claim': 'Multiple devices announced the same IP address.',
    };
    if (summaries[alert.alert_type]) return summaries[alert.alert_type];
    const description = String(alert.description || 'No additional description.');
    return description.length > 120 ? `${description.slice(0, 117)}...` : description;
}

function renderIdsAlerts() {
    const alertTable = document.getElementById('idsAlertTable');
    const severityFilter = document.getElementById('alertSeverityFilter');
    if (!alertTable) return;

    const severity = severityFilter ? severityFilter.value : 'all';
    const alerts = severity === 'all'
        ? currentIdsAlerts
        : currentIdsAlerts.filter((alert) => alert.severity === severity);

    if (!alerts.length) {
        const message = currentIdsAlerts.length
            ? `No ${severity} severity alerts.`
            : 'No IDS alerts recorded.';
        alertTable.innerHTML = `<tr><td class="empty-state" colspan="7">${escapeHtml(message)}</td></tr>`;
        return;
    }

    alertTable.innerHTML = alerts.map((alert) => `
        <tr>
            <td>${escapeHtml(alert.created_at)}</td>
            <td class="severity-${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</td>
            <td>${escapeHtml(alert.alert_type)}${alert.mitre_id ? `<span class="mitre-tag">${escapeHtml(alert.mitre_id)}</span>` : ''}</td>
            <td>${escapeHtml(alert.source_ip || 'Unknown')}</td>
            <td>${escapeHtml(alert.destination_ip || 'Unknown')}</td>
            <td>${escapeHtml(summarizeAlert(alert))}</td>
            <td>
                <div class="alert-actions">
                    <button class="detail-button" type="button" data-alert-id="${escapeHtml(alert.id)}">Details</button>
                    <button class="delete-alert-button" type="button" data-alert-id="${escapeHtml(alert.id)}" aria-label="Delete alert">Delete</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function loadIdsAlerts() {
    try {
        currentIdsAlerts = await fetchJson('/api/ids/alerts');
        updateExemptionAlertTypes();
        renderIdsAlerts();
    } catch (error) {
        console.error('Failed to load IDS alerts:', error);
    }
}

function updateExemptionAlertTypes() {
    const select = document.getElementById('exemptionAlertType');
    if (!select) return;
    const selected = select.value;
    const builtinTypes = [
        ['*', 'All built-in alert types'],
        ['Port scan', 'Port scan'],
        ['Packet burst', 'Packet burst'],
        ['Conflicting ARP claim', 'Conflicting ARP claim'],
    ];
    const known = new Set(builtinTypes.map(([value]) => value));
    select.innerHTML = builtinTypes.map(([value, label]) =>
        `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`
    ).join('');
    select.value = known.has(selected) ? selected : '*';
}

function renderAlertExemptions() {
    const table = document.getElementById('alertExemptionTable');
    if (!table) return;
    if (!currentAlertExemptions.length) {
        table.innerHTML = '<tr><td class="empty-state" colspan="4">No alert exemptions configured.</td></tr>';
        return;
    }

    table.innerHTML = currentAlertExemptions.map((exemption) => `
        <tr>
            <td>${escapeHtml(exemption.device_ip)}</td>
            <td>${escapeHtml(exemption.alert_type === '*' ? 'All built-in alert types' : exemption.alert_type)}</td>
            <td>${escapeHtml(exemption.created_at)}</td>
            <td><button class="delete-exemption-button" type="button" data-exemption-id="${escapeHtml(exemption.id)}">Remove</button></td>
        </tr>
    `).join('');
}

async function loadAlertExemptions() {
    try {
        currentAlertExemptions = await fetchJson('/api/ids/exemptions');
        renderAlertExemptions();
    } catch (error) {
        console.error('Failed to load alert exemptions:', error);
    }
}

async function submitAlertExemption(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const message = document.getElementById('exemptionFormMessage');
    const values = new FormData(form);
    if (message) message.textContent = '';
    try {
        const response = await fetch('/api/ids/exemptions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.fromEntries(values.entries())),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Could not add exemption.');
        form.reset();
        if (message) message.textContent = `Exemption added for ${result.device_ip}.`;
        await loadAlertExemptions();
    } catch (error) {
        if (message) message.textContent = error.message;
    }
}

async function deleteAlertExemption(exemptionId) {
    try {
        await fetchJson(`/api/ids/exemptions/${encodeURIComponent(exemptionId)}`, { method: 'DELETE' });
        currentAlertExemptions = currentAlertExemptions.filter(
            (exemption) => String(exemption.id) !== String(exemptionId)
        );
        renderAlertExemptions();
    } catch (error) {
        console.error('Failed to remove alert exemption:', error);
    }
}

function renderIdsRules() {
    const ruleTable = document.getElementById('idsRuleTable');
    if (!ruleTable) return;

    if (!currentIdsRules.length) {
        ruleTable.innerHTML = '<tr><td class="empty-state" colspan="10">No custom rules yet. Create a rule to start watching a specific traffic pattern.</td></tr>';
        return;
    }

    ruleTable.innerHTML = currentIdsRules.map((rule) => {
        const conditionLabels = {
            packet_burst: 'Packet burst',
            port_scan: 'Distinct ports',
            ping_activity: 'Ping activity',
            ping_sweep: 'Ping sweep',
            arp_sweep: 'ARP sweep',
            syn_scan: 'TCP SYN scan',
            target_flood: 'Target flood',
            new_device: 'New device',
        };
        const condition = conditionLabels[rule.rule_type] || rule.rule_type;
        const metricLabels = {
            count: 'packet count',
            unique_destinations: 'distinct destinations',
            unique_ports: 'distinct ports',
            unique_sources: 'distinct sources',
            event: 'event',
        };
        const threshold = rule.rule_type === 'new_device'
            ? 'Each event'
            : `${rule.threshold} ${metricLabels[rule.metric] || rule.metric}`;
        const window = rule.rule_type === 'new_device' ? 'Event' : `${rule.window_seconds} sec`;
        const groupLabel = rule.group_by === 'destination_ip' ? 'target' : 'source';
        const grouping = `${metricLabels[rule.metric] || rule.metric} / ${groupLabel}`;
        const filters = [
            `src ${rule.source_ip || 'any'}`,
            `dst ${rule.destination_ip || 'any'}`,
            rule.protocol === 'ANY' ? '' : rule.protocol,
            rule.min_sources > 1 ? `${rule.min_sources}+ sources` : '',
            rule.excluded_ips?.length ? `${rule.excluded_ips.length} excluded` : '',
        ].filter(Boolean).join(' · ');
        const nextEnabled = !rule.enabled;
        return `
            <tr>
                <td>${escapeHtml(rule.name)}</td>
                <td>${condition}</td>
                <td>${escapeHtml(grouping)}</td>
                <td>${threshold}</td>
                <td>${escapeHtml(window)}</td>
                <td>${escapeHtml(filters)}</td>
                <td>${rule.mitre_id ? `<span class="mitre-tag">${escapeHtml(rule.mitre_id)}</span>` : 'Unmapped'}</td>
                <td class="severity-${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</td>
                <td><span class="rule-status ${rule.enabled ? 'enabled' : ''}">${rule.enabled ? 'Enabled' : 'Disabled'}</span></td>
                <td>
                    <div class="alert-actions">
                        <button class="rule-toggle-button" type="button" data-rule-id="${escapeHtml(rule.id)}" data-enabled="${nextEnabled}">${nextEnabled ? 'Enable' : 'Disable'}</button>
                        <button class="delete-rule-button" type="button" data-rule-id="${escapeHtml(rule.id)}">Delete</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

async function loadIdsRules() {
    try {
        currentIdsRules = await fetchJson('/api/ids/rules');
        renderIdsRules();
    } catch (error) {
        console.error('Failed to load custom IDS rules:', error);
    }
}

async function setIdsRuleEnabled(ruleId, enabled) {
    try {
        await fetchJson(`/api/ids/rules/${encodeURIComponent(ruleId)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
        });
        await loadIdsRules();
    } catch (error) {
        console.error('Failed to update IDS rule:', error);
    }
}

async function deleteIdsRule(ruleId) {
    if (!window.confirm('Delete this custom IDS rule?')) return;
    try {
        await fetchJson(`/api/ids/rules/${encodeURIComponent(ruleId)}`, { method: 'DELETE' });
        currentIdsRules = currentIdsRules.filter((rule) => String(rule.id) !== String(ruleId));
        renderIdsRules();
    } catch (error) {
        console.error('Failed to delete IDS rule:', error);
    }
}

function updateRuleMetricGrouping() {
    const ruleType = document.getElementById('idsRuleType');
    const metricInput = document.getElementById('idsRuleMetric');
    const groupInput = document.getElementById('idsRuleGroup');
    const minSourcesInput = document.querySelector('#idsRuleForm [name="min_sources"]');
    const minSourcesField = document.querySelector('.rule-min-sources-field');
    const thresholdInput = document.querySelector('#idsRuleForm [name="threshold"]');
    const thresholdLabel = document.getElementById('idsRuleThresholdLabel');
    if (!ruleType || !metricInput || !groupInput || !minSourcesInput) return;

    const metric = metricInput.value;
    if (metric === 'unique_destinations') groupInput.value = 'source_ip';
    if (metric === 'unique_sources') groupInput.value = 'destination_ip';
    const byDestination = groupInput.value === 'destination_ip';
    const isNewDevice = ruleType.value === 'new_device';
    groupInput.disabled = isNewDevice || metric === 'unique_destinations' || metric === 'unique_sources';
    minSourcesInput.disabled = isNewDevice || !byDestination;
    if (!byDestination && !isNewDevice) minSourcesInput.value = '1';
    if (minSourcesField) minSourcesField.hidden = isNewDevice || !byDestination;

    const labels = {
        count: 'Packet threshold',
        unique_destinations: 'Distinct destination threshold',
        unique_ports: 'Distinct port threshold',
        unique_sources: 'Distinct source threshold',
        event: 'Event threshold',
    };
    setText(thresholdLabel, labels[metric] || 'Threshold');
    if (thresholdInput) thresholdInput.max = metric.startsWith('unique_') ? '65536' : '10000000';
}

function updateRuleThresholdField() {
    const ruleType = document.getElementById('idsRuleType');
    const thresholdInput = document.querySelector('#idsRuleForm [name="threshold"]');
    const windowInput = document.querySelector('#idsRuleForm [name="window_seconds"]');
    const protocolInput = document.querySelector('#idsRuleForm [name="protocol"]');
    const metricInput = document.getElementById('idsRuleMetric');
    const groupInput = document.getElementById('idsRuleGroup');
    const minSourcesInput = document.querySelector('#idsRuleForm [name="min_sources"]');
    const mitreInput = document.getElementById('idsRuleMitreId');
    const thresholdField = document.querySelector('.rule-threshold-field');
    const windowField = document.querySelector('.rule-window-field');
    const protocolField = document.querySelector('.rule-protocol-field');
    const metricField = document.querySelector('.rule-metric-field');
    const groupField = document.querySelector('.rule-group-field');
    const destinationField = document.querySelector('.rule-destination-field');
    const isNewDevice = ruleType?.value === 'new_device';
    if (!ruleType || !thresholdInput || !windowInput || !protocolInput || !metricInput
        || !groupInput || !minSourcesInput || !mitreInput) return;

    const configs = {
        packet_burst: { metrics: ['count', 'unique_destinations', 'unique_ports', 'unique_sources'], metric: 'count', group: 'source_ip', threshold: 250, protocols: ['ANY', 'TCP', 'UDP', 'ICMP'], protocol: 'ANY', mitre: '' },
        port_scan: { metrics: ['unique_ports', 'count'], metric: 'unique_ports', group: 'source_ip', threshold: 20, protocols: ['ANY', 'TCP', 'UDP'], protocol: 'ANY', mitre: 'T1046' },
        ping_activity: { metrics: ['count', 'unique_destinations'], metric: 'count', group: 'source_ip', threshold: 10, protocols: ['ICMP'], protocol: 'ICMP', mitre: '' },
        ping_sweep: { metrics: ['unique_destinations'], metric: 'unique_destinations', group: 'source_ip', threshold: 20, protocols: ['ICMP'], protocol: 'ICMP', mitre: 'T1018' },
        arp_sweep: { metrics: ['unique_destinations'], metric: 'unique_destinations', group: 'source_ip', threshold: 20, protocols: ['ARP'], protocol: 'ARP', mitre: 'T1018' },
        syn_scan: { metrics: ['unique_ports', 'count'], metric: 'unique_ports', group: 'source_ip', threshold: 20, protocols: ['TCP'], protocol: 'TCP', mitre: 'T1046' },
        target_flood: { metrics: ['count', 'unique_sources'], metric: 'count', group: 'destination_ip', threshold: 500, protocols: ['ANY', 'TCP', 'UDP', 'ICMP'], protocol: 'ANY', mitre: 'T1498.001', minSources: 3 },
        new_device: { metrics: ['event'], metric: 'event', group: 'source_ip', threshold: 1, protocols: ['ANY'], protocol: 'ANY', mitre: '' },
    };
    const config = configs[ruleType.value] || configs.packet_burst;
    const isFixedProtocol = config.protocols.length === 1;
    const protocolLabels = { ANY: 'Any', TCP: 'TCP', UDP: 'UDP', ICMP: 'ICMP', ARP: 'ARP' };
    const metricLabels = {
        count: 'Packet count',
        unique_destinations: 'Distinct destination IPs',
        unique_ports: 'Distinct destination ports',
        unique_sources: 'Distinct source IPs',
        event: 'Event',
    };

    metricInput.innerHTML = config.metrics.map((metric) =>
        `<option value="${metric}">${metricLabels[metric]}</option>`
    ).join('');
    metricInput.value = config.metric;
    groupInput.value = config.group;
    protocolInput.innerHTML = config.protocols.map((protocol) =>
        `<option value="${protocol}">${protocolLabels[protocol]}</option>`
    ).join('');
    protocolInput.value = config.protocol;
    thresholdInput.value = String(config.threshold);
    thresholdInput.min = isNewDevice ? '1' : '2';
    windowInput.value = isNewDevice ? '60' : ruleType.value === 'target_flood' ? '10' : '30';
    minSourcesInput.value = String(config.minSources || 1);
    mitreInput.value = config.mitre;

    thresholdInput.disabled = isNewDevice;
    windowInput.disabled = isNewDevice;
    metricInput.disabled = isNewDevice;
    protocolInput.disabled = isFixedProtocol || isNewDevice;
    if (thresholdField) thresholdField.hidden = isNewDevice;
    if (windowField) windowField.hidden = isNewDevice;
    if (metricField) metricField.hidden = isNewDevice;
    if (groupField) groupField.hidden = isNewDevice;
    if (protocolField) protocolField.hidden = isNewDevice;
    if (destinationField) destinationField.hidden = isNewDevice;
    updateRuleMetricGrouping();

    const helpTextByType = {
        packet_burst: 'Choose packet counts or unique values, grouped by source or destination.',
        port_scan: 'Count distinct TCP or UDP ports contacted by one source.',
        ping_activity: 'Measure ICMP echo requests or distinct destinations.',
        ping_sweep: 'Count distinct targets receiving ICMP echo requests from one source.',
        arp_sweep: 'Count distinct target IPs in ARP requests from one source.',
        syn_scan: 'Count unique TCP ports contacted with SYN packets, excluding SYN-ACKs.',
        target_flood: 'Group packets by target; require multiple unique sources to flag a possible distributed flood.',
        new_device: 'Alert when a scan discovers a previously unseen IP/MAC pair.',
    };
    const helpText = document.getElementById('idsRuleTypeHelp');
    if (helpText) helpText.textContent = helpTextByType[ruleType.value] || '';
}

async function submitIdsRule(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const errorMessage = document.getElementById('idsRuleFormError');
    const values = new FormData(form);
    const rule = Object.fromEntries(values.entries());
    rule.threshold = Number(rule.threshold);
    rule.window_seconds = Number(rule.window_seconds);
    rule.excluded_ips = String(rule.excluded_ips || '').split(/[\s,]+/).filter(Boolean);
    rule.enabled = form.elements.enabled.checked;

    if (errorMessage) errorMessage.textContent = '';
    try {
        const response = await fetch('/api/ids/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rule),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Could not save rule.');
        document.getElementById('idsRuleDialog').close();
        form.reset();
        updateRuleThresholdField();
        await loadIdsRules();
    } catch (error) {
        if (errorMessage) errorMessage.textContent = error.message;
    }
}

function showAlertDetails(alertId) {
    const alert = currentIdsAlerts.find((item) => String(item.id) === String(alertId));
    const dialog = document.getElementById('alertDetailsDialog');
    if (!alert || !dialog) return;

    setText(document.getElementById('alertDetailsTitle'), alert.alert_type);
    setText(document.getElementById('alertDetailsSeverity'), alert.severity);
    setText(document.getElementById('alertDetailsSource'), alert.source_ip || 'Unknown');
    setText(document.getElementById('alertDetailsTarget'), alert.destination_ip || 'Unknown');
    setText(document.getElementById('alertDetailsMitre'), alert.mitre_id || 'Unmapped');
    setText(document.getElementById('alertDetailsTime'), alert.created_at);
    setText(document.getElementById('alertDetailsSummary'), summarizeAlert(alert));
    setText(document.getElementById('alertDetailsDescription'), alert.description || 'No additional description.');
    dialog.showModal();
}

async function deleteAlert(alertId) {
    try {
        await fetchJson(`/api/ids/alerts/${encodeURIComponent(alertId)}`, { method: 'DELETE' });
        currentIdsAlerts = currentIdsAlerts.filter((alert) => String(alert.id) !== String(alertId));
        renderIdsAlerts();
    } catch (error) {
        console.error('Failed to delete IDS alert:', error);
    }
}

async function clearAlerts() {
    if (!currentIdsAlerts.length || !window.confirm('Delete all stored IDS alerts? This cannot be undone.')) {
        return;
    }
    try {
        await fetchJson('/api/ids/alerts', { method: 'DELETE' });
        currentIdsAlerts = [];
        renderIdsAlerts();
    } catch (error) {
        console.error('Failed to clear IDS alerts:', error);
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
    if (statusEl) statusEl.classList.toggle('active', enabled);
    if (btn) {
        btn.innerText = enabled ? 'Stop capture' : 'Start capture';
        btn.dataset.running = String(enabled);
        btn.classList.toggle('active', enabled);
    }
}

async function toggleSniffer() {
    const btn = document.getElementById('snifferToggle');
    if (!btn) return;
    const currentlyRunning = btn.dataset.running === 'true';
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
    const removeExemptionButton = event.target.closest('.delete-exemption-button');
    if (removeExemptionButton) {
        deleteAlertExemption(removeExemptionButton.dataset.exemptionId);
        return;
    }

    const ruleToggle = event.target.closest('.rule-toggle-button');
    if (ruleToggle) {
        setIdsRuleEnabled(ruleToggle.dataset.ruleId, ruleToggle.dataset.enabled === 'true');
        return;
    }

    const deleteRuleButton = event.target.closest('.delete-rule-button');
    if (deleteRuleButton) {
        deleteIdsRule(deleteRuleButton.dataset.ruleId);
        return;
    }

    const detailButton = event.target.closest('.detail-button');
    if (detailButton) {
        showAlertDetails(detailButton.dataset.alertId);
        return;
    }

    const deleteAlertButton = event.target.closest('.delete-alert-button');
    if (deleteAlertButton) {
        deleteAlert(deleteAlertButton.dataset.alertId);
        return;
    }

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
        return;
    }

    if (event.target.closest('#clearAlerts')) {
        clearAlerts();
    }
});

const alertExemptionForm = document.getElementById('alertExemptionForm');
if (alertExemptionForm) {
    alertExemptionForm.addEventListener('submit', submitAlertExemption);
}

const createRuleButton = document.getElementById('createIdsRule');
const idsRuleDialog = document.getElementById('idsRuleDialog');
const idsRuleForm = document.getElementById('idsRuleForm');
const idsRuleType = document.getElementById('idsRuleType');
if (createRuleButton && idsRuleDialog) {
    createRuleButton.addEventListener('click', () => {
        idsRuleForm.reset();
        updateRuleThresholdField();
        document.getElementById('idsRuleFormError').textContent = '';
        idsRuleDialog.showModal();
    });
}
if (idsRuleType) {
    idsRuleType.addEventListener('change', updateRuleThresholdField);
}
const ruleMetricSelect = document.getElementById('idsRuleMetric');
const ruleGroupSelect = document.getElementById('idsRuleGroup');
if (ruleMetricSelect) ruleMetricSelect.addEventListener('change', updateRuleMetricGrouping);
if (ruleGroupSelect) ruleGroupSelect.addEventListener('change', updateRuleMetricGrouping);
if (idsRuleForm) {
    idsRuleForm.addEventListener('submit', submitIdsRule);
}
for (const closeButton of [
    document.getElementById('closeIdsRuleDialog'),
    document.getElementById('cancelIdsRule'),
]) {
    if (closeButton && idsRuleDialog) {
        closeButton.addEventListener('click', () => idsRuleDialog.close());
    }
}

const severityFilter = document.getElementById('alertSeverityFilter');
if (severityFilter) {
    severityFilter.addEventListener('change', renderIdsAlerts);
}

const alertDetailsDialog = document.getElementById('alertDetailsDialog');
const closeAlertDetails = document.getElementById('closeAlertDetails');
if (closeAlertDetails && alertDetailsDialog) {
    closeAlertDetails.addEventListener('click', () => alertDetailsDialog.close());
    alertDetailsDialog.addEventListener('click', (event) => {
        if (event.target === alertDetailsDialog) alertDetailsDialog.close();
    });
}

const snifferToggle = document.getElementById('snifferToggle');
if (snifferToggle) {
    snifferToggle.addEventListener('click', toggleSniffer);
}

loadDevices();
loadNetworkInfo();
loadIdsRules();
loadAlertExemptions();
fetchSnifferStatus();
setInterval(loadDevices, 10000);
setInterval(loadNetworkInfo, 30000);
setInterval(loadIdsRules, 15000);
setInterval(loadAlertExemptions, 15000);
setInterval(loadIdsAlerts, 5000);
setInterval(fetchSnifferStatus, 10000);
