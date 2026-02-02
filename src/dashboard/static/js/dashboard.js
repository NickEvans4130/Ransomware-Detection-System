"use strict";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
    feedPaused: false,
    config: {},
    selectedBackups: new Set(),
    ws: null,
    charts: {},
    // Track cumulative stats across sessions (reset on page load)
    statsRecovered: 0,
    demoRunning: false,
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function api(path, opts) {
    const resp = await fetch("/api" + path, opts);
    return resp.json();
}

function apiGet(path)  { return api(path); }

function apiPost(path, body) {
    return api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
}

function apiPut(path, body) {
    return api(path, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function esc(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
}

function fmtTime(iso) {
    if (!iso) return "--";
    const d = new Date(iso);
    return d.toLocaleTimeString();
}

function fmtDate(iso) {
    if (!iso) return "--";
    const d = new Date(iso);
    return d.toLocaleString();
}

function basename(path) {
    return path ? path.split("/").pop().split("\\").pop() : "";
}

function scoreColor(score) {
    if (score >= 71) return "#dc3545";
    if (score >= 51) return "#fd7e14";
    if (score >= 31) return "#ffc107";
    return "#198754";
}

function threatBadgeClass(level) {
    if (level === "CRITICAL") return "threat-critical";
    if (level === "ELEVATED") return "threat-elevated";
    return "threat-normal";
}

function showToast(message, variant) {
    variant = variant || "info";
    const id = "toast-" + Date.now();
    const html = '<div id="' + id + '" class="toast align-items-center text-bg-' + variant +
        ' border-0" role="alert"><div class="d-flex"><div class="toast-body">' +
        esc(message) + '</div><button type="button" class="btn-close btn-close-white me-2 m-auto" ' +
        'data-bs-dismiss="toast"></button></div></div>';
    document.getElementById("toast-container").insertAdjacentHTML("beforeend", html);
    const el = document.getElementById(id);
    const t = new bootstrap.Toast(el, { delay: 4000 });
    t.show();
    el.addEventListener("hidden.bs.toast", function () { el.remove(); });
}

// ---------------------------------------------------------------------------
// 1. Real-Time Monitoring View
// ---------------------------------------------------------------------------

async function refreshStatus() {
    const data = await apiGet("/status");
    // Header
    const dot = document.getElementById("status-dot");
    const txt = document.getElementById("status-text");
    const badge = document.getElementById("threat-level-badge");

    txt.textContent = data.status === "running" ? "Protected" : data.status;
    dot.className = "bi bi-circle-fill " +
        (data.threat_level === "NORMAL" ? "text-success" :
         data.threat_level === "ELEVATED" ? "text-warning" : "text-danger");

    badge.textContent = data.threat_level;
    badge.className = "badge " + threatBadgeClass(data.threat_level);

    // System health
    document.getElementById("health-status").textContent = data.status;
    document.getElementById("health-threat").textContent = data.threat_level;
    document.getElementById("health-ws").textContent = data.websocket_clients;

    document.getElementById("last-updated").textContent = "Updated: " + fmtTime(data.timestamp);

    // Processes
    renderProcesses(data.active_processes || {});
}

function renderProcesses(procs) {
    const el = document.getElementById("process-list");
    const pids = Object.keys(procs);
    document.getElementById("process-count").textContent = pids.length;

    if (pids.length === 0) {
        el.innerHTML = '<div class="list-group-item text-muted small">No active processes</div>';
        return;
    }

    el.innerHTML = pids.map(function (pid) {
        const p = procs[pid];
        const color = scoreColor(p.score);
        return '<div class="list-group-item process-item">' +
            '<div>' +
                '<span class="process-name">' + esc(p.process_name) + '</span> ' +
                '<small class="text-muted">PID ' + esc(pid) + '</small>' +
            '</div>' +
            '<div class="d-flex align-items-center gap-2">' +
                '<span class="badge" style="background:' + color + '">' + p.level + '</span>' +
                '<div class="score-bar"><div class="score-fill" style="width:' +
                    p.score + '%;background:' + color + '"></div></div>' +
                '<button class="btn btn-sm btn-outline-danger quarantine-btn" data-pid="' +
                    esc(pid) + '">Quarantine</button>' +
            '</div></div>';
    }).join("");

    // Wire quarantine buttons
    el.querySelectorAll(".quarantine-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            quarantineProcess(parseInt(btn.dataset.pid));
        });
    });
}

async function quarantineProcess(pid) {
    const data = await apiPost("/quarantine", { pid: pid });
    if (data.success) {
        showToast("Process " + pid + " suspended", "success");
    } else {
        showToast("Failed to suspend " + pid + ": " + (data.error || "unknown"), "danger");
    }
    refreshStatus();
}

async function refreshEvents() {
    const typeFilter = document.getElementById("event-type-filter").value;
    const params = typeFilter ? "?type=" + typeFilter + "&limit=100" : "?limit=100";
    const data = await apiGet("/events" + params);
    document.getElementById("event-count").textContent = data.total;

    const feed = document.getElementById("event-feed");
    if (data.events.length === 0) {
        feed.innerHTML = '<div class="text-muted text-center py-4">No events recorded</div>';
        return;
    }

    feed.innerHTML = data.events.map(function (ev) {
        const t = ev.event_type || "unknown";
        return '<div class="event-row">' +
            '<span class="event-time">' + fmtTime(ev.timestamp) + '</span>' +
            '<span class="event-type type-' + t + '">' + t + '</span>' +
            '<span class="event-path" title="' + esc(ev.file_path || "") + '">' +
                esc(ev.file_path || "") + '</span>' +
            '</div>';
    }).join("");

    // Scroll to top to show latest
    feed.scrollTop = 0;
}

// ---------------------------------------------------------------------------
// 2. Threat History
// ---------------------------------------------------------------------------

let currentThreats = [];

async function refreshThreats() {
    const sev = document.getElementById("threat-severity-filter").value;
    const params = sev ? "?severity=" + sev : "";
    const data = await apiGet("/threats" + params);
    currentThreats = data.threats;

    // Update header badge
    document.getElementById("header-threats").textContent =
        "Threats: " + data.total + " Today";

    const tbody = document.getElementById("threat-table-body");
    if (data.threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">' +
            'No threats recorded</td></tr>';
        return;
    }

    tbody.innerHTML = data.threats.map(function (t, i) {
        const color = scoreColor(t.score);
        const levelLabels = { 1: "Monitor", 2: "Warn", 3: "Quarantine", 4: "Terminate" };
        return '<tr>' +
            '<td class="small">' + fmtDate(t.timestamp) + '</td>' +
            '<td><span class="fw-bold">' + esc(t.process_name) + '</span>' +
                '<br><small class="text-muted">PID ' + t.process_id + '</small></td>' +
            '<td><span class="badge" style="background:' + color + '">' +
                t.score + '</span></td>' +
            '<td>' + esc(t.level) + '</td>' +
            '<td>Level ' + t.escalation_level + ' - ' +
                (levelLabels[t.escalation_level] || "?") + '</td>' +
            '<td class="small">' + (t.actions_taken || []).slice(0, 2).map(esc).join("<br>") +
                '</td>' +
            '<td><button class="btn btn-sm btn-outline-info view-threat-btn" data-idx="' +
                i + '">View</button></td></tr>';
    }).join("");

    tbody.querySelectorAll(".view-threat-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            showThreatDetail(parseInt(btn.dataset.idx));
        });
    });
}

function showThreatDetail(idx) {
    const t = currentThreats[idx];
    if (!t) return;

    const body = document.getElementById("threat-detail-body");
    let html = '<h6>Process: ' + esc(t.process_name) + ' (PID ' + t.process_id + ')</h6>' +
        '<div class="row mb-3">' +
        '<div class="col-4"><strong>Score:</strong> ' + t.score + '</div>' +
        '<div class="col-4"><strong>Level:</strong> ' + esc(t.level) + '</div>' +
        '<div class="col-4"><strong>Escalation:</strong> ' + t.escalation_level + '</div>' +
        '</div>' +
        '<div class="mb-3"><strong>Time:</strong> ' + fmtDate(t.timestamp) + '</div>';

    // Triggered indicators
    if (t.triggered_indicators && Object.keys(t.triggered_indicators).length > 0) {
        html += '<div class="mb-3"><strong>Triggered Indicators:</strong><ul>';
        for (const key in t.triggered_indicators) {
            html += '<li><code>' + esc(key) + '</code>: ' +
                esc(String(t.triggered_indicators[key])) + '</li>';
        }
        html += '</ul></div>';
    }

    // Actions taken
    if (t.actions_taken && t.actions_taken.length) {
        html += '<div class="mb-3"><strong>Actions Taken:</strong><ul>';
        t.actions_taken.forEach(function (a) {
            html += '<li>' + esc(a) + '</li>';
        });
        html += '</ul></div>';
    }

    // Incident report
    if (t.incident_report) {
        html += '<div class="mb-3"><strong>Incident Report:</strong>' +
            '<pre class="bg-light p-2 rounded" style="max-height:200px;overflow:auto">' +
            esc(JSON.stringify(t.incident_report, null, 2)) + '</pre></div>';
    }

    body.innerHTML = html;

    // Store current threat for export
    document.getElementById("export-single-threat").onclick = function () {
        downloadJSON(t, "threat_" + t.process_id + "_" + Date.now() + ".json");
    };

    new bootstrap.Modal(document.getElementById("threatDetailModal")).show();
}

function exportThreats() {
    downloadJSON(currentThreats, "threats_export_" + Date.now() + ".json");
}

function downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// 3. File Recovery Interface
// ---------------------------------------------------------------------------

async function refreshBackups() {
    const search = document.getElementById("backup-search").value;
    const process = document.getElementById("backup-process-filter").value;
    let params = "?limit=100";
    if (search) params += "&path=" + encodeURIComponent(search);
    if (process) params += "&process=" + encodeURIComponent(process);

    const data = await apiGet("/backups" + params);
    document.getElementById("backup-total").textContent = data.total;
    state.selectedBackups.clear();
    updateBatchButton();

    const tbody = document.getElementById("backup-table-body");
    if (data.backups.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">' +
            'No backups available</td></tr>';
        return;
    }

    tbody.innerHTML = data.backups.map(function (b) {
        return '<tr>' +
            '<td><input type="checkbox" class="form-check-input backup-check" ' +
                'data-id="' + b.id + '"></td>' +
            '<td title="' + esc(b.original_path) + '">' +
                '<span class="fw-bold">' + esc(basename(b.original_path)) + '</span>' +
                '<br><small class="text-muted">' + esc(b.original_path) + '</small></td>' +
            '<td>' + esc(b.process_name || "--") + '</td>' +
            '<td class="small">' + fmtDate(b.timestamp) + '</td>' +
            '<td><code class="small">' + esc((b.file_hash || "").substring(0, 12)) +
                '...</code></td>' +
            '<td><button class="btn btn-sm btn-outline-warning restore-single-btn" ' +
                'data-id="' + b.id + '">Restore</button></td></tr>';
    }).join("");

    // Wire restore buttons
    tbody.querySelectorAll(".restore-single-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            restoreSingle(parseInt(btn.dataset.id));
        });
    });

    // Wire checkboxes
    tbody.querySelectorAll(".backup-check").forEach(function (cb) {
        cb.addEventListener("change", function () {
            const id = parseInt(cb.dataset.id);
            if (cb.checked) { state.selectedBackups.add(id); }
            else { state.selectedBackups.delete(id); }
            updateBatchButton();
        });
    });
}

function updateBatchButton() {
    const btn = document.getElementById("batch-restore");
    const cnt = document.getElementById("backup-selected-count");
    cnt.textContent = state.selectedBackups.size;
    btn.disabled = state.selectedBackups.size === 0;
}

async function restoreSingle(backupId) {
    const data = await apiPost("/restore", { backup_id: backupId });
    showRestoreResults(data);
}

async function restoreBatch() {
    const ids = Array.from(state.selectedBackups);
    if (ids.length === 0) return;
    const data = await apiPost("/restore", { backup_ids: ids });
    showRestoreResults(data);
    refreshBackups();
}

async function restoreByProcess() {
    const name = document.getElementById("restore-process-name").value.trim();
    if (!name) { showToast("Enter a process name", "warning"); return; }
    const data = await apiPost("/restore", { process_name: name });
    showRestoreResults(data);
}

function showRestoreResults(data) {
    state.statsRecovered += (data.succeeded || 0);
    const el = document.getElementById("restore-results");
    if (!data.results || data.results.length === 0) {
        el.innerHTML = '<div class="list-group-item text-muted small">No files to restore</div>';
        showToast("No files matched for restore", "warning");
        return;
    }

    el.innerHTML = data.results.map(function (r) {
        const cls = r.success ? "restore-success" : "restore-failure";
        const icon = r.success ? "bi-check-circle text-success" : "bi-x-circle text-danger";
        return '<div class="list-group-item small ' + cls + '">' +
            '<i class="bi ' + icon + '"></i> ' +
            esc(basename(r.original_path)) +
            (r.error ? ' <span class="text-danger">(' + esc(r.error) + ')</span>' : '') +
            (r.integrity_ok === false ? ' <span class="text-warning">(integrity mismatch)</span>' : '') +
            '</div>';
    }).join("");

    showToast(data.succeeded + " of " + data.total + " files restored",
              data.succeeded === data.total ? "success" : "warning");
}

// ---------------------------------------------------------------------------
// 4. Configuration Panel
// ---------------------------------------------------------------------------

async function loadConfig() {
    state.config = await apiGet("/config");
    renderConfig();
}

function renderConfig() {
    const c = state.config;
    const mon = c.monitor || {};

    // Watch directories
    renderDirList("watch-dirs-list", mon.watch_directories || [], function (idx) {
        const dirs = (state.config.monitor || {}).watch_directories || [];
        dirs.splice(idx, 1);
    });

    // Exclude directories
    renderDirList("exclude-dirs-list", mon.exclude_directories || [], function (idx) {
        const dirs = (state.config.monitor || {}).exclude_directories || [];
        dirs.splice(idx, 1);
    });

    // Entropy threshold
    const et = ((c.entropy || {}).delta_threshold) || 2.0;
    document.getElementById("entropy-threshold").value = et;
    document.getElementById("entropy-threshold-val").textContent = et;

    // Recursive
    document.getElementById("config-recursive").checked = mon.recursive !== false;

    // Safe mode
    document.getElementById("config-safe-mode").checked =
        !!((c.response || {}).safe_mode);

    // Log level
    const ll = (c.logging || {}).level || "INFO";
    document.getElementById("config-log-level").value = ll;

    // Whitelist
    renderDirList("whitelist-list", (c.response || {}).process_whitelist || [], function (idx) {
        const wl = (state.config.response || {}).process_whitelist || [];
        wl.splice(idx, 1);
    });
}

function renderDirList(containerId, items, onRemove) {
    const el = document.getElementById(containerId);
    if (items.length === 0) {
        el.innerHTML = '<span class="text-muted small">None configured</span>';
        return;
    }
    el.innerHTML = items.map(function (item, i) {
        return '<span class="dir-tag">' + esc(item) +
            ' <button class="remove-dir" data-idx="' + i + '">&times;</button></span>';
    }).join("");

    el.querySelectorAll(".remove-dir").forEach(function (btn) {
        btn.addEventListener("click", function () {
            onRemove(parseInt(btn.dataset.idx));
            renderConfig();
        });
    });
}

function addWatchDir() {
    const input = document.getElementById("new-watch-dir");
    const val = input.value.trim();
    if (!val) return;
    if (!state.config.monitor) state.config.monitor = {};
    if (!state.config.monitor.watch_directories) state.config.monitor.watch_directories = [];
    state.config.monitor.watch_directories.push(val);
    input.value = "";
    renderConfig();
}

function addExcludeDir() {
    const input = document.getElementById("new-exclude-dir");
    const val = input.value.trim();
    if (!val) return;
    if (!state.config.monitor) state.config.monitor = {};
    if (!state.config.monitor.exclude_directories) state.config.monitor.exclude_directories = [];
    state.config.monitor.exclude_directories.push(val);
    input.value = "";
    renderConfig();
}

function addWhitelist() {
    const input = document.getElementById("new-whitelist");
    const val = input.value.trim();
    if (!val) return;
    if (!state.config.response) state.config.response = {};
    if (!state.config.response.process_whitelist) state.config.response.process_whitelist = [];
    state.config.response.process_whitelist.push(val);
    input.value = "";
    renderConfig();
}

async function saveConfig() {
    const payload = {
        monitor: {
            watch_directories: (state.config.monitor || {}).watch_directories || [],
            exclude_directories: (state.config.monitor || {}).exclude_directories || [],
            recursive: document.getElementById("config-recursive").checked,
        },
        entropy: {
            delta_threshold: parseFloat(document.getElementById("entropy-threshold").value),
        },
        response: {
            safe_mode: document.getElementById("config-safe-mode").checked,
            process_whitelist: ((state.config.response || {}).process_whitelist) || [],
        },
        logging: {
            level: document.getElementById("config-log-level").value,
        },
    };

    state.config = await apiPut("/config", payload);
    renderConfig();
    const msg = document.getElementById("config-saved-msg");
    msg.classList.remove("d-none");
    setTimeout(function () { msg.classList.add("d-none"); }, 3000);
    showToast("Configuration saved", "success");
}

// ---------------------------------------------------------------------------
// 5. Statistics Dashboard
// ---------------------------------------------------------------------------

function initCharts() {
    // Activity timeline (line chart)
    const actCtx = document.getElementById("activity-chart").getContext("2d");
    state.charts.activity = new Chart(actCtx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Events",
                    data: [],
                    borderColor: "#0d6efd",
                    backgroundColor: "rgba(13,110,253,0.1)",
                    fill: true,
                    tension: 0.3,
                },
                {
                    label: "Threats",
                    data: [],
                    borderColor: "#dc3545",
                    backgroundColor: "rgba(220,53,69,0.1)",
                    fill: true,
                    tension: 0.3,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { position: "top" } },
        },
    });

    // Threat distribution (doughnut)
    const tdCtx = document.getElementById("threat-dist-chart").getContext("2d");
    state.charts.threatDist = new Chart(tdCtx, {
        type: "doughnut",
        data: {
            labels: ["Level 1 - Monitor", "Level 2 - Warn",
                     "Level 3 - Quarantine", "Level 4 - Terminate"],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ["#ffc107", "#fd7e14", "#dc3545", "#842029"],
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: "bottom" } },
        },
    });

    // Event type bar chart
    const etCtx = document.getElementById("event-type-chart").getContext("2d");
    state.charts.eventType = new Chart(etCtx, {
        type: "bar",
        data: {
            labels: ["Created", "Modified", "Deleted", "Moved"],
            datasets: [{
                label: "Count",
                data: [0, 0, 0, 0],
                backgroundColor: ["#198754", "#0d6efd", "#dc3545", "#6f42c1"],
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } },
        },
    });

    // Escalation levels bar chart
    const esCtx = document.getElementById("escalation-chart").getContext("2d");
    state.charts.escalation = new Chart(esCtx, {
        type: "bar",
        data: {
            labels: ["No Action", "Level 1", "Level 2", "Level 3", "Level 4"],
            datasets: [{
                label: "Responses",
                data: [0, 0, 0, 0, 0],
                backgroundColor: ["#6c757d", "#ffc107", "#fd7e14", "#dc3545", "#842029"],
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } },
        },
    });
}

async function refreshStats() {
    // Fetch data
    const [evData, thrData, bkData] = await Promise.all([
        apiGet("/events?limit=1000"),
        apiGet("/threats?limit=1000"),
        apiGet("/backups?limit=1000"),
    ]);

    // Summary cards
    document.getElementById("stat-events").textContent = evData.total;
    document.getElementById("stat-threats").textContent = thrData.total;
    document.getElementById("stat-recovered").textContent = state.statsRecovered;
    document.getElementById("stat-backups").textContent = bkData.total;

    // Event type breakdown
    const typeCounts = { created: 0, modified: 0, deleted: 0, moved: 0 };
    evData.events.forEach(function (e) {
        const t = e.event_type;
        if (t in typeCounts) typeCounts[t]++;
    });
    state.charts.eventType.data.datasets[0].data = [
        typeCounts.created, typeCounts.modified, typeCounts.deleted, typeCounts.moved,
    ];
    state.charts.eventType.update();

    // Threat distribution by escalation level
    const escCounts = [0, 0, 0, 0];
    thrData.threats.forEach(function (t) {
        if (t.escalation_level >= 1 && t.escalation_level <= 4) {
            escCounts[t.escalation_level - 1]++;
        }
    });
    state.charts.threatDist.data.datasets[0].data = escCounts;
    state.charts.threatDist.update();

    // Escalation bar chart (include level 0 = no action)
    const escAll = [0, 0, 0, 0, 0];
    escCounts.forEach(function (c, i) { escAll[i + 1] = c; });
    state.charts.escalation.data.datasets[0].data = escAll;
    state.charts.escalation.update();

    // Activity timeline - group events by hour
    const hourBuckets = {};
    const threatHourBuckets = {};
    evData.events.forEach(function (e) {
        if (!e.timestamp) return;
        const h = e.timestamp.substring(0, 13); // "YYYY-MM-DDTHH"
        hourBuckets[h] = (hourBuckets[h] || 0) + 1;
    });
    thrData.threats.forEach(function (t) {
        if (!t.timestamp) return;
        const h = t.timestamp.substring(0, 13);
        threatHourBuckets[h] = (threatHourBuckets[h] || 0) + 1;
    });

    const allHours = Array.from(new Set(
        Object.keys(hourBuckets).concat(Object.keys(threatHourBuckets))
    )).sort();

    const last24 = allHours.slice(-24);
    state.charts.activity.data.labels = last24.map(function (h) {
        return h.substring(11, 13) + ":00";
    });
    state.charts.activity.data.datasets[0].data = last24.map(function (h) {
        return hourBuckets[h] || 0;
    });
    state.charts.activity.data.datasets[1].data = last24.map(function (h) {
        return threatHourBuckets[h] || 0;
    });
    state.charts.activity.update();
}

// ---------------------------------------------------------------------------
// Demo simulation
// ---------------------------------------------------------------------------

async function toggleDemo() {
    if (state.demoRunning) {
        await apiPost("/demo/stop", {});
        state.demoRunning = false;
        updateDemoButton();
        showToast("Demo stopped", "warning");
    } else {
        const data = await apiPost("/demo/start", {});
        if (data.error) {
            showToast("Demo: " + data.error, "danger");
            return;
        }
        state.demoRunning = true;
        updateDemoButton();
        showToast("Demo simulation started", "info");
    }
}

function updateDemoButton() {
    var btn = document.getElementById("demo-btn");
    if (!btn) return;
    if (state.demoRunning) {
        btn.className = "btn btn-sm btn-warning";
        btn.innerHTML = '<i class="bi bi-stop-circle"></i> Stop Demo';
    } else {
        btn.className = "btn btn-sm btn-outline-warning";
        btn.innerHTML = '<i class="bi bi-play-circle"></i> Run Demo';
    }
}

function updateDemoState(data) {
    if (data.phase === "complete" || data.phase === "stopped") {
        state.demoRunning = false;
        updateDemoButton();
        var variant = data.phase === "complete" ? "success" : "warning";
        showToast("Demo: " + (data.description || data.phase), variant);
    } else {
        state.demoRunning = true;
        updateDemoButton();
        showToast("Demo [" + data.phase + "] " +
            (data.progress || 0) + "% - " + (data.description || ""), "info");
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

function connectWebSocket() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = proto + "//" + location.host + "/ws/live";
    const wsStatus = document.getElementById("ws-status");

    try {
        state.ws = new WebSocket(url);
    } catch (e) {
        wsStatus.textContent = "Unavailable";
        return;
    }

    state.ws.onopen = function () {
        wsStatus.textContent = "Connected";
        document.getElementById("header-ws").classList.replace("bg-info", "bg-success");
    };

    state.ws.onclose = function () {
        wsStatus.textContent = "Disconnected";
        document.getElementById("header-ws").classList.replace("bg-success", "bg-info");
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };

    state.ws.onerror = function () {
        wsStatus.textContent = "Error";
    };

    state.ws.onmessage = function (evt) {
        try {
            var msg = JSON.parse(evt.data);
        } catch (e) {
            return;
        }

        switch (msg.type) {
            case "file_event":
                if (!state.feedPaused) {
                    prependEvent(msg.data);
                }
                break;
            case "threat":
                showToast("Threat detected: " + (msg.data.process_name || "unknown") +
                    " (score " + (msg.data.score || "?") + ")", "danger");
                refreshThreats();
                refreshStatus();
                break;
            case "quarantine":
                showToast("Quarantine: PID " + msg.data.pid +
                    (msg.data.success ? " suspended" : " failed"),
                    msg.data.success ? "warning" : "danger");
                break;
            case "restore":
                showToast("Restore operation completed", "success");
                refreshBackups();
                break;
            case "config_updated":
                showToast("Configuration updated", "info");
                loadConfig();
                break;
            case "demo_status":
                updateDemoState(msg.data);
                break;
        }
    };
}

function prependEvent(ev) {
    const feed = document.getElementById("event-feed");
    const t = ev.event_type || "unknown";
    const html = '<div class="event-row">' +
        '<span class="event-time">' + fmtTime(ev.timestamp || new Date().toISOString()) +
        '</span>' +
        '<span class="event-type type-' + t + '">' + t + '</span>' +
        '<span class="event-path" title="' + esc(ev.file_path || "") + '">' +
            esc(ev.file_path || "") + '</span></div>';
    feed.insertAdjacentHTML("afterbegin", html);

    // Keep max 200 rows
    while (feed.children.length > 200) {
        feed.removeChild(feed.lastChild);
    }
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

function wireEvents() {
    // Monitor tab
    document.getElementById("pause-feed").addEventListener("click", function () {
        state.feedPaused = !state.feedPaused;
        this.innerHTML = state.feedPaused
            ? '<i class="bi bi-play-fill"></i> Resume'
            : '<i class="bi bi-pause-fill"></i> Pause';
    });

    document.getElementById("event-type-filter").addEventListener("change", refreshEvents);

    // Threats tab
    document.getElementById("threat-severity-filter").addEventListener("change", refreshThreats);
    document.getElementById("refresh-threats").addEventListener("click", refreshThreats);
    document.getElementById("export-threats").addEventListener("click", exportThreats);

    // Recovery tab
    document.getElementById("refresh-backups").addEventListener("click", refreshBackups);
    document.getElementById("batch-restore").addEventListener("click", restoreBatch);
    document.getElementById("restore-by-process").addEventListener("click", restoreByProcess);
    document.getElementById("select-all-backups").addEventListener("change", function () {
        const checked = this.checked;
        document.querySelectorAll(".backup-check").forEach(function (cb) {
            cb.checked = checked;
            const id = parseInt(cb.dataset.id);
            if (checked) state.selectedBackups.add(id);
            else state.selectedBackups.delete(id);
        });
        updateBatchButton();
    });

    document.getElementById("backup-search").addEventListener("input", debounce(refreshBackups, 300));
    document.getElementById("backup-process-filter").addEventListener("input",
        debounce(refreshBackups, 300));

    // Config tab
    document.getElementById("add-watch-dir").addEventListener("click", addWatchDir);
    document.getElementById("add-exclude-dir").addEventListener("click", addExcludeDir);
    document.getElementById("add-whitelist").addEventListener("click", addWhitelist);
    document.getElementById("save-config").addEventListener("click", saveConfig);
    document.getElementById("entropy-threshold").addEventListener("input", function () {
        document.getElementById("entropy-threshold-val").textContent = this.value;
    });

    // Enter key support for inputs
    ["new-watch-dir", "new-exclude-dir", "new-whitelist", "restore-process-name"].forEach(
        function (id) {
            document.getElementById(id).addEventListener("keydown", function (e) {
                if (e.key === "Enter") {
                    e.preventDefault();
                    // Trigger the adjacent button
                    this.parentElement.querySelector("button").click();
                }
            });
        }
    );

    // Refresh data when switching tabs
    document.querySelectorAll('#dashboardTabs button[data-bs-toggle="tab"]').forEach(
        function (tab) {
            tab.addEventListener("shown.bs.tab", function (e) {
                const target = e.target.dataset.bsTarget;
                if (target === "#monitor")  { refreshStatus(); refreshEvents(); }
                if (target === "#threats")  { refreshThreats(); }
                if (target === "#recovery") { refreshBackups(); }
                if (target === "#config")   { loadConfig(); }
                if (target === "#stats")    { refreshStats(); }
            });
        }
    );
}

function debounce(fn, ms) {
    var timer;
    return function () {
        clearTimeout(timer);
        timer = setTimeout(fn, ms);
    };
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", function () {
    wireEvents();
    initCharts();

    // Initial data load
    refreshStatus();
    refreshEvents();
    refreshThreats();
    loadConfig();

    // WebSocket
    connectWebSocket();

    // Periodic refresh (every 10 seconds)
    setInterval(function () {
        refreshStatus();
        if (!state.feedPaused) refreshEvents();
    }, 10000);
});
