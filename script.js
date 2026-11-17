/* THREATWATCH: all generated data and behaviors are local educational simulation. */
"use strict";

const STORAGE_KEY = "threatwatch-demo-v1";
const SEED_EVENT_COUNT = 12;

const threats = [
  { ip: "198.51.100.24", category: "Credential abuse", risk: "High", origin: "North America (simulated)", status: "Under review" },
  { ip: "203.0.113.47", category: "Network scanning", risk: "Medium", origin: "Western Europe (simulated)", status: "Monitoring" },
  { ip: "192.0.2.88", category: "Malware indicator", risk: "Critical", origin: "Asia-Pacific (simulated)", status: "Escalated" },
  { ip: "198.51.100.91", category: "Suspicious login", risk: "High", origin: "Eastern Europe (simulated)", status: "Under review" },
  { ip: "203.0.113.66", category: "Traffic anomaly", risk: "Medium", origin: "South America (simulated)", status: "Monitoring" }
];

const scenarios = [
  {
    title: "Brute-force login detection", severity: "HIGH",
    description: "A fictional account has multiple authentication failures within a short sample window.",
    logs: "auth-gateway-01: Authentication failed; account=demo.user source=198.51.100.24 (repeated in sample records).",
    questions: ["Which account and source are involved?", "Do the timestamps show a burst or a pattern over time?", "Is there a successful login after the failures?"],
    response: "Validate the alert, check account and session context, follow the organization's account-protection playbook, and document evidence. Do not block or contact real systems from this demo.",
    investigate: "Correlate authentication events, compare with normal behavior, check for successful sign-ins, and establish scope before deciding whether escalation is warranted."
  },
  {
    title: "Suspicious PowerShell activity", severity: "HIGH",
    description: "Training telemetry indicates script execution on a fictional workstation.",
    logs: "demo-ws-11: PowerShell process start observed in training logs; review parent process and command context.",
    questions: ["What process launched the script?", "Is the execution expected for this host and user?", "Are there related endpoint or authentication events?"],
    response: "Preserve relevant logs and follow the endpoint investigation and containment procedures defined by the organization. Confirm activity with the system owner through approved channels.",
    investigate: "Review process lineage, command context, user, host, and timing. Correlate with other available endpoint events; a process name alone is not proof of malicious activity."
  },
  {
    title: "Port scanning detection", severity: "MEDIUM",
    description: "A sample network sensor records sequential connection attempts against demo services.",
    logs: "demo-web-02: Training sensor: sequential connection attempts observed in sample telemetry.",
    questions: ["Which fictional destination is involved?", "What time window and services appear in the evidence?", "Is the activity expected for an authorized test?"],
    response: "Verify ownership and approved testing windows. Follow local network monitoring and escalation procedures; this simulated dashboard performs no scanning.",
    investigate: "Review network flow metadata, determine the apparent scope and timing, correlate with asset inventory, and distinguish approved assessment from unapproved activity."
  },
  {
    title: "Unusual login location", severity: "HIGH",
    description: "A fictional login is associated with an unfamiliar simulated region.",
    logs: "vpn-demo-01: Login success from unfamiliar simulated region; review session context.",
    questions: ["Is the location information reliable?", "Does the account have a known travel or remote-work context?", "Are device and session details consistent?"],
    response: "Verify the signal with trusted identity context and the user or account owner using approved procedures. Follow the organization's identity response playbook.",
    investigate: "Treat geolocation as an imperfect signal. Compare account history, device, timing, authentication method, and related activity before drawing conclusions."
  },
  {
    title: "Potential malware alert", severity: "CRITICAL",
    description: "A lab fixture triggers a fictional endpoint malware alert.",
    logs: "demo-ws-07: SIMULATED endpoint alert: sample malware indicator triggered by lab fixture.",
    questions: ["Which host and sample indicator generated the alert?", "Is the alert a known test fixture or a false positive?", "What other evidence is available in the event timeline?"],
    response: "Validate against approved lab documentation. In a real environment, use the authorized incident response plan and evidence-handling process; this demo cannot isolate hosts.",
    investigate: "Confirm the source and reliability of the alert, collect associated host and timeline context, assess potential scope, and escalate according to policy."
  }
];

const mitreMappings = [
  { alert: "Multiple authentication failures", tactic: "Credential Access", id: "T1110", technique: "Brute Force", url: "https://attack.mitre.org/techniques/T1110/" },
  { alert: "Suspicious PowerShell activity", tactic: "Execution", id: "T1059.001", technique: "PowerShell", url: "https://attack.mitre.org/techniques/T1059/001/" },
  { alert: "Port scan detection", tactic: "Discovery", id: "T1046", technique: "Network Service Discovery", url: "https://attack.mitre.org/techniques/T1046/" },
  { alert: "Unusual login activity", tactic: "Initial Access", id: "T1078", technique: "Valid Accounts", url: "https://attack.mitre.org/techniques/T1078/" },
  { alert: "Malware alert", tactic: "Execution", id: "T1204", technique: "User Execution (illustrative)", url: "https://attack.mitre.org/techniques/T1204/" },
  { alert: "Privilege escalation alert", tactic: "Privilege Escalation", id: "TA0004", technique: "Tactic reference", url: "https://attack.mitre.org/tactics/TA0004/" }
];

const generatedTypes = [
  ["Failed login attempt", "Authentication", ["Low", "Medium"]],
  ["Multiple authentication failures", "Authentication", ["High"]],
  ["Suspicious login activity", "Authentication", ["High"]],
  ["Port scan detection", "Network", ["Medium", "Low"]],
  ["Malware alert", "Endpoint", ["Critical"]],
  ["Unusual network traffic", "Network", ["Medium", "High"]],
  ["Privilege escalation alert", "Endpoint", ["Critical", "High"]]
];
const fictionalIps = ["192.0.2.37", "198.51.100.72", "203.0.113.109", "192.0.2.201", "198.51.100.154"];
const fictionalHosts = ["auth-gateway-01", "demo-web-02", "demo-ws-07", "vpn-demo-01", "demo-srv-03"];

let state = { events: [], logs: [], incidents: [] };
let charts = {};
let generatorTimer = null;
let toastTimer = null;

const $ = (selector) => document.querySelector(selector);
const severityClass = (value) => `sev-${String(value).toLowerCase()}`;
const statusClass = (value) => `status-${String(value).toLowerCase().replace(/\s+/g, "-")}`;
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
}[char]));
const formatTime = (iso) => new Date(iso).toLocaleString(undefined, {
  month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
});
const formatShortTime = (iso) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });

async function loadSeedData() {
  try {
    const response = await fetch("data/logs.json");
    if (!response.ok) throw new Error("Unable to load sample data");
    const payload = await response.json();
    return payload;
  } catch (error) {
    console.warn("Sample JSON could not be loaded. Start a local HTTP server; an empty demo fallback will be used.", error);
    return { events: [], logs: [] };
  }
}

function createInitialIncidents(events) {
  return events.filter((event) => ["Critical", "High"].includes(event.severity))
    .slice(0, 5)
    .map((event, index) => ({
      id: `INC-${String(2101 + index)}`,
      eventId: event.id,
      title: event.type,
      sourceIp: event.sourceIp,
      destination: event.destination,
      severity: event.severity,
      status: event.status === "Resolved" ? "Resolved" : (index % 2 ? "Investigating" : "Open"),
      createdAt: event.timestamp,
      notes: ""
    }));
}

function saveState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

async function initialize() {
  const seed = await loadSeedData();
  const saved = readSavedState();
  if (saved) {
    state = saved;
    // Keep demo seed events/logs current while retaining incident edits and generated events.
    if (!Array.isArray(state.events) || !state.events.length) state.events = seed.events || [];
    if (!Array.isArray(state.logs) || !state.logs.length) state.logs = seed.logs || [];
  } else {
    state = { events: seed.events || [], logs: seed.logs || [], incidents: createInitialIncidents(seed.events || []) };
  }
  normalizeState();
  populateTypeFilter();
  renderAll();
  initializeCharts();
  bindEvents();
  updateClock();
  setInterval(updateClock, 1000);
}

function readSavedState() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (value && Array.isArray(value.events) && Array.isArray(value.logs) && Array.isArray(value.incidents)) return value;
  } catch (_) { /* Ignore invalid local demo state and use fresh sample data. */ }
  return null;
}

function normalizeState() {
  state.events.forEach((event) => { if (!event.category) event.category = inferCategory(event.type); });
  state.incidents.forEach((incident) => {
    incident.notes ??= "";
    incident.status ??= "Open";
  });
}

function inferCategory(type) {
  if (/login|authentication/i.test(type)) return "Authentication";
  if (/port|network|traffic/i.test(type)) return "Network";
  return "Endpoint";
}

function populateTypeFilter() {
  const types = [...new Set(state.events.map((event) => event.type))].sort();
  $("#typeFilter").innerHTML = '<option value="all">All event types</option>' +
    types.map((type) => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("");
}

function filteredEvents() {
  const severity = $("#severityFilter").value;
  const type = $("#typeFilter").value;
  return state.events.filter((event) =>
    (severity === "all" || event.severity === severity) &&
    (type === "all" || event.type === type)
  );
}

function renderAll() {
  renderMetrics();
  renderEvents();
  renderThreats();
  renderIncidents();
  renderLogs();
  renderScenarios();
  renderMitre();
  updateCharts();
}

function renderMetrics() {
  const events = state.events;
  $("#metricEvents").textContent = events.length;
  $("#metricCritical").textContent = events.filter((e) => e.severity === "Critical").length;
  $("#metricHigh").textContent = events.filter((e) => e.severity === "High").length;
  $("#metricMedium").textContent = events.filter((e) => e.severity === "Medium").length;
  $("#metricResolved").textContent = state.incidents.filter((i) => i.status === "Resolved").length;
  $("#metricActive").textContent = state.incidents.filter((i) => i.status !== "Resolved").length;
  $("#navEventCount").textContent = events.length;
}

function renderEvents() {
  const events = filteredEvents().slice().sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  $("#eventTableBody").innerHTML = events.length ? events.slice(0, 30).map((event) => `
    <tr>
      <td class="mono">${escapeHtml(formatTime(event.timestamp))}</td>
      <td class="mono">${escapeHtml(event.sourceIp)}</td>
      <td>${escapeHtml(event.type)}</td>
      <td><span class="severity-tag ${severityClass(event.severity)}">${escapeHtml(event.severity)}</span></td>
      <td class="mono">${escapeHtml(event.destination)}</td>
      <td><span class="status-tag ${statusClass(event.status)}">${escapeHtml(event.status)}</span></td>
      <td><button class="row-action" type="button" data-investigate-event="${escapeHtml(event.id)}">Investigate ↗</button></td>
    </tr>`).join("") : '<tr><td class="empty-state" colspan="7">No events match these filters.</td></tr>';
  $("#eventCountLabel").textContent = `Showing ${Math.min(events.length, 30)} of ${events.length} events`;
}

function renderThreats() {
  $("#threatTableBody").innerHTML = threats.map((threat) => `
    <tr><td class="mono">${escapeHtml(threat.ip)}</td><td>${escapeHtml(threat.category)}</td>
    <td><span class="severity-tag ${severityClass(threat.risk)}">${escapeHtml(threat.risk)}</span></td>
    <td>${escapeHtml(threat.origin)}</td><td><span class="status-tag">${escapeHtml(threat.status)}</span></td></tr>
  `).join("");
}

function renderIncidents() {
  const list = state.incidents.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  $("#incidentCountBadge").textContent = `${list.length} incident${list.length === 1 ? "" : "s"}`;
  $("#incidentList").innerHTML = list.length ? list.map((incident) => `
    <article class="incident-card">
      <div class="incident-card-top"><span class="mono">${escapeHtml(incident.id)}</span><span class="severity-tag ${severityClass(incident.severity)}">${escapeHtml(incident.severity)}</span></div>
      <h3>${escapeHtml(incident.title)}</h3>
      <p>${escapeHtml(incident.sourceIp)} → ${escapeHtml(incident.destination)}</p>
      <div class="incident-meta"><span class="status-tag ${statusClass(incident.status)}">${escapeHtml(incident.status)}</span><button class="row-action" type="button" data-open-incident="${escapeHtml(incident.id)}">Open investigation ↗</button></div>
    </article>
  `).join("") : '<div class="empty-state">No incidents yet. Use “Investigate” on an event to open one.</div>';
}

function filteredLogs() {
  const search = $("#logSearch").value.trim().toLowerCase();
  const severity = $("#logSeverity").value;
  const from = $("#dateFrom").value ? new Date(`${$("#dateFrom").value}T00:00:00`).getTime() : -Infinity;
  const to = $("#dateTo").value ? new Date(`${$("#dateTo").value}T23:59:59`).getTime() : Infinity;
  return state.logs.filter((log) => {
    const time = new Date(log.timestamp).getTime();
    const searchable = `${log.id} ${log.host} ${log.user} ${log.message} ${log.severity}`.toLowerCase();
    return (!search || searchable.includes(search)) &&
      (severity === "all" || log.severity === severity) &&
      time >= from && time <= to;
  }).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

function renderLogs() {
  const logs = filteredLogs();
  $("#logTableBody").innerHTML = logs.length ? logs.slice(0, 100).map((log) => `
    <tr class="${log.suspicious ? "pattern-row" : ""}">
      <td class="mono">${escapeHtml(formatTime(log.timestamp))}</td><td class="mono">${escapeHtml(log.host)}</td>
      <td><span class="severity-tag ${severityClass(log.severity)}">${escapeHtml(log.severity)}</span></td>
      <td>${escapeHtml(log.user)}</td><td>${escapeHtml(log.message)}</td>
      <td><button class="row-action" type="button" data-log-detail="${escapeHtml(log.id)}">Details</button></td>
    </tr>`).join("") : '<tr><td class="empty-state" colspan="6">No logs match your search and filters.</td></tr>';
  $("#logCountLabel").textContent = `Showing ${Math.min(logs.length, 100)} of ${logs.length} logs`;
}

function renderScenarios() {
  $("#scenarioList").innerHTML = scenarios.map((scenario) => `
    <article class="scenario-card"><details>
      <summary><span class="severity-tag ${severityClass(scenario.severity)}">${escapeHtml(scenario.severity)}</span>
        <h3>${escapeHtml(scenario.title)}</h3><p>${escapeHtml(scenario.description)}</p></summary>
      <div class="scenario-content">
        <h4>Relevant sample log</h4><p>${escapeHtml(scenario.logs)}</p>
        <h4>Investigation questions</h4><ul>${scenario.questions.map((question) => `<li>${escapeHtml(question)}</li>`).join("")}</ul>
        <h4>Recommended defensive response</h4><p>${escapeHtml(scenario.response)}</p>
        <h4>What an analyst should investigate</h4><p>${escapeHtml(scenario.investigate)}</p>
      </div>
    </details></article>
  `).join("");
}

function renderMitre() {
  $("#mitreTableBody").innerHTML = mitreMappings.map((item) => `
    <tr><td>${escapeHtml(item.alert)}</td><td>${escapeHtml(item.tactic)}</td>
    <td><span class="mono">${escapeHtml(item.id)}</span> · ${escapeHtml(item.technique)}</td>
    <td><a class="mitre-link" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">Official MITRE reference ↗</a></td></tr>
  `).join("");
}

function initializeCharts() {
  if (typeof Chart === "undefined") {
    document.querySelectorAll(".chart-wrap").forEach((wrap) => {
      wrap.innerHTML = '<p class="muted-copy">Charts require the Chart.js CDN. Check your connection or include Chart.js locally.</p>';
    });
    return;
  }
  Chart.defaults.color = "#8998aa";
  Chart.defaults.font.family = '"DM Mono", monospace';
  Chart.defaults.font.size = 9;
  const gridColor = "#1d2a3a";
  const commonOptions = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { usePointStyle: true, boxWidth: 7, padding: 14 } } }
  };
  charts.severity = new Chart($("#severityChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: ["#ff6073", "#ffa55c", "#eec45c", "#3bc8e8"], borderWidth: 0, hoverOffset: 5 }] },
    options: { ...commonOptions, cutout: "72%", plugins: { legend: { position: "right", labels: { usePointStyle: true, boxWidth: 7, padding: 9 } } } }
  });
  charts.timeline = new Chart($("#timelineChart"), {
    type: "line", data: { labels: [], datasets: [{ label: "Events", data: [], borderColor: "#39e6a1", backgroundColor: "#39e6a11a", fill: true, tension: .35, pointRadius: 2 }] },
    options: { ...commonOptions, scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: gridColor } } } }
  });
  charts.failed = new Chart($("#failedChart"), {
    type: "bar", data: { labels: [], datasets: [{ label: "Failed logins", data: [], backgroundColor: "#3bc8e8", borderRadius: 3 }] },
    options: { ...commonOptions, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: gridColor } } } }
  });
  charts.resolution = new Chart($("#resolutionChart"), {
    type: "doughnut", data: { labels: [], datasets: [{ data: [], backgroundColor: ["#39e6a1", "#eec45c", "#ff6073"], borderWidth: 0, hoverOffset: 5 }] },
    options: { ...commonOptions, cutout: "68%" }
  });
  charts.category = new Chart($("#categoryChart"), {
    type: "bar", data: { labels: [], datasets: [{ label: "Events", data: [], backgroundColor: "#a68aff", borderRadius: 3 }] },
    options: { ...commonOptions, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: gridColor } }, y: { grid: { display: false } } } }
  });
  updateCharts();
}

function updateCharts() {
  if (!charts.severity) return;
  const events = filteredEvents();
  const severityOrder = ["Critical", "High", "Medium", "Low"];
  charts.severity.data.labels = severityOrder;
  charts.severity.data.datasets[0].data = severityOrder.map((s) => events.filter((event) => event.severity === s).length);
  charts.severity.update();

  const hours = [];
  const now = new Date();
  for (let i = 7; i >= 0; i--) {
    const date = new Date(now.getTime() - i * 60 * 60 * 1000);
    const key = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}`;
    hours.push({ key, label: date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false }) });
  }
  const timeData = hours.map(({ key }) => events.filter((event) => {
    const d = new Date(event.timestamp);
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}` === key;
  }).length);
  charts.timeline.data.labels = hours.map((h) => h.label);
  charts.timeline.data.datasets[0].data = timeData;
  charts.timeline.update();

  const loginEvents = events.filter((event) => /failed login|authentication failures/i.test(event.type));
  const loginHours = hours.map((hour) => ({
    label: hour.label,
    count: loginEvents.filter((event) => {
      const d = new Date(event.timestamp);
      return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}` === hour.key;
    }).length
  }));
  charts.failed.data.labels = loginHours.map((h) => h.label);
  charts.failed.data.datasets[0].data = loginHours.map((h) => h.count);
  charts.failed.update();

  const statuses = ["Resolved", "Investigating", "Open"];
  charts.resolution.data.labels = statuses;
  charts.resolution.data.datasets[0].data = statuses.map((status) => state.incidents.filter((incident) => incident.status === status).length);
  charts.resolution.update();

  const categories = [...new Set(events.map((event) => event.category || inferCategory(event.type)))].sort();
  charts.category.data.labels = categories;
  charts.category.data.datasets[0].data = categories.map((category) => events.filter((event) => (event.category || inferCategory(event.type)) === category).length);
  charts.category.update();
}

function openModal(title, eyebrow, html) {
  $("#modalTitle").textContent = title;
  $("#modalEyebrow").textContent = eyebrow;
  $("#modalBody").innerHTML = html;
  $("#modalBackdrop").hidden = false;
  $("#modalClose").focus();
  document.body.style.overflow = "hidden";
}

function closeModal() {
  $("#modalBackdrop").hidden = true;
  $("#modalBody").innerHTML = "";
  document.body.style.overflow = "";
}

function openIncident(incidentId) {
  const incident = state.incidents.find((item) => item.id === incidentId);
  if (!incident) return;
  openModal(`${incident.id} · ${incident.title}`, "INCIDENT INVESTIGATION", `
    <form id="incidentForm">
      <div class="form-grid">
        <div class="form-field"><label for="incidentSeverity">Severity</label><select id="incidentSeverity"><option ${incident.severity === "Critical" ? "selected" : ""}>Critical</option><option ${incident.severity === "High" ? "selected" : ""}>High</option><option ${incident.severity === "Medium" ? "selected" : ""}>Medium</option><option ${incident.severity === "Low" ? "selected" : ""}>Low</option></select></div>
        <div class="form-field"><label for="incidentStatus">Status</label><select id="incidentStatus"><option ${incident.status === "Open" ? "selected" : ""}>Open</option><option ${incident.status === "Investigating" ? "selected" : ""}>Investigating</option><option ${incident.status === "Monitoring" ? "selected" : ""}>Monitoring</option><option ${incident.status === "Resolved" ? "selected" : ""}>Resolved</option></select></div>
        <div class="form-field"><label>Source IP (fictional)</label><div class="detail-box">${escapeHtml(incident.sourceIp)}</div></div>
        <div class="form-field"><label>Destination</label><div class="detail-box">${escapeHtml(incident.destination)}</div></div>
        <div class="form-field full"><label for="incidentNotes">Investigation notes</label><textarea id="incidentNotes" placeholder="Record your observations, evidence, and next steps…">${escapeHtml(incident.notes)}</textarea></div>
      </div>
      <div class="modal-actions"><button class="button button-secondary" type="button" id="cancelIncident">Cancel</button><button class="button button-primary" type="submit">Save investigation</button></div>
    </form>
  `);
  $("#incidentForm").addEventListener("submit", (event) => {
    event.preventDefault();
    incident.severity = $("#incidentSeverity").value;
    incident.status = $("#incidentStatus").value;
    incident.notes = $("#incidentNotes").value;
    const sourceEvent = state.events.find((item) => item.id === incident.eventId);
    if (sourceEvent) sourceEvent.status = incident.status;
    saveState();
    renderAll();
    closeModal();
    showToast("Investigation saved to this browser.");
  });
  $("#cancelIncident").addEventListener("click", closeModal);
}

function investigateEvent(eventId) {
  const event = state.events.find((item) => item.id === eventId);
  if (!event) return;
  let incident = state.incidents.find((item) => item.eventId === event.id);
  if (!incident) {
    const next = 2101 + state.incidents.length;
    incident = {
      id: `INC-${String(next)}`, eventId: event.id, title: event.type,
      sourceIp: event.sourceIp, destination: event.destination,
      severity: event.severity, status: "Open", createdAt: new Date().toISOString(), notes: ""
    };
    state.incidents.push(incident);
    event.status = "Open";
    saveState();
    renderAll();
    showToast(`${incident.id} created.`);
  }
  openIncident(incident.id);
}

function showLogDetails(logId) {
  const log = state.logs.find((item) => item.id === logId);
  if (!log) return;
  openModal(`Log entry · ${log.id}`, "SAMPLE LOG DETAIL", `
    <div class="detail-box">${escapeHtml(JSON.stringify(log, null, 2))}</div>
    <p class="muted-copy">This is fictional training data. A highlighted pattern is a learning cue, not a confirmed detection.</p>
    <div class="modal-actions"><button class="button button-secondary" type="button" id="closeLogDetail">Close</button></div>
  `);
  $("#closeLogDetail").addEventListener("click", closeModal);
}

function generateEvent() {
  const [type, category, severities] = generatedTypes[Math.floor(Math.random() * generatedTypes.length)];
  const severity = severities[Math.floor(Math.random() * severities.length)];
  const sourceIp = fictionalIps[Math.floor(Math.random() * fictionalIps.length)];
  const destination = fictionalHosts[Math.floor(Math.random() * fictionalHosts.length)];
  const now = new Date().toISOString();
  const event = {
    id: `EVT-${Date.now()}`, timestamp: now, sourceIp, type, severity, destination,
    status: "Open", category, summary: "Generated locally for this educational demo."
  };
  state.events.unshift(event);
  state.logs.unshift({
    id: `LOG-${Date.now()}`, timestamp: now, host: destination, severity,
    user: "demo.user", message: `SIMULATED ${type.toLowerCase()} event; source=${sourceIp}; generated locally for training.`,
    suspicious: ["Critical", "High"].includes(severity)
  });
  saveState();
  populateTypeFilter();
  renderAll();
  showToast("A fictional demo event was added.");
}

function toggleGenerator() {
  const button = $("#generatorToggle");
  if (generatorTimer) {
    clearInterval(generatorTimer);
    generatorTimer = null;
    button.innerHTML = '<span class="pulse-dot"></span> Start live simulation';
    $("#generatorStatus").textContent = "Stopped";
    showToast("Demo event generator stopped.");
  } else {
    generatorTimer = setInterval(generateEvent, 8000);
    button.innerHTML = "Ⅱ Stop live simulation";
    $("#generatorStatus").textContent = "Running";
    showToast("Demo generator started; one fictional event every 8 seconds.");
  }
}

function resetDemo() {
  if (!window.confirm("Reset all demo events, incidents, notes, and filters to the original sample data?")) return;
  localStorage.removeItem(STORAGE_KEY);
  if (generatorTimer) {
    clearInterval(generatorTimer);
    generatorTimer = null;
  }
  $("#generatorToggle").innerHTML = '<span class="pulse-dot"></span> Start live simulation';
  $("#generatorStatus").textContent = "Stopped";
  loadSeedData().then((seed) => {
    state = { events: seed.events || [], logs: seed.logs || [], incidents: createInitialIncidents(seed.events || []) };
    $("#severityFilter").value = "all";
    $("#typeFilter").value = "all";
    $("#logSearch").value = "";
    $("#dateFrom").value = "";
    $("#dateTo").value = "";
    $("#logSeverity").value = "all";
    populateTypeFilter();
    saveState();
    renderAll();
    showToast("Demo data reset.");
  });
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2800);
}

function updateClock() {
  $("#clock").textContent = `${new Date().toISOString().slice(11, 19)} UTC`;
}

function bindEvents() {
  $("#severityFilter").addEventListener("change", renderAll);
  $("#typeFilter").addEventListener("change", renderAll);
  $("#logSearch").addEventListener("input", renderLogs);
  $("#logSeverity").addEventListener("change", renderLogs);
  $("#dateFrom").addEventListener("change", renderLogs);
  $("#dateTo").addEventListener("change", renderLogs);
  $("#clearLogFilters").addEventListener("click", () => {
    $("#logSearch").value = "";
    $("#dateFrom").value = "";
    $("#dateTo").value = "";
    $("#logSeverity").value = "all";
    renderLogs();
  });
  $("#generateButton").addEventListener("click", generateEvent);
  $("#generatorToggle").addEventListener("click", toggleGenerator);
  $("#resetDemoButton").addEventListener("click", resetDemo);
  $("#dismissBanner").addEventListener("click", () => $(".simulation-banner").remove());
  $("#modalClose").addEventListener("click", closeModal);
  $("#modalBackdrop").addEventListener("click", (event) => {
    if (event.target === $("#modalBackdrop")) closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("#modalBackdrop").hidden) closeModal();
  });
  document.body.addEventListener("click", (event) => {
    const incidentButton = event.target.closest("[data-open-incident]");
    const eventButton = event.target.closest("[data-investigate-event]");
    const logButton = event.target.closest("[data-log-detail]");
    if (incidentButton) openIncident(incidentButton.dataset.openIncident);
    if (eventButton) investigateEvent(eventButton.dataset.investigateEvent);
    if (logButton) showLogDetails(logButton.dataset.logDetail);
  });
  $("#menuButton").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
      link.classList.add("active");
      $("#sidebar").classList.remove("open");
    });
  });
}

initialize();