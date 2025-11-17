// ------------------------- GLOBAL ELEMENTS -------------------------

// Telemetry elements
const speedEl = document.getElementById("speed-value");
const brakeStatusEl = document.getElementById("brake-status");
const anomalyScoreEl = document.getElementById("anomaly-score");
const anomalyBarFillEl = document.getElementById("anomaly-bar-fill");
const lastUpdateEl = document.getElementById("last-update");

// ECU + Heatmap
const ecuHealthListEl = document.getElementById("ecu-health-list");
const heatmapGridEl = document.getElementById("heatmap-grid");

// Alerts
const alertsListEl = document.getElementById("alerts-list");
const clearAlertsBtn = document.getElementById("clear-alerts-btn");

// Attack Toggle
const attackToggleBtn = document.getElementById("attack-toggle-btn");
const systemStatusText = document.getElementById("system-status-text");

// CAN Bus
const canTableBody = document.getElementById("can-table-body");
const canRateEl = document.getElementById("can-rate");
let canHistory = [];

// Timeline canvas
const rootEl = document.getElementById("app");

// Analytics
const ecuChartCanvas = document.getElementById("ecu-chart");
const typeChartCanvas = document.getElementById("type-chart");
const eventsChartCanvas = document.getElementById("events-chart");
const attackersTableBody = document.getElementById("attackers-table-body");

// State
let alertHistory = [];
let attackMode = false;

// ------------------------- TELEMETRY POLLING -------------------------

async function fetchTelemetry() {
  try {
    const res = await fetch("/api/telemetry");
    const data = await res.json();

    updateDashboard(data);
    systemStatusText.textContent = "Live";

  } catch (err) {
    console.error("Telemetry error:", err);
    systemStatusText.textContent = "Error";
  }
}

setInterval(fetchTelemetry, 1000);
fetchTelemetry();


// ------------------------- UPDATE DASHBOARD -------------------------

function updateDashboard(data) {
  // Basic telemetry
  speedEl.textContent = data.speed;
  brakeStatusEl.textContent = data.brake_status;
  brakeStatusEl.style.color =
    data.brake_status === "ON" ? "#f97316" : "#10b981";

  anomalyScoreEl.textContent = data.can_anomaly_score.toFixed(2);
  anomalyBarFillEl.style.width = `${data.can_anomaly_score * 100}%`;

  lastUpdateEl.textContent = data.timestamp;

  // Attack mode UI
  if (data.attack_active) rootEl.classList.add("attack-active");
  else rootEl.classList.remove("attack-active");

  attackMode = data.forced_attack;
  updateAttackButtonLabel();

  // ECU + Heatmap
  renderEcuHealth(data.ecu_health);
  renderHeatmap(data.heatmap);

  // Alerts
  if (data.security_alerts.length > 0) {
    addAlerts(data.security_alerts);
  }

  // CAN packets
  updateCanPackets(data.can_packets);

  // Timeline
  updateTimeline(data.can_anomaly_score, data.attack_active);
}


// ------------------------- ECU HEALTH -------------------------

function renderEcuHealth(ecuHealth) {
  ecuHealthListEl.innerHTML = "";

  Object.entries(ecuHealth).forEach(([name, value]) => {
    const pct = Math.round(value * 100);

    const row = document.createElement("div");
    row.className = "ecu-row";

    row.innerHTML = `
      <span class="ecu-name">${name}</span>
      <div class="ecu-health-bar">
          <div class="ecu-health-fill" style="width:${pct}%"></div>
      </div>
      <span class="ecu-health-value">${pct}%</span>
    `;

    ecuHealthListEl.appendChild(row);
  });
}


// ------------------------- HEATMAP -------------------------

function renderHeatmap(heatmap) {
  heatmapGridEl.innerHTML = "";
  heatmap.forEach((h) => {
    const div = document.createElement("div");
    div.className = `heatmap-cell ${h.status}`;
    div.textContent = h.name;
    heatmapGridEl.appendChild(div);
  });
}


// ------------------------- ALERTS -------------------------

function addAlerts(alerts) {
  const time = new Date().toLocaleTimeString("en-GB", { hour12: false });

  alerts.forEach((a) => {
    alertHistory.unshift({
      level: a.level,
      source: a.source,
      message: a.message,
      time: time,
    });
  });

  if (alertHistory.length > 50) alertHistory = alertHistory.slice(0, 50);

  renderAlerts();
}

function renderAlerts() {
  alertsListEl.innerHTML = "";

  if (alertHistory.length === 0) {
    alertsListEl.innerHTML = `<p style="color:#9ca3af;font-size:.85rem;">No alerts yet.</p>`;
    return;
  }

  alertHistory.forEach((a) => {
    const div = document.createElement("div");
    div.className = "alert-item";

    div.innerHTML = `
      <span class="alert-badge ${a.level}">${a.level}</span>
      <div>
        <div class="alert-source">${a.source}</div>
        <div class="alert-message">${a.message}</div>
      </div>
      <div class="alert-time">${a.time}</div>
    `;

    alertsListEl.appendChild(div);
  });
}

clearAlertsBtn.addEventListener("click", () => {
  alertHistory = [];
  renderAlerts();
});


// ------------------------- CAN BUS LIVE PACKETS -------------------------

function updateCanPackets(packets) {
  packets.forEach((pkt) => {
    canHistory.unshift({
      timestamp: pkt.timestamp,   // FIXED TIMESTAMP FORMAT
      id: pkt.id,
      ecu: pkt.ecu,
      dlc: pkt.dlc,
      data: pkt.data,
      anomaly: pkt.anomaly,
    });
  });

  canHistory = canHistory.slice(0, 100);
  canRateEl.textContent = packets.length + " frames/s";

  renderCanTable();
}

function renderCanTable() {
  canTableBody.innerHTML = "";

  canHistory.forEach((f) => {
    const tr = document.createElement("tr");
    if (f.anomaly) tr.classList.add("can-row-anomaly");

    ["timestamp", "id", "ecu", "dlc", "data"].forEach((k) => {
      const td = document.createElement("td");
      td.textContent = f[k];
      tr.appendChild(td);
    });

    const anomalyTd = document.createElement("td");
    anomalyTd.textContent = f.anomaly ? "Yes" : "No";
    tr.appendChild(anomalyTd);

    canTableBody.appendChild(tr);
  });
}


// ------------------------- REALTIME TIMELINE (NEON CHART) -------------------------

const timelineCtx = document.getElementById("attackTimelineChart").getContext("2d");

let anomalyTimeline = [];
let attackTimeline = [];

const gradient = timelineCtx.createLinearGradient(0, 0, 0, 200);
gradient.addColorStop(0, "rgba(34,197,94,0.55)");
gradient.addColorStop(1, "rgba(34,197,94,0.05)");

let timelineChart = new Chart(timelineCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "Anomaly Score",
        data: [],
        borderColor: "#4ade80",
        backgroundColor: gradient,
        borderWidth: 3,
        tension: 0.35,
        pointRadius: 0,
        fill: true,
      },
      {
        label: "Attack Zone",
        data: [],
        type: "bar",
        backgroundColor: "rgba(255,0,0,0.18)",
        borderWidth: 0,
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }},
    scales: {
      x: { ticks: { display: false }, grid: { display: false }},
      y: {
        min: 0, max: 1,
        ticks: { color: "#e5e7eb" },
        grid: { color: "rgba(100,116,139,0.2)" }
      }
    },
    animation: { duration: 350, easing: "easeOutQuart" }
  }
});

function updateTimeline(score, attackActive) {
  const MAX = 60;
  anomalyTimeline.push(score);
  attackTimeline.push(attackActive ? 1 : 0);

  if (anomalyTimeline.length > MAX) anomalyTimeline.shift();
  if (attackTimeline.length > MAX) attackTimeline.shift();

  timelineChart.data.labels = anomalyTimeline.map((_, i) => i);
  timelineChart.data.datasets[0].data = anomalyTimeline;
  timelineChart.data.datasets[1].data = attackTimeline;

  timelineChart.update();
}


// ------------------------- ATTACK BUTTON -------------------------

function updateAttackButtonLabel() {
  attackToggleBtn.textContent = attackMode ? "Stop Attack" : "Simulate Attack";
  attackToggleBtn.style.background = attackMode
    ? "rgba(239,68,68,0.35)"
    : "rgba(31,41,55,0.95)";
}

async function toggleAttackMode() {
  const newMode = !attackMode;
  attackMode = newMode;
  updateAttackButtonLabel();

  try {
    await fetch("/api/force_attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: newMode ? "on" : "off" }),
    });
  } catch (err) {
    console.error("Force attack error:", err);
  }
}

attackToggleBtn.addEventListener("click", toggleAttackMode);


// ------------------------- ANALYTICS -------------------------

let ecuChart = null;
let typeChart = null;
let eventsChart = null;

async function fetchAnalytics() {
  try {
    const res = await fetch("/api/analytics");
    const data = await res.json();
    updateAnalytics(data);
  } catch (err) {
    console.error("Analytics error:", err);
  }
}

setInterval(fetchAnalytics, 5000);
fetchAnalytics();


function updateAnalytics(data) {
  // -------- Top ECU attacks --------
  const ecuLabels = data.top_ecu_targets.map(x => x.ecu);
  const ecuCounts = data.top_ecu_targets.map(x => x.count);

  if (!ecuChart) {
    ecuChart = new Chart(ecuChartCanvas, {
      type: "bar",
      data: {
        labels: ecuLabels,
        datasets: [{
          data: ecuCounts,
          backgroundColor: "rgba(59,130,246,0.8)"
        }]
      },
      options: { plugins:{legend:{display:false}} }
    });
  } else {
    ecuChart.data.labels = ecuLabels;
    ecuChart.data.datasets[0].data = ecuCounts;
    ecuChart.update();
  }

  // -------- Attack Types --------
  const typeLabels = data.top_attack_types.map(x => x.type);
  const typeCounts = data.top_attack_types.map(x => x.count);

  if (!typeChart) {
    typeChart = new Chart(typeChartCanvas, {
      type: "bar",
      data: {
        labels: typeLabels,
        datasets: [{
          data: typeCounts,
          backgroundColor: "rgba(248,113,113,0.8)"
        }]
      },
      options: { plugins:{legend:{display:false}} }
    });
  } else {
    typeChart.data.labels = typeLabels;
    typeChart.data.datasets[0].data = typeCounts;
    typeChart.update();
  }

  // -------- Timeline Alerts --------
  const timeline = data.events_timeline;
  const timeLabels = timeline.map(x => x.timestamp);
  const totalAlerts = timeline.map(x => x.total_alerts);
  const criticalAlerts = timeline.map(x => x.critical_alerts);

  if (!eventsChart) {
    eventsChart = new Chart(eventsChartCanvas, {
      type: "line",
      data: {
        labels: timeLabels,
        datasets: [
          {
            label: "Total Alerts",
            data: totalAlerts,
            borderColor: "rgba(59,130,246)",
            backgroundColor: "rgba(59,130,246,0.2)",
            tension: 0.3
          },
          {
            label: "Critical/High",
            data: criticalAlerts,
            borderColor: "rgba(248,113,113)",
            backgroundColor: "rgba(248,113,113,0.2)",
            tension: 0.3
          }
        ]
      }
    });
  } else {
    eventsChart.data.labels = timeLabels;
    eventsChart.data.datasets[0].data = totalAlerts;
    eventsChart.data.datasets[1].data = criticalAlerts;
    eventsChart.update();
  }

  // -------- Attackers Table --------
  attackersTableBody.innerHTML = "";
  data.top_attackers.forEach(row => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${row.attacker}</td>
      <td>${row.count}</td>
    `;
    attackersTableBody.appendChild(tr);
  });
}
