/* ===========================================================
   GLOBAL ELEMENTS
=========================================================== */

// Telemetry
const speedEl = document.getElementById("speed-value");
const brakeStatusEl = document.getElementById("brake-status");
const anomalyScoreEl = document.getElementById("anomaly-score");
const anomalyBarFillEl = document.getElementById("anomaly-bar-fill");
const lastUpdateEl = document.getElementById("last-update");

// ECU & Heatmap
const ecuHealthListEl = document.getElementById("ecu-health-list");
const heatmapGridEl = document.getElementById("heatmap-grid");

// Alerts
const alertsListEl = document.getElementById("alerts-list");
const clearAlertsBtn = document.getElementById("clear-alerts-btn");

// Attack Controls
const attackButtons = document.querySelectorAll(".attack-btn");
const stopAttackBtn = document.getElementById("attack-toggle-btn");
const systemStatusText = document.getElementById("system-status-text");

// CAN Table
const canTableBody = document.getElementById("can-table-body");
const canRateEl = document.getElementById("can-rate");
let canHistory = [];

// Analytics Overview
const ecuChartCanvas = document.getElementById("ecu-chart");
const typeChartCanvas = document.getElementById("type-chart");
const eventsChartCanvas = document.getElementById("events-chart");
const attackersTableBody = document.getElementById("attackers-table-body");

// Dashboard Layout
const rootEl = document.getElementById("app");

// State
let alertHistory = [];
let currentAttackMode = null;

// ⭐ POPUPS ONLY WHEN MANUAL ATTACK ENABLED
let alertsEnabled = false;


/* ===========================================================
   TELEMETRY LOOP
=========================================================== */

async function fetchTelemetry() {
  try {
    const res = await fetch("/api/telemetry");
    const data = await res.json();

    updateDashboard(data);
    systemStatusText.textContent = "Live";
  } catch (err) {
    console.error("Telemetry Error:", err);
    systemStatusText.textContent = "Offline";
  }
}

fetchTelemetry();
setInterval(fetchTelemetry, 1000);


/* ===========================================================
   UPDATE DASHBOARD
=========================================================== */

function updateDashboard(data) {
  speedEl.textContent = data.speed;
  brakeStatusEl.textContent = data.brake_status;
  brakeStatusEl.style.color =
    data.brake_status === "ON" ? "#f97316" : "#10b981";

  const score = data.can_anomaly_score ?? 0;
  anomalyScoreEl.textContent = score.toFixed(2);
  anomalyBarFillEl.style.width = `${score * 100}%`;

  lastUpdateEl.textContent = data.timestamp || "--";

  if (data.attack_active) rootEl.classList.add("attack-active");
  else rootEl.classList.remove("attack-active");

  currentAttackMode = data.attack_mode;
  syncAttackButtons();

  renderEcuHealth(data.ecu_health);
  renderHeatmap(data.heatmap);

  if (data.security_alerts?.length) {
    addAlerts(data.security_alerts);
  }

  if (alertsEnabled && data.security_alerts?.length) {
    data.security_alerts.forEach((a) =>
      showPopupAlert(a.level, a.message)
    );
  }

  updateCanPackets(data.can_packets);
  updateTimeline(score, data.attack_active);
}


/* ===========================================================
   ECU HEALTH
=========================================================== */

function renderEcuHealth(ecu) {
  ecuHealthListEl.innerHTML = "";

  Object.entries(ecu).forEach(([name, val]) => {
    const pct = Math.round(val * 100);

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


/* ===========================================================
   HEATMAP
=========================================================== */

function renderHeatmap(map) {
  heatmapGridEl.innerHTML = "";

  map.forEach((h) => {
    const div = document.createElement("div");
    div.className = `heatmap-cell ${h.status}`;
    div.textContent = h.name;
    heatmapGridEl.appendChild(div);
  });
}


/* ===========================================================
   ALERT TABLE
=========================================================== */

function addAlerts(alerts) {
  const time = new Date().toLocaleTimeString("en-GB", { hour12: false });

  alerts.forEach((a) => {
    alertHistory.unshift({
      source: a.source,
      level: a.level,
      message: a.message,
      time,
    });
  });

  alertHistory = alertHistory.slice(0, 50);
  renderAlerts();
}

function renderAlerts() {
  alertsListEl.innerHTML = "";

  if (!alertHistory.length) {
    alertsListEl.innerHTML =
      `<p style="color:#9ca3af;">No alerts yet.</p>`;
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

clearAlertsBtn.onclick = () => {
  alertHistory = [];
  renderAlerts();
};


/* ===========================================================
   CAN PACKETS
=========================================================== */

function updateCanPackets(pkts) {
  pkts.forEach((p) => {
    canHistory.unshift({
      timestamp: p.timestamp,
      ecu: p.ecu,
      signal: p.signal,
      value: p.value,
      anomaly: p.anomaly,
    });
  });

  canHistory = canHistory.slice(0, 150);
  renderCanTable();

  canRateEl.textContent = pkts.length + " signals/s";
}

function renderCanTable() {
  canTableBody.innerHTML = "";

  canHistory.forEach((p) => {
    const tr = document.createElement("tr");
    if (p.anomaly) tr.classList.add("can-row-anomaly");

    tr.innerHTML = `
      <td>${p.timestamp}</td>
      <td>${p.ecu}</td>
      <td>${p.signal || "-"}</td>
      <td>${p.value || "-"}</td>
      <td>${p.anomaly ? "Yes" : "No"}</td>
    `;
    canTableBody.appendChild(tr);
  });
}


/* ===========================================================
   TIMELINE CHART
=========================================================== */

const timelineCtx = document
  .getElementById("attackTimelineChart")
  .getContext("2d");

let anomalyTimeline = [];
let attackTimeline = [];

let timelineChart = new Chart(timelineCtx, {
  type: "line",
  data: {
    labels: [],
    datasets: [
      {
        label: "Anomaly Score",
        data: [],
        borderColor: "#4ade80",
        backgroundColor: "rgba(74,222,128,0.2)",
        tension: 0.3,
        borderWidth: 2,
        fill: true,
      },
      {
        label: "Attack",
        data: [],
        type: "bar",
        backgroundColor: "rgba(239,68,68,0.25)",
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: { x: { display: false }, y: { min: 0, max: 1 } },
  },
});

function updateTimeline(score, atk) {
  const MAX = 60;

  anomalyTimeline.push(score);
  attackTimeline.push(atk ? 1 : 0);

  if (anomalyTimeline.length > MAX) anomalyTimeline.shift();
  if (attackTimeline.length > MAX) attackTimeline.shift();

  timelineChart.data.labels = anomalyTimeline.map((_, i) => i);
  timelineChart.data.datasets[0].data = anomalyTimeline;
  timelineChart.data.datasets[1].data = attackTimeline;

  timelineChart.update();
}


/* ===========================================================
   ATTACK MODE (MANUAL ONLY)
=========================================================== */

async function setAttackMode(mode) {
  try {
    await fetch("/api/attack_mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode || "off" }),
    });

    currentAttackMode = mode || null;
    alertsEnabled = Boolean(mode);

    if (!mode) {
      document.getElementById("popup-alert-container").innerHTML = "";
    }

    syncAttackButtons();
  } catch (e) {
    console.error("AttackMode Error:", e);
  }
}

attackButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const mode = btn.getAttribute("data-attack");

    if (currentAttackMode === mode) setAttackMode(null);
    else setAttackMode(mode);
  });
});

stopAttackBtn.onclick = () => setAttackMode(null);

function syncAttackButtons() {
  attackButtons.forEach((btn) =>
    btn.classList.toggle(
      "active",
      btn.getAttribute("data-attack") === currentAttackMode
    )
  );

  stopAttackBtn.textContent = currentAttackMode
    ? "Stop Attack"
    : "No Attack Active";
}


/* ===========================================================
   ANALYTICS (FULLY WORKING)
=========================================================== */

let ecuChart = null;
let typeChart = null;
let eventsChart = null;

async function fetchAnalytics() {
  try {
    const res = await fetch("/api/analytics");
    const data = await res.json();
    updateAnalytics(data);
  } catch (err) {
    console.error("Analytics Error:", err);
  }
}

fetchAnalytics();
setInterval(fetchAnalytics, 5000);

function updateAnalytics(data) {
  /* ---------- ECU CHART ---------- */
  const ecuLabels = data.top_ecu_targets.map((e) => e.ecu);
  const ecuCounts = data.top_ecu_targets.map((e) => e.count);

  if (ecuChart) ecuChart.destroy();
  ecuChart = new Chart(ecuChartCanvas, {
    type: "bar",
    data: {
      labels: ecuLabels,
      datasets: [
        {
          label: "ECU Attack Count",
          data: ecuCounts,
          backgroundColor: "#4ade80",
        },
      ],
    },
  });

  /* ---------- ATTACK TYPE CHART ---------- */
  const typeLabels = data.top_attack_types.map((e) => e.type);
  const typeCounts = data.top_attack_types.map((e) => e.count);

  if (typeChart) typeChart.destroy();
  typeChart = new Chart(typeChartCanvas, {
    type: "bar",
    data: {
      labels: typeLabels,
      datasets: [
        {
          label: "Attack Type Count",
          data: typeCounts,
          backgroundColor: "#60a5fa",
        },
      ],
    },
  });

  /* ---------- TOP ATTACKERS TABLE ---------- */
  attackersTableBody.innerHTML = "";
  data.top_attackers.forEach((a) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.attacker}</td>
      <td>${a.count}</td>
    `;
    attackersTableBody.appendChild(tr);
  });

  /* ---------- ALERT VOLUME GRAPH (WORKING) ---------- */
  const labels = data.events_timeline.map((e) =>
    e.timestamp.slice(11, 19)
  );

  const totalAlerts = data.events_timeline.map((e) => e.total_alerts);
  const criticalAlerts = data.events_timeline.map(
    (e) => e.critical_alerts
  );

  if (eventsChart) eventsChart.destroy();

  eventsChart = new Chart(eventsChartCanvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Total Alerts",
          data: totalAlerts,
          borderColor: "#f87171",
          backgroundColor: "rgba(248,113,113,0.3)",
          tension: 0.35,
          borderWidth: 2,
          fill: true,
        },
        {
          label: "Critical Alerts",
          data: criticalAlerts,
          borderColor: "#ef4444",
          backgroundColor: "rgba(239,68,68,0.35)",
          tension: 0.35,
          borderWidth: 2,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#eee" } } },
      scales: {
        x: { ticks: { color: "#ccc" } },
        y: { beginAtZero: true, ticks: { color: "#ccc" } },
      },
    },
  });
}


/* ===========================================================
   POPUP ALERTS WITH FADE-OUT
=========================================================== */

function showPopupAlert(level, message) {
  if (!alertsEnabled) return;

  const container = document.getElementById("popup-alert-container");
  const div = document.createElement("div");

  div.className = "popup-alert";
  if (level === "CRITICAL") div.classList.add("popup-critical");
  if (level === "HIGH") div.classList.add("popup-high");

  div.innerHTML = `
    <strong>${level}</strong><br>${message}
    <button class="alert-close">&times;</button>
  `;

  container.appendChild(div);

  // close manually
  div.querySelector(".alert-close").onclick = () => {
    div.classList.add("popup-hide");
    setTimeout(() => div.remove(), 600);
  };

  // auto remove
  setTimeout(() => {
    div.classList.add("popup-hide");
    setTimeout(() => div.remove(), 600);
  }, 5000);
}


// Feedback

// OPEN FEEDBACK MODAL
document.getElementById("feedback-btn").onclick = () => {
    document.getElementById("feedback-modal").style.display = "block";
};

// CLOSE MODAL
document.getElementById("close-feedback").onclick = () => {
    document.getElementById("feedback-modal").style.display = "none";
};