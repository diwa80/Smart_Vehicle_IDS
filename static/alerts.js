/* ===========================================================
   ALL ALERTS PAGE SCRIPT
=========================================================== */

const alertsListEl = document.getElementById("alerts-list-full");
const backBtn = document.getElementById("back-btn");
const clearAllBtn = document.getElementById("clear-all-btn");
const exportBtn = document.getElementById("export-alerts-btn");

// Filter elements
const levelFilter = document.getElementById("level-filter");
const sourceFilter = document.getElementById("source-filter");
const sortFilter = document.getElementById("sort-filter");

// Stats
const criticalCountEl = document.getElementById("critical-count");
const warningCountEl = document.getElementById("warning-count");
const infoCountEl = document.getElementById("info-count");
const totalCountEl = document.getElementById("total-count");

// Pagination
const prevPageBtn = document.getElementById("prev-page");
const nextPageBtn = document.getElementById("next-page");
const pageInfoEl = document.getElementById("page-info");

let allAlerts = [];
let filteredAlerts = [];
let currentPage = 1;
const alertsPerPage = 20;

/* ===========================================================
   LOAD ALERTS FROM LOCALSTORAGE
=========================================================== */

function loadAlerts() {
  const stored = localStorage.getItem("alertHistory");
  if (stored) {
    try {
      allAlerts = JSON.parse(stored);
        console.log("Loaded alerts from localStorage:", allAlerts.length, "alerts");
        console.log("Sample alert:", allAlerts[0]);
    } catch (e) {
      console.error("Error loading alerts:", e);
      allAlerts = [];
    }
    } else {
      console.log("No alerts found in localStorage");
  }
  
  updateSourceFilter();
  applyFilters();
  updateStats();
}

/* ===========================================================
   UPDATE SOURCE FILTER OPTIONS
=========================================================== */

function updateSourceFilter() {
  const sources = new Set(allAlerts.map(a => a.source));
  sourceFilter.innerHTML = '<option value="all">All Sources</option>';
  
  sources.forEach(source => {
    const option = document.createElement("option");
    option.value = source;
    option.textContent = source;
    sourceFilter.appendChild(option);
  });
}

/* ===========================================================
   APPLY FILTERS AND SORTING
=========================================================== */

function applyFilters() {
  const levelValue = levelFilter.value;
  const sourceValue = sourceFilter.value;
  const sortValue = sortFilter.value;

  // Filter
  filteredAlerts = allAlerts.filter(alert => {
      const levelMatch = levelValue === "all" || alert.level.toLowerCase() === levelValue.toLowerCase();
    const sourceMatch = sourceValue === "all" || alert.source === sourceValue;
    return levelMatch && sourceMatch;
  });

  // Sort
  if (sortValue === "newest") {
    // Already in newest first order from localStorage
  } else if (sortValue === "oldest") {
    filteredAlerts.reverse();
  } else if (sortValue === "level") {
      const levelOrder = { critical: 0, high: 1, warning: 1, info: 2 };
      filteredAlerts.sort((a, b) => levelOrder[a.level.toLowerCase()] - levelOrder[b.level.toLowerCase()]);
  }

  currentPage = 1;
  renderAlerts();
}

/* ===========================================================
   RENDER ALERTS WITH PAGINATION
=========================================================== */

function renderAlerts() {
  alertsListEl.innerHTML = "";

  if (!filteredAlerts.length) {
    alertsListEl.innerHTML = '<div class="no-alerts">No alerts to display.</div>';
    updatePagination();
    return;
  }

  const startIndex = (currentPage - 1) * alertsPerPage;
  const endIndex = startIndex + alertsPerPage;
  const pageAlerts = filteredAlerts.slice(startIndex, endIndex);

  pageAlerts.forEach(alert => {
    const div = document.createElement("div");
    div.className = "alert-item-full";
    
    div.innerHTML = `
      <div class="alert-header-row">
        <div class="alert-meta">
          <span class="alert-badge ${alert.level}">${alert.level.toUpperCase()}</span>
          <span class="alert-source-full">${alert.source}</span>
        </div>
        <span class="alert-time-full">${alert.time}</span>
      </div>
      <div class="alert-message-full">${alert.message}</div>
    `;
    
    alertsListEl.appendChild(div);
  });

  updatePagination();
}

/* ===========================================================
   UPDATE PAGINATION
=========================================================== */

function updatePagination() {
  const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage) || 1;
  
  pageInfoEl.textContent = `Page ${currentPage} of ${totalPages}`;
  
  prevPageBtn.disabled = currentPage === 1;
  nextPageBtn.disabled = currentPage === totalPages || filteredAlerts.length === 0;
}

/* ===========================================================
   UPDATE STATISTICS
=========================================================== */

function updateStats() {
  const critical = allAlerts.filter(a => a.level.toLowerCase() === "critical" || a.level.toLowerCase() === "high").length;
  const warning = allAlerts.filter(a => a.level.toLowerCase() === "warning").length;
  const info = allAlerts.filter(a => a.level.toLowerCase() === "info").length;

    console.log("Stats - Critical:", critical, "Warning:", warning, "Info:", info, "Total:", allAlerts.length);

  criticalCountEl.textContent = critical;
  warningCountEl.textContent = warning;
  infoCountEl.textContent = info;
  totalCountEl.textContent = allAlerts.length;
}

/* ===========================================================
   EVENT LISTENERS
=========================================================== */

backBtn.onclick = () => {
  window.location.href = "index.html";
};

clearAllBtn.onclick = () => {
  if (confirm("Are you sure you want to clear all alerts?")) {
    localStorage.removeItem("alertHistory");
    allAlerts = [];
    applyFilters();
    updateStats();
  }
};

exportBtn.onclick = () => {
  if (!allAlerts.length) {
    alert("No alerts to export yet.");
    return;
  }

  const header = ["Level", "Source", "Message", "Time"];

  const escape = (value) => {
    if (value === undefined || value === null) return "";
    const str = String(value).replace(/"/g, '""');
    return `"${str}"`;
  };

  const rows = allAlerts.map((a) => [
    escape(a.level),
    escape(a.source),
    escape(a.message),
    escape(a.time),
  ].join(","));

  const csv = [header.join(","), ...rows].join("\n");

  const blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "alerts_export.csv";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

levelFilter.onchange = applyFilters;
sourceFilter.onchange = applyFilters;
sortFilter.onchange = applyFilters;

prevPageBtn.onclick = () => {
  if (currentPage > 1) {
    currentPage--;
    renderAlerts();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
};

nextPageBtn.onclick = () => {
  const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);
  if (currentPage < totalPages) {
    currentPage++;
    renderAlerts();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
};

/* ===========================================================
   INITIALIZE
=========================================================== */

loadAlerts();
