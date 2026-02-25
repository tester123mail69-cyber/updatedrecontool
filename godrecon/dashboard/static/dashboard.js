/**
 * GODRECON Dashboard — Comprehensive Client-Side JavaScript
 */
"use strict";

// ============================================================
// THEME
// ============================================================
function initTheme() {
  const saved = localStorage.getItem("godrecon-theme") || "dark";
  applyTheme(saved);
}
function applyTheme(theme) {
  if (theme === "light") {
    document.body.classList.add("light-mode");
    const btn = document.getElementById("themeToggle");
    if (btn) btn.textContent = "☀️";
  } else {
    document.body.classList.remove("light-mode");
    const btn = document.getElementById("themeToggle");
    if (btn) btn.textContent = "🌙";
  }
  localStorage.setItem("godrecon-theme", theme);
}
function toggleTheme() {
  const isLight = document.body.classList.contains("light-mode");
  applyTheme(isLight ? "dark" : "light");
}

// ============================================================
// SIDEBAR
// ============================================================
function initSidebar() {
  const ham = document.getElementById("hamburgerBtn");
  const sidebar = document.getElementById("sidebar");
  if (ham && sidebar) {
    ham.addEventListener("click", function() {
      sidebar.classList.toggle("open");
    });
    document.addEventListener("click", function(e) {
      if (window.innerWidth <= 768 && !sidebar.contains(e.target) && e.target !== ham) {
        sidebar.classList.remove("open");
      }
    });
  }
}
function toggleNavGroup(groupId) {
  const el = document.getElementById(groupId);
  const chevron = document.getElementById(groupId + "-chevron");
  if (!el) return;
  const open = el.style.display === "block";
  el.style.display = open ? "none" : "block";
  if (chevron) chevron.style.transform = open ? "rotate(0deg)" : "rotate(90deg)";
}

// ============================================================
// NOTIFICATIONS
// ============================================================
let _notifications = [];

function initNotifications() {
  const btn = document.getElementById("notifBtn");
  const panel = document.getElementById("notifPanel");
  if (!btn || !panel) return;
  btn.addEventListener("click", function(e) {
    e.stopPropagation();
    panel.classList.toggle("open");
  });
  document.addEventListener("click", function(e) {
    if (!panel.contains(e.target) && e.target !== btn) panel.classList.remove("open");
  });
  loadNotifications();
}

function loadNotifications() {
  fetch("/dashboard/api/notifications")
    .then(r => r.ok ? r.json() : { notifications: [] })
    .then(data => {
      _notifications = data.notifications || [];
      renderNotifications();
    })
    .catch(() => {});
}

function renderNotifications() {
  const list = document.getElementById("notifList");
  const badge = document.getElementById("notifCount");
  if (!list) return;
  const unread = _notifications.filter(n => !n.read).length;
  if (badge) badge.textContent = unread > 0 ? unread : "0";
  if (badge) badge.style.display = unread > 0 ? "flex" : "none";
  if (_notifications.length === 0) {
    list.innerHTML = '<div class="notif-item"><div class="notif-item-title text-muted">No notifications</div></div>';
    return;
  }
  list.innerHTML = _notifications.slice(0, 20).map(n => `
    <div class="notif-item ${n.read ? '' : 'unread'}" onclick="markNotifRead('${n.id}')">
      <div class="notif-item-title">${escHtml(n.title)}</div>
      <div class="notif-item-time">${n.time || ''}</div>
    </div>
  `).join("");
}

function markNotifRead(id) {
  _notifications = _notifications.map(n => n.id === id ? { ...n, read: true } : n);
  renderNotifications();
}

function markAllRead() {
  _notifications = _notifications.map(n => ({ ...n, read: true }));
  renderNotifications();
}

function addNotification(title, type) {
  const n = { id: Date.now().toString(), title, type: type || "info", read: false, time: new Date().toLocaleTimeString() };
  _notifications.unshift(n);
  renderNotifications();
  showToast(title, type || "info");
}

// ============================================================
// TOAST
// ============================================================
function showToast(message, type, duration) {
  type = type || "info";
  duration = duration || 3500;
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const icons = { success: "✅", error: "❌", warning: "⚠️", info: "ℹ️" };
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${escHtml(message)}</span><button class="toast-close" onclick="this.parentElement.remove()">✕</button>`;
  container.appendChild(toast);
  setTimeout(() => { if (toast.parentElement) toast.remove(); }, duration);
}

// ============================================================
// GLOBAL SEARCH
// ============================================================
const SEARCH_PAGES = [
  { icon: "🏠", title: "Dashboard", sub: "Overview", url: "/dashboard/" },
  { icon: "🎯", title: "Targets", sub: "Manage scan targets", url: "/dashboard/targets" },
  { icon: "🔍", title: "Subdomains", sub: "Subdomain enumeration results", url: "/dashboard/subdomains" },
  { icon: "🐛", title: "Vulnerabilities", sub: "All findings", url: "/dashboard/vulnerabilities" },
  { icon: "⛓️", title: "Vuln Chains", sub: "Chained vulnerabilities", url: "/dashboard/chains" },
  { icon: "🔑", title: "Secrets", sub: "Discovered secrets", url: "/dashboard/secrets" },
  { icon: "📋", title: "Kanban Board", sub: "Bug tracking board", url: "/dashboard/kanban" },
  { icon: "📊", title: "Reports", sub: "Generate and download reports", url: "/dashboard/reports" },
  { icon: "📈", title: "Analytics", sub: "Charts and insights", url: "/dashboard/analytics" },
  { icon: "🤖", title: "AI Validation", sub: "AI-powered finding validation", url: "/dashboard/ai-validation" },
  { icon: "🎯", title: "Bounty Matcher", sub: "Bug bounty program matching", url: "/dashboard/bounty-matcher" },
  { icon: "🏆", title: "Leaderboard", sub: "Stats and rankings", url: "/dashboard/leaderboard" },
  { icon: "📋", title: "Activity Log", sub: "All actions log", url: "/dashboard/activity-log" },
  { icon: "🔔", title: "Alerts", sub: "Notification configuration", url: "/dashboard/alerts" },
  { icon: "⚙️", title: "Settings", sub: "API keys and config", url: "/dashboard/settings" },
  { icon: "🔬", title: "Nuclei Scanner", sub: "Nuclei vulnerability scan results", url: "/dashboard/scanners/nuclei" },
  { icon: "☁️", title: "Cloud Misconfig", sub: "Cloud misconfiguration results", url: "/dashboard/scanners/cloud" },
  { icon: "🌐", title: "DNS Analysis", sub: "DNS scan results", url: "/dashboard/scanners/dns" },
  { icon: "🔒", title: "SSL/TLS", sub: "SSL/TLS scan results", url: "/dashboard/scanners/ssl" },
  { icon: "👻", title: "Passive Recon", sub: "Passive reconnaissance results", url: "/dashboard/scanners/passive-recon" },
  { icon: "📜", title: "Wayback Machine", sub: "Historical URL analysis", url: "/dashboard/scanners/wayback" },
  { icon: "🐙", title: "GitHub Dorking", sub: "GitHub secret scanning", url: "/dashboard/scanners/github-dorking" },
  { icon: "🗂", title: "Scan History", sub: "All scans", url: "/dashboard/scans" },
];

function openSearchModal() {
  const overlay = document.getElementById("searchModalOverlay");
  const input = document.getElementById("searchModalInput");
  if (!overlay) return;
  overlay.classList.add("open");
  if (input) { input.value = ""; input.focus(); renderSearchResults(""); }
}
function closeSearchModal(e) {
  if (e && e.target !== document.getElementById("searchModalOverlay")) return;
  document.getElementById("searchModalOverlay")?.classList.remove("open");
}
function renderSearchResults(q) {
  const container = document.getElementById("searchModalResults");
  if (!container) return;
  const results = q
    ? SEARCH_PAGES.filter(p => p.title.toLowerCase().includes(q.toLowerCase()) || p.sub.toLowerCase().includes(q.toLowerCase()))
    : SEARCH_PAGES.slice(0, 8);
  if (results.length === 0) {
    container.innerHTML = '<div class="search-result-item text-muted">No results found</div>';
    return;
  }
  container.innerHTML = results.map(r => `
    <div class="search-result-item" onclick="window.location='${r.url}'">
      <span class="search-result-icon">${r.icon}</span>
      <div>
        <div class="search-result-title">${escHtml(r.title)}</div>
        <div class="search-result-sub">${escHtml(r.sub)}</div>
      </div>
    </div>
  `).join("");
}

function initSearch() {
  const input = document.getElementById("searchModalInput");
  if (input) {
    input.addEventListener("input", () => renderSearchResults(input.value));
    input.addEventListener("keydown", e => {
      if (e.key === "Escape") document.getElementById("searchModalOverlay")?.classList.remove("open");
    });
  }
  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") { e.preventDefault(); openSearchModal(); }
    if (e.key === "Escape") document.getElementById("searchModalOverlay")?.classList.remove("open");
  });
}

// ============================================================
// TABLE UTILS
// ============================================================
function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  const table = document.getElementById(tableId);
  if (!input || !table) return;
  input.addEventListener("input", function() {
    const q = this.value.toLowerCase();
    table.querySelectorAll("tbody tr:not(.row-detail)").forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
    });
  });
}

function makeSortable(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  table.querySelectorAll("th.sortable").forEach((th, idx) => {
    th.addEventListener("click", function() {
      const dir = this.classList.contains("sort-asc") ? -1 : 1;
      table.querySelectorAll("th").forEach(t => t.classList.remove("sort-asc", "sort-desc"));
      this.classList.add(dir === 1 ? "sort-asc" : "sort-desc");
      const tbody = table.querySelector("tbody");
      const rows = Array.from(tbody.querySelectorAll("tr:not(.row-detail)"));
      rows.sort((a, b) => {
        const at = (a.cells[idx]?.textContent || "").trim();
        const bt = (b.cells[idx]?.textContent || "").trim();
        const an = parseFloat(at), bn = parseFloat(bt);
        if (!isNaN(an) && !isNaN(bn)) return (an - bn) * dir;
        return at.localeCompare(bt) * dir;
      });
      rows.forEach(r => tbody.appendChild(r));
    });
  });
}

function setupExpandableRows(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  table.querySelectorAll("tr.row-expandable").forEach(row => {
    row.addEventListener("click", function() {
      const next = this.nextElementSibling;
      if (next && next.classList.contains("row-detail")) next.classList.toggle("open");
    });
  });
}

// ============================================================
// AUTO-REFRESH
// ============================================================
function setupAutoRefresh(intervalMs) {
  intervalMs = intervalMs || 5000;
  const hasActive = document.querySelector(".status-running, .status-pending");
  if (hasActive) setTimeout(() => location.reload(), intervalMs);
}

// ============================================================
// API HELPERS
// ============================================================
async function apiGet(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function apiPost(url, data) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${r.status}`); }
  return r.json();
}
async function apiDelete(url) {
  const r = await fetch(url, { method: "DELETE" });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json().catch(() => ({}));
}

// ============================================================
// SCAN START
// ============================================================
async function startScan(target, mode, statusEl) {
  if (!target) { showToast("Please enter a target", "warning"); return null; }
  if (statusEl) { statusEl.textContent = "Starting scan…"; statusEl.style.color = "var(--text-muted)"; }
  try {
    const data = await apiPost("/api/v1/scan", { target, scan_mode: mode || "standard" });
    if (statusEl) { statusEl.textContent = `Scan started! ID: ${data.scan_id}`; statusEl.style.color = "var(--green)"; }
    addNotification(`Scan started for ${target}`, "info");
    showToast(`Scan started for ${target}`, "success");
    return data;
  } catch (err) {
    if (statusEl) { statusEl.textContent = `Error: ${err.message}`; statusEl.style.color = "var(--red)"; }
    showToast(`Scan error: ${err.message}`, "error");
    return null;
  }
}

// ============================================================
// EXPORT UTILS
// ============================================================
function exportTableCSV(tableId, filename) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = [];
  table.querySelectorAll("tr").forEach(row => {
    const cells = Array.from(row.querySelectorAll("th, td")).map(c => `"${c.textContent.trim().replace(/"/g, '""')}"`);
    rows.push(cells.join(","));
  });
  downloadFile(rows.join("\n"), filename || "export.csv", "text/csv");
}
function exportJSON(data, filename) {
  downloadFile(JSON.stringify(data, null, 2), filename || "export.json", "application/json");
}
function downloadFile(content, filename, mime) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast("Copied!", "success")).catch(() => showToast("Failed to copy", "error"));
}

// ============================================================
// TABS
// ============================================================
function initTabs(containerId) {
  const container = document.getElementById(containerId) || document;
  container.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", function() {
      const target = this.dataset.tab;
      const parent = this.closest(".tabs-container") || container;
      parent.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      parent.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      this.classList.add("active");
      const content = document.getElementById(target);
      if (content) content.classList.add("active");
    });
  });
}

// ============================================================
// MODAL
// ============================================================
function openModal(id) {
  document.getElementById(id)?.classList.add("open");
}
function closeModal(id) {
  document.getElementById(id)?.classList.remove("open");
}
function initModalClose() {
  document.querySelectorAll(".modal-overlay").forEach(overlay => {
    overlay.addEventListener("click", function(e) {
      if (e.target === this) this.classList.remove("open");
    });
  });
  document.querySelectorAll("[data-modal-close]").forEach(btn => {
    btn.addEventListener("click", function() {
      this.closest(".modal-overlay")?.classList.remove("open");
    });
  });
}

// ============================================================
// SEVERITY FILTER
// ============================================================
function filterBySeverity(tableId, sev) {
  const table = document.getElementById(tableId);
  if (!table) return;
  table.querySelectorAll("tbody tr:not(.row-detail)").forEach(row => {
    if (!sev) { row.style.display = ""; return; }
    const badge = row.querySelector(".badge");
    const rowSev = badge ? badge.textContent.trim().toLowerCase() : "";
    row.style.display = rowSev.includes(sev.toLowerCase()) ? "" : "none";
  });
}

// ============================================================
// KANBAN DRAG & DROP (native HTML5)
// ============================================================
let _draggedCard = null;

function initKanban() {
  document.querySelectorAll(".kanban-card").forEach(card => {
    card.setAttribute("draggable", "true");
    card.addEventListener("dragstart", function(e) {
      _draggedCard = this;
      this.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
    });
    card.addEventListener("dragend", function() {
      this.classList.remove("dragging");
      _draggedCard = null;
      document.querySelectorAll(".kanban-cards").forEach(col => col.classList.remove("drag-over"));
    });
  });
  document.querySelectorAll(".kanban-cards").forEach(col => {
    col.addEventListener("dragover", function(e) {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      this.classList.add("drag-over");
    });
    col.addEventListener("dragleave", function() {
      this.classList.remove("drag-over");
    });
    col.addEventListener("drop", function(e) {
      e.preventDefault();
      this.classList.remove("drag-over");
      if (_draggedCard && _draggedCard.parentElement !== this) {
        this.appendChild(_draggedCard);
        updateKanbanColCounts();
        saveKanbanState();
      }
    });
  });
}

function updateKanbanColCounts() {
  document.querySelectorAll(".kanban-col").forEach(col => {
    const count = col.querySelectorAll(".kanban-card").length;
    const badge = col.querySelector(".col-count");
    if (badge) badge.textContent = count;
  });
}

function saveKanbanState() {
  const state = {};
  document.querySelectorAll(".kanban-col").forEach(col => {
    const colId = col.dataset.col;
    state[colId] = Array.from(col.querySelectorAll(".kanban-card")).map(c => c.dataset.id);
  });
  fetch("/dashboard/api/kanban", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state })
  }).catch(() => {});
}

// ============================================================
// SCAN STATS LOADER
// ============================================================
async function loadScanStats() {
  try {
    const data = await apiGet("/dashboard/api/scan-stats");
    return data;
  } catch (e) {
    return null;
  }
}

// ============================================================
// SSE LIVE TERMINAL
// ============================================================
function initSSETerminal(scanId, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const es = new EventSource(`/dashboard/api/scan-stream/${scanId}`);
  es.onmessage = function(e) {
    const line = document.createElement("div");
    line.className = "terminal-line";
    try {
      const data = JSON.parse(e.data);
      line.className += " " + (data.type || "info");
      line.textContent = data.message || e.data;
    } catch {
      line.textContent = e.data;
    }
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
  };
  es.onerror = function() { es.close(); };
  return es;
}

// ============================================================
// CHART HELPERS (Chart.js)
// ============================================================
function createSeverityChart(canvasId, counts) {
  if (typeof Chart === "undefined") return;
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  return new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low", "Info"],
      datasets: [{
        data: [counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, counts.info || 0],
        backgroundColor: ["#f85149", "#e3b341", "#d29922", "#58a6ff", "#484f58"],
        borderColor: "transparent",
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue("--text") || "#e6edf3" } } }
    }
  });
}

function createTimelineChart(canvasId, labels, datasets) {
  if (typeof Chart === "undefined") return;
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const textColor = getComputedStyle(document.documentElement).getPropertyValue("--text-muted") || "#8b949e";
  return new Chart(ctx, {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: textColor } } },
      scales: {
        x: { ticks: { color: textColor }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: textColor }, grid: { color: "rgba(255,255,255,0.05)" } }
      }
    }
  });
}

function createBarChart(canvasId, labels, data, label) {
  if (typeof Chart === "undefined") return;
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const textColor = getComputedStyle(document.documentElement).getPropertyValue("--text-muted") || "#8b949e";
  return new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: label || "Count", data, backgroundColor: "rgba(88,166,255,0.5)", borderColor: "#58a6ff", borderWidth: 1 }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: textColor } } },
      scales: {
        x: { ticks: { color: textColor }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { ticks: { color: textColor }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true }
      }
    }
  });
}

// ============================================================
// UTILS
// ============================================================
function escHtml(s) {
  if (!s) return "";
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function severityClass(s) {
  s = (s || "").toLowerCase();
  if (s === "critical") return "badge-critical";
  if (s === "high") return "badge-high";
  if (s === "medium") return "badge-medium";
  if (s === "low") return "badge-low";
  return "badge-info";
}
function formatDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}
function relativeTime(iso) {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
function debounce(fn, delay) {
  let timer;
  return function(...args) { clearTimeout(timer); timer = setTimeout(() => fn.apply(this, args), delay); };
}

// ============================================================
// QUICK SCAN (index page)
// ============================================================
function initQuickScan() {
  const form = document.getElementById("quick-scan-form");
  if (!form) return;
  form.addEventListener("submit", async function(e) {
    e.preventDefault();
    const targetEl = document.getElementById("qs-target");
    const modeEl = document.getElementById("qs-mode");
    const statusEl = document.getElementById("qs-status");
    const target = targetEl?.value.trim() || "";
    const mode = modeEl?.value || "standard";
    if (!target) { showToast("Please enter a target", "warning"); return; }
    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    const data = await startScan(target, mode, statusEl);
    if (data && data.scan_id) {
      setTimeout(() => window.location.href = "/dashboard/scans/" + data.scan_id, 1500);
    }
    if (btn) btn.disabled = false;
  });
}

// ============================================================
// INIT
// ============================================================
document.addEventListener("DOMContentLoaded", function() {
  initTheme();
  initSidebar();
  initNotifications();
  initSearch();
  initTabs();
  initModalClose();
  initQuickScan();
  setupAutoRefresh();

  // Theme toggle
  const themeBtn = document.getElementById("themeToggle");
  if (themeBtn) themeBtn.addEventListener("click", toggleTheme);

  // Kanban (if present)
  if (document.querySelector(".kanban-board")) initKanban();

  // Sortable tables
  document.querySelectorAll("table[data-sortable]").forEach(t => makeSortable(t.id));

  // Expandable rows
  document.querySelectorAll("table[data-expandable]").forEach(t => setupExpandableRows(t.id));
});

// Expose globals
window.GODRECON = {
  showToast, openModal, closeModal, toggleNavGroup, filterTable, makeSortable,
  filterBySeverity, exportTableCSV, exportJSON, copyToClipboard,
  createSeverityChart, createTimelineChart, createBarChart,
  startScan, apiGet, apiPost, apiDelete, loadScanStats, initSSETerminal,
  relativeTime, formatDate, escHtml, severityClass, debounce, openSearchModal
};
