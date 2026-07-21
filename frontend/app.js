// Relative on purpose: the backend now serves this dashboard itself (see the
// StaticFiles mount at the bottom of backend/main.py), so API calls are
// always same-origin -- no CORS, and it works unchanged whether this is
// running locally or deployed to a free host under any domain.
const API_BASE = "";

const el = {
  bootOverlay: document.getElementById("boot-overlay"),
  bootFill: document.getElementById("boot-fill"),
  bootLabel: document.getElementById("boot-label"),
  statusDot: document.getElementById("status-dot"),
  statusText: document.getElementById("status-text"),
  metricAuc: document.getElementById("metric-auc"),
  metricPrec: document.getElementById("metric-prec"),
  metricPrecBack: document.getElementById("metric-prec-back"),
  metricRec: document.getElementById("metric-rec"),
  metricUnseen: document.getElementById("metric-unseen"),
  ifaceSelect: document.getElementById("iface-select"),
  captureToggleBtn: document.getElementById("capture-toggle-btn"),
  captureStatus: document.getElementById("capture-status"),
  liveFeedTbody: document.getElementById("live-feed-tbody"),
  liveEmptyRow: document.getElementById("live-empty-row"),
  detailContent: document.getElementById("detail-content"),
  pulseCanvas: document.getElementById("pulse-canvas"),
  dropzone: document.getElementById("dropzone"),
  pcapInput: document.getElementById("pcap-input"),
  uploadBtn: document.getElementById("upload-btn"),
  simulateBtn: document.getElementById("simulate-attack-btn"),
  analyzeResult: document.getElementById("analyze-result"),
  pipelineRow: document.getElementById("pipeline-row"),
  alertBellBtn: document.getElementById("alert-bell-btn"),
  alertBadge: document.getElementById("alert-badge"),
  alertPanel: document.getElementById("alert-panel"),
  alertPanelList: document.getElementById("alert-panel-list"),
  alertPanelCount: document.getElementById("alert-panel-count"),
  alertDetailPage: document.getElementById("alert-detail-page"),
  alertDetailBack: document.getElementById("alert-detail-back"),
  alertModalTitle: document.getElementById("alert-modal-title"),
  alertModalBody: document.getElementById("alert-modal-body"),
  blockedBellBtn: document.getElementById("blocked-bell-btn"),
  blockedBadge: document.getElementById("blocked-badge"),
  blockedPanel: document.getElementById("blocked-panel"),
  blockedPanelList: document.getElementById("blocked-panel-list"),
  blockedPanelCount: document.getElementById("blocked-panel-count"),
  statPps: document.getElementById("stat-pps"),
  statScored: document.getElementById("stat-scored"),
  statFlagged: document.getElementById("stat-flagged"),
  statHighrisk: document.getElementById("stat-highrisk"),
  pulseStatLine: document.getElementById("pulse-stat-line"),
  bfObserved: document.getElementById("bf-observed"),
  bfMax: document.getElementById("bf-max"),
  bfTriggered: document.getElementById("bf-triggered"),
  settingsBellBtn: document.getElementById("settings-bell-btn"),
  settingsPanel: document.getElementById("settings-panel"),
  desktopNotifToggle: document.getElementById("desktop-notif-toggle"),
  webhookUrlInput: document.getElementById("webhook-url-input"),
  webhookEnabledToggle: document.getElementById("webhook-enabled-toggle"),
  webhookTestBtn: document.getElementById("webhook-test-btn"),
  webhookSaveBtn: document.getElementById("webhook-save-btn"),
  webhookStatus: document.getElementById("webhook-status"),
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ============================== Session-wide real-time stats ============================== */
const ALERT_THRESHOLD = 70;
const AUTH_SERVICES = new Set(["ftp", "ssh", "telnet"]);

const sessionStats = { scored: 0, flagged: 0, bruteforceTriggered: 0, authObserved: 0, authMax: 0 };
const alertState = { items: [], unread: 0, open: false };
const ppsTracker = { lastCount: null, lastTime: null, pps: 0 };

function isBruteforceItem(item) {
  return item.reasons && item.reasons.some((r) => r.includes("brute-force"));
}

function updateStatDom() {
  el.statScored.textContent = sessionStats.scored.toLocaleString();
  el.statFlagged.textContent = sessionStats.flagged.toLocaleString();
  el.statHighrisk.textContent = alertState.items.length.toLocaleString();
  el.bfObserved.textContent = sessionStats.authObserved.toLocaleString();
  el.bfMax.textContent = sessionStats.authMax.toLocaleString();
  el.bfTriggered.textContent = sessionStats.bruteforceTriggered.toLocaleString();
}

function getRemediationSteps(item) {
  const reasonText = (item.reasons || []).join(" ");
  const steps = [];
  if (reasonText.includes("brute-force")) {
    steps.push(
      "Block or rate-limit the source IP at the firewall for the affected port.",
      "Enforce account lockout / MFA on the target auth service (ftp/ssh/telnet).",
      "Rotate credentials for that service if any attempt may have succeeded.",
      "Review auth logs on the destination host for the exact time window."
    );
  }
  if (reasonText.includes("SYN error") || reasonText.includes("SYN flood")) {
    steps.push(
      "Enable SYN cookies on the target host to absorb the flood.",
      "Rate-limit new connections per source at the firewall/load balancer.",
      "Verify the targeted service is still responsive to legitimate traffic."
    );
  }
  if (reasonText.includes("connection count")) {
    steps.push("Rate-limit or temporarily block the source — this volume is well outside normal baseline.");
  }
  if (reasonText.includes("scan-like") || reasonText.includes("many services")) {
    steps.push(
      "Block the source IP — this pattern matches port-scanning behavior.",
      "Audit which ports on this host actually need to be externally reachable.",
      "Check firewall/IDS logs for a broader campaign from the same source range."
    );
  }
  if (steps.length === 0) {
    steps.push(
      "Correlate this connection with logs on the destination host around this timestamp.",
      "Compare against this source's historical baseline before acting.",
      "Low-confidence statistical flag — monitor rather than block unless it recurs."
    );
  }
  // de-duplicate while preserving order
  return [...new Set(steps)];
}

function renderAlertPanel() {
  el.alertPanelCount.textContent = alertState.items.length;
  if (alertState.items.length === 0) {
    el.alertPanelList.innerHTML = `<div class="alert-empty">No high-risk anomalies yet — this fills in from live capture and pcap analysis (score ≥ ${ALERT_THRESHOLD}), not the simulated demo feed.</div>`;
    return;
  }
  el.alertPanelList.innerHTML = alertState.items
    .map((item, i) => {
      const verdict = riskVerdict(item);
      return `
        <div class="alert-item" data-idx="${i}">
          <div class="alert-item-score">${item.risk_score.toFixed(0)}</div>
          <div class="alert-item-body">
            <div class="alert-item-title">${item.src_ip || "—"} → ${item.service}${item.dst_port != null ? " :" + item.dst_port : ""}</div>
            <div class="alert-item-sub">${verdict.label} · ${new Date(item._seenAt).toLocaleTimeString("en-GB")}</div>
          </div>
        </div>
      `;
    })
    .join("");
  el.alertPanelList.querySelectorAll(".alert-item").forEach((row) => {
    row.addEventListener("click", () => openAlertModal(alertState.items[Number(row.dataset.idx)]));
  });
}

/* Blocked IP is a real, hard-to-reverse system change (adds a Windows Firewall
   rule) -- everything here requires an explicit click + a confirm() dialog
   naming the exact IP, never happens automatically off a risk score alone. */
const blockedState = { items: [], open: false };
const NEVER_BLOCK = new Set(["0.0.0.0", "255.255.255.255", "127.0.0.1", "::1", "::"]);

function isBlockable(ip) {
  return !!ip && ip !== "—" && !NEVER_BLOCK.has(ip);
}

async function loadBlockedIps() {
  try {
    const res = await fetch(`${API_BASE}/firewall/blocked`);
    const data = await res.json();
    blockedState.items = data.blocked;
    renderBlockedPanel();
  } catch (e) {
    // backend unreachable; leave last known list displayed
  }
}

function renderBlockedPanel() {
  el.blockedPanelCount.textContent = blockedState.items.length;
  el.blockedBadge.textContent = blockedState.items.length;
  el.blockedBadge.style.display = blockedState.items.length > 0 ? "flex" : "none";
  if (blockedState.items.length === 0) {
    el.blockedPanelList.innerHTML = `<div class="alert-empty">Nothing blocked yet. Block an IP from an alert's detail view.</div>`;
    return;
  }
  el.blockedPanelList.innerHTML = blockedState.items
    .map(
      (b) => `
      <div class="alert-item blocked-item">
        <div class="alert-item-score">✕</div>
        <div class="alert-item-body">
          <div class="alert-item-title">${b.ip}</div>
          <div class="alert-item-sub">blocked ${new Date(b.blocked_at * 1000).toLocaleString()}${b.reason ? " · " + b.reason : ""}</div>
        </div>
        <button class="unblock-btn" data-ip="${b.ip}" type="button">Unblock</button>
      </div>
    `
    )
    .join("");
  el.blockedPanelList.querySelectorAll(".unblock-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      unblockIp(btn.dataset.ip);
    });
  });
}

async function blockIp(ip, statusEl) {
  if (!isBlockable(ip)) return;
  const confirmed = confirm(
    `Block ${ip} at the Windows Firewall?\n\nThis adds a real inbound-block rule on this machine. ` +
    `It requires the backend to be running as Administrator, and you can undo it any time from the shield icon in the header.`
  );
  if (!confirmed) return;

  if (statusEl) {
    statusEl.textContent = "Blocking…";
    statusEl.className = "modal-block-status";
  }
  try {
    const res = await fetch(`${API_BASE}/firewall/block`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason: "blocked from alert detail" }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Block failed");
    if (statusEl) {
      statusEl.textContent = `Blocked ${ip} (rule ${data.rule_name}).`;
      statusEl.className = "modal-block-status is-ok";
    }
    await loadBlockedIps();
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = `Error: ${e.message}`;
      statusEl.className = "modal-block-status is-error";
    }
  }
}

async function unblockIp(ip) {
  if (!confirm(`Remove the firewall block for ${ip}?`)) return;
  try {
    const res = await fetch(`${API_BASE}/firewall/unblock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Unblock failed");
  } catch (e) {
    alert(`Error unblocking ${ip}: ${e.message}`);
  }
  await loadBlockedIps();
}

function openAlertModal(item) {
  const verdict = riskVerdict(item);
  el.alertModalTitle.textContent = `${item.src_ip || "—"} → ${item.dst_ip || "—"}${item.dst_port != null ? " :" + item.dst_port : ""}`;
  const reasonsHtml = (item.reasons || []).map((r) => `<li>${r}</li>`).join("");
  const stepsHtml = getRemediationSteps(item).map((s) => `<li>${s}</li>`).join("");
  const blockable = isBlockable(item.src_ip);
  const alreadyBlocked = blockedState.items.some((b) => b.ip === item.src_ip);

  el.alertModalBody.innerHTML = `
    <p style="margin:0 0 10px"><strong>${verdict.label}</strong> · risk score ${item.risk_score.toFixed(0)} · ${item.protocol_type}/${item.service}</p>
    <p style="font-weight:700;margin-bottom:4px">Why it was flagged</p>
    <ul style="margin:0 0 14px;padding-left:18px">${reasonsHtml}</ul>
    ${renderTopFeaturesHtml(item)}
    <p style="font-weight:700;margin:14px 0 4px">Steps to bring this back to normal</p>
    <ol style="margin:0;padding-left:18px">${stepsHtml}</ol>
    ${
      blockable
        ? `<button class="btn btn-primary modal-block-btn" id="modal-block-btn" type="button" ${alreadyBlocked ? "disabled" : ""}>
             ${alreadyBlocked ? `Already blocked` : `Block ${item.src_ip} at the firewall`}
           </button>
           <div class="modal-block-status" id="modal-block-status"></div>`
        : ""
    }
  `;

  // Close whatever dropdown was open (alerts/blocked/settings) before navigating --
  // otherwise it stays open behind the full-page view and looks broken.
  alertState.open = false;
  el.alertPanel.style.display = "none";
  blockedState.open = false;
  el.blockedPanel.style.display = "none";
  el.settingsPanel.style.display = "none";

  el.alertDetailPage.style.display = "flex";
  window.scrollTo(0, 0);
  history.pushState({ guardianDetail: true }, "", "#alert");

  const blockBtn = document.getElementById("modal-block-btn");
  if (blockBtn && !alreadyBlocked) {
    blockBtn.addEventListener("click", () => blockIp(item.src_ip, document.getElementById("modal-block-status")));
  }
}

function closeAlertDetailPage() {
  el.alertDetailPage.style.display = "none";
  if (location.hash === "#alert") history.back();
}

el.alertDetailBack.addEventListener("click", closeAlertDetailPage);
window.addEventListener("popstate", () => {
  if (el.alertDetailPage.style.display !== "none") el.alertDetailPage.style.display = "none";
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && el.alertDetailPage.style.display !== "none") closeAlertDetailPage();
});

el.alertBellBtn.addEventListener("click", () => {
  alertState.open = !alertState.open;
  el.alertPanel.style.display = alertState.open ? "flex" : "none";
  if (alertState.open) {
    alertState.unread = 0;
    el.alertBadge.style.display = "none";
    blockedState.open = false;
    el.blockedPanel.style.display = "none";
    el.settingsPanel.style.display = "none";
  }
});
el.blockedBellBtn.addEventListener("click", () => {
  blockedState.open = !blockedState.open;
  el.blockedPanel.style.display = blockedState.open ? "flex" : "none";
  if (blockedState.open) {
    alertState.open = false;
    el.alertPanel.style.display = "none";
    el.settingsPanel.style.display = "none";
  }
});
document.addEventListener("click", (e) => {
  if (alertState.open && !e.target.closest(".alert-bell-wrap")) {
    alertState.open = false;
    el.alertPanel.style.display = "none";
  }
  if (blockedState.open && !e.target.closest(".alert-bell-wrap")) {
    blockedState.open = false;
    el.blockedPanel.style.display = "none";
  }
});

/* Called for every REAL (live capture / pcap upload / simulate-attack) scored
   item -- NOT the simulated NSL-KDD demo feed, so the alert inbox and these
   live counters only ever reflect actual packet-derived scoring. */
function recordRealItem(item) {
  sessionStats.scored += 1;
  if (item.flagged) sessionStats.flagged += 1;

  if (AUTH_SERVICES.has(item.service)) {
    sessionStats.authObserved += 1;
    const m = (item.reasons || []).join(" ").match(/(\d+) connection attempts/);
    if (m) sessionStats.authMax = Math.max(sessionStats.authMax, parseInt(m[1], 10));
  }
  if (isBruteforceItem(item)) sessionStats.bruteforceTriggered += 1;

  if (item.risk_score >= ALERT_THRESHOLD || isBruteforceItem(item)) {
    alertState.items.unshift({ ...item, _seenAt: Date.now() });
    if (alertState.items.length > 50) alertState.items.length = 50;
    if (!alertState.open) {
      alertState.unread += 1;
      el.alertBadge.textContent = alertState.unread > 99 ? "99+" : String(alertState.unread);
      el.alertBadge.style.display = "flex";
    }
    renderAlertPanel();
    fireDesktopNotification(item);
  }
  updateStatDom();
}

/* ============================== Notification settings ============================== */
const DESKTOP_NOTIF_KEY = "guardian_desktop_notifs_enabled";

function desktopNotifsEnabled() {
  return localStorage.getItem(DESKTOP_NOTIF_KEY) === "1" && window.Notification && Notification.permission === "granted";
}

function fireDesktopNotification(item) {
  if (!desktopNotifsEnabled()) return;
  const verdict = riskVerdict(item);
  try {
    new Notification(`Network Guardian: ${verdict.label}`, {
      body: `${item.src_ip || "?"} → ${item.service}${item.dst_port != null ? ":" + item.dst_port : ""} · risk ${item.risk_score.toFixed(0)}`,
      tag: `guardian-${item.src_ip}-${item.dst_port}`,
    });
  } catch (e) {
    // Notification constructor can throw in some contexts (e.g. insecure origin); fail silently
  }
}

async function initDesktopToggle() {
  if (!window.Notification) {
    el.desktopNotifToggle.disabled = true;
    return;
  }
  el.desktopNotifToggle.checked = desktopNotifsEnabled();
  el.desktopNotifToggle.addEventListener("change", async () => {
    if (el.desktopNotifToggle.checked) {
      const perm = await Notification.requestPermission();
      if (perm !== "granted") {
        el.desktopNotifToggle.checked = false;
        localStorage.setItem(DESKTOP_NOTIF_KEY, "0");
        return;
      }
      localStorage.setItem(DESKTOP_NOTIF_KEY, "1");
      new Notification("Network Guardian", { body: "Desktop alerts are on. You'll see high-risk detections here." });
    } else {
      localStorage.setItem(DESKTOP_NOTIF_KEY, "0");
    }
  });
}

async function loadWebhookSettings() {
  try {
    const res = await fetch(`${API_BASE}/settings/webhook`);
    const data = await res.json();
    el.webhookUrlInput.value = data.url || "";
    el.webhookEnabledToggle.checked = !!data.enabled;
  } catch (e) {}
}

el.webhookSaveBtn.addEventListener("click", async () => {
  el.webhookStatus.textContent = "Saving…";
  el.webhookStatus.className = "modal-block-status";
  try {
    const res = await fetch(`${API_BASE}/settings/webhook`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: el.webhookUrlInput.value.trim(), enabled: el.webhookEnabledToggle.checked }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Save failed");
    el.webhookStatus.textContent = "Saved.";
    el.webhookStatus.className = "modal-block-status is-ok";
  } catch (e) {
    el.webhookStatus.textContent = `Error: ${e.message}`;
    el.webhookStatus.className = "modal-block-status is-error";
  }
});

el.webhookTestBtn.addEventListener("click", async () => {
  const url = el.webhookUrlInput.value.trim();
  if (!url) {
    el.webhookStatus.textContent = "Enter a webhook URL first.";
    el.webhookStatus.className = "modal-block-status is-error";
    return;
  }
  el.webhookStatus.textContent = "Sending test…";
  el.webhookStatus.className = "modal-block-status";
  try {
    const res = await fetch(`${API_BASE}/settings/webhook/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, enabled: true }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Test failed");
    el.webhookStatus.textContent = "Test sent — check your webhook destination.";
    el.webhookStatus.className = "modal-block-status is-ok";
  } catch (e) {
    el.webhookStatus.textContent = `Error: ${e.message}`;
    el.webhookStatus.className = "modal-block-status is-error";
  }
});

el.settingsBellBtn.addEventListener("click", () => {
  const willOpen = el.settingsPanel.style.display === "none";
  el.settingsPanel.style.display = willOpen ? "flex" : "none";
  if (willOpen) {
    alertState.open = false;
    el.alertPanel.style.display = "none";
    blockedState.open = false;
    el.blockedPanel.style.display = "none";
  }
});
document.addEventListener("click", (e) => {
  if (el.settingsPanel.style.display !== "none" && !e.target.closest(".alert-bell-wrap")) {
    el.settingsPanel.style.display = "none";
  }
});

/* Pulls persisted history from the backend (SQLite-backed, survives reloads
   and backend restarts) so the alert inbox and live counters don't reset to
   zero every time the page loads -- only the current tab session used to be
   remembered before this. Treated as "already seen" (no unread badge spike)
   since it's catch-up, not brand-new activity. */
async function hydrateFromHistory() {
  const [statsRes, alertsRes] = await Promise.all([
    fetch(`${API_BASE}/alerts/stats`),
    fetch(`${API_BASE}/alerts?limit=50&min_risk=${ALERT_THRESHOLD}`),
  ]);
  const stats = await statsRes.json();
  const alertsData = await alertsRes.json();

  sessionStats.scored = stats.scored;
  sessionStats.flagged = stats.flagged;
  sessionStats.bruteforceTriggered = stats.bruteforce_triggered;
  sessionStats.authObserved = stats.auth_observed;
  sessionStats.authMax = stats.auth_max;

  alertState.items = alertsData.alerts.map((a) => ({ ...a, _seenAt: a.created_at * 1000 }));

  updateStatDom();
  renderAlertPanel();
}

/* ============================== Boot sequence ============================== */
// Never let a slow/hanging backend call keep the full-screen boot overlay up
// forever (it would silently block every click behind it). Each network step
// below is capped, and there's a hard overall ceiling that force-hides the
// overlay no matter what.
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(null), ms)),
  ]);
}

async function runBoot() {
  const setBoot = (pct, label) => {
    el.bootFill.style.width = `${pct}%`;
    el.bootLabel.textContent = label;
  };
  const hardCeiling = setTimeout(() => el.bootOverlay.classList.add("hidden"), 8000);

  setBoot(8, "Loading model artifacts…");
  let metrics = null;
  try {
    const res = await withTimeout(fetch(`${API_BASE}/metrics`), 4000);
    if (res) metrics = await res.json();
  } catch (e) {
    // handled by the header status indicator instead
  }
  setBoot(40, "Warming Isolation Forest…");
  await sleep(220);
  setBoot(65, "Calibrating anomaly thresholds…");
  try {
    await withTimeout(loadInterfaces(), 4000);
  } catch (e) {}
  setBoot(82, "Loading alert history…");
  try {
    await withTimeout(
      Promise.all([hydrateFromHistory(), loadBlockedIps(), loadWebhookSettings(), initDesktopToggle()]),
      4000
    );
  } catch (e) {}
  setBoot(90, "Ready.");
  await sleep(200);
  setBoot(100, "Ready.");
  await sleep(250);
  clearTimeout(hardCeiling);
  el.bootOverlay.classList.add("hidden");

  if (metrics) applyMetrics(metrics);
  else fetchMetrics();
}

/* ============================== Metrics (hero) ============================== */
function animateCountUp(setter, target, durationMs = 1200) {
  const t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - t0) / durationMs);
    const e = 1 - Math.pow(1 - p, 3);
    setter(target * e);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  // rAF is throttled/suspended on hidden or backgrounded tabs, which would
  // otherwise leave the metric stuck at 0 -- guarantee the true final value
  // lands regardless of tab visibility.
  setTimeout(() => setter(target), durationMs + 80);
}

function applyMetrics(data) {
  animateCountUp((v) => (el.metricAuc.textContent = v.toFixed(3)), data.roc_auc);
  const precPct = data.precision_attack * 100;
  animateCountUp((v) => (el.metricPrec.textContent = v.toFixed(1)), precPct);
  animateCountUp((v) => (el.metricRec.textContent = v.toFixed(1)), data.recall_attack * 100);
  animateCountUp((v) => (el.metricUnseen.textContent = v.toFixed(1)), (data.novel_attack_detection_rate || 0) * 100);
  if (el.metricPrecBack) {
    el.metricPrecBack.textContent = `${precPct.toFixed(1)}% of flags are real attacks — very few false alarms to chase.`;
  }
  setLive(true);
}

async function fetchMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics`);
    const data = await res.json();
    applyMetrics(data);
  } catch (e) {
    setLive(false);
  }
}

function setLive(isLive) {
  el.statusDot.classList.toggle("down", !isLive);
  el.statusText.textContent = isLive ? "Model loaded" : "API unreachable — start the backend";
}

document.querySelectorAll(".flip-card[data-metric]").forEach((card) => {
  card.addEventListener("click", () => card.classList.toggle("is-flipped"));
});

/* ============================== Tilt-on-hover ============================== */
function attachTilt(elm) {
  elm.addEventListener("mousemove", (e) => {
    const r = elm.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    elm.style.transition = "transform .08s linear";
    elm.style.transform = `perspective(900px) rotateY(${(x * 9).toFixed(2)}deg) rotateX(${(-y * 9).toFixed(2)}deg) translateY(-5px) scale(1.015)`;
    elm.style.zIndex = 2;
  });
  elm.addEventListener("mouseleave", () => {
    elm.style.transition = "transform .45s cubic-bezier(.2,.8,.2,1)";
    elm.style.transform = "";
    elm.style.zIndex = "";
  });
}
document.querySelectorAll(".tilt-card").forEach(attachTilt);

/* ============================== Live packet capture ============================== */
const NOISY_ADAPTER_HINTS = ["loopback", "virtual", "bluetooth", "miniport", "vpn", "tap-"];
const liveState = { running: false, socket: null, selectedRowId: null, cloudUnavailable: false };

function isLikelyRealAdapter(iface) {
  const haystack = `${iface.name} ${iface.description}`.toLowerCase();
  return !NOISY_ADAPTER_HINTS.some((hint) => haystack.includes(hint));
}

async function loadInterfaces() {
  try {
    const res = await fetch(`${API_BASE}/interfaces`);
    const data = await res.json();
    if (data.cloud_deployment) {
      el.ifaceSelect.innerHTML = `<option value="">Not available on this deployment</option>`;
      el.ifaceSelect.disabled = true;
      el.captureToggleBtn.disabled = true;
      el.captureStatus.textContent =
        "Live capture needs a real local network interface and OS-level privileges " +
        "this cloud host doesn't have (and shouldn't be given) -- clone the repo and " +
        "run it locally to use this feature. Everything else on this page runs for real.";
      el.captureStatus.className = "capture-status";
      liveState.cloudUnavailable = true;
      return;
    }
    const sorted = [...data.interfaces].sort((a, b) => isLikelyRealAdapter(b) - isLikelyRealAdapter(a));
    el.ifaceSelect.innerHTML = sorted
      .map((iface) => {
        const label = iface.description ? `${iface.name} — ${iface.description}` : iface.name;
        return `<option value="${iface.device}">${label}</option>`;
      })
      .join("");
  } catch (e) {
    el.ifaceSelect.innerHTML = `<option value="">(could not load interfaces)</option>`;
  }
}

function riskVerdict(item) {
  const isBruteforce = item.flagged && item.reasons.some((r) => r.includes("brute-force"));
  if (isBruteforce) return { label: "Brute-force", tagClass: "tag-accent-2" };
  if (item.flagged) return { label: "Anomaly", tagClass: "tag-accent" };
  return { label: "Normal", tagClass: "tag-neutral" };
}

function renderLiveRow(item) {
  if (el.liveEmptyRow) {
    el.liveEmptyRow.remove();
    el.liveEmptyRow = null;
  }

  const id = `row-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const verdict = riskVerdict(item);
  const time = new Date().toLocaleTimeString("en-GB");

  const row = document.createElement("tr");
  row.className = "data-row" + (item.flagged ? " is-flagged" : "");
  row.dataset.rowId = id;
  row.innerHTML = `
    <td>${time}</td>
    <td>${item.src_ip || "—"}</td>
    <td>${item.service} :${item.dst_port != null ? item.dst_port : "—"}</td>
    <td class="num">${Math.round(item.src_bytes).toLocaleString()}</td>
    <td class="num">${item.risk_score.toFixed(0)}</td>
    <td><span class="tag ${verdict.tagClass}">${verdict.label}</span></td>
  `;
  row.addEventListener("click", () => selectLiveRow(row, item, verdict));
  el.liveFeedTbody.prepend(row);
  row._item = item;
  row._verdict = verdict;

  while (el.liveFeedTbody.children.length > 40) {
    el.liveFeedTbody.removeChild(el.liveFeedTbody.lastChild);
  }
}

/* SHAP-derived per-feature attribution from the backend (main.py score_rows):
   most-negative shap value = biggest driver of the anomaly. Shown as a small
   ranked list so "statistical deviation" becomes "specifically THIS feature". */
function renderTopFeaturesHtml(item) {
  if (!item.top_features || item.top_features.length === 0) return "";
  const rows = item.top_features
    .map((f, i) => {
      const magnitude = Math.min(100, Math.abs(f.shap) * 40);
      return `
        <div class="shap-row">
          <span class="shap-rank">#${i + 1}</span>
          <span class="shap-feature">${f.feature}</span>
          <span class="shap-value">= ${f.value}</span>
          <span class="shap-bar-track"><span class="shap-bar" style="width:${magnitude}%"></span></span>
        </div>
      `;
    })
    .join("");
  return `
    <div class="shap-section">
      <div class="detail-kicker" style="margin:14px 0 8px">Model's top signals (SHAP)</div>
      ${rows}
    </div>
  `;
}

function selectLiveRow(row, item, verdict) {
  el.liveFeedTbody.querySelectorAll(".data-row.is-selected").forEach((r) => r.classList.remove("is-selected"));
  row.classList.add("is-selected");

  const reasonsHtml = item.reasons
    .map((r) => `<div class="detail-reason"><span class="dot"></span><span>${r}</span></div>`)
    .join("");

  el.detailContent.innerHTML = `
    <div class="detail-title">${item.src_ip || "—"} → ${item.dst_ip || "—"} :${item.dst_port != null ? item.dst_port : "—"}</div>
    <div class="detail-sub">anomaly score ${item.risk_score.toFixed(0)} · ${verdict.label}</div>
    ${reasonsHtml}
    ${renderTopFeaturesHtml(item)}
  `;
}

function connectLiveSocket() {
  const wsUrl = API_BASE.replace(/^http/, "ws") + "/ws/live";
  const socket = new WebSocket(wsUrl);
  liveState.socket = socket;

  socket.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type !== "results") return;
    msg.results.forEach((item) => {
      if (item.error) return;
      renderLiveRow(item);
      recordRealItem(item);
    });
  });

  socket.addEventListener("close", () => {
    if (liveState.running) {
      el.captureStatus.textContent = "Live socket disconnected.";
      el.captureStatus.className = "capture-status is-error";
    }
  });
}

async function refreshCaptureStatus() {
  if (liveState.cloudUnavailable) return;
  try {
    const res = await fetch(`${API_BASE}/live/status`);
    const data = await res.json();
    liveState.running = data.running;
    el.captureToggleBtn.textContent = data.running ? "Stop live capture" : "Start live capture";

    if (data.error) {
      el.captureStatus.textContent = `Error: ${data.error}`;
      el.captureStatus.className = "capture-status is-error";
    } else if (data.running) {
      el.captureStatus.textContent = `Capturing on ${data.interface || "default interface"} — ${data.packet_count} packets seen.`;
      el.captureStatus.className = "capture-status is-active";
      if (!liveState.socket || liveState.socket.readyState > WebSocket.OPEN) {
        connectLiveSocket();
      }
      updatePps(data.packet_count);
    } else {
      el.captureStatus.textContent = "Not capturing.";
      el.captureStatus.className = "capture-status";
      ppsTracker.lastCount = null;
      ppsTracker.lastTime = null;
      el.statPps.textContent = "0.0";
    }
  } catch (e) {
    // backend unreachable; leave last known status displayed
  }
}

function updatePps(currentCount) {
  const now = Date.now();
  if (ppsTracker.lastCount != null && ppsTracker.lastTime != null) {
    const dCount = currentCount - ppsTracker.lastCount;
    const dTime = (now - ppsTracker.lastTime) / 1000;
    if (dTime > 0) {
      ppsTracker.pps = Math.max(0, dCount / dTime);
      el.statPps.textContent = ppsTracker.pps.toFixed(1);
    }
  }
  ppsTracker.lastCount = currentCount;
  ppsTracker.lastTime = now;
}

el.captureToggleBtn.addEventListener("click", async () => {
  el.captureToggleBtn.disabled = true;
  try {
    if (!liveState.running) {
      const res = await fetch(`${API_BASE}/live/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: el.ifaceSelect.value || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to start capture");
      el.liveFeedTbody.innerHTML = `<tr class="live-empty-row" id="live-empty-row"><td colspan="6">No live connections yet — waiting for traffic on this interface…</td></tr>`;
      el.liveEmptyRow = document.getElementById("live-empty-row");
      connectLiveSocket();
    } else {
      await fetch(`${API_BASE}/live/stop`, { method: "POST" });
      if (liveState.socket) liveState.socket.close();
    }
  } catch (e) {
    el.captureStatus.textContent = `Error: ${e.message}`;
    el.captureStatus.className = "capture-status is-error";
  }
  await refreshCaptureStatus();
  el.captureToggleBtn.disabled = false;
});

/* ============================== Simulated traffic pulse (canvas) ============================== */
const pulseState = { hist: [], t: 0 };

function drawPulseFrame() {
  const c = el.pulseCanvas;
  const ctx = c.getContext("2d");
  const W = c.width, H = c.height, N = 190;
  const cs = getComputedStyle(c);
  const accent = cs.getPropertyValue("--color-accent").trim() || "#c67139";
  const sage = cs.getPropertyValue("--color-accent-2").trim() || "#7a8a5e";

  ctx.clearRect(0, 0, W, H);
  const bw = W / N;
  pulseState.hist.forEach((d, i) => {
    ctx.fillStyle = d.flagged ? accent : sage;
    ctx.globalAlpha = d.flagged ? 1 : 0.3 + (i / N) * 0.35;
    const x = i * bw + 1, w = bw - 4, h = d.h;
    const rr = Math.min(w / 2, 6);
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, H - h, w, h + rr, [rr, rr, 0, 0]);
    } else {
      ctx.rect(x, H - h, w, h);
    }
    ctx.fill();
  });
  ctx.globalAlpha = 1;
}

function pushPulseBar(riskScore, flagged) {
  const H = el.pulseCanvas.height;
  const h = Math.max(6, (riskScore / 100) * H * 0.92);
  pulseState.hist.push({ h, flagged, risk: riskScore });
  if (pulseState.hist.length > 190) pulseState.hist.shift();
  drawPulseFrame();
  updatePulseStatLine();
}

function updatePulseStatLine() {
  const visible = pulseState.hist;
  if (visible.length === 0) return;
  const flaggedCount = visible.filter((d) => d.flagged).length;
  const avgRisk = visible.reduce((s, d) => s + d.risk, 0) / visible.length;
  el.pulseStatLine.textContent =
    `Last ${visible.length} samples: ${flaggedCount} flagged (${((flaggedCount / visible.length) * 100).toFixed(0)}%), ` +
    `avg risk ${avgRisk.toFixed(0)}. Terracotta = above threshold, sage = normal. This feed samples test data — capture/upload above run on real packets.`;
}

async function pollSampleTraffic() {
  try {
    const res = await fetch(`${API_BASE}/sample-traffic?n=4&attack_ratio=0.3`);
    const data = await res.json();
    data.traffic.forEach((item) => pushPulseBar(item.risk_score, item.flagged));
    setLive(true);
  } catch (e) {
    setLive(false);
  }
}

/* ============================== Analyze real traffic ============================== */
function renderAnalyzeResult(data, sourceLabel) {
  const total = data.results.length;
  const flaggedCount = data.results.filter((r) => r.flagged).length;
  const bruteforceCount = data.results.filter((r) => r.flagged && r.reasons.some((x) => x.includes("brute-force"))).length;

  el.analyzeResult.innerHTML = `
    <div class="result-card">
      <div class="result-kicker">${sourceLabel} — result</div>
      <div class="result-stats">
        <div class="result-stat">
          <div class="result-stat-value">${total}</div>
          <div class="result-stat-label">connections</div>
        </div>
        <div class="result-stat is-accent">
          <div class="result-stat-value">${flaggedCount}</div>
          <div class="result-stat-label">flagged anomalous</div>
        </div>
        <div class="result-stat is-accent-2">
          <div class="result-stat-value">${bruteforceCount}</div>
          <div class="result-stat-label">brute-force rule hits</div>
        </div>
      </div>
      <div class="result-note">${data.note || ""}</div>
    </div>
  `;

  // Feed these real, packet-derived results into the same session stats /
  // alert inbox as live capture -- pcap analysis is real traffic too.
  data.results.forEach((item) => recordRealItem(item));
}

async function analyzeFile(file) {
  el.analyzeResult.innerHTML = `<div class="analyze-placeholder">Analyzing ${file.name}…</div>`;
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch(`${API_BASE}/analyze-pcap`, { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Upload failed");
    renderAnalyzeResult(data, file.name);
  } catch (e) {
    el.analyzeResult.innerHTML = `<div class="analyze-placeholder">Error: ${e.message}</div>`;
  }
}

el.uploadBtn.addEventListener("click", () => el.pcapInput.click());
el.pcapInput.addEventListener("change", () => {
  const file = el.pcapInput.files[0];
  if (file) analyzeFile(file);
  el.pcapInput.value = "";
});

["dragenter", "dragover"].forEach((evt) =>
  el.dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    el.dropzone.classList.add("is-dragover");
  })
);
["dragleave", "drop"].forEach((evt) =>
  el.dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    el.dropzone.classList.remove("is-dragover");
  })
);
el.dropzone.addEventListener("drop", (e) => {
  const file = e.dataTransfer.files[0];
  if (file) analyzeFile(file);
});

el.simulateBtn.addEventListener("click", async (e) => {
  e.stopPropagation();
  el.simulateBtn.disabled = true;
  el.analyzeResult.innerHTML = `<div class="analyze-placeholder">Running canned attack scenario (port scan + SYN flood + SSH brute-force)…</div>`;
  try {
    const res = await fetch(`${API_BASE}/demo/simulate-attack`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Simulation failed");
    renderAnalyzeResult(data, "Simulated attack scenario");
  } catch (e2) {
    el.analyzeResult.innerHTML = `<div class="analyze-placeholder">Error: ${e2.message}</div>`;
  }
  el.simulateBtn.disabled = false;
});

/* ============================== Pipeline (static) ============================== */
const PIPELINE = [
  { n: "CAPTURE", title: "Packets", sub: "scapy AsyncSniffer / pcap upload" },
  { n: "EXTRACT", title: "41 + 1 features", sub: "NSL-KDD flow features + brute-force score" },
  { n: "PREP", title: "Encode + scale", sub: "same artifacts as training" },
  { n: "SCORE", title: "Isolation Forest (ML)", sub: "unsupervised model, trained on normal traffic only" },
  { n: "EXPLAIN", title: "SHAP attribution", sub: "per-connection feature importance, not a black box" },
  { n: "ENRICH", title: "WAF + threat intel", sub: "payload rule engine + IP reputation lookup" },
  { n: "DECIDE", title: "Verdict + response", sub: "force-flag rules · auto-response engine · WebSocket" },
];

function renderPipeline() {
  el.pipelineRow.innerHTML = PIPELINE.map((step, i) => `
    <div class="pipeline-step-wrap">
      <div class="pipeline-card tilt-card">
        <div class="pipeline-n">${step.n}</div>
        <div class="pipeline-title">${step.title}</div>
        <div class="pipeline-sub">${step.sub}</div>
      </div>
      ${i < PIPELINE.length - 1 ? '<div class="pipeline-arrow">→</div>' : ""}
    </div>
  `).join("");
  el.pipelineRow.querySelectorAll(".tilt-card").forEach(attachTilt);
}

/* ============================== Init ============================== */
renderPipeline();
runBoot();
refreshCaptureStatus();
pollSampleTraffic();
setInterval(pollSampleTraffic, 1800);
setInterval(fetchMetrics, 15000);
setInterval(refreshCaptureStatus, 4000);
