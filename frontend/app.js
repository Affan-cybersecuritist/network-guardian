const API_BASE = "http://localhost:8000";

const state = {
  running: true,
  attackRatio: 0.30,
  pulseHistory: [], // recent risk scores for the oscilloscope
  totalAnalyzed: 0,
  pollHandle: null,
};

const el = {
  statusPill: document.getElementById("status-pill"),
  statusText: document.getElementById("status-text"),
  statAuc: document.getElementById("stat-auc"),
  statPrecision: document.getElementById("stat-precision"),
  statNovel: document.getElementById("stat-novel"),
  statCount: document.getElementById("stat-count"),
  ratioSlider: document.getElementById("ratio-slider"),
  ratioLabel: document.getElementById("ratio-label"),
  toggleBtn: document.getElementById("toggle-btn"),
  feedBody: document.getElementById("feed-body"),
  canvas: document.getElementById("pulse-canvas"),
  pcapInput: document.getElementById("pcap-input"),
  uploadBtn: document.getElementById("upload-btn"),
  uploadStatus: document.getElementById("upload-status"),
  ifaceSelect: document.getElementById("iface-select"),
  liveToggleBtn: document.getElementById("live-toggle-btn"),
  liveStatus: document.getElementById("live-status"),
};

const liveState = {
  running: false,
  socket: null,
};

el.uploadBtn.addEventListener("click", () => el.pcapInput.click());

el.pcapInput.addEventListener("change", async () => {
  const file = el.pcapInput.files[0];
  if (!file) return;

  el.uploadStatus.textContent = `Analyzing ${file.name}...`;
  el.uploadStatus.className = "upload-status active";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(`${API_BASE}/analyze-pcap`, { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload failed");
    }
    const data = await res.json();
    const flaggedCount = data.results.filter(r => r.flagged).length;
    el.uploadStatus.innerHTML = `<strong>${data.results.length}</strong> connections extracted from capture — ` +
      `<strong style="color:var(--danger-red)">${flaggedCount} flagged</strong> as anomalous.<br/>` +
      `<span style="opacity:0.7">${data.note || ""}</span>`;

    // Feed real results into the pulse + table, same as live traffic
    data.results.forEach(item => {
      state.pulseHistory.push({ risk: item.risk_score, flagged: item.flagged });
      state.totalAnalyzed += 1;
      renderFeedRow(item);
    });
    el.statCount.textContent = state.totalAnalyzed.toLocaleString();
    drawPulse();
  } catch (e) {
    el.uploadStatus.textContent = `Error: ${e.message}`;
    el.uploadStatus.className = "upload-status error";
  }

  el.pcapInput.value = "";
});

// --- Live packet capture ---
async function loadInterfaces() {
  try {
    const res = await fetch(`${API_BASE}/interfaces`);
    const data = await res.json();
    el.ifaceSelect.innerHTML = data.interfaces
      .map((iface) => `<option value="${iface}">${iface}</option>`)
      .join("");
  } catch (e) {
    el.ifaceSelect.innerHTML = `<option value="">(could not load interfaces)</option>`;
  }
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
      state.pulseHistory.push({ risk: item.risk_score, flagged: item.flagged });
      state.totalAnalyzed += 1;
      renderFeedRow(item);
    });
    el.statCount.textContent = state.totalAnalyzed.toLocaleString();
    drawPulse();
  });

  socket.addEventListener("close", () => {
    if (liveState.running) {
      el.liveStatus.textContent = "Live socket disconnected.";
      el.liveStatus.className = "upload-status error";
    }
  });
}

async function refreshLiveStatus() {
  try {
    const res = await fetch(`${API_BASE}/live/status`);
    const data = await res.json();
    liveState.running = data.running;
    el.liveToggleBtn.textContent = data.running ? "Stop Live Capture" : "Start Live Capture";
    el.liveToggleBtn.classList.toggle("live-active", data.running);
    if (data.error) {
      el.liveStatus.textContent = `Error: ${data.error}`;
      el.liveStatus.className = "upload-status error";
    } else if (data.running) {
      el.liveStatus.textContent = `Capturing on ${data.interface || "default interface"} — ${data.packet_count} packets seen.`;
      el.liveStatus.className = "upload-status active";
    } else {
      el.liveStatus.textContent = "Not capturing.";
      el.liveStatus.className = "upload-status";
    }
  } catch (e) {
    // backend unreachable; leave last known status displayed
  }
}

el.liveToggleBtn.addEventListener("click", async () => {
  el.liveToggleBtn.disabled = true;
  try {
    if (!liveState.running) {
      const res = await fetch(`${API_BASE}/live/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interface: el.ifaceSelect.value || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to start capture");
      connectLiveSocket();
    } else {
      await fetch(`${API_BASE}/live/stop`, { method: "POST" });
      if (liveState.socket) liveState.socket.close();
    }
  } catch (e) {
    el.liveStatus.textContent = `Error: ${e.message}`;
    el.liveStatus.className = "upload-status error";
  }
  await refreshLiveStatus();
  el.liveToggleBtn.disabled = false;
});

loadInterfaces();
refreshLiveStatus();
setInterval(refreshLiveStatus, 4000);

const ctx = el.canvas.getContext("2d");

function resizeCanvas() {
  const rect = el.canvas.getBoundingClientRect();
  el.canvas.width = rect.width * window.devicePixelRatio;
  el.canvas.height = rect.height * window.devicePixelRatio;
  ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
}
window.addEventListener("resize", resizeCanvas);

function drawPulse() {
  const w = el.canvas.getBoundingClientRect().width;
  const h = el.canvas.getBoundingClientRect().height;
  ctx.clearRect(0, 0, w, h);

  // baseline grid
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (h / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  const history = state.pulseHistory;
  if (history.length < 2) return;

  const maxPoints = 80;
  const visible = history.slice(-maxPoints);
  const stepX = w / (maxPoints - 1);
  const startX = w - (visible.length - 1) * stepX;

  ctx.beginPath();
  visible.forEach((point, i) => {
    const x = startX + i * stepX;
    const y = h - (point.risk / 100) * (h - 16) - 8;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "rgba(110, 124, 246, 0.9)";
  ctx.lineWidth = 2;
  ctx.stroke();

  // glow dots on flagged points
  visible.forEach((point, i) => {
    if (!point.flagged) return;
    const x = startX + i * stepX;
    const y = h - (point.risk / 100) * (h - 16) - 8;
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = "#EF4D5E";
    ctx.shadowColor = "#EF4D5E";
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
}

function riskClass(score) {
  if (score >= 65) return "risk-high";
  if (score >= 35) return "risk-med";
  return "risk-low";
}

function renderFeedRow(item) {
  const row = document.createElement("div");
  row.className = "feed-row feed-row--data";

  let truthClass, truthLabel;
  if (item.true_label === "normal") {
    truthClass = "truth-normal";
    truthLabel = "normal";
  } else if (item.true_label === "unknown" || !item.true_label) {
    truthClass = "";
    truthLabel = "real capture (unlabeled)";
  } else {
    truthClass = "truth-attack";
    truthLabel = `attack (${item.true_label})`;
  }

  row.innerHTML = `
    <span><span class="risk-badge ${riskClass(item.risk_score)}">${item.risk_score.toFixed(0)}</span></span>
    <span>${item.protocol_type}</span>
    <span>${item.service}</span>
    <span>${item.flag}</span>
    <span>${Math.round(item.src_bytes)} → ${Math.round(item.dst_bytes)}</span>
    <span class="${truthClass}">${truthLabel}</span>
  `;

  const drawer = document.createElement("div");
  drawer.className = "reasons-drawer";
  drawer.style.display = "none";
  drawer.innerHTML = `<strong>Why flagged:</strong><ul>${item.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`;

  row.addEventListener("click", () => {
    drawer.style.display = drawer.style.display === "none" ? "block" : "none";
  });

  el.feedBody.prepend(drawer);
  el.feedBody.prepend(row);

  // cap the feed length so DOM doesn't grow forever
  while (el.feedBody.children.length > 60) {
    el.feedBody.removeChild(el.feedBody.lastChild);
  }
}

async function fetchMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics`);
    const data = await res.json();
    el.statAuc.textContent = data.roc_auc.toFixed(3);
    el.statPrecision.textContent = (data.precision_attack * 100).toFixed(1) + "%";
    el.statNovel.textContent = (data.novel_attack_detection_rate * 100).toFixed(1) + "%";
    setLive(true);
  } catch (e) {
    setLive(false);
  }
}

function setLive(isLive) {
  el.statusPill.classList.toggle("live", isLive);
  el.statusText.textContent = isLive ? "Model live" : "API unreachable — start the backend";
}

async function pollTraffic() {
  if (!state.running) return;
  try {
    const n = 4;
    const res = await fetch(`${API_BASE}/sample-traffic?n=${n}&attack_ratio=${state.attackRatio}`);
    const data = await res.json();
    data.traffic.forEach(item => {
      state.pulseHistory.push({ risk: item.risk_score, flagged: item.flagged });
      state.totalAnalyzed += 1;
      renderFeedRow(item);
    });
    el.statCount.textContent = state.totalAnalyzed.toLocaleString();
    drawPulse();
    setLive(true);
  } catch (e) {
    setLive(false);
  }
}

el.ratioSlider.addEventListener("input", (e) => {
  state.attackRatio = e.target.value / 100;
  el.ratioLabel.textContent = `${e.target.value}%`;
});

el.toggleBtn.addEventListener("click", () => {
  state.running = !state.running;
  el.toggleBtn.textContent = state.running ? "Pause Monitoring" : "Resume Monitoring";
});

resizeCanvas();
fetchMetrics();
pollTraffic();
setInterval(pollTraffic, 1800);
setInterval(fetchMetrics, 15000);
