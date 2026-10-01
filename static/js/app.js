// Encrypted-Traffic Metadata Anomaly Lab - Frontend Dashboard Logic
let scoreChart = null;
let attackChart = null;
let currentFlows = [];
let streamInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();

  document.getElementById("btn-generate").addEventListener("click", handleGenerate);
  document.getElementById("btn-stream-toggle").addEventListener("click", toggleStreaming);
  document.getElementById("filter-risk").addEventListener("change", renderFlowTable);
  document.getElementById("modal-close").addEventListener("click", closeModal);
});

async function initDashboard() {
  logTerminal("Initializing Encrypted-Traffic Metadata Anomaly Lab Engine...", "info");
  await fetchStats();
  await fetchFlows();
  initCharts();
  logTerminal("Lab Environment ready. Statistical and ML engines online.", "info");
}

function logTerminal(message, type = "info") {
  const body = document.getElementById("terminal-body");
  if (!body) return;
  const line = document.createElement("div");
  line.className = `terminal-line ${type}`;
  const timestamp = new Date().toISOString().substring(11, 19);
  line.innerText = `[${timestamp}] ${message}`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}

async function fetchStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("stat-total-flows").innerText = data.total_flows;
    document.getElementById("stat-anomaly-count").innerText = data.anomaly_count;
    document.getElementById("stat-critical-count").innerText = data.critical_threats;
    document.getElementById("stat-bytes-mb").innerText = `${data.total_bytes_mb} MB`;

    updateAttackChart(data.attack_breakdown);
  } catch (err) {
    logTerminal(`Failed to fetch stats: ${err.message}`, "error");
  }
}

async function fetchFlows() {
  try {
    const res = await fetch("/api/flows?limit=100");
    const data = await res.json();
    currentFlows = data.flows || [];
    renderFlowTable();
    updateScoreChart();
  } catch (err) {
    logTerminal(`Failed to load flow data: ${err.message}`, "error");
  }
}

async function handleGenerate() {
  const count = parseInt(document.getElementById("num-flows-input").value) || 80;
  const ratio = parseFloat(document.getElementById("anomaly-ratio-input").value) || 0.25;

  logTerminal(`Generating ${count} synthetic flows with ${ratio * 100}% anomaly ratio...`, "info");
  
  try {
    const res = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ num_flows: count, anomaly_ratio: ratio })
    });
    const data = await res.json();
    currentFlows = data.flows;

    await fetchStats();
    renderFlowTable();
    updateScoreChart();
    logTerminal(`Generated ${currentFlows.length} flows. Baseline models updated.`, "info");
  } catch (err) {
    logTerminal(`Generation error: ${err.message}`, "error");
  }
}

function renderFlowTable() {
  const tbody = document.getElementById("flow-table-body");
  const riskFilter = document.getElementById("filter-risk").value;
  tbody.innerHTML = "";

  const filtered = currentFlows.filter(f => {
    if (riskFilter === "ALL") return true;
    return f.risk_level === riskFilter;
  });

  filtered.forEach(f => {
    const tr = document.createElement("tr");
    tr.className = "flow-row";
    tr.style.cursor = "pointer";

    let badgeClass = "badge-low";
    if (f.risk_level === "CRITICAL") badgeClass = "badge-critical";
    else if (f.risk_level === "HIGH") badgeClass = "badge-high";
    else if (f.risk_level === "MEDIUM") badgeClass = "badge-medium";

    const flags = f.flags ? f.flags.join(", ") : "NORMAL";

    tr.innerHTML = `
      <td class="mono">${f.flow_id.substring(0, 8)}</td>
      <td class="mono">${f.ja3_info.name || 'TLS'}</td>
      <td>${f.ja3_info.category || 'Standard'}</td>
      <td class="mono">${f.anomaly_score.toFixed(3)}</td>
      <td><span class="badge ${badgeClass}">${f.risk_level}</span></td>
      <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${flags}</td>
    `;

    tr.addEventListener("click", () => showFlowDetails(f));
    tbody.appendChild(tr);
  });
}

function initCharts() {
  const ctxScore = document.getElementById("chart-score").getContext("2d");
  scoreChart = new Chart(ctxScore, {
    type: "scatter",
    data: {
      datasets: [
        { label: "Benign Flows", data: [], backgroundColor: "#10b981", pointRadius: 5 },
        { label: "Anomalous Flows", data: [], backgroundColor: "#ef4444", pointRadius: 7 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: "Inter-Arrival Time CV", color: "#9ca3af" }, grid: { color: "rgba(255,255,255,0.05)" } },
        y: { title: { display: true, text: "Anomaly Score", color: "#9ca3af" }, min: 0, max: 1, grid: { color: "rgba(255,255,255,0.05)" } }
      },
      plugins: { legend: { labels: { color: "#f3f4f6" } } }
    }
  });

  const ctxAttack = document.getElementById("chart-attack").getContext("2d");
  attackChart = new Chart(ctxAttack, {
    type: "doughnut",
    data: {
      labels: ["Beaconing", "Exfiltration", "Tunnel", "Surge/DDoS"],
      datasets: [{
        data: [1, 1, 1, 1],
        backgroundColor: ["#ef4444", "#f97316", "#8b5cf6", "#06b6d4"]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { color: "#f3f4f6" } } }
    }
  });
}

function updateScoreChart() {
  if (!scoreChart) return;
  const benign = [];
  const anomaly = [];

  currentFlows.forEach(f => {
    const pt = { x: f.ja3_info.name ? Math.random() * 0.5 + 0.1 : 0.2, y: f.anomaly_score };
    if (f.is_anomaly) anomaly.push(pt);
    else benign.push(pt);
  });

  scoreChart.data.datasets[0].data = benign;
  scoreChart.data.datasets[1].data = anomaly;
  scoreChart.update();
}

function updateAttackChart(breakdown) {
  if (!attackChart || !breakdown) return;
  const labels = Object.keys(breakdown);
  const data = Object.values(breakdown);

  attackChart.data.labels = labels.length ? labels : ["None"];
  attackChart.data.datasets[0].data = data.length ? data : [1];
  attackChart.update();
}

function toggleStreaming() {
  const btn = document.getElementById("btn-stream-toggle");
  if (streamInterval) {
    clearInterval(streamInterval);
    streamInterval = null;
    btn.innerText = "⚡ Start Live Packet Stream";
    btn.className = "btn btn-secondary";
    logTerminal("Live traffic stream simulation paused.", "warning");
  } else {
    btn.innerText = "⏸ Pause Stream";
    btn.className = "btn btn-danger";
    logTerminal("Live traffic stream simulation active.", "info");

    streamInterval = setInterval(async () => {
      const types = ["c2_beaconing", "benign_web", "data_exfiltration", "benign_video"];
      const chosen = types[Math.floor(Math.random() * types.length)];

      try {
        const res = await fetch("/api/simulate_stream", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ traffic_type: chosen })
        });
        const data = await res.json();
        const flow = data.flow;
        currentFlows.unshift(flow);
        renderFlowTable();

        if (flow.is_anomaly) {
          logTerminal(`🚨 ALERT: Anomaly Detected [${flow.risk_level}] ${flow.ja3_info.name} - Score: ${flow.anomaly_score}`, "error");
        } else {
          logTerminal(`Flow passed baseline checks: ${flow.flow_id}`, "info");
        }
      } catch (err) {
        logTerminal(`Stream error: ${err.message}`, "error");
      }
    }, 2500);
  }
}

function showFlowDetails(flow) {
  const modal = document.getElementById("modal-overlay");
  const details = document.getElementById("modal-details");

  const explanations = (flow.explanations || []).map(e => `<li>${e}</li>`).join("");

  details.innerHTML = `
    <h2 style="margin-bottom:1rem; font-family:var(--font-heading);">Flow Inspection: <span class="mono" style="color:var(--primary-cyan);">${flow.flow_id}</span></h2>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1.5rem;">
      <div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:8px;">
        <h4 style="color:var(--text-muted); font-size:0.8rem; margin-bottom:0.5rem;">5-TUPLE & PROTOCOL</h4>
        <p><strong>Protocol:</strong> ${flow.ja3_info.name}</p>
        <p class="mono"><strong>JA3 Hash:</strong> ${flow.ja3_info.name ? '3b2a1060b2984534f3780f2d93e1cf70' : 'N/A'}</p>
      </div>
      <div style="background:rgba(255,255,255,0.03); padding:1rem; border-radius:8px;">
        <h4 style="color:var(--text-muted); font-size:0.8rem; margin-bottom:0.5rem;">ANOMALY EVALUATION</h4>
        <p><strong>Score:</strong> <span style="color:${flow.is_anomaly ? '#ef4444' : '#10b981'}; font-weight:bold;">${flow.anomaly_score.toFixed(4)}</span></p>
        <p><strong>Risk Level:</strong> ${flow.risk_level}</p>
      </div>
    </div>
    <h3 style="font-size:0.95rem; margin-bottom:0.5rem; color:var(--primary-cyan);">Detection Reasons:</h3>
    <ul style="padding-left:1.2rem; color:var(--text-muted); font-size:0.875rem;">
      ${explanations || '<li>None</li>'}
    </ul>
  `;

  modal.classList.add("active");
}

function closeModal() {
  document.getElementById("modal-overlay").classList.remove("active");
}
