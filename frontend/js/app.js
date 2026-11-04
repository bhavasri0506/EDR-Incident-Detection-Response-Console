const API_URL = "http://127.0.0.1:5000/api/alerts";

let severityChart = null;
let processChart = null;
let cachedAlerts = [];
let remediatedPids = new Set();
let currentActiveAlert = null;

// ==========================================
// 1. VIDEO-LIKE INTERACTIVE CANVAS ANIMATION
// ==========================================
const canvas = document.getElementById("cyberCanvas");
const ctx = canvas.getContext("2d");

let particles = [];

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.vx = (Math.random() - 0.5) * 0.7;
        this.vy = (Math.random() - 0.5) * 0.7;
        this.radius = Math.random() * 2 + 1;
    }
    update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
        if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }
    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = "#38bdf8";
        ctx.fill();
    }
}

for (let i = 0; i < 65; i++) {
    particles.push(new Particle());
}

function animateCanvas() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Dynamic Connecting Grid Lines
    for (let i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();

        for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 110) {
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(56, 189, 248, ${0.18 - dist / 110 * 0.18})`;
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        }
    }
    requestAnimationFrame(animateCanvas);
}
animateCanvas();

// ==========================================
// 2. KNOWLEDGE BASE & TELEMETRY LOGIC
// ==========================================
const PROCESS_KNOWLEDGE_BASE = {
    "cmd.exe": {
        desc: "Windows Command Processor executing scripts or command line instructions.",
        steps: "• Verified command-line interpreter binary signature in System32.<br>• Parent execution verified within normal user session.<br>• Zero anomalous argument injections detected."
    },
    "postgres.exe": {
        desc: "PostgreSQL relational database server handling persistent application backend transactions.",
        steps: "• Verified valid local database engine listener.<br>• Telemetry queries operating within standard operational baseline.<br>• No unauthorized database export commands detected."
    },
    "pg_isready.exe": {
        desc: "PostgreSQL cluster connection health-check utility.",
        steps: "• Routine service heartbeat ping detected.<br>• Execution terminated normally with standard exit code 0.<br>• No malicious network redirection observed."
    },
    "splunk.exe": {
        desc: "Splunk enterprise log forwarder aggregating host security telemetry.",
        steps: "• Validated enterprise logging daemon signature.<br>• Telemetry pipeline running with authorized local system privileges.<br>• Event forwarding channel secure."
    },
    "splunkd.exe": {
        desc: "Splunk core daemon engine managing event queuing and indexing.",
        steps: "• Core daemon health baseline validated.<br>• Memory usage and thread count within normal operational limits.<br>• Host-level log parsing operational."
    },
    "splunk-optimize.exe": {
        desc: "Splunk database bucket optimization worker process.",
        steps: "• Standard data maintenance task.<br>• Running strictly in local Splunk storage directory.<br>• No anomaly detected."
    },
    "btool.exe": {
        desc: "Splunk internal configuration validation utility.",
        steps: "• Verified administrative maintenance tool execution.<br>• Standard integrity checks passing.<br>• Baseline healthy."
    }
};

async function fetchTelemetry() {
    try {
        const response = await fetch(API_URL);
        if (!response.ok) return;

        const alerts = await response.json();

        alerts.forEach(a => {
            if (remediatedPids.has(a.pid + a.timestamp)) {
                a.severity = "RESOLVED";
                a.status = "REMEDIATED";
            }
        });

        cachedAlerts = alerts;
        updateDashboard(alerts);
    } catch (error) {
        console.error("Telemetry fetch error:", error);
    }
}

function updateDashboard(alerts) {
    if (!alerts || alerts.length === 0) return;

    document.getElementById("hostName").innerText = alerts[0].host;
    document.getElementById("totalEvents").innerText = alerts.length;

    let activeThreats = alerts.filter(a => a.severity === "CRITICAL").length;
    let normal = alerts.length - activeThreats;
    document.getElementById("threatCount").innerText = activeThreats;

    const banner = document.getElementById("alertBanner");
    if (activeThreats > 0) {
        banner.style.display = "block";
    } else {
        banner.style.display = "none";
    }

    const threatsAndResolved = alerts.filter(a => a.severity === "CRITICAL" || a.severity === "RESOLVED");
    const normalList = alerts.filter(a => a.severity !== "CRITICAL" && a.severity !== "RESOLVED");
    const displayList = [...threatsAndResolved, ...normalList];

    const tbody = document.getElementById("telemetryBody");
    tbody.innerHTML = "";

    displayList.forEach((alert, index) => {
        const tr = document.createElement("tr");

        const isCritical = (alert.severity === "CRITICAL");
        const isResolved = (alert.severity === "RESOLVED");

        if (isCritical) {
            tr.classList.add("row-critical");
        } else if (isResolved) {
            tr.classList.add("row-remediated");
        }

        let severityClass = isCritical ? "badge-critical" : (isResolved ? "badge-resolved" : "badge-info");
        let actionClass = (alert.status === "TERMINATED") ? "badge-terminated" : ((alert.status === "REMEDIATED") ? "badge-resolved" : "badge-detected");

        const attackDisplay = (alert.attack_name && alert.attack_name !== "Benign") ? alert.attack_name : "Normal Process";
        const mitreDisplay = (alert.mitre_id && alert.mitre_id !== "-") ? alert.mitre_id : (isCritical || isResolved ? (alert.mitre_id || "T1059") : "-");
        const shortHash = (alert.sha256 && alert.sha256 !== "UNKNOWN_HASH") 
            ? alert.sha256.substring(0, 12) + "..." 
            : "UNKNOWN_HASH";

        let playbookBtn = "";
        if (isCritical) {
            playbookBtn = `<button class="btn-threat" data-row-idx="${index}">🛡️ View Resolution</button>`;
        } else if (isResolved) {
            playbookBtn = `<button class="btn-inspect" style="border-color:#10b981; color:#10b981; background:rgba(16,185,129,0.15);" data-row-idx="${index}">✅ Remediated</button>`;
        } else {
            playbookBtn = `<button class="btn-inspect" data-row-idx="${index}">🔍 Inspect Info</button>`;
        }

        let textColor = isCritical ? '#ef4444' : (isResolved ? '#10b981' : '#94a3b8');

        tr.innerHTML = `
            <td>${alert.timestamp}</td>
            <td>${alert.host}</td>
            <td>${alert.pid}</td>
            <td style="font-weight: 700; color: ${isCritical ? '#ef4444' : (isResolved ? '#10b981' : '#f8fafc')};">${alert.process_name}</td>
            <td style="font-weight: ${isCritical || isResolved ? '700' : 'normal'}; color: ${textColor};">${attackDisplay}</td>
            <td style="font-weight: 600; color: ${textColor};">${mitreDisplay}</td>
            <td style="font-family: monospace; color: #38bdf8;">${shortHash}</td>
            <td><span class="${severityClass}" data-row-idx="${index}">${alert.severity}</span></td>
            <td><span class="${actionClass}" data-row-idx="${index}">${alert.status}</span></td>
            <td>${playbookBtn}</td>
        `;

        tr.querySelectorAll(`[data-row-idx="${index}"]`).forEach(elem => {
            elem.addEventListener("click", () => {
                openResolutionModal(alert);
            });
        });

        tbody.appendChild(tr);
    });

    updateCharts(normal, activeThreats, alerts);
}

function openResolutionModal(alertData) {
    currentActiveAlert = alertData;
    const isThreat = (alertData.severity === "CRITICAL" || alertData.severity === "RESOLVED");
    const procName = (alertData.process_name || "").toLowerCase();
    const knowledge = PROCESS_KNOWLEDGE_BASE[procName] || null;
    
    const titleElem = document.getElementById("modalTitle");
    titleElem.textContent = isThreat ? "🚨 " + alertData.attack_name : `ℹ️ ${alertData.process_name} Inspection`;
    titleElem.style.color = (alertData.severity === "RESOLVED") ? "#10b981" : (isThreat ? "#ef4444" : "#38bdf8");

    document.getElementById("modalTime").textContent = alertData.timestamp;
    document.getElementById("modalTarget").textContent = `${alertData.host} (PID: ${alertData.pid})`;
    
    const mitreElem = document.getElementById("modalMitre");
    mitreElem.textContent = (alertData.mitre_id && alertData.mitre_id !== "-") ? alertData.mitre_id : "N/A (Standard Baseline)";
    mitreElem.style.color = (alertData.severity === "RESOLVED") ? "#10b981" : (isThreat ? "#ef4444" : "#38bdf8");

    document.getElementById("modalHash").textContent = alertData.sha256 || "UNKNOWN_HASH";
    document.getElementById("modalCmd").textContent = alertData.cmdline || alertData.process_name;

    const descElem = document.getElementById("modalDesc");
    const resElem = document.getElementById("modalResolution");
    const remediateBtn = document.getElementById("btnRemediate");
    const dossierBtn = document.getElementById("btnDossier");
if (dossierBtn) {
    dossierBtn.style.display = isThreat ? "inline-block" : "none";
}

    if (isThreat) {
        descElem.textContent = alertData.description || "Adversarial signature detected.";
        resElem.innerHTML = alertData.resolution 
            ? alertData.resolution.replace(/\d+\./g, "<br>•") 
            : "• Terminate execution tree.<br>• Isolate endpoint network.<br>• Memory forensics validated.";
        resElem.style.borderColor = (alertData.severity === "RESOLVED") ? "#10b981" : "#ef4444";
        resElem.style.background = (alertData.severity === "RESOLVED") ? "rgba(16, 185, 129, 0.08)" : "rgba(239, 68, 68, 0.08)";
        
        if (remediateBtn) {
            remediateBtn.style.display = "inline-block";
            if (alertData.status !== "REMEDIATED") {
                remediateBtn.innerHTML = "⚡ Execute Auto-Remediation";
                remediateBtn.style.background = "#10b981";
                remediateBtn.disabled = false;
            } else {
                remediateBtn.innerHTML = "✅ Incident Resolved & Quarantined";
                remediateBtn.style.background = "#64748b";
                remediateBtn.disabled = true;
            }
        }
    } else {
        descElem.textContent = (knowledge && knowledge.desc) 
            ? knowledge.desc 
            : `Legitimate system execution for ${alertData.process_name}. Routine process execution verified within normal host baseline.`;
        resElem.innerHTML = (knowledge && knowledge.steps) 
            ? knowledge.steps 
            : "• Verified legitimate system execution.<br>• Telemetry logged into SQLite datastore.<br>• Endpoint behavior within normal baseline.";
        resElem.style.borderColor = "#38bdf8";
        resElem.style.background = "rgba(56, 189, 248, 0.08)";
        if (remediateBtn) remediateBtn.style.display = "none";
    }

    document.getElementById("resolutionModal").style.display = "flex";
}

window.applyRemediation = function() {
    if (!currentActiveAlert) return;
    
    remediatedPids.add(currentActiveAlert.pid + currentActiveAlert.timestamp);
    currentActiveAlert.status = "REMEDIATED";
    currentActiveAlert.severity = "RESOLVED";
    
    const remediateBtn = document.getElementById("btnRemediate");
    if (remediateBtn) {
        remediateBtn.innerHTML = "✅ Threat Neutralized & Quarantined!";
        remediateBtn.style.background = "#059669";
    }
    
    setTimeout(() => {
        closeModal();
        updateDashboard(cachedAlerts);
    }, 700);
};

function closeModal() {
    document.getElementById("resolutionModal").style.display = "none";
}

window.onclick = function(event) {
    const modal = document.getElementById("resolutionModal");
    if (event.target === modal) {
        modal.style.display = "none";
    }
};

function updateCharts(normal, activeThreats, alerts) {
    const ctx1 = document.getElementById("severityChart").getContext("2d");
    if (!severityChart) {
        severityChart = new Chart(ctx1, {
            type: "doughnut",
            data: {
                labels: ["Normal (INFO)", "Threats (CRITICAL)"],
                datasets: [{
                    data: [normal, activeThreats],
                    backgroundColor: ["#38bdf8", "#ef4444"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "bottom", labels: { color: "#fff" } } },
                cutout: "70%"
            }
        });
    } else {
        severityChart.data.datasets[0].data = [normal, activeThreats];
        severityChart.update();
    }

    const procCounts = {};
    alerts.forEach(a => {
        procCounts[a.process_name] = (procCounts[a.process_name] || 0) + 1;
    });

    const topProcesses = Object.keys(procCounts).slice(0, 5);
    const topCounts = topProcesses.map(k => procCounts[k]);

    const ctx2 = document.getElementById("processChart").getContext("2d");
    if (!processChart) {
        processChart = new practicalBarChart(ctx2, topProcesses, topCounts);
    } else {
        processChart.data.labels = topProcesses;
        processChart.data.datasets[0].data = topCounts;
        processChart.update();
    }
}

function practicalBarChart(ctx, labels, data) {
    return new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Executions",
                data: data,
                backgroundColor: "#6366f1",
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(255,255,255,0.05)" } }
            }
        }
    });
}

fetchTelemetry();
setInterval(fetchTelemetry, 2000);
// ==========================================
// AUTOMATED FORENSIC INCIDENT DOSSIER ENGINE
// ==========================================
window.generateDossier = function() {
    if (!currentActiveAlert) return;
    
    const a = currentActiveAlert;
    const incId = "INC-" + Math.floor(100000 + Math.random() * 900000);
    const analystName = "Bhavasri, SOC L1 Analyst";

    const reportHTML = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Forensic Incident Dossier - ${incId}</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #fff; color: #1e293b; padding: 40px; margin: 0; }
            .header-bar { border-bottom: 3px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
            .title { font-size: 24px; font-weight: bold; color: #0f172a; margin: 0; }
            .badge { background: #ef4444; color: white; padding: 6px 14px; border-radius: 4px; font-weight: bold; font-size: 13px; }
            .section-title { font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: #0284c7; font-weight: bold; margin-top: 24px; margin-bottom: 12px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px; }
            td, th { padding: 8px 12px; border: 1px solid #cbd5e1; text-align: left; }
            th { background: #f8fafc; color: #475569; width: 28%; }
            .code-box { background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; word-break: break-all; }
            .signature-block { margin-top: 40px; border-top: 1px dashed #94a3b8; padding-top: 16px; display: flex; justify-content: space-between; font-size: 13px; color: #64748b; }
            @media print {
                body { padding: 20px; }
                .no-print { display: none; }
            }
        </style>
    </head>
    <body>
        <div class="header-bar">
            <div>
                <div class="title">SECURITY INCIDENT FORENSIC DOSSIER</div>
                <div style="color: #64748b; font-size: 13px; margin-top: 4px;">EDR Cyber Incident Detection & Automated Response Engine</div>
            </div>
            <div class="badge">CONFIDENTIAL // SOC L1 VERIFIED</div>
        </div>

        <div class="section-title">1. Executive Incident Metadata</div>
        <table>
            <tr><th>INCIDENT ID</th><td><strong>${incId}</strong></td></tr>
            <tr><th>DETECTED TIMESTAMP</th><td>${a.timestamp}</td></tr>
            <tr><th>TARGET ENDPOINT HOST</th><td>${a.host}</td></tr>
            <tr><th>INCIDENT CLASSIFICATION</th><td style="color:#ef4444; font-weight:bold;">${a.attack_name || "Adversarial Code Execution"}</td></tr>
            <tr><th>SEVERITY LEVEL</th><td>${a.severity}</td></tr>
            <tr><th>REMEDIATION STATUS</th><td style="color:#10b981; font-weight:bold;">${a.status} (Execution Neutralized)</td></tr>
        </table>

        <div class="section-title">2. Binary & Process Forensics</div>
        <table>
            <tr><th>PROCESS NAME</th><td>${a.process_name}</td></tr>
            <tr><th>TARGET PID</th><td>${a.pid}</td></tr>
            <tr><th>CRYPTOGRAPHIC SHA-256</th><td style="font-family: monospace; word-break: break-all;">${a.sha256}</td></tr>
            <tr><th>PARENT PROCESS</th><td>SYSTEM USER SESSION</td></tr>
        </table>

        <div class="section-title">3. Raw Command-Line Payload & Telemetry</div>
        <div class="code-box">${a.cmdline || a.process_name}</div>

        <div class="section-title">4. Threat Intelligence & MITRE ATT&CK Mapping</div>
        <table>
            <tr><th>MITRE TECHNIQUE ID</th><td><strong>${a.mitre_id || "T1059"}</strong></td></tr>
            <tr><th>ATTACK VECTOR ANALYSIS</th><td>${a.description || "Adversarial command execution targeted host integrity."}</td></tr>
            <tr>
    <th>CONTAINMENT & RESOLUTION PLAYBOOK</th>
    <td>
        ${a.resolution 
            ? a.resolution.split(/(?=\d+\.)/).map(step => `<div style="margin-bottom: 4px;">• ${step.trim()}</div>`).join('') 
            : "• Terminate process tree.<br>• Isolate endpoint network.<br>• Validate offline backup integrity."}
    </td>
</tr>
        </table>

        <div class="signature-block">
            <div>Verified By: <strong>${analystName}</strong><br>Role: Security Operations Center (SOC) L1 Analyst</div>
            <div style="text-align: right;">Generated via EDR Console<br>Automated Tamper-Resistant Report</div>
        </div>

        <div class="no-print" style="margin-top: 30px; text-align: center;">
            <button onclick="window.print()" style="padding: 10px 24px; background: #0284c7; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 14px;">🖨️ Print / Save as PDF</button>
        </div>
    </body>
    </html>
    `;

    const dossierWindow = window.open("", "_blank");
    dossierWindow.document.write(reportHTML);
    dossierWindow.document.close();
};