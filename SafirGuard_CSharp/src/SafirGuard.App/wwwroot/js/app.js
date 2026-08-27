// SafirGuard .NET Suite Client Controller

let isScanning = false;
let currentTab = "scan-tab";

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initShieldToggle();
    initStopButton();
    startStatusPolling();
});

// 1. Navigation Tab Handling
function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            navItems.forEach(n => n.classList.remove("active"));
            item.classList.add("active");

            const tabId = item.getAttribute("data-tab");
            currentTab = tabId;

            document.querySelectorAll(".tab-content").forEach(tab => {
                tab.classList.remove("active");
            });

            const activeTabElem = document.getElementById(tabId);
            if (activeTabElem) {
                activeTabElem.classList.add("active");
            }

            // Tab-specific lazy loading
            if (tabId === "autoruns-tab") loadAutoruns();
            if (tabId === "process-tab") loadProcesses();
            if (tabId === "network-tab") loadNetwork();
            if (tabId === "quarantine-tab") loadQuarantine();
        });
    });
}

// 2. Shield Toggle
function initShieldToggle() {
    const cb = document.getElementById("shield-toggle-cb");
    const statusText = document.getElementById("shield-status-text");

    cb.addEventListener("change", async () => {
        try {
            const res = await fetch("/api/shield/toggle", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enable: cb.checked })
            });
            const data = await res.json();
            statusText.textContent = data.isActive ? "Aktif" : "Devre Dışı";
            statusText.style.color = data.isActive ? "var(--status-safe)" : "var(--status-danger)";
        } catch (e) {
            console.error("Shield toggle error:", e);
        }
    });
}

// 3. Status Polling Loop
function startStatusPolling() {
    fetchStatus();
    setInterval(fetchStatus, 1000);
}

async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();
        updateUI(data);
    } catch (e) {
        console.error("Status fetch error:", e);
    }
}

function updateUI(data) {
    const scanner = data.scanner;
    isScanning = scanner.isScanning;

    // Stat Cards
    document.getElementById("stat-scanned-count").textContent = scanner.scannedFiles || 0;
    document.getElementById("stat-threats-count").textContent = scanner.threatsCount || 0;
    document.getElementById("stat-vault-count").textContent = data.quarantineCount || 0;
    document.getElementById("quarantine-badge").textContent = data.quarantineCount || 0;
    document.getElementById("stat-time-elapsed").textContent = `${scanner.elapsedSeconds || 0}s`;

    // Canary Trap Data
    if (data.canaryTrap) {
        document.getElementById("canary-trap-count").textContent = `${data.canaryTrap.totalTraps} Dizin Korumada`;
        const alertCountElem = document.getElementById("canary-alert-count");
        alertCountElem.textContent = `${data.canaryTrap.triggeredAlerts} Saldırı`;
        if (data.canaryTrap.triggeredAlerts > 0) {
            alertCountElem.className = "text-red";
        }

        const pathsList = document.getElementById("canary-paths-list");
        if (pathsList && data.canaryTrap.trapPaths) {
            pathsList.innerHTML = data.canaryTrap.trapPaths.map(p => `<li>🛡️ ${escapeHtml(p)}</li>`).join("");
        }
    }

    // Progress Bar & Monitor
    const progressBar = document.getElementById("scan-progress-bar");
    const progressPercent = document.getElementById("scan-progress-percent");
    const activeTitle = document.getElementById("scan-active-title");
    const currentTarget = document.getElementById("scan-current-target");
    const statusSummary = document.getElementById("scan-status-summary");
    const stopBtn = document.getElementById("btn-stop-scan");

    progressBar.style.width = `${scanner.progress}%`;
    progressPercent.textContent = `${scanner.progress}%`;

    if (isScanning) {
        activeTitle.textContent = `💎 SafirGuard ${scanner.scanType} Taraması Devam Ediyor...`;
        currentTarget.textContent = scanner.currentTarget || "Dosyalar taranıyor...";
        statusSummary.textContent = `${scanner.scannedFiles} dosya incelendi`;
        stopBtn.classList.remove("hidden");
        setSystemStatus("warning", "TARAMA YAPILIYOR...");
    } else {
        if (scanner.progress === 100) {
            activeTitle.textContent = "✅ Son Tarama Tamamlandı";
            currentTarget.textContent = scanner.threatsCount > 0 
                ? `Dikkat: ${scanner.threatsCount} adet potansiyel tehdit tespit edildi!` 
                : "Sisteminiz temiz ve güvende.";
            statusSummary.textContent = "Tamamlandı";
        } else {
            activeTitle.textContent = "Savunma Motoru Hazır";
            currentTarget.textContent = "Başlatmak için bir tarama modu seçin";
            statusSummary.textContent = "Hazır";
        }
        stopBtn.classList.add("hidden");

        if (scanner.threatsCount > 0) {
            setSystemStatus("warning", `${scanner.threatsCount} TEHDİT BULUNDU`);
        } else {
            setSystemStatus("safe", "GÜVENLİ & KORUNUYOR");
        }
    }

    // Threats Table
    renderThreatsTable(scanner.threats || []);

    // Logs view
    renderLogs(scanner.logs || []);
}

function setSystemStatus(type, text) {
    const pill = document.getElementById("system-status-pill");
    const textElem = document.getElementById("system-status-text");

    pill.className = `status-pill status-${type}`;
    textElem.textContent = text;
}

// 4. Threats Table Renderer
function renderThreatsTable(threats) {
    const tbody = document.getElementById("threats-table-body");
    const badge = document.getElementById("threats-list-badge");
    badge.textContent = `${threats.length} Tehdit`;

    if (threats.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Henüz tespit edilen bir tehdit yok. Sistem temiz.</td></tr>`;
        return;
    }

    tbody.innerHTML = threats.map(t => {
        const sevClass = (t.severity || "Medium").toLowerCase();
        const safeFilePath = escapeHtml(t.filePath || "");
        const safeThreatName = escapeHtml(t.threatName || "Unknown");
        const safeThreatType = escapeHtml(t.threatType || "Malware");

        return `
            <tr>
                <td><strong>${safeThreatName}</strong></td>
                <td><span class="threat-tag threat-${sevClass}">${safeThreatType} (${t.severity})</span></td>
                <td><small>${escapeHtml(t.detectionMethod || 'Engine')}</small></td>
                <td style="max-width: 280px; word-break: break-all; font-family: var(--font-mono); font-size: 11px;">${safeFilePath}</td>
                <td>
                    ${t.filePath && !t.filePath.startsWith("PID:") ? `
                    <button class="btn btn-danger btn-sm" onclick="quarantineThreat('${safeFilePath}', '${safeThreatName}', '${safeThreatType}')">
                        🔒 Karantinaya Al
                    </button>` : (t.pid ? `
                    <button class="btn btn-danger btn-sm" onclick="killProcess(${t.pid})">
                        🛑 Süreci Durdur
                    </button>` : '-')}
                </td>
            </tr>
        `;
    }).join("");
}

// 5. Scan Launchers
async function launchScan(type) {
    if (isScanning) {
        alert("Halihazırda devam eden bir tarama var!");
        return;
    }
    try {
        const res = await fetch("/api/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: type })
        });
        const data = await res.json();
        if (data.status === "error") {
            alert(data.message);
        }
    } catch (e) {
        console.error("Scan launch error:", e);
    }
}

async function launchCustomScan() {
    const input = document.getElementById("custom-scan-path");
    const path = input.value.trim();
    if (!path) {
        alert("Lütfen taranacak bir dosya veya klasör yolu girin!");
        return;
    }
    try {
        await fetch("/api/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: "custom", customPath: path })
        });
    } catch (e) {
        console.error("Custom scan error:", e);
    }
}

function initStopButton() {
    document.getElementById("btn-stop-scan").addEventListener("click", async () => {
        await fetch("/api/scan/stop", { method: "POST" });
    });
}

// 6. Quarantine Actions
async function quarantineThreat(filePath, threatName, threatType) {
    if (!confirm(`'${filePath}' dosyasını güvenli karantina kasasına kilitlemek istiyor musunuz?`)) return;

    try {
        const res = await fetch("/api/quarantine/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: "quarantine",
                filePath: filePath,
                threatName: threatName,
                threatType: threatType
            })
        });
        const data = await res.json();
        if (data.status === "success") {
            alert("Dosya başarıyla şifrelenerek karantina kasasına izole edildi!");
            fetchStatus();
        } else {
            alert("İşlem başarısız oldu.");
        }
    } catch (e) {
        console.error("Quarantine error:", e);
    }
}

async function loadQuarantine() {
    const tbody = document.getElementById("quarantine-table-body");
    try {
        const res = await fetch("/api/quarantine/list");
        const data = await res.json();
        const items = data.items || [];

        if (items.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Karantina kasası boş.</td></tr>`;
            return;
        }

        tbody.innerHTML = items.map(item => `
            <tr>
                <td><strong>${escapeHtml(item.fileName)}</strong></td>
                <td><span class="threat-tag threat-high">${escapeHtml(item.threatName)}</span></td>
                <td><small>${item.quarantinedAt}</small></td>
                <td style="max-width: 250px; font-family: var(--font-mono); font-size: 11px; word-break: break-all;">${escapeHtml(item.originalPath)}</td>
                <td><code style="font-size: 10px;">${item.sha256.substring(0, 16)}...</code></td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="restoreQuarantine('${item.id}')">🔓 Geri Yükle</button>
                    <button class="btn btn-danger btn-sm" onclick="deleteQuarantine('${item.id}')">🗑️ Kalıcı Sil</button>
                </td>
            </tr>
        `).join("");
    } catch (e) {
        console.error("Quarantine list error:", e);
    }
}

async function restoreQuarantine(id) {
    if (!confirm("Dosyayı orijinal konumuna geri yüklemek istediğinize emin misiniz?")) return;
    try {
        const res = await fetch("/api/quarantine/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "restore", id: id })
        });
        const data = await res.json();
        if (data.status === "success") {
            alert("Dosya orijinal konumuna geri yüklendi.");
            loadQuarantine();
            fetchStatus();
        }
    } catch (e) {
        console.error("Restore error:", e);
    }
}

async function deleteQuarantine(id) {
    if (!confirm("Bu dosyayı kasadan KALICI olarak imha etmek istediğinize emin misiniz?")) return;
    try {
        const res = await fetch("/api/quarantine/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "delete", id: id })
        });
        const data = await res.json();
        if (data.status === "success") {
            alert("Dosya kasadan kalıcı olarak imha edildi.");
            loadQuarantine();
            fetchStatus();
        }
    } catch (e) {
        console.error("Delete error:", e);
    }
}

// 7. Autoruns Inspector (Norton Power Eraser)
async function loadAutoruns() {
    const tbody = document.getElementById("autoruns-table-body");
    try {
        const res = await fetch("/api/autoruns");
        const data = await res.json();
        const entries = data.entries || [];

        if (entries.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Hiç başlangıç kaydı bulunamadı.</td></tr>`;
            return;
        }

        tbody.innerHTML = entries.map(e => {
            const riskClass = (e.riskLevel || "Safe").toLowerCase();
            return `
                <tr>
                    <td><strong>${escapeHtml(e.name)}</strong></td>
                    <td><small>${escapeHtml(e.location)}</small></td>
                    <td><span class="threat-tag threat-${riskClass}">${e.riskLevel}</span></td>
                    <td style="max-width: 320px; word-break: break-all; font-family: var(--font-mono); font-size: 11px;">${escapeHtml(e.command)}</td>
                    <td><small>${e.reasons.length ? e.reasons.join(', ') : 'Standart Başlangıç Programı'}</small></td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Autoruns fetch error:", e);
    }
}

// 8. Process Monitor (Kaspersky System Watcher)
async function loadProcesses() {
    const tbody = document.getElementById("process-table-body");
    try {
        const res = await fetch("/api/processes");
        const data = await res.json();
        const procs = data.processes || [];

        if (procs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">İşlem listesi alınamadı.</td></tr>`;
            return;
        }

        tbody.innerHTML = procs.slice(0, 50).map(p => {
            const riskClass = (p.riskLevel || "Safe").toLowerCase();
            return `
                <tr>
                    <td><code>${p.pid}</code></td>
                    <td><strong>${escapeHtml(p.name)}</strong></td>
                    <td><span class="threat-tag threat-${riskClass}">${p.riskLevel}</span></td>
                    <td>${p.memoryMb} MB</td>
                    <td style="max-width: 250px; font-family: var(--font-mono); font-size: 11px; word-break: break-all;">${escapeHtml(p.executablePath || '-')}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="killProcess(${p.pid})">🛑 Sonlandır</button>
                    </td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Processes fetch error:", e);
    }
}

async function killProcess(pid) {
    if (!confirm(`PID ${pid} sürecini sonlandırmak istiyor musunuz?`)) return;
    try {
        const res = await fetch("/api/process/kill", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pid: pid })
        });
        const data = await res.json();
        alert(data.message || "İşlem tamamlandı.");
        loadProcesses();
        fetchStatus();
    } catch (e) {
        console.error("Kill proc error:", e);
    }
}

// 9. Network Auditor (Bitdefender / Norton Firewall)
async function loadNetwork() {
    const tbody = document.getElementById("network-table-body");
    try {
        const res = await fetch("/api/network");
        const data = await res.json();
        const conns = data.connections || [];

        if (conns.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Aktif TCP bağlantısı bulunamadı.</td></tr>`;
            return;
        }

        tbody.innerHTML = conns.slice(0, 50).map(c => {
            const riskClass = (c.riskLevel || "Safe").toLowerCase();
            return `
                <tr>
                    <td><code>${escapeHtml(c.localEndpoint)}</code></td>
                    <td><code>${escapeHtml(c.remoteEndpoint)}</code></td>
                    <td><span class="badge">${c.protocol} (${c.state})</span></td>
                    <td><span class="threat-tag threat-${riskClass}">${c.riskLevel}</span></td>
                    <td><small>${escapeHtml(c.reason)}</small></td>
                </tr>
            `;
        }).join("");
    } catch (e) {
        console.error("Network fetch error:", e);
    }
}

// 10. Logs Renderer
function renderLogs(logs) {
    const container = document.getElementById("console-logs-container");
    if (!container) return;

    container.innerHTML = logs.map(l => `
        <div class="log-line">
            <span class="log-time">[${l.time}]</span>
            <span class="log-${l.level}">${escapeHtml(l.message)}</span>
        </div>
    `).join("");

    container.scrollTop = container.scrollHeight;
}

function clearLogsView() {
    const container = document.getElementById("console-logs-container");
    if (container) container.innerHTML = "";
}

// 11. AI Threat & Prompt Tester
async function testAiPrompt() {
    const input = document.getElementById("ai-test-input");
    const resultBox = document.getElementById("ai-test-result-box");
    const promptText = input.value.trim();

    if (!promptText) {
        alert("Lütfen analiz edilecek bir prompt metni veya model girdisi yazın!");
        return;
    }

    resultBox.classList.remove("hidden");
    resultBox.innerHTML = "<em>🤖 Yapay Zeka Güvenlik Modeli Tarafından Analiz Ediliyor...</em>";
    resultBox.className = "ai-result-panel";

    try {
        const res = await fetch("/api/ai/test-prompt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt: promptText })
        });
        const data = await res.json();

        if (data.isSafe) {
            resultBox.className = "ai-result-panel ai-result-safe";
            resultBox.innerHTML = `<strong>[✓] GÜVENLİ:</strong> ${escapeHtml(data.message)}`;
        } else {
            resultBox.className = "ai-result-panel ai-result-threat";
            resultBox.innerHTML = `
                <strong>[⚠️] YAPAY ZEKA SALDIRISI / TEHDİT TESPİT EDİLDİ!</strong><br>
                <strong>Tehdit Adı:</strong> ${escapeHtml(data.threatName)}<br>
                <strong>Kategori:</strong> ${escapeHtml(data.threatType)} (${data.severity})<br>
                <strong>Açıklama:</strong> ${escapeHtml(data.description)}
            `;
        }
    } catch (e) {
        resultBox.className = "ai-result-panel ai-result-threat";
        resultBox.innerHTML = `Hata: ${escapeHtml(e.message)}`;
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
