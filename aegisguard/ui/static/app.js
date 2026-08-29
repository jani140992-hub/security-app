// AegisGuard Enterprise SOC Dashboard Controller

const INITIAL_ALERTS = [
    { timestamp: "10:42:15", severity: "CRITICAL", title: "Adversary C2 Beacon Hit: 198.51.100.42", src_ip: "198.51.100.42", rule_id: "AEGIS-IOC-001", status: "ACTIVE" },
    { timestamp: "10:41:50", severity: "HIGH", title: "PowerShell Suspicious Download Cradle", src_ip: "10.0.4.18", rule_id: "SIG-0001", status: "INVESTIGATING" },
    { timestamp: "10:40:02", severity: "CRITICAL", title: "LSASS Process Memory Dump via Comsvcs", src_ip: "10.0.4.22", rule_id: "SIG-0002", status: "CONTAINED" },
    { timestamp: "10:38:44", severity: "HIGH", title: "Brute-Force Authentication Threshold Reached", src_ip: "192.168.1.105", rule_id: "AEGIS-CORR-001", status: "TRIAGED" },
    { timestamp: "10:35:12", severity: "MEDIUM", title: "Dynamic DNS Resolution from Database Server", src_ip: "10.0.12.5", rule_id: "SIG-0013", status: "MONITORING" }
];

const MITRE_TACTICS = [
    { id: "TA0043", name: "Recon", count: 25 },
    { id: "TA0042", name: "Resource Dev", count: 25 },
    { id: "TA0001", name: "Initial Access", count: 30 },
    { id: "TA0002", name: "Execution", count: 30 },
    { id: "TA0003", name: "Persistence", count: 25 },
    { id: "TA0004", name: "Priv Escalation", count: 20 },
    { id: "TA0005", name: "Defense Evasion", count: 35 },
    { id: "TA0006", name: "Credential Access", count: 30 },
    { id: "TA0007", name: "Discovery", count: 35 },
    { id: "TA0008", name: "Lateral Movement", count: 25 },
    { id: "TA0009", name: "Collection", count: 25 },
    { id: "TA0011", name: "Command & Control", count: 25 },
    { id: "TA0010", name: "Exfiltration", count: 15 },
    { id: "TA0040", name: "Impact", count: 15 }
];

function switchTab(tabName) {
    const tabs = ["triage", "mitre", "cve", "compliance", "soar"];
    tabs.forEach(t => {
        const btn = document.getElementById(`tab-${t}`);
        const view = document.getElementById(`view-${t}`);
        if (t === tabName) {
            btn.className = "py-4 border-b-2 border-cyan-500 text-cyan-400 font-semibold focus:outline-none";
            view.classList.remove("hidden");
        } else {
            btn.className = "py-4 border-b-2 border-transparent text-slate-400 hover:text-slate-200 focus:outline-none";
            view.classList.add("hidden");
        }
    });
}

function renderAlerts(alerts) {
    const tbody = document.getElementById("alerts-table-body");
    tbody.innerHTML = "";
    alerts.forEach(a => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-slate-800/30 transition";

        const sevClass = a.severity === "CRITICAL"
            ? "bg-red-500/20 text-red-400 border border-red-500/30"
            : (a.severity === "HIGH" ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" : "bg-blue-500/20 text-blue-400 border border-blue-500/30");

        tr.innerHTML = `
            <td class="py-3 px-4 text-slate-400">${a.timestamp}</td>
            <td class="py-3 px-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${sevClass}">${a.severity}</span></td>
            <td class="py-3 px-4 text-slate-100 font-semibold">${a.title}</td>
            <td class="py-3 px-4 text-cyan-400">${a.src_ip}</td>
            <td class="py-3 px-4 text-slate-400">${a.rule_id}</td>
            <td class="py-3 px-4"><span class="text-[11px] text-emerald-400 font-bold">${a.status}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderMitreGrid() {
    const grid = document.getElementById("mitre-matrix-grid");
    grid.innerHTML = "";
    MITRE_TACTICS.forEach(t => {
        const card = document.createElement("div");
        card.className = "bg-slate-950/80 border border-slate-800 p-3 rounded-lg hover:border-cyan-500/50 transition cursor-pointer";
        card.innerHTML = `
            <div class="text-[10px] text-slate-500 font-mono">${t.id}</div>
            <div class="text-xs font-bold text-slate-200 mt-1">${t.name}</div>
            <div class="text-lg font-mono font-extrabold text-cyan-400 mt-2">${t.count} <span class="text-[10px] font-normal text-slate-500">techs</span></div>
        `;
        grid.appendChild(card);
    });
}

function performCveSearch() {
    const query = document.getElementById("cve-search-input").value.trim().toLowerCase();
    const container = document.getElementById("cve-results-list");
    container.innerHTML = "";

    if (!query) {
        container.innerHTML = `<div class="text-slate-500 text-xs font-mono">Please enter a search query above.</div>`;
        return;
    }

    // Mock search results
    const sampleResults = [
        { id: "CVE-2021-44228", title: "Apache Log4j JNDI Remote Code Execution (Log4Shell)", score: 10.0, sev: "CRITICAL", cwe: "CWE-502", kev: true },
        { id: "CVE-2022-22965", title: "Spring Framework RCE via Data Binding (Spring4Shell)", score: 9.8, sev: "CRITICAL", cwe: "CWE-94", kev: true },
        { id: "CVE-2024-3400", title: "Palo Alto Networks PAN-OS GlobalProtect Command Injection", score: 10.0, sev: "CRITICAL", cwe: "CWE-78", kev: true }
    ];

    sampleResults.forEach(c => {
        const card = document.createElement("div");
        card.className = "bg-slate-950/80 border border-slate-800 p-4 rounded-xl flex items-center justify-between";
        card.innerHTML = `
            <div>
                <div class="flex items-center gap-3 mb-1">
                    <span class="text-sm font-bold text-white font-mono">${c.id}</span>
                    <span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono text-[10px] font-bold">CVSS ${c.score} ${c.sev}</span>
                    <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">${c.cwe}</span>
                    ${c.kev ? '<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-mono text-[10px] font-bold">CISA KEV</span>' : ''}
                </div>
                <p class="text-xs text-slate-400">${c.title}</p>
            </div>
            <button class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono">View Advisory</button>
        `;
        container.appendChild(card);
    });
}

function simulateAttackEvent() {
    const newAlert = {
        timestamp: new Date().toTimeString().split(" ")[0],
        severity: "CRITICAL",
        title: "Active Kerberoasting & Token Theft Detected",
        src_ip: "10.0.105.12",
        rule_id: "SIG-0019",
        status: "AUTO-CONTAINING"
    };
    INITIAL_ALERTS.unshift(newAlert);
    renderAlerts(INITIAL_ALERTS);
}

function simulateSyslogBatch() {
    alert("Ingested 1,500 sample Syslog and CloudTrail events. 0 new critical correlation alerts.");
}

function triggerPlaybook(name, target) {
    alert(`Triggered automated SOAR playbook ${name} targeting resource ${target}. Execution completed with status: SUCCESS.`);
}

document.addEventListener("DOMContentLoaded", () => {
    renderAlerts(INITIAL_ALERTS);
    renderMitreGrid();
});
