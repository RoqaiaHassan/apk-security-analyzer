let selectedFile = null;
let currentScanId = null;
let socket = null;
let currentFindings = [];
let permChart = null;
let cryptoChart = null;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
});

function initCharts() {
    const ctx1 = document.getElementById('permChart').getContext('2d');
    permChart = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: ['1', '2', '3', '4', '5', '6'],
            datasets: [{
                label: 'Permissions',
                data: [12, 19, 3, 5, 2, 3],
                borderColor: '#00f2fe',
                tension: 0.4,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { display: false }, y: { display: false } }
        }
    });

    const ctx2 = document.getElementById('cryptoChart').getContext('2d');
    cryptoChart = new Chart(ctx2, {
        type: 'line',
        data: {
            labels: ['1', '2', '3', '4', '5', '6'],
            datasets: [{
                label: 'Crypto Ops',
                data: [5, 12, 8, 15, 10, 20],
                borderColor: '#00e676',
                tension: 0.4,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { display: false }, y: { display: false } }
        }
    });
}

function handleFileSelect(event) {
    const files = event.target.files;
    if (files.length > 0) {
        selectedFile = files[0];
        document.getElementById('filePathDisplay').value = selectedFile.name + ` (${(selectedFile.size / (1024*1024)).toFixed(2)} MB)`;
        logConsole(`[FILE] Selected file: ${selectedFile.name}`);
    }
}

async function startAnalysis() {
    if (!selectedFile) {
        alert("الرجاء اختيار ملف APK أولاً!");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    logConsole("[UPLOAD] Uploading and analyzing APK file...");
    updateProgress(30, "Analyzing APK & Manifest");
    document.getElementById('startBtn').disabled = true;

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error("Analysis failed");
        }

        const data = await response.json();
        currentScanId = data.id || data.scan_id;
        logConsole(`[SCAN] Analysis complete! Scan ID: ${currentScanId}`);
        updateProgress(100, "Completed");

        currentFindings = data.findings || [];
        renderTable(currentFindings);

        if (data.counts) {
            cryptoChart.data.datasets[0].data = [
                data.counts.Critical || 0,
                data.counts.High || 0,
                data.counts.Medium || 0,
                data.counts.Low || 0
            ];
            cryptoChart.update();
        }

    } catch (err) {
        logConsole(`[ERROR] ${err.message}`);
    } finally {
        document.getElementById('startBtn').disabled = false;
    }
}

function updateProgress(percent, stage) {
    document.getElementById('progressBar').style.width = `${percent}%`;
    document.getElementById('progressText').innerText = `${percent}%`;
    document.getElementById('stageStatus').innerText = `STATIC ANALYSIS: ${stage} (${percent}%)`;
}

function logConsole(msg) {
    const box = document.getElementById('consoleBox');
    box.innerHTML += `<div>${msg}</div>`;
    box.scrollTop = box.scrollHeight;
}

async function fetchResults(scanId) {
    try {
        const res = await fetch(`/api/scan/${scanId}`);
        const data = await res.json();
        currentFindings = data.findings || [];
        renderTable(currentFindings);

        // Update charts with actual findings distribution
        if (data.counts) {
            cryptoChart.data.datasets[0].data = [
                data.counts.Critical || 0,
                data.counts.High || 0,
                data.counts.Medium || 0,
                data.counts.Low || 0
            ];
            cryptoChart.update();
        }

    } catch (e) {
        logConsole(`[ERROR] Failed to fetch scan results: ${e.message}`);
    }
}

function renderTable(findings) {
    const tbody = document.getElementById('vulnTbody');
    tbody.innerHTML = '';

    if (findings.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-muted);">لم يتم العثور على ثغرات أمنية. التطبيق سليم!</td></tr>`;
        return;
    }

    findings.forEach((item, index) => {
        const sevClass = `sev-${item.severity.toLowerCase()}`;
        const row = document.createElement('tr');
        row.className = 'vuln-row';
        row.onclick = () => showDetails(item);

        row.innerHTML = `
            <td><span class="badge-sev ${sevClass}">${item.severity}</span></td>
            <td style="direction:ltr; text-align:right;">
                <div style="font-weight:bold; color:var(--text-primary);">${item.vulnerability}</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">${item.file}:${item.line}</div>
            </td>
            <td><code style="color:var(--accent-cyan);">${item.algorithm}</code></td>
            <td><span style="font-family:monospace; color:var(--text-muted);">${item.rule_id}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function filterTable() {
    const searchVal = document.getElementById('searchInput').value.toLowerCase();
    const sevVal = document.getElementById('severityFilter').value;

    const filtered = currentFindings.filter(item => {
        const matchesSearch = item.vulnerability.toLowerCase().includes(searchVal) || 
                              item.file.toLowerCase().includes(searchVal) ||
                              item.algorithm.toLowerCase().includes(searchVal);
        const matchesSev = (sevVal === 'ALL') || (item.severity === sevVal);
        return matchesSearch && matchesSev;
    });

    renderTable(filtered);
}

function showDetails(item) {
    document.getElementById('modalTitle').innerText = `${item.vulnerability} (${item.rule_id})`;
    document.getElementById('modalBody').innerHTML = `
        <p><strong>مستوى الخطورة:</strong> <span class="badge-sev sev-${item.severity.toLowerCase()}">${item.severity}</span></p>
        <p><strong>التصنيف:</strong> ${item.category}</p>
        <p><strong>الخوارزمية المكتشفة:</strong> <code>${item.algorithm}</code></p>
        <p><strong>الموقع في الكود:</strong> <code>${item.file}:${item.line}</code></p>
        <hr style="border-color:var(--card-border); margin:10px 0;">
        <p><strong>وصف المشكلة:</strong> ${item.description}</p>
        <p><strong>السبب (Why It Matters):</strong> ${item.reason}</p>
        <p><strong>الدليل (Evidence):</strong> <pre style="background:#050811; padding:10px; color:#38bdf8; border-radius:4px; font-size:0.8rem;">${item.evidence}</pre></p>
        <hr style="border-color:var(--card-border); margin:10px 0;">
        <p><strong>التوصية للإصلاح:</strong> ${item.recommendation}</p>
        <p><strong>البديل الآمن (Secure Alternative):</strong> <code style="color:#00e676;">${item.secure_alternative}</code></p>
    `;
    document.getElementById('detailsModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('detailsModal').style.display = 'none';
}

function downloadReport() {
    if (!currentScanId) {
        alert("الرجاء إجراء فحص أولاً لتحميل التقرير!");
        return;
    }
    window.open(`/api/report/${currentScanId}`, '_blank');
}
