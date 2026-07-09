document.addEventListener("DOMContentLoaded", () => {
    // Global chart instances
    let distributionChart = null;
    let attackTypesChart = null;
    let activityChart = null;
    
    let currentLogFilter = "all";

    // Setup filter button listeners
    const logFilters = document.querySelectorAll(".log-filter-btn");
    logFilters.forEach(btn => {
        btn.addEventListener("click", (e) => {
            logFilters.forEach(b => b.classList.remove("active", "btn-primary"));
            logFilters.forEach(b => b.classList.add("btn-outline-secondary"));
            
            btn.classList.remove("btn-outline-secondary");
            btn.classList.add("active", "btn-primary");
            
            currentLogFilter = btn.dataset.filter;
            fetchLogs();
        });
    });

    // Initial Load
    fetchStats();
    fetchLogs();

    // Auto Refresh every 5 seconds
    setInterval(() => {
        fetchStats(true); // silent refresh (don't redraw charts to prevent jumpiness)
    }, 5000);

    // Fetch and render stats cards & charts
    function fetchStats(silent = false) {
        fetch("/api/dashboard/stats")
            .then(res => res.json())
            .then(data => {
                // Update numerical values
                document.getElementById("total-requests").innerText = data.summary.total_requests;
                document.getElementById("blocked-requests").innerText = data.summary.blocked_requests;
                document.getElementById("sanitized-requests").innerText = data.summary.sanitized_requests;
                document.getElementById("avg-score").innerText = data.summary.average_score + "%";
                document.getElementById("avg-latency").innerText = data.summary.average_latency_ms.toFixed(1) + " ms";
                document.getElementById("false-positives").innerText = data.summary.false_positives;

                if (!silent) {
                    renderCharts(data);
                }
            })
            .catch(err => console.error("Error loading stats:", err));
    }

    // Fetch and render transaction logs
    function fetchLogs() {
        const tbody = document.getElementById("logs-tbody");
        if (!tbody) return;

        fetch(`/api/dashboard/logs?action=${currentLogFilter}&limit=25`)
            .then(res => res.json())
            .then(logs => {
                tbody.innerHTML = "";
                if (logs.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No request logs captured matching filter.</td></tr>`;
                    return;
                }

                logs.forEach(log => {
                    const row = document.createElement("tr");
                    
                    // Format Action badge
                    let badgeClass = "badge-allow";
                    if (log.action_taken === "block") badgeClass = "badge-block";
                    else if (log.action_taken === "sanitize") badgeClass = "badge-sanitize";
                    else if (log.action_taken === "warn") badgeClass = "badge-warn";

                    // Format matched rules
                    const rulesStr = log.matched_detectors.length > 0 
                        ? log.matched_detectors.map(r => `<span class="badge bg-secondary me-1" style="font-size:0.7rem">${r}</span>`).join("")
                        : '<span class="text-muted" style="font-size:0.75rem">None</span>';

                    // Formatting datetime string
                    const dateObj = new Date(log.timestamp);
                    const formattedTime = dateObj.toLocaleTimeString() + " " + dateObj.toLocaleDateString();

                    // Formatting sanitized prompt
                    const sanitizedBlock = log.sanitized_prompt 
                        ? `<p class="mt-2 mb-0 text-info" style="font-size:0.8rem"><strong>Sanitized:</strong> ${escapeHTML(log.sanitized_prompt)}</p>` 
                        : "";

                    // False Positive Button Text/Style
                    const fpBtnClass = log.is_false_positive ? "btn-success" : "btn-outline-warning";
                    const fpBtnText = log.is_false_positive ? "False Positive (Flagged)" : "Review False Positive";

                    row.innerHTML = `
                        <td>${formattedTime}</td>
                        <td><code>${log.client_ip}</code></td>
                        <td>
                            <pre class="code-view">${escapeHTML(log.raw_prompt)}</pre>
                            ${sanitizedBlock}
                        </td>
                        <td><strong class="${log.threat_score > 50 ? 'text-danger' : 'text-success'}">${log.threat_score}%</strong></td>
                        <td><span class="${badgeClass}">${log.action_taken.toUpperCase()}</span></td>
                        <td>${rulesStr}</td>
                        <td>
                            <div class="d-flex flex-column gap-1">
                                <span class="text-muted" style="font-size: 0.75rem">Latency: ${log.latency_ms.toFixed(1)}ms</span>
                                ${log.action_taken === "block" ? `
                                    <button class="btn btn-sm ${fpBtnClass} fp-toggle-btn" style="font-size:0.75rem" data-id="${log.id}">
                                        ${fpBtnText}
                                    </button>
                                ` : ""}
                            </div>
                        </td>
                    `;
                    tbody.appendChild(row);
                });

                // Attach button listener
                document.querySelectorAll(".fp-toggle-btn").forEach(btn => {
                    btn.addEventListener("click", () => {
                        const logId = btn.dataset.id;
                        toggleFalsePositive(logId, btn);
                    });
                });
            })
            .catch(err => console.error("Error loading logs:", err));
    }

    // Toggle False Positive action API call
    function toggleFalsePositive(logId, buttonElement) {
        fetch(`/api/dashboard/logs/${logId}/false-positive`, { method: "POST" })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    if (data.is_false_positive) {
                        buttonElement.classList.remove("btn-outline-warning");
                        buttonElement.classList.add("btn-success");
                        buttonElement.innerText = "False Positive (Flagged)";
                    } else {
                        buttonElement.classList.remove("btn-success");
                        buttonElement.classList.add("btn-outline-warning");
                        buttonElement.innerText = "Review False Positive";
                    }
                    // Refresh metrics totals silently
                    fetchStats(true);
                }
            })
            .catch(err => console.error("Error toggling false positive status:", err));
    }

    // Escape raw HTML strings safely
    function escapeHTML(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    // Setup and render Chart.js graphics
    function renderCharts(data) {
        // 1. Threat Distribution Doughnut Chart
        const distCtx = document.getElementById("threatDistributionChart");
        if (distCtx) {
            const distData = [
                data.distribution.allow,
                data.distribution.warn,
                data.distribution.sanitize,
                data.distribution.block
            ];
            
            if (distributionChart) {
                distributionChart.data.datasets[0].data = distData;
                distributionChart.update();
            } else {
                distributionChart = new Chart(distCtx, {
                    type: "doughnut",
                    data: {
                        labels: ["Allow (0-25)", "Warn (26-50)", "Sanitize (51-75)", "Block (76-100)"],
                        datasets: [{
                            data: distData,
                            backgroundColor: ["#10b981", "#f59e0b", "#8b5cf6", "#ef4444"],
                            borderWidth: 1,
                            borderColor: "rgba(255,255,255,0.08)"
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: "bottom",
                                labels: { color: "#94a3b8", font: { family: "Inter" } }
                            }
                        }
                    }
                });
            }
        }

        // 2. Top Attack Categories Bar Chart
        const attackCtx = document.getElementById("topAttackTypesChart");
        if (attackCtx) {
            const labels = ["Direct", "Indirect", "Jailbreak", "Extraction", "Obfuscation", "Heuristics"];
            const attackData = [
                data.attack_types.direct_injection,
                data.attack_types.indirect_injection,
                data.attack_types.jailbreak,
                data.attack_types.data_extraction,
                data.attack_types.encoding,
                data.attack_types.heuristics
            ];

            if (attackTypesChart) {
                attackTypesChart.data.datasets[0].data = attackData;
                attackTypesChart.update();
            } else {
                attackTypesChart = new Chart(attackCtx, {
                    type: "bar",
                    data: {
                        labels: labels,
                        datasets: [{
                            label: "Attacks Detected",
                            data: attackData,
                            backgroundColor: "rgba(139, 92, 246, 0.65)",
                            borderColor: "#8b5cf6",
                            borderWidth: 1,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            x: { grid: { display: false }, ticks: { color: "#94a3b8" } },
                            y: { grid: { color: "rgba(255,255,255,0.08)" }, ticks: { color: "#94a3b8", precision: 0 } }
                        }
                    }
                });
            }
        }

        // 3. Recent Activity Line Chart
        const activityCtx = document.getElementById("recentActivityChart");
        if (activityCtx) {
            const labels = data.timeline.labels;
            const requests = data.timeline.requests;
            const blocks = data.timeline.blocks;

            if (activityChart) {
                activityChart.data.labels = labels;
                activityChart.data.datasets[0].data = requests;
                activityChart.data.datasets[1].data = blocks;
                activityChart.update();
            } else {
                activityChart = new Chart(activityCtx, {
                    type: "line",
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: "Total Requests",
                                data: requests,
                                borderColor: "#3b82f6",
                                backgroundColor: "rgba(59, 130, 246, 0.15)",
                                fill: true,
                                tension: 0.3,
                                borderWidth: 2
                            },
                            {
                                label: "Blocked Attacks",
                                data: blocks,
                                borderColor: "#ef4444",
                                backgroundColor: "rgba(239, 68, 68, 0.15)",
                                fill: true,
                                tension: 0.3,
                                borderWidth: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: "top",
                                labels: { color: "#94a3b8" }
                            }
                        },
                        scales: {
                            x: { grid: { display: false }, ticks: { color: "#94a3b8" } },
                            y: { grid: { color: "rgba(255,255,255,0.08)" }, ticks: { color: "#94a3b8", precision: 0 } }
                        }
                    }
                });
            }
        }
    }
});
