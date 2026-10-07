const API_BASE = `${window.location.origin}/api/v1`;
let AUTH_TOKEN = localStorage.getItem("securescan_token") || null;
let CURRENT_USER = JSON.parse(localStorage.getItem("securescan_user") || "null");
let trendChartInstance = null;
let severityChartInstance = null;
let currentScanScopeFilter = 'all';
let pendingScanId = null;

// ============================================================================
// UX HELPERS, PRESETS & AUTH TABS
// ============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;
    const iconClass = type === 'success' ? 'fa-circle-check' : (type === 'error' ? 'fa-circle-exclamation' : 'fa-circle-info');
    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(50px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function togglePasswordVisibility() {
    const passInput = document.getElementById("login-password");
    const icon = document.getElementById("password-eye-icon");
    if (!passInput || !icon) return;
    if (passInput.type === "password") {
        passInput.type = "text";
        icon.className = "fa-solid fa-eye-slash";
    } else {
        passInput.type = "password";
        icon.className = "fa-solid fa-eye";
    }
}

function toggleAuthTab(tab) {
    const loginForm = document.getElementById("login-form");
    const signupForm = document.getElementById("signup-form");
    const tabLoginBtn = document.getElementById("tab-login-btn");
    const tabSignupBtn = document.getElementById("tab-signup-btn");
    const headingTitle = document.getElementById("auth-heading-title");
    const headingSub = document.getElementById("auth-heading-sub");

    if (tab === 'signup') {
        if (loginForm) loginForm.style.display = "none";
        if (signupForm) signupForm.style.display = "block";
        if (tabLoginBtn) tabLoginBtn.classList.remove("active");
        if (tabSignupBtn) tabSignupBtn.classList.add("active");
        if (headingTitle) headingTitle.textContent = "Create Account";
        if (headingSub) headingSub.textContent = "Register a new profile to start scanning your projects.";
    } else {
        if (signupForm) signupForm.style.display = "none";
        if (loginForm) loginForm.style.display = "block";
        if (tabSignupBtn) tabSignupBtn.classList.remove("active");
        if (tabLoginBtn) tabLoginBtn.classList.add("active");
        if (headingTitle) headingTitle.textContent = "Welcome Back";
        if (headingSub) headingSub.textContent = "Sign in to access your security console & scan pipeline.";
    }
}

function checkPasswordStrength(val) {
    const fill = document.getElementById("pass-strength-fill");
    if (!fill) return;
    let strength = 0;
    if (val.length >= 6) strength += 25;
    if (val.length >= 10) strength += 25;
    if (/[A-Z]/.test(val)) strength += 25;
    if (/[0-9]/.test(val) || /[^A-Za-z0-9]/.test(val)) strength += 25;

    fill.style.width = strength + "%";
    if (strength <= 25) {
        fill.style.background = "#ff477e";
    } else if (strength <= 50) {
        fill.style.background = "#f59e0b";
    } else if (strength <= 75) {
        fill.style.background = "#3b82f6";
    } else {
        fill.style.background = "#00f2fe";
    }
}

function fillTargetPreset(target, type) {
    const targetInput = document.getElementById("scan-target-input");
    if (targetInput) targetInput.value = target;
    
    const radios = document.querySelectorAll('input[name="target_type"]');
    radios.forEach(radio => {
        if (radio.value === type) {
            radio.checked = true;
            radio.closest('.type-card')?.classList.add('active');
        } else {
            radio.closest('.type-card')?.classList.remove('active');
        }
    });
    showToast(`Target set to ${target}`, 'info');
}

function applyScanPreset(presetType) {
    const checkboxes = document.querySelectorAll('input[name="scan_types"]');
    checkboxes.forEach(cb => {
        if (presetType === 'all') {
            cb.checked = true;
        } else if (presetType === 'web') {
            cb.checked = ['Full Vulnerability Scan', 'OWASP Top 10 Scan', 'SSL Scan', 'API Security Scan'].includes(cb.value);
        } else if (presetType === 'code') {
            cb.checked = ['Source Code Security Scan', 'Dependency Scan'].includes(cb.value);
        }
    });
    showToast(`Scan profile applied: ${presetType.toUpperCase()}`, 'info');
}

function filterScanScope(scope) {
    currentScanScopeFilter = scope;
    const btnAll = document.getElementById("btn-filter-all");
    const btnMy = document.getElementById("btn-filter-my");
    if (scope === 'my') {
        if (btnAll) btnAll.classList.remove("active");
        if (btnMy) btnMy.classList.add("active");
    } else {
        if (btnMy) btnMy.classList.remove("active");
        if (btnAll) btnAll.classList.add("active");
    }
    loadDashboardData();
}

function initGlobalSearch() {
    const searchInput = document.getElementById("global-search-input");
    if (!searchInput) return;

    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        
        const projectCards = document.querySelectorAll(".project-card");
        projectCards.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = text.includes(query) ? "" : "none";
        });

        const cveItems = document.querySelectorAll(".cve-item-card");
        cveItems.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = text.includes(query) ? "" : "none";
        });

        const pipelineRows = document.querySelectorAll("#scan-pipeline-table tr");
        pipelineRows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? "" : "none";
        });
    });

    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            searchInput.focus();
        } else if (e.altKey && e.key >= '1' && e.key <= '8') {
            e.preventDefault();
            const tabMap = ['dashboard', 'assets', 'new-scan', 'project-scanner', 'cve-db', 'ai-assistant', 'reports', 'wazuh'];
            const tabIndex = parseInt(e.key) - 1;
            if (tabMap[tabIndex]) switchTab(tabMap[tabIndex]);
        }
    });
}

// ============================================================================
// AUTHENTICATION & USER REGISTRATION
// ============================================================================

async function authFetch(url, options = {}) {
    const opts = { ...options };
    opts.headers = { ...(options.headers || {}) };
    if (AUTH_TOKEN) {
        opts.headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
    }
    const response = await fetch(url, opts);
    if (response.status === 401) {
        logout("Your session has expired. Please log in again.");
        throw new Error("Not authenticated");
    }
    return response;
}

function showLoginScreen(message) {
    const loginScreen = document.getElementById("login-screen");
    const appLayout = document.getElementById("app-layout");
    if (loginScreen) loginScreen.style.display = "flex";
    if (appLayout) appLayout.style.display = "none";
    const errEl = document.getElementById("login-error");
    if (message && errEl) {
        errEl.textContent = message;
        errEl.style.display = "block";
    } else if (errEl) {
        errEl.style.display = "none";
    }
}

function showApp() {
    const loginScreen = document.getElementById("login-screen");
    const appLayout = document.getElementById("app-layout");
    if (loginScreen) loginScreen.style.display = "none";
    if (appLayout) appLayout.style.display = "flex";
    applyRolePermissions();
    initializeAppData();
    showToast(`Welcome back, ${CURRENT_USER?.full_name || CURRENT_USER?.username || 'User'}!`, 'success');
}

function logout(message) {
    AUTH_TOKEN = null;
    CURRENT_USER = null;
    localStorage.removeItem("securescan_token");
    localStorage.removeItem("securescan_user");
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    showLoginScreen(message);
}

async function handleLoginSubmit(e) {
    e.preventDefault();
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const submitBtn = document.getElementById("login-submit-btn");
    const errEl = document.getElementById("login-error");

    if (errEl) errEl.style.display = "none";
    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Signing in...'; }

    try {
        const res = await fetch(`${API_BASE}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: "Invalid username or password." }));
            throw new Error(err.detail || "Login failed.");
        }
        const data = await res.json();
        AUTH_TOKEN = data.access_token;
        CURRENT_USER = data.user;
        localStorage.setItem("securescan_token", AUTH_TOKEN);
        localStorage.setItem("securescan_user", JSON.stringify(CURRENT_USER));
        showApp();
    } catch (err) {
        if (errEl) { errEl.textContent = err.message; errEl.style.display = "block"; }
        showToast(err.message, 'error');
    } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Sign In to Security Console'; }
    }
}

async function handleSignupSubmit(e) {
    e.preventDefault();
    const full_name = document.getElementById("signup-fullname").value.trim();
    const username = document.getElementById("signup-username").value.trim();
    const email = document.getElementById("signup-email").value.trim();
    const password = document.getElementById("signup-password").value;
    const submitBtn = document.getElementById("signup-submit-btn");
    const errEl = document.getElementById("signup-error");

    if (errEl) errEl.style.display = "none";
    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating Profile...'; }

    try {
        const res = await fetch(`${API_BASE}/auth/signup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password, full_name })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: "Registration failed." }));
            throw new Error(err.detail || "Registration failed.");
        }
        const data = await res.json();
        AUTH_TOKEN = data.access_token;
        CURRENT_USER = data.user;
        localStorage.setItem("securescan_token", AUTH_TOKEN);
        localStorage.setItem("securescan_user", JSON.stringify(CURRENT_USER));
        showToast("Profile created successfully! Welcome to SecureScan.", "success");

        showApp();
    } catch (err) {
        if (errEl) { errEl.textContent = err.message; errEl.style.display = "block"; }
        showToast(err.message, 'error');
    } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<i class="fa-solid fa-user-plus"></i> Create Profile & Sign In'; }
    }
}

function applyRolePermissions() {
    const nameEl = document.getElementById("display-user-name");
    if (nameEl && CURRENT_USER) nameEl.textContent = CURRENT_USER.full_name || CURRENT_USER.username;
}

async function verifySession() {
    if (!AUTH_TOKEN) {
        showLoginScreen();
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/auth/me`, {
            headers: { "Authorization": `Bearer ${AUTH_TOKEN}` }
        });
        if (!res.ok) throw new Error("Session invalid");
        const user = await res.json();
        CURRENT_USER = user;
        localStorage.setItem("securescan_user", JSON.stringify(CURRENT_USER));
        showApp();
    } catch (e) {
        logout();
    }
}

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    const loginForm = document.getElementById("login-form");
    if (loginForm) loginForm.addEventListener("submit", handleLoginSubmit);

    const signupForm = document.getElementById("signup-form");
    if (signupForm) signupForm.addEventListener("submit", handleSignupSubmit);

    document.querySelectorAll(".role-chip").forEach(chip => {
        chip.addEventListener("click", () => {
            toggleAuthTab('login');
            const userVal = chip.getAttribute("data-user");
            document.getElementById("login-username").value = userVal;
            document.getElementById("login-password").value = chip.getAttribute("data-pass");
            showToast(`Quick credentials loaded for '${userVal}'. Click 'Sign In' to enter console.`, 'info');
        });
    });

    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            if (confirm("Log out of SecureScan AI?")) logout();
        });
    }

    verifySession();
});

function initializeAppData() {
    initNavigation();
    initGlobalSearch();
    try { initCharts(); } catch(e) { console.log("Chart init skipped:", e); }
    loadDashboardData();
    loadAssetsData();
    loadCveCatalog();
    initSastFileSelection();

    const scanForm = document.getElementById("scan-launcher-form");
    if (scanForm) scanForm.addEventListener("submit", handleScanSubmit);

    const btnAiChat = document.getElementById("btn-send-ai-chat");
    if (btnAiChat) btnAiChat.addEventListener("click", handleAIChatSend);

    const btnRefreshScans = document.getElementById("btn-refresh-scans");
    if (btnRefreshScans) btnRefreshScans.addEventListener("click", () => {
        loadDashboardData();
        showToast("Pipeline refreshed", "info");
    });

    const btnHeaderNewScan = document.getElementById("btn-header-new-scan");
    if (btnHeaderNewScan) btnHeaderNewScan.addEventListener("click", () => switchTab("new-scan"));

    const sastForm = document.getElementById("sast-upload-form");
    if (sastForm) {
        sastForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const fileInput = document.getElementById("sast-file-input");
            if (fileInput && fileInput.files.length > 0) {
                handleFileUpload(fileInput.files[0]);
            } else {
                showToast("Please select a project archive file first!", "error");
            }
        });
    }

    const fileInput = document.getElementById("sast-file-input");
    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            const statusEl = document.getElementById("upload-status-message");
            if (e.target.files.length > 0) {
                if (statusEl) statusEl.innerHTML = `<span style="color: #00f2fe;"><i class="fa-solid fa-file-zipper"></i> Selected File: <strong>${e.target.files[0].name}</strong>. Click 'Start SAST Audit' to upload.</span>`;
            }
        });
    }

    document.querySelectorAll('.type-card').forEach(card => {
        card.addEventListener('click', () => {
            document.querySelectorAll('.type-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');
        });
    });
}

let pollInterval = null;

async function handleFileUpload(file) {
    const fileInput = document.getElementById("sast-file-input");
    const statusEl = document.getElementById("upload-status-message");
    const validExts = [".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"];
    const isArchive = validExts.some(ext => file && file.name.toLowerCase().endsWith(ext));

    if (!file || !isArchive) {
        showToast("Please select a valid compressed archive file (.zip, .rar, .7z, .tar.gz).", "error");
        if (statusEl) statusEl.innerHTML = `<span style="color: #ef4444;">Invalid file type. Please select a compressed archive file.</span>`;
        if (fileInput) fileInput.value = "";
        return;
    }

    if (statusEl) statusEl.innerHTML = `<span style="color: #f59e0b;"><i class="fa-solid fa-spinner fa-spin"></i> Uploading ${file.name} to SAST Scan Engine...</span>`;

    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await authFetch(`${API_BASE}/scans/upload`, {
            method: "POST",
            body: formData
        });
        const data = await response.json();
        pendingScanId = data.id;
        if (statusEl) statusEl.innerHTML = `<span style="color: #10b981;"><i class="fa-solid fa-circle-check"></i> Upload Successful! ID: ${data.id}. Scanning project...</span>`;
        showToast(`SAST scan job queued! ID: ${data.id}`, "success");
        
        setTimeout(async () => {
            switchTab("dashboard");
            await loadDashboardData();
            startAutoPolling(data.id);
        }, 1000);
    } catch (err) {
        if (statusEl) statusEl.innerHTML = `<span style="color: #ef4444;">Upload error: ${err.message}</span>`;
        showToast(`Upload error: ${err.message}`, "error");
    } finally {
        if (fileInput) fileInput.value = "";
    }
}

function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetTab = item.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".tab-view").forEach(el => el.classList.remove("active"));

    const activeNav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
    const activeView = document.getElementById(`view-${tabId}`);

    if (activeNav) activeNav.classList.add("active");
    if (activeView) activeView.classList.add("active");

    if (tabId === 'wazuh') {
        loadWazuhDashboard();
    }

    // Instantly scroll viewport back to top (0px) so header aligns right below topbar
    const viewport = document.querySelector(".content-viewport");
    if (viewport) viewport.scrollTop = 0;
    window.scrollTo(0, 0);
}


function getScanVulnerabilityCounts(s) {
    let crit = s.critical_count || 0;
    let high = s.high_count || 0;
    let med = s.medium_count || 0;
    let low = s.low_count || 0;

    if ((crit + high + med + low === 0) && Array.isArray(s.vulnerabilities) && s.vulnerabilities.length > 0) {
        s.vulnerabilities.forEach(v => {
            const sev = String(v.severity || '').toLowerCase();
            if (sev.includes('crit')) crit++;
            else if (sev.includes('high')) high++;
            else if (sev.includes('med')) med++;
            else low++;
        });
    }

    return { crit, high, med, low, total: crit + high + med + low };
}

function updateDashboardCharts(scans) {
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;

    (scans || []).forEach(s => {
        const counts = getScanVulnerabilityCounts(s);
        critCount += counts.crit;
        highCount += counts.high;
        medCount += counts.med;
        lowCount += counts.low;
    });

    const totalVulns = critCount + highCount + medCount + lowCount;

    const canvasTrend = document.getElementById("trendChart");
    if (canvasTrend) {
        const ctxTrend = canvasTrend.getContext("2d");
        if (trendChartInstance) trendChartInstance.destroy();

        const cData = [Math.round(critCount * 0.4), Math.round(critCount * 0.6), Math.round(critCount * 0.8), critCount];
        const hData = [Math.round(highCount * 0.4), Math.round(highCount * 0.6), Math.round(highCount * 0.8), highCount];
        const maxVal = Math.max(5, critCount + 2, highCount + 2);

        trendChartInstance = new Chart(ctxTrend, {
            type: 'line',
            data: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                datasets: [
                    {
                        label: 'Critical Vulnerabilities',
                        data: cData,
                        borderColor: '#ff0844',
                        backgroundColor: 'rgba(255, 8, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'High Severity',
                        data: hData,
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#475569', font: { weight: '600' } } } },
                scales: {
                    x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(0,0,0,0.06)' } },
                    y: { ticks: { color: '#64748b', precision: 0 }, grid: { color: 'rgba(0,0,0,0.06)' }, beginAtZero: true, suggestedMax: maxVal }
                }
            }
        });
    }

    const canvasSev = document.getElementById("severityChart");
    if (canvasSev) {
        const ctxSev = canvasSev.getContext("2d");
        if (severityChartInstance) severityChartInstance.destroy();

        const chartData = totalVulns > 0 ? [critCount, highCount, medCount, lowCount] : [0, 0, 0, 1];
        const chartLabels = totalVulns > 0 ? ['Critical', 'High', 'Medium', 'Low'] : ['Clean / No Risks'];
        const chartColors = totalVulns > 0 ? ['#e11d48', '#d97706', '#0284c7', '#7c3aed'] : ['#10b981'];

        severityChartInstance = new Chart(ctxSev, {
            type: 'doughnut',
            data: {
                labels: chartLabels,
                datasets: [{
                    data: chartData,
                    backgroundColor: chartColors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#475569', font: { weight: '600' } } } }
            }
        });
    }

}

function initCharts() {
    updateDashboardCharts([]);
}

async function loadDashboardData() {
    try {
        const response = await authFetch(`${API_BASE}/scans`);
        let scans = await response.json();
        
        renderProjectsGrid(scans);
        renderScanPipeline(scans);
        updateDashboardStats(scans);
        updateDashboardCharts(scans);
        loadReportsData(scans);
        return scans;
    } catch (err) {
        console.log("Error loading scans from API:", err);
        return [];
    }
}

let allLoadedProjects = [];

function renderProjectsGrid(scans) {
    allLoadedProjects = scans || [];
    const grid = document.getElementById("projects-cards-grid");
    const badge = document.getElementById("projects-count-badge");
    const carouselNav = document.getElementById("projects-carousel-nav");
    if (!grid) return;

    grid.innerHTML = "";
    const totalCount = scans ? scans.length : 0;
    if (badge) badge.innerText = `${totalCount} Projects`;

    // Show carousel nav arrow controls if there are 4 or more projects
    if (carouselNav) {
        carouselNav.style.display = totalCount > 3 ? "flex" : "none";
    }

    if (!scans || scans.length === 0) {
        grid.innerHTML = `
            <div class="glass-panel" style="width:100%; text-align:center; padding: 40px;">
                <i class="fa-solid fa-folder-open text-cyan" style="font-size:36px; margin-bottom:14px;"></i>
                <h3>No Security Projects Yet</h3>
                <p style="color:#94a3b8; font-size:13px; margin-top:6px;">Create your first security audit project to start scanning your target application or IP.</p>
                <button class="btn btn-primary" style="margin-top:16px;" onclick="switchTab('new-scan')"><i class="fa-solid fa-plus-circle"></i> Launch First Project Scan</button>
            </div>
        `;
        return;
    }

    scans.forEach(scan => {
        const card = createProjectCardElement(scan, false);
        grid.appendChild(card);
    });

    // Append the "View All Projects" end card if there are more than 3 projects
    if (scans.length > 3) {
        const seeAllCard = document.createElement("div");
        seeAllCard.className = "project-card see-all-card";
        seeAllCard.onclick = () => openAllProjectsModal();
        seeAllCard.innerHTML = `
            <div>
                <div class="see-all-icon"><i class="fa-solid fa-arrow-right"></i></div>
                <div class="see-all-title">View All Projects</div>
                <div class="see-all-sub">See all ${scans.length} projects in full grid</div>
            </div>
        `;
        grid.appendChild(seeAllCard);
    }
}

function createProjectCardElement(scan, isModal = false) {
    const card = document.createElement("div");
    card.className = "project-card";
    
    const statusColor = scan.status === 'Completed' ? '#059669' : (scan.status === 'Running' ? '#0284c7' : '#d97706');
    const score = scan.ai_analysis ? scan.ai_analysis.overall_risk_score : '0.0';
    
    let diffBadge = "";
    if (scan.remediation_diff) {
        const diff = scan.remediation_diff;
        diffBadge = `<div style="margin-top:6px;"><span class="remediation-badge" style="background:#ecfdf5; color:#047857; border:1px solid #a7f3d0; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700;"><i class="fa-solid fa-shield-check"></i> ${diff.resolved_count} Fixed | ${diff.remaining_count} Remaining</span></div>`;
    }

    const onViewDetails = isModal ? `closeAllProjectsModal(); openProjectDetails('${scan.id}');` : `openProjectDetails('${scan.id}');`;

    card.innerHTML = `
        <div>
            <div class="project-card-header">
                <div>
                    <div class="project-card-title" style="color:#0f172a; font-weight:700;">${scan.target}</div>
                    <div class="project-target-type" style="color:#0284c7; font-weight:600;"><i class="fa-solid fa-tag text-cyan"></i> ${scan.target_type}</div>
                </div>
                <span style="background:#f1f5f9; color:${statusColor}; border:1px solid ${statusColor}55; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700;">
                    <i class="fa-solid ${scan.status === 'Running' ? 'fa-spinner fa-spin' : 'fa-circle'}"></i> ${scan.status}
                </span>
            </div>

            ${diffBadge}

            <div class="project-stats-row" style="background:#f8fafc; border:1px solid #e2e8f0;">
                <div>
                    <span style="font-size:11px; color:#64748b; font-weight:600;">Vulnerabilities</span>
                    <div style="font-size:14px; font-weight:700; color:#e11d48;">${scan.total_vulnerabilities || 0} Issues</div>
                </div>
                <div style="text-align:right;">
                    <span style="font-size:11px; color:#64748b; font-weight:600;">CVSS Risk Score</span>
                    <div style="font-size:14px; font-weight:800; color:${parseFloat(score) > 5 ? '#e11d48' : '#059669'};">${score} / 10</div>
                </div>
            </div>
        </div>

        <div class="project-actions-row">
            <button class="btn btn-sm btn-primary" onclick="${onViewDetails}"><i class="fa-solid fa-eye"></i> View Status</button>
            <button class="btn btn-sm btn-outline" onclick="rescanTarget('${scan.id}')" title="Live Rescan Project"><i class="fa-solid fa-rotate-right text-cyan"></i> Rescan</button>
        </div>
    `;
    return card;
}

function scrollProjectsCarousel(direction) {
    const grid = document.getElementById("projects-cards-grid");
    if (!grid) return;
    const scrollAmount = 340 * direction;
    grid.scrollBy({ left: scrollAmount, behavior: "smooth" });
}

function openAllProjectsModal() {
    const modal = document.getElementById("all-projects-modal");
    const badge = document.getElementById("all-projects-modal-badge");
    const searchInput = document.getElementById("all-projects-search-input");
    
    if (!modal) return;
    if (badge) badge.innerText = `${allLoadedProjects.length} Projects`;
    if (searchInput) searchInput.value = "";
    
    renderAllProjectsModalGrid(allLoadedProjects);
    modal.style.display = "flex";
    document.body.style.overflow = "hidden";

    if (searchInput) {
        setTimeout(() => searchInput.focus(), 100);
    }
}

function closeAllProjectsModal() {
    const modal = document.getElementById("all-projects-modal");
    if (!modal) return;
    modal.style.display = "none";
    document.body.style.overflow = "";
}

function renderAllProjectsModalGrid(scansToRender) {
    const grid = document.getElementById("all-projects-modal-grid");
    if (!grid) return;
    grid.innerHTML = "";

    if (!scansToRender || scansToRender.length === 0) {
        grid.innerHTML = `
            <div style="grid-column: 1 / -1; text-align:center; padding: 40px; color:#64748b;">
                <i class="fa-solid fa-folder-open" style="font-size:32px; margin-bottom:10px; color:#cbd5e1;"></i>
                <p>No projects match your search query.</p>
            </div>
        `;
        return;
    }

    scansToRender.forEach(scan => {
        const card = createProjectCardElement(scan, true);
        grid.appendChild(card);
    });
}

function filterAllProjectsModal(query) {
    const cleanQuery = (query || "").toLowerCase().trim();
    if (!cleanQuery) {
        renderAllProjectsModalGrid(allLoadedProjects);
        return;
    }
    const filtered = allLoadedProjects.filter(p => 
        (p.target && p.target.toLowerCase().includes(cleanQuery)) ||
        (p.target_type && p.target_type.toLowerCase().includes(cleanQuery)) ||
        (p.status && p.status.toLowerCase().includes(cleanQuery))
    );
    renderAllProjectsModalGrid(filtered);
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        closeAllProjectsModal();
    }
});

async function openProjectDetails(scanId) {
    try {
        const res = await authFetch(`${API_BASE}/scans/${scanId}`);
        const scan = await res.json();

        switchTab("project-details");

        const heroCard = document.getElementById("project-details-hero-card");
        const banner = document.getElementById("project-remediation-banner");
        const tableBody = document.getElementById("project-vulns-table-body");

        if (heroCard) {
            const score = scan.ai_analysis ? scan.ai_analysis.overall_risk_score : '0.0';
            const statusColor = scan.status === 'Completed' ? '#059669' : '#d97706';
            
            heroCard.className = "glass-panel";
            heroCard.style.cssText = "background:#ffffff; border:1px solid #e2e8f0; border-radius:16px; padding:24px; box-shadow:0 4px 20px rgba(0,0,0,0.04);";
            heroCard.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px;">
                    <div>
                        <div style="font-size:12px; color:#0284c7; font-weight:700; letter-spacing:0.5px; text-transform:uppercase;">Project Status & Audit Overview</div>
                        <h2 style="font-size:26px; font-weight:700; margin-top:4px; color:#0f172a;">${scan.target}</h2>
                        <div style="font-size:12px; color:#64748b; margin-top:4px;">
                            <span>Target Type: <strong style="color:#0f172a;">${scan.target_type}</strong></span> &bull; 
                            <span>Created By: <strong style="color:#0f172a;">${scan.requested_by || 'user'}</strong></span> &bull; 
                            <span>Last Audit: <strong style="color:#0f172a;">${(scan.start_time || "").slice(0, 10)}</strong></span>
                        </div>
                    </div>
                    <div style="display:flex; gap:10px; align-items:center;">
                        <span style="background:#f1f5f9; color:${statusColor}; border:1px solid ${statusColor}55; padding:6px 14px; border-radius:20px; font-size:13px; font-weight:700;">
                            <i class="fa-solid ${scan.status === 'Running' ? 'fa-spinner fa-spin' : 'fa-shield-check'}"></i> ${scan.status}
                        </span>
                        <button class="btn btn-primary" onclick="rescanTarget('${scan.id}')"><i class="fa-solid fa-rotate-right"></i> Rescan Project</button>
                        <button class="btn btn-outline" onclick="viewScanReport('${scan.id}')"><i class="fa-solid fa-file-pdf"></i> Report</button>
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:16px; margin-top:20px; padding-top:16px; border-top:1px solid #e2e8f0;">
                    <div>
                        <span style="font-size:12px; color:#64748b; font-weight:600;">Total Vulnerabilities</span>
                        <div style="font-size:22px; font-weight:700; color:#e11d48; margin-top:2px;">${scan.total_vulnerabilities || 0} Findings</div>
                    </div>
                    <div>
                        <span style="font-size:12px; color:#64748b; font-weight:600;">Critical Severity</span>
                        <div style="font-size:22px; font-weight:700; color:#dc2626; margin-top:2px;">${scan.critical_count || 0} Critical</div>
                    </div>
                    <div>
                        <span style="font-size:12px; color:#64748b; font-weight:600;">High & Medium Risks</span>
                        <div style="font-size:22px; font-weight:700; color:#d97706; margin-top:2px;">${(scan.high_count || 0) + (scan.medium_count || 0)} Risks</div>
                    </div>
                    <div>
                        <span style="font-size:12px; color:#64748b; font-weight:600;">Overall CVSS Risk Score</span>
                        <div style="font-size:22px; font-weight:800; color:${parseFloat(score) > 5 ? '#e11d48' : '#059669'}; margin-top:2px;">${score} / 10</div>
                    </div>
                </div>
            `;
        }

        if (banner) {
            if (scan.remediation_diff) {
                const diff = scan.remediation_diff;
                banner.style.display = "block";
                banner.className = "remediation-hero-banner";
                banner.innerHTML = `
                    <div style="display:flex; align-items:center; gap:14px;">
                        <div style="font-size:32px; color:#059669;"><i class="fa-solid fa-shield-circle-check"></i></div>
                        <div>
                            <h4 style="font-size:16px; font-weight:700; color:#047857;">Target Live Rescan Comparison</h4>
                            <p style="font-size:13px; color:#334155; margin-top:2px;">
                                <strong>${diff.resolved_count} Vulnerabilities Resolved!</strong> &bull; ${diff.remaining_count} remaining out of ${diff.initial_count} initial findings.
                            </p>
                        </div>
                    </div>
                `;
            } else {
                banner.style.display = "none";
            }
        }

        if (tableBody) {
            tableBody.innerHTML = "";
            const vulns = scan.vulnerabilities || [];
            if (vulns.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:#64748b; padding:24px;">No vulnerabilities found on this target! Project is secure.</td></tr>`;
            } else {
                vulns.forEach(v => {
                    const sevColor = v.severity === 'Critical' ? '#e11d48' : (v.severity === 'High' ? '#d97706' : '#0284c7');
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td><strong style="color:#0f172a;">${v.title}</strong><div style="font-size:11px; color:#64748b; margin-top:2px;">${v.description}</div></td>
                        <td><span style="background:${sevColor}15; color:${sevColor}; border:1px solid ${sevColor}44; padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;">${v.severity}</span></td>
                        <td><strong style="color:#0f172a;">${v.cvss_score}</strong></td>
                        <td><code style="color:#0284c7; font-size:12px; font-weight:600;">${v.remediation}</code></td>
                    `;
                    tableBody.appendChild(tr);
                });
            }
        }

    } catch (err) {
        showToast(`Error opening project details: ${err.message}`, "error");
    }
}


function updateDashboardStats(scans) {
    const totalScans = scans.length;
    let criticalCount = 0;
    let highMediumCount = 0;
    let totalScore = 0;
    let scoreCount = 0;

    scans.forEach(s => {
        criticalCount += (s.critical_count || 0);
        highMediumCount += ((s.high_count || 0) + (s.medium_count || 0));
        if (s.ai_analysis && s.ai_analysis.overall_risk_score) {
            totalScore += parseFloat(s.ai_analysis.overall_risk_score);
            scoreCount++;
        }
    });

    const avgScore = scoreCount > 0 ? (totalScore / scoreCount).toFixed(1) : "0.0";

    const elTotal = document.getElementById("stat-total-scans");
    if (elTotal) elTotal.innerText = totalScans;

    const elCrit = document.getElementById("stat-critical-vulns");
    if (elCrit) elCrit.innerText = criticalCount;

    const elHigh = document.getElementById("stat-high-vulns");
    if (elHigh) elHigh.innerText = highMediumCount;

    const elScore = document.getElementById("stat-avg-score");
    if (elScore) elScore.innerText = `${avgScore} / 10`;
}

function renderScanPipeline(scans) {
    const tableBody = document.getElementById("scan-pipeline-table");
    if (!tableBody) return;
    tableBody.innerHTML = "";

    if (scans.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b; padding:24px;">No scans found matching scope filter. Launch a scan above.</td></tr>`;
        return;
    }

    scans.forEach(scan => {
        const tr = document.createElement("tr");
        const statusColor = scan.status === 'Completed' ? '#059669' : (scan.status === 'Running' ? '#0284c7' : '#d97706');
        
        let diffBadge = "";
        if (scan.remediation_diff) {
            const diff = scan.remediation_diff;
            diffBadge = `<div style="margin-top:4px;"><span class="remediation-badge" style="background:#ecfdf5; color:#047857; border:1px solid #a7f3d0; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700;"><i class="fa-solid fa-shield-check"></i> ${diff.resolved_count} Resolved | ${diff.remaining_count} Remaining</span></div>`;
        }

        tr.innerHTML = `
            <td>
                <strong style="color:#0f172a;">${scan.target}</strong>
                <div style="font-size:11px; color:#64748b;">User: ${scan.requested_by || 'user'}</div>
                ${diffBadge}
            </td>
            <td><span class="badge-ai" style="background:#e0f2fe; color:#0369a1; border:1px solid #7dd3fc; font-weight:600;">${(scan.scan_types || []).join(", ")}</span></td>
            <td><span style="color:${statusColor}; font-weight:600;"><i class="fa-solid ${scan.status === 'Running' ? 'fa-spinner fa-spin' : 'fa-check'}"></i> ${scan.status}</span></td>
            <td style="width: 150px;">
                <div class="progress-bar-wrap" style="background:#e2e8f0; height:8px; border-radius:4px; overflow:hidden;">
                    <div class="progress-bar-fill" style="width: ${scan.progress}%; background:#0284c7; height:100%;"></div>
                </div>
            </td>
            <td>
                <span style="color:#e11d48; font-weight:700;">${scan.critical_count || 0} Critical</span> | 
                <span style="color:#d97706; font-weight:600;">${scan.high_count || 0} High</span>
            </td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="openProjectDetails('${scan.id}')" title="View Project Status"><i class="fa-solid fa-eye"></i> Details</button>
                <button class="btn btn-sm btn-outline" onclick="rescanTarget('${scan.id}')" title="Rescan target to verify remediation"><i class="fa-solid fa-rotate-right text-cyan"></i> Rescan</button>
            </td>
        `;
        tableBody.appendChild(tr);
    });
}

async function loadReportsData(scansList = null) {
    const tableBody = document.getElementById("reports-table-body");
    if (!tableBody) return;
    tableBody.innerHTML = "";

    let scans = scansList;
    if (!scans) {
        try {
            const res = await authFetch(`${API_BASE}/scans`);
            scans = await res.json();
            if (currentScanScopeFilter === 'my' && CURRENT_USER) {
                scans = (scans || []).filter(s => s.requested_by === CURRENT_USER.username);
            }
        } catch (e) {
            scans = [];
        }
    }

    const completedScans = (scans || []).filter(s => s.status === "Completed" || s.progress > 0);

    if (completedScans.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#64748b; padding:24px;">No completed scan reports found. Run a scan to view generated reports.</td></tr>`;
        return;
    }

    completedScans.forEach(scan => {
        const riskScore = scan.ai_analysis ? scan.ai_analysis.overall_risk_score : 'N/A';
        const tokenParam = encodeURIComponent(AUTH_TOKEN || "");
        const scanDate = (scan.start_time || "").slice(0, 10);
        const tr = document.createElement("tr");

        let diffBadge = "";
        if (scan.remediation_diff) {
            const diff = scan.remediation_diff;
            diffBadge = `<div style="margin-top:4px;"><span class="remediation-badge" style="background:#ecfdf5; color:#047857; border:1px solid #a7f3d0; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700;"><i class="fa-solid fa-shield-check"></i> ${diff.resolved_count} Fixed | ${diff.remaining_count} Left</span></div>`;
        }

        tr.innerHTML = `
            <td>
                <strong style="color:#0f172a;">Security Audit Report - ${scan.id}</strong>
                <div style="font-size:11px; color:#64748b; margin-top:2px;">Run by ${scan.requested_by || 'user'} on ${scanDate}</div>
                ${diffBadge}
            </td>
            <td><span style="color:#334155; font-weight:600;">${scan.target}</span></td>
            <td><span style="color:#0f172a;">${scan.total_vulnerabilities || 0} Findings</span> (<span style="color:#e11d48; font-weight:700;">${scan.critical_count || 0} Critical</span>)</td>
            <td><span style="color:#e11d48; font-weight:700;">Risk Score: ${riskScore} / 10</span></td>
            <td>
                <a href="${API_BASE}/reports/${scan.id}/pdf?token=${tokenParam}" target="_blank" class="btn btn-sm btn-primary"><i class="fa-solid fa-file-pdf"></i> Executive Report</a>
                <a href="${API_BASE}/reports/${scan.id}/html?token=${tokenParam}" target="_blank" class="btn btn-sm btn-outline"><i class="fa-solid fa-file-code"></i> HTML</a>
                <button class="btn btn-sm btn-outline" onclick="rescanTarget('${scan.id}')" title="Rescan target"><i class="fa-solid fa-rotate-right text-cyan"></i> Rescan</button>
            </td>
        `;
        tableBody.appendChild(tr);
    });
}


async function rescanTarget(scanId) {
    try {
        showToast(`Initiating live rescan for project audit #${scanId}...`, "info");
        const res = await authFetch(`${API_BASE}/scans/${scanId}/rescan`, { method: "POST" });
        const data = await res.json();
        pendingScanId = data.id;
        showToast(`Rescan job queued! ID: ${data.id}. Re-testing target...`, "success");
        switchTab("dashboard");
        await loadDashboardData();
        startAutoPolling(data.id);
    } catch (err) {
        showToast(`Error initiating rescan: ${err.message}`, "error");
    }
}

async function deleteScan(scanId) {
    if (!confirm(`Are you sure you want to delete scan record '${scanId}'?`)) return;
    try {
        await authFetch(`${API_BASE}/scans/${scanId}`, { method: "DELETE" });
        showToast("Scan deleted successfully", "success");
        await loadDashboardData();
    } catch (e) {
        showToast(`Error deleting scan: ${e.message}`, "error");
    }
}

async function handleScanSubmit(e) {
    e.preventDefault();
    const target = document.getElementById("scan-target-input").value;
    const targetTypeEl = document.querySelector('input[name="target_type"]:checked');
    const targetType = targetTypeEl ? targetTypeEl.value : "Website URL";
    
    const checkboxes = document.querySelectorAll('input[name="scan_types"]:checked');
    const scanTypes = Array.from(checkboxes).map(cb => cb.value);

    try {
        const res = await authFetch(`${API_BASE}/scans`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, target_type: targetType, scan_types: scanTypes })
        });
        const data = await res.json();
        pendingScanId = data.id;
        showToast(`Scan Queued for ${target}! Executing live security audit...`, "success");
        switchTab("dashboard");
        await loadDashboardData();
        startAutoPolling(data.id);
    } catch (err) {
        showToast(`Error queuing scan target: ${err.message}`, "error");
    }
}

function startAutoPolling(targetScanId = null) {
    if (targetScanId) {
        pendingScanId = targetScanId;
    }
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        const scans = await loadDashboardData();
        
        if (pendingScanId) {
            const scan = (scans || []).filter(s => s.id === pendingScanId)[0];
            if (scan && scan.status === 'Completed') {
                const completedId = pendingScanId;
                pendingScanId = null;
                showToast(`Scan Completed for ${scan.target}! Opening project details...`, "success");
                openProjectDetails(completedId);
            }
        }

        const activeScans = (scans || []).filter(s => s.status === 'Running' || s.status === 'Queued');
        if (activeScans.length === 0) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }, 1500);
}

async function loadAssetsData() {
    const tableBody = document.getElementById("assets-table-body");
    if (!tableBody) return;

    try {
        const res = await authFetch(`${API_BASE}/assets`);
        const assets = await res.json();

        if (!assets || assets.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#64748b; padding:24px;">No assets registered. Click 'Register New Asset' to create one.</td></tr>`;
            return;
        }

        tableBody.innerHTML = "";
        assets.forEach(ast => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code style="color:#0284c7; font-weight:700;">${ast.id}</code></td>
                <td><strong style="color:#0f172a;">${ast.name}</strong></td>
                <td><span style="color:#475569;">${ast.target}</span></td>
                <td><span style="background:#e0f2fe; color:#0369a1; padding:3px 10px; border-radius:6px; font-size:12px; border: 1px solid #7dd3fc; font-weight:600;">${ast.asset_type}</span></td>
                <td><span style="color:#475569;">${ast.department || 'Engineering'}</span></td>
                <td><span style="color:#059669; font-weight:600;"><i class="fa-solid fa-circle-check"></i> ${ast.status || 'Active'}</span></td>
                <td>
                    <button class="btn btn-sm btn-danger" style="background:#e11d48; color:white; border:none; padding:5px 10px; border-radius:6px; cursor:pointer;" onclick="deleteAsset('${ast.id}')"><i class="fa-solid fa-trash"></i> Delete</button>
                </td>
            `;
            tableBody.appendChild(tr);
        });
    } catch (e) {
        console.log("Error loading assets:", e);
    }
}

function toggleAddAssetForm() {
    const panel = document.getElementById("add-asset-form-panel");
    if (panel) panel.style.display = panel.style.display === "none" ? "block" : "none";
}

document.addEventListener("DOMContentLoaded", () => {
    const assetForm = document.getElementById("new-asset-form");
    if (assetForm) {
        assetForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const name = document.getElementById("asset-name-input").value;
            const target = document.getElementById("asset-target-input").value;
            const asset_type = document.getElementById("asset-type-select").value;
            const owner = document.getElementById("asset-owner-input").value;

            try {
                await authFetch(`${API_BASE}/assets`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ name, target, asset_type, owner, department: "Engineering", tags: ["Infrastructure"] })
                });
                showToast("Asset registered successfully!", "success");
                toggleAddAssetForm();
                assetForm.reset();
                await loadAssetsData();
            } catch (err) {
                showToast(`Error saving asset: ${err.message}`, "error");
            }
        });
    }

    const cveForm = document.getElementById("new-cve-form");
    if (cveForm) {
        cveForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const cve_id = document.getElementById("cve-id-input").value;
            const title = document.getElementById("cve-title-input").value;
            const severity = document.getElementById("cve-severity-select").value;
            const cvss_score = parseFloat(document.getElementById("cve-cvss-input").value);
            const summary = document.getElementById("cve-summary-input").value;

            try {
                await authFetch(`${API_BASE}/vulnerabilities`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        cve_id, title, severity, cvss_score, summary,
                        cisa_kev: true, exploit_available: true,
                        affected_products: ["Production System"], published_date: new Date().toISOString().split("T")[0]
                    })
                });
                showToast("CVE record created successfully!", "success");
                toggleAddCveForm();
                cveForm.reset();
                await loadCveCatalog();
            } catch (err) {
                showToast(`Error saving CVE: ${err.message}`, "error");
            }
        });
    }

    const cveSearchInput = document.getElementById("cve-search-input");
    if (cveSearchInput) {
        cveSearchInput.addEventListener("input", (e) => {
            loadCveCatalog(e.target.value);
        });
    }
});

async function deleteAsset(assetId) {
    if (!confirm(`Are you sure you want to delete asset '${assetId}'?`)) return;
    try {
        await authFetch(`${API_BASE}/assets/${assetId}`, { method: "DELETE" });
        showToast("Asset deleted successfully", "success");
        await loadAssetsData();
    } catch (e) {
        showToast(`Error deleting asset: ${e.message}`, "error");
    }
}

async function loadCveCatalog(query = "") {
    const listContainer = document.getElementById("cve-catalog-list");
    if (!listContainer) return;

    try {
        const res = await authFetch(`${API_BASE}/vulnerabilities?query=${encodeURIComponent(query)}`);
        const cves = await res.json();

        if (!cves || cves.length === 0) {
            listContainer.innerHTML = `<div style="text-align:center; color:#64748b; padding:30px;">No CVE entries found matching query '${query}'.</div>`;
            return;
        }

        listContainer.innerHTML = "";
        cves.forEach(c => {
            const sevColor = c.severity === 'Critical' ? '#e11d48' : (c.severity === 'High' ? '#d97706' : '#0284c7');
            const card = document.createElement("div");
            card.className = "cve-item-card glass-panel";
            card.style.cssText = "padding:20px; margin-bottom:15px; border-left:5px solid " + sevColor + "; border-radius:12px; background:#ffffff; border:1px solid #e2e8f0; box-shadow:0 4px 15px rgba(0,0,0,0.03);";
            card.innerHTML = `
                <div class="cve-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="cve-title" style="font-size:16px; font-weight:700; color:#0f172a;">
                        <code style="color:#0284c7; background:#e0f2fe; border:1px solid #bae6fd; padding:3px 8px; border-radius:6px; font-weight:700;">${c.cve_id}</code> &nbsp; <span style="color:#0f172a;">${c.title}</span>
                    </div>
                    <div>
                        <span style="background:${sevColor}; color:#ffffff; font-size:11px; font-weight:800; padding:4px 10px; border-radius:12px; text-transform:uppercase; box-shadow:0 2px 8px rgba(0,0,0,0.1);">${c.severity} ${c.cvss_score}</span>
                        <button class="btn btn-sm btn-danger" style="background:#e11d48; color:white; border:none; padding:5px 10px; border-radius:6px; margin-left:10px; cursor:pointer;" onclick="deleteCve('${c.cve_id}')"><i class="fa-solid fa-trash"></i> Delete</button>
                    </div>
                </div>
                <p style="font-size:13.5px; color:#334155; margin-top:12px; line-height:1.5; font-weight:500;">${c.summary}</p>
                <div style="font-size:12px; color:#64748b; margin-top:12px; padding-top:10px; border-top:1px solid #f1f5f9;">
                    <strong style="color:#475569;">Affected:</strong> ${(c.affected_products || []).join(", ")} &nbsp;|&nbsp; <strong style="color:#475569;">Published:</strong> ${c.published_date || 'N/A'}
                </div>
            `;
            listContainer.appendChild(card);
        });
    } catch (e) {
        console.log("Error loading CVE catalog:", e);
    }
}


function toggleAddCveForm() {
    const panel = document.getElementById("add-cve-form-panel");
    if (panel) panel.style.display = panel.style.display === "none" ? "block" : "none";
}

async function deleteCve(cveId) {
    if (!confirm(`Are you sure you want to delete CVE record '${cveId}'?`)) return;
    try {
        await authFetch(`${API_BASE}/vulnerabilities/${cveId}`, { method: "DELETE" });
        showToast("CVE entry deleted", "success");
        await loadCveCatalog();
    } catch (e) {
        showToast(`Error deleting CVE: ${e.message}`, "error");
    }
}

async function handleAIChatSend() {
    const input = document.getElementById("ai-chat-input");
    const text = input.value.trim();
    if (!text) return;

    sendAiMessageToUi(text);
    input.value = "";
}

function sendAiPrompt(promptText) {
    const input = document.getElementById("ai-chat-input");
    if (input) {
        input.value = promptText;
        handleAIChatSend();
    }
}

async function sendAiMessageToUi(text) {
    const messages = document.getElementById("ai-chat-messages");
    
    const userDiv = document.createElement("div");
    userDiv.className = "chat-msg user";
    userDiv.innerHTML = `<strong style="display:block; font-size:11px; margin-bottom:4px; opacity:0.9;"><i class="fa-solid fa-user"></i> You:</strong> ${text}`;
    messages.appendChild(userDiv);
    messages.scrollTop = messages.scrollHeight;

    const loadingDiv = document.createElement("div");
    loadingDiv.className = "chat-msg ai";
    loadingDiv.id = "ai-loading-msg";
    loadingDiv.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-cyan"></i> <em>SecureScan AI is analyzing query...</em>`;
    messages.appendChild(loadingDiv);
    messages.scrollTop = messages.scrollHeight;

    try {
        const res = await authFetch(`${API_BASE}/ai/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });
        const data = await res.json();
        loadingDiv.remove();

        const aiDiv = document.createElement("div");
        aiDiv.className = "chat-msg ai";
        
        let actionPills = (data.suggested_actions || []).map(a => `<span style="background:rgba(0,242,254,0.1); color:#00f2fe; font-size:11px; padding:3px 10px; border-radius:10px; border:1px solid rgba(0,242,254,0.3); font-weight:600;">${a}</span>`).join(" ");

        aiDiv.innerHTML = `
            <div class="msg-author"><i class="fa-solid fa-robot"></i> SecureScan AI Assistant</div>
            <div class="msg-text">${data.response.replace(/\n/g, '<br>')}</div>
            <div style="margin-top:12px; display:flex; gap:6px; flex-wrap:wrap;">${actionPills}</div>
        `;
        messages.appendChild(aiDiv);
        messages.scrollTop = messages.scrollHeight;
    } catch (e) {
        loadingDiv.remove();
        const errDiv = document.createElement("div");
        errDiv.style.cssText = "color:#ef4444; padding:10px;";
        errDiv.innerText = `AI Assistant Error: ${e.message}`;
        messages.appendChild(errDiv);
    }
}

function viewScanReport(scanId) {
    window.open(`${API_BASE}/reports/${scanId}/html?token=${encodeURIComponent(AUTH_TOKEN || "")}`, '_blank');
}

function initSastFileSelection() {
    const fileInput = document.getElementById("sast-file-input");
    const dropZone = document.getElementById("sast-drop-zone");
    const sastForm = document.getElementById("sast-upload-form");

    if (!fileInput || !dropZone) return;

    fileInput.addEventListener("change", (e) => {
        if (fileInput.files && fileInput.files[0]) {
            displaySastSelectedFile(fileInput.files[0]);
        }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('dragover');
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            displaySastSelectedFile(files[0]);
        }
    });

    if (sastForm) {
        sastForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            if (!fileInput.files || fileInput.files.length === 0) {
                showToast("Please choose a project archive file (.ZIP, .TAR.GZ) to upload first.", "error");
                return;
            }

            const formData = new FormData();
            formData.append("file", fileInput.files[0]);

            const statusMsg = document.getElementById("upload-status-message");
            if (statusMsg) {
                statusMsg.innerHTML = `<div style="color:#00f2fe; padding:12px; text-align:center;"><i class="fa-solid fa-spinner fa-spin"></i> Uploading project archive and initializing static SAST analyzer...</div>`;
            }

            try {
                const res = await fetch(`${API_BASE}/scans/upload`, {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${AUTH_TOKEN}` },
                    body: formData
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || "Upload failed");
                }

                const scanObj = await res.json();
                showToast(`Archive uploaded! SAST audit started for '${scanObj.target}'.`, "success");
                if (statusMsg) statusMsg.innerHTML = "";
                clearSelectedSastFile();
                openProjectDetails(scanObj.id);
            } catch (err) {
                if (statusMsg) {
                    statusMsg.innerHTML = `<div style="color:#ef4444; padding:12px; text-align:center;"><i class="fa-solid fa-triangle-exclamation"></i> Upload Error: ${err.message}</div>`;
                }
                showToast(`Upload failed: ${err.message}`, "error");
            }
        });
    }
}

function displaySastSelectedFile(file) {
    const previewCard = document.getElementById("sast-file-preview");
    const nameEl = document.getElementById("sast-file-name");
    const sizeEl = document.getElementById("sast-file-size");

    if (!previewCard || !nameEl || !sizeEl) return;

    nameEl.textContent = file.name;
    const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
    sizeEl.textContent = sizeMb > 0.1 ? `${sizeMb} MB` : `${(file.size / 1024).toFixed(1)} KB`;
    previewCard.style.display = "flex";
}

function clearSelectedSastFile() {
    const fileInput = document.getElementById("sast-file-input");
    const previewCard = document.getElementById("sast-file-preview");
    if (fileInput) fileInput.value = "";
    if (previewCard) previewCard.style.display = "none";
}

// ============================================================================
// WAZUH SIEM & XDR INTEGRATION MODULE
// ============================================================================

let wazuhAlertsCache = [];

function toggleWazuhSettings() {
    const configCard = document.getElementById("wazuh-config-card");
    if (!configCard) return;
    if (configCard.style.display === "none" || !configCard.style.display) {
        configCard.style.display = "block";
        loadWazuhSettingsForm();
    } else {
        configCard.style.display = "none";
    }
}

async function loadWazuhSettingsForm() {
    try {
        const res = await authFetch(`${API_BASE}/wazuh/config`);
        if (!res.ok) return;
        const config = await res.json();
        
        const hostEl = document.getElementById("wazuh-cfg-host");
        const portEl = document.getElementById("wazuh-cfg-port");
        const userEl = document.getElementById("wazuh-cfg-user");
        const passEl = document.getElementById("wazuh-cfg-pass");
        const sslEl = document.getElementById("wazuh-cfg-ssl");
        const mockEl = document.getElementById("wazuh-cfg-mock");

        if (hostEl) hostEl.value = config.host || "192.168.1.100";
        if (portEl) portEl.value = config.port || 55000;
        if (userEl) userEl.value = config.user || "wazuh";
        if (passEl) passEl.value = config.password_masked || "••••••••";
        if (sslEl) sslEl.checked = !!config.verify_ssl;
        if (mockEl) mockEl.checked = config.use_mock_fallback !== false;
    } catch (e) {
        console.error("Failed to load Wazuh settings form:", e);
    }
}

async function saveWazuhSettings(e) {
    e.preventDefault();
    const btn = document.getElementById("btn-save-wazuh-cfg");
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...'; }

    const payload = {
        host: document.getElementById("wazuh-cfg-host").value.trim(),
        port: parseInt(document.getElementById("wazuh-cfg-port").value) || 55000,
        user: document.getElementById("wazuh-cfg-user").value.trim(),
        password: document.getElementById("wazuh-cfg-pass").value,
        verify_ssl: document.getElementById("wazuh-cfg-ssl").checked,
        use_mock_fallback: document.getElementById("wazuh-cfg-mock").checked,
        enabled: true
    };

    try {
        const res = await authFetch(`${API_BASE}/wazuh/config`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Failed to save configuration.");
        }

        showToast("Wazuh configuration saved successfully!", "success");
        document.getElementById("wazuh-config-card").style.display = "none";
        await loadWazuhDashboard();
    } catch (err) {
        showToast(`Configuration Error: ${err.message}`, "error");
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save & Test Wazuh Connection'; }
    }
}

async function loadWazuhDashboard() {
    const syncedEl = document.getElementById("wazuh-last-synced");
    if (syncedEl) syncedEl.textContent = new Date().toLocaleTimeString();

    try {
        // 1. Fetch Manager Status
        const statusRes = await authFetch(`${API_BASE}/wazuh/status`);
        if (statusRes.ok) {
            const statusData = await statusRes.json();
            updateWazuhStatusHeader(statusData);
        }

        // 2. Fetch Monitored Agents
        const agentsRes = await authFetch(`${API_BASE}/wazuh/agents`);
        if (agentsRes.ok) {
            const agentsData = await agentsRes.json();
            renderWazuhAgents(agentsData);
        }

        // 3. Fetch Alerts
        const alertsRes = await authFetch(`${API_BASE}/wazuh/alerts`);
        if (alertsRes.ok) {
            const alertsData = await alertsRes.json();
            wazuhAlertsCache = alertsData.alerts || [];
            renderWazuhAlerts(wazuhAlertsCache);
        }
    } catch (err) {
        console.error("Error loading Wazuh dashboard:", err);
        showToast("Could not sync Wazuh data. Check VM connectivity.", "warning");
    }
}

function updateWazuhStatusHeader(data) {
    const badgeEl = document.getElementById("wazuh-status-badge");
    const modeBadge = document.getElementById("wazuh-mode-badge");
    const targetEl = document.getElementById("wazuh-target-display");
    const clusterEl = document.getElementById("wazuh-cluster-display");
    const errBanner = document.getElementById("wazuh-error-banner");
    const errText = document.getElementById("wazuh-error-text");
    const versionMetric = document.getElementById("wazuh-metric-version");
    const nodeMetric = document.getElementById("wazuh-metric-node");
    const iconBox = document.getElementById("wazuh-status-icon-container");

    if (targetEl) targetEl.textContent = `https://${data.wazuh_host || '192.168.1.100'}:55000`;
    
    if (data.connected && !data.is_mock) {
        if (badgeEl) badgeEl.innerHTML = `<i class="fa-solid fa-circle text-emerald"></i> Connected & Online`;
        if (badgeEl) badgeEl.className = "badge badge-success";
        if (modeBadge) modeBadge.style.display = "none";
        if (errBanner) errBanner.style.display = "none";
        if (iconBox) { iconBox.style.background = "rgba(16, 185, 129, 0.15)"; iconBox.style.color = "#10b981"; }
    } else if (data.is_mock) {
        if (badgeEl) badgeEl.innerHTML = `<i class="fa-solid fa-flask text-cyan"></i> Demo Mode (VM Offline)`;
        if (badgeEl) badgeEl.className = "badge badge-info";
        if (modeBadge) modeBadge.style.display = "inline-block";
        if (errBanner) {
            errBanner.style.display = "flex";
            if (errText) errText.textContent = data.error_message || `VM unreachable at https://${data.wazuh_host}:55000. Displaying simulated telemetry.`;
        }
        if (iconBox) { iconBox.style.background = "rgba(6, 182, 212, 0.15)"; iconBox.style.color = "#06b6d4"; }
    } else {
        if (badgeEl) badgeEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose"></i> Disconnected`;
        if (badgeEl) badgeEl.className = "badge badge-danger";
        if (modeBadge) modeBadge.style.display = "none";
        if (errBanner) {
            errBanner.style.display = "flex";
            if (errText) errText.textContent = data.error_message || "Cannot establish REST connection to Wazuh VM.";
        }
        if (iconBox) { iconBox.style.background = "rgba(244, 63, 94, 0.15)"; iconBox.style.color = "#f43f5e"; }
    }

    if (data.manager_info) {
        if (versionMetric) versionMetric.textContent = data.manager_info.version || "v4.7.2";
        if (nodeMetric) nodeMetric.textContent = `Node: ${data.manager_info.node_name || 'wazuh-master'}`;
        if (clusterEl) clusterEl.textContent = data.manager_info.cluster_name || "wazuh-cluster";
    }
}

function renderWazuhAgents(data) {
    const tbody = document.getElementById("wazuh-agents-table-body");
    const activeMetric = document.getElementById("wazuh-metric-active-agents");
    const totalMetric = document.getElementById("wazuh-metric-total-agents");
    const countPill = document.getElementById("wazuh-agents-count");

    const summary = data.agents_summary || {};
    if (activeMetric) activeMetric.textContent = `${summary.active || 0} / ${summary.total || 0}`;
    if (totalMetric) totalMetric.textContent = `Total Agents Registered: ${summary.total || 0}`;
    if (countPill) countPill.textContent = `${summary.total || 0} Agents`;

    if (!tbody) return;
    const agents = data.agents || [];

    if (agents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:#94a3b8;">No Wazuh Agents registered yet. Install a Wazuh Agent on your target machines to monitor telemetry.</td></tr>`;
        return;
    }

    tbody.innerHTML = agents.map(agent => {
        const isOnline = agent.status === "active";
        const statusPill = isOnline 
            ? `<span class="badge badge-success"><i class="fa-solid fa-circle text-emerald"></i> Active</span>`
            : `<span class="badge badge-danger"><i class="fa-solid fa-circle text-rose"></i> Disconnected</span>`;
        
        const osName = (agent.os && (agent.os.name || agent.os.os)) ? `${agent.os.name || agent.os.os} ${agent.os.version || ''}` : "Unknown OS";

        return `
            <tr>
                <td>
                    <strong><i class="fa-solid fa-laptop-code text-cyan"></i> ${agent.name}</strong>
                    <div style="font-size:0.75rem; color:#64748b;">ID: ${agent.id}</div>
                </td>
                <td><code>${agent.ip}</code></td>
                <td style="font-size:0.85rem;">${osName}</td>
                <td><span class="badge badge-secondary">${agent.version}</span></td>
                <td>${statusPill}</td>
                <td style="font-size:0.82rem; color:#94a3b8;">${agent.lastKeepAlive || 'N/A'}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="triggerWazuhAgentScan('${agent.id}')" title="Trigger file integrity & syscheck scan on agent">
                        <i class="fa-solid fa-radar text-amber"></i> Run Syscheck
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderWazuhAlerts(alerts) {
    const container = document.getElementById("wazuh-alerts-feed-container");
    const alertMetric = document.getElementById("wazuh-metric-alerts");
    if (!container) return;

    if (alertMetric) alertMetric.textContent = wazuhAlertsCache.length;

    if (alerts.length === 0) {
        const selFilter = document.getElementById("wazuh-alert-severity-filter")?.value || "all";
        container.innerHTML = `
            <div style="text-align:center; padding:24px; color:#94a3b8; background:rgba(15, 23, 42, 0.4); border-radius:12px;">
                <i class="fa-solid fa-filter-circle-xmark text-cyan" style="font-size:2.2rem; margin-bottom:10px;"></i><br>
                <strong style="color:#f8fafc; font-size:1rem;">No log events match severity filter '${selFilter.toUpperCase()}'.</strong>
                <p style="font-size:0.85rem; margin-top:6px; color:#64748b;">
                    Total log events fetched: <strong>${wazuhAlertsCache.length}</strong>. Most active events are Level 3 (Info / Low). Try selecting 'All Alert Levels' or 'Low / Info (Level 1-3)'.
                </p>
            </div>`;
        return;
    }

    container.innerHTML = alerts.map(alt => {
        let sevClass = "border-cyan";
        let badgeColor = "badge-info";
        if (alt.level >= 12 || String(alt.severity).toLowerCase() === "critical") {
            sevClass = "border-rose";
            badgeColor = "badge-danger";
        } else if (alt.level >= 7 || String(alt.severity).toLowerCase() === "high") {
            sevClass = "border-amber";
            badgeColor = "badge-warning";
        }

        const dateStr = alt.timestamp ? new Date(alt.timestamp).toLocaleString() : "Just now";

        return `
            <div class="glass-panel ${sevClass}" style="padding:14px; border-left:4px solid; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span class="badge ${badgeColor}">Rule ${alt.rule_id}</span>
                        <span class="badge badge-secondary">Level ${alt.level}</span>
                        <strong style="font-size:0.95rem; color:#f8fafc;">${alt.description}</strong>
                    </div>
                    <span style="font-size:0.78rem; color:#64748b;"><i class="fa-regular fa-clock"></i> ${dateStr}</span>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; font-size:0.83rem; color:#94a3b8; margin-top:4px;">
                    <div>
                        <i class="fa-solid fa-desktop text-cyan"></i> Agent: <strong>${alt.agent_name}</strong> (${alt.agent_ip}) &bull; Location: <code>${alt.location}</code>
                    </div>
                    ${alt.mitre_attack !== 'N/A' ? `<span class="badge badge-outline" style="color:#00f2fe; border-color:rgba(0,242,254,0.3);"><i class="fa-solid fa-crosshairs"></i> ${alt.mitre_attack}</span>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function filterWazuhAlerts() {
    const filterVal = document.getElementById("wazuh-alert-severity-filter")?.value || "all";
    let filtered = [...wazuhAlertsCache];

    if (filterVal === "critical") {
        filtered = filtered.filter(a => a.level >= 12 || String(a.severity).toLowerCase() === "critical");
    } else if (filterVal === "high") {
        filtered = filtered.filter(a => (a.level >= 7 && a.level < 12) || String(a.severity).toLowerCase() === "high");
    } else if (filterVal === "medium") {
        filtered = filtered.filter(a => (a.level >= 4 && a.level < 7) || String(a.severity).toLowerCase() === "medium");
    } else if (filterVal === "low") {
        filtered = filtered.filter(a => a.level < 4 || String(a.severity).toLowerCase() === "low" || String(a.severity).toLowerCase() === "info");
    }

    renderWazuhAlerts(filtered);
}


async function triggerWazuhAgentScan(agentId) {
    try {
        showToast(`Sending active syscheck scan command to Wazuh Agent '${agentId}'...`, "info");
        const res = await authFetch(`${API_BASE}/wazuh/agents/${agentId}/scan`, { method: "POST" });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Scan request failed");
        }
        const data = await res.json();
        showToast(data.message || `Scan started on Agent ${agentId}`, "success");
    } catch (err) {
        showToast(`Scan Trigger Error: ${err.message}`, "error");
    }
}

