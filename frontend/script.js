        console.log("🔥 MAILTRACE JS LOADED");

        // Shared page-header helper used by both DOM-ready navigation handlers
        // and the result renderer, which lives outside that callback scope.
        window.updatePageHeader = function updatePageHeader(title, subtitle) {
            const titleElement = document.querySelector(".page-title h1");
            const subtitleElement = document.querySelector(".page-title p");
            if (titleElement) titleElement.textContent = title;
            if (subtitleElement) subtitleElement.textContent = subtitle;
        }

        /* =========================================
        MAILTRACE AI
        FRONTEND INTERACTIONS
        ========================================= */

        document.addEventListener("DOMContentLoaded", () => {
        // Keep this helper in the same closure as navigation and result rendering.
        // This avoids global-name lookup failures in embedded/static preview contexts.
        const setPageHeader = (title, subtitle) => {
            const titleElement = document.querySelector(".page-title h1");
            const subtitleElement = document.querySelector(".page-title p");
            if (titleElement) titleElement.textContent = title;
            if (subtitleElement) subtitleElement.textContent = subtitle;
        };
        const flaggedAlertSeenStorageKey = "mailtraceSeenFlaggedAlertSignatures";
        const getFlaggedInvestigations = () => {
            // The live investigation feed includes non-routed medium/suspicious
            // messages. Only durable policy alerts belong in this SOC queue.
            if (!window.mailtraceAlertsLoaded) return [];
            return (window.mailtraceAlerts || []).map(alert => ({
                ...alert,
                id: alert.investigation_id,
                threat_verdict: alert.severity,
                alert_id: alert.alert_id,
                alert_status: alert.status,
                user_notification: alert.user_notification
            }));
        };
        const loadPersistedSecurityAlerts = async () => {
            try {
                const response = await fetch("http://127.0.0.1:8000/api/alerts?limit=100", { cache: "no-store" });
                if (!response.ok) return;
                const payload = await response.json();
                if (!Array.isArray(payload.alerts)) return;
                window.mailtraceAlerts = payload.alerts;
                window.mailtraceAlertsLoaded = true;
                window.mailtraceUpdateFlaggedNotificationBadge?.();
                window.mailtraceRefreshAlertsPanel?.();
            } catch (_) {
                // Fail closed: the investigation feed is not the SOC alert queue.
            }
        };
        const getFlaggedAlertSignature = item => [
            item.investigation_id || item.id || item.filename || item.subject || "unknown-investigation",
            String(item.threat_verdict || "UNKNOWN").trim().toUpperCase(),
            String(item.severity || item.threat_level || "").trim().toUpperCase(),
            item.threat_score ?? item.risk_score ?? item.score ?? "",
            item.updated_at || item.last_updated || item.created_at || ""
        ].join("|");
        const getLegacyFlaggedAlertSignature = item => [
            item.investigation_id || item.id || item.filename || item.subject || "unknown-investigation",
            String(item.threat_verdict || "UNKNOWN").trim().toUpperCase(),
            item.updated_at || item.last_updated || item.created_at || ""
        ].join("|");
        const getSeenFlaggedAlertSignatures = () => {
            try {
                const stored = JSON.parse(localStorage.getItem(flaggedAlertSeenStorageKey) || "[]");
                return new Set(Array.isArray(stored) ? stored : []);
            } catch (_) {
                return new Set();
            }
        };
        window.mailtraceUpdateFlaggedNotificationBadge = ({ markSeen = false } = {}) => {
            const flagged = getFlaggedInvestigations();
            const seen = getSeenFlaggedAlertSignatures();
            let migratedSeenState = false;
            for (const item of flagged) {
                const legacySignature = getLegacyFlaggedAlertSignature(item);
                if (seen.delete(legacySignature)) {
                    seen.add(getFlaggedAlertSignature(item));
                    migratedSeenState = true;
                }
            }
            if (markSeen) flagged.forEach(item => seen.add(getFlaggedAlertSignature(item)));
            const unreadCount = flagged.reduce((count, item) => {
                if (item.alert_id) return count + Number(String(item.alert_status || "NEW").toUpperCase() === "NEW");
                return count + Number(!seen.has(getFlaggedAlertSignature(item)));
            }, 0);
            const badge = document.getElementById("flaggedInvestigationCount");
            if (badge) {
                badge.textContent = unreadCount ? (unreadCount > 99 ? "99+" : String(unreadCount)) : "";
                badge.hidden = unreadCount === 0;
                badge.title = unreadCount
                    ? `${unreadCount.toLocaleString()} unread security alerts`
                    : "No unread security alerts";
                const trigger = badge.closest(".notification");
                if (trigger) {
                    trigger.title = unreadCount ? `${unreadCount.toLocaleString()} unread security alerts. Click to review.` : "Open flagged investigations";
                    trigger.setAttribute("aria-label", unreadCount
                        ? `${unreadCount.toLocaleString()} unread security alerts. Open alerts`
                        : "Open flagged investigations");
                }
            }
            if (markSeen || migratedSeenState) {
                try {
                    localStorage.setItem(flaggedAlertSeenStorageKey, JSON.stringify([...seen].slice(-5000)));
                } catch (_) {}
            }
            return unreadCount;
        };
        window.addEventListener("storage", event => {
            if (event.key === flaggedAlertSeenStorageKey) window.mailtraceUpdateFlaggedNotificationBadge();
        });
        refreshBackendStatus();
        void loadPersistedSecurityAlerts();
        window.setInterval(refreshBackendStatus, 30000);
        loadDashboardStats();
        loadRecentInvestigations();
        loadDashboardCharts();
        window.setInterval(() => {
            if (document.hidden) return;
            void loadPersistedSecurityAlerts();
            loadDashboardStats();
            loadRecentInvestigations();
            loadDashboardCharts();
        }, 20000);

        document.getElementById("openDashboardCampaigns")?.addEventListener("click", () => {
            document.querySelector('.nav-item[data-page="campaigns"]')?.click();
        });

        const openThreatBreakdown = event => {
            event?.preventDefault?.();
            document.getElementById("threatBreakdownModal")?.remove();
            const rows = window.mailtraceInvestigations || [];
            const groups = [
                { label: "Critical", key: ["CRITICAL"], className: "critical" },
                { label: "High", key: ["HIGH", "HIGH RISK"], className: "high" },
                { label: "Medium", key: ["MEDIUM", "SUSPICIOUS"], className: "medium" },
                { label: "Low risk", key: ["LOW", "LOW RISK", "SAFE", "BENIGN"], className: "low" },
                { label: "Unclassified", key: ["UNKNOWN", "UNASSESSED", ""], className: "unknown" }
            ];
            const normalized = rows.map(item => ({ item, verdict: String(item.threat_verdict || "UNASSESSED").trim().toUpperCase() }));
            const recognizedVerdicts = groups.slice(0, -1).flatMap(group => group.key);
            const counts = groups.map((group, index) => ({
                ...group,
                count: index === groups.length - 1
                    ? normalized.filter(row => !recognizedVerdicts.includes(row.verdict)).length
                    : normalized.filter(row => group.key.includes(row.verdict)).length
            }));
            const total = rows.length;
            const modal = document.createElement("div");
            modal.id = "threatBreakdownModal";
            modal.className = "threat-breakdown-modal";
            modal.innerHTML = `<section class="threat-breakdown-dialog" role="dialog" aria-modal="true" aria-labelledby="threatBreakdownTitle">
                <button type="button" class="threat-breakdown-close" aria-label="Close">×</button>
                <div class="eyebrow">SECURITY POSTURE</div><h2 id="threatBreakdownTitle">Threat distribution</h2>
                <p>Verdict counts from ${total.toLocaleString()} investigations currently available in this workspace.</p>
                <div class="threat-breakdown-total"><strong>${total.toLocaleString()}</strong><span>total investigations</span></div>
                <div class="threat-breakdown-rows">${counts.map(group => {
                    const pct = total ? Math.round(group.count / total * 100) : 0;
                    const filterValue = group.className === "low" ? "LOW RISK" : group.className === "unknown" ? "UNASSESSED" : group.key[0];
                    return `<button type="button" class="threat-breakdown-row ${group.className}" data-verdict="${filterValue}">
                        <span class="threat-breakdown-dot"></span><strong>${group.label}</strong><span class="threat-breakdown-meter"><i style="width:${pct}%"></i></span><b>${group.count.toLocaleString()}</b><small>${pct}%</small>
                    </button>`;
                }).join("")}</div><small class="threat-breakdown-note">Counts reflect backend verdict labels; review the underlying evidence before making a disposition.</small>
            </section>`;
            document.body.appendChild(modal);
            const close = () => modal.remove();
            modal.querySelector(".threat-breakdown-close")?.addEventListener("click", close);
            modal.addEventListener("click", e => { if (e.target === modal) close(); });
            modal.querySelectorAll(".threat-breakdown-row").forEach(row => row.addEventListener("click", () => {
                window.mailTraceInitialThreatFilter = row.dataset.verdict;
                close();
                document.querySelector('.nav-item[data-page="investigation"]')?.click();
            }));
        };

        const renderFlaggedInvestigationPanel = panel => {
            const trigger = document.querySelector(".notification");
            const flagged = getFlaggedInvestigations();
            const recent = flagged.slice(0, 6);
            panel.innerHTML = `
                <div class="flagged-panel-heading"><div><span>SECURITY ALERTS</span><strong>${flagged.length.toLocaleString()} flagged investigations</strong></div><button type="button" class="flagged-panel-close" aria-label="Close alerts">×</button></div>
                <div class="flagged-panel-list">${recent.length ? recent.map((item, index) => `
                    <button type="button" class="flagged-investigation-item" data-investigation-id="${escapeHTML(item.investigation_id || item.id || "")}">
                        <span class="flagged-item-severity severity-${escapeHTML(String(item.threat_verdict || "unknown").toLowerCase().replace(/[^a-z]+/g, "-"))}">${escapeHTML(item.threat_verdict || "FLAGGED")}</span>
                        <strong>${escapeHTML(item.subject || item.filename || "Email investigation")}</strong>
                        <small>${escapeHTML(item.sender || item.from_address || item.investigation_id || "Investigation")}</small>
                    </button>`).join("") : `<div class="flagged-panel-empty">${window.mailtraceAlertsLoaded ? "No high-risk alerts awaiting SOC review." : "Loading SOC alert queue…"}</div>`}</div>
                <button type="button" class="flagged-panel-all">Open case management <span>→</span></button>`;
            const linkedCaseCount = flagged.filter(item => item.case_id).length;
            const panelCount = panel.querySelector(".flagged-panel-heading strong");
            if (panelCount) panelCount.textContent = `${flagged.length.toLocaleString()} risk emails · ${linkedCaseCount.toLocaleString()} linked cases`;
            panel.querySelectorAll(".flagged-investigation-item").forEach(button => {
                const item = flagged.find(row => (row.investigation_id || row.id || "") === button.dataset.investigationId);
                if (!item) return;
                if (item.alert_id) button.dataset.alertId = item.alert_id;
                if (item.case_id) button.dataset.caseId = item.case_id;
                if (item.case_id) {
                    const meta = document.createElement("small");
                    meta.className = "flagged-item-case";
                    meta.textContent = `${item.case_id} · ${item.alert_status || "NEW"}`;
                    button.appendChild(meta);
                }
                const whyRisky = item.user_notification?.why_risky;
                if (Array.isArray(whyRisky) && whyRisky.length) {
                    const guidance = document.createElement("small");
                    guidance.className = "flagged-item-guidance";
                    guidance.textContent = `${whyRisky[0]} Don’t click links or open attachments.`;
                    button.appendChild(guidance);
                }
            });
            panel.querySelector(".flagged-panel-close")?.addEventListener("click", () => {
                window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                panel.remove();
                trigger?.setAttribute("aria-expanded", "false");
            });
            panel.querySelectorAll(".flagged-investigation-item").forEach(button => button.addEventListener("click", async () => {
                const id = button.dataset.investigationId;
                const alertId = button.dataset.alertId;
                const caseId = button.dataset.caseId;
                window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                panel.remove();
                trigger?.setAttribute("aria-expanded", "false");
                if (alertId) {
                    void fetch(`http://127.0.0.1:8000/api/alerts/${encodeURIComponent(alertId)}/acknowledge`, { method: "POST" }).then(() => loadPersistedSecurityAlerts()).catch(() => {});
                }
                if (caseId) await openCase(caseId);
                else if (id) await openInvestigation(id);
            }));
            panel.querySelector(".flagged-panel-all")?.addEventListener("click", () => {
                window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                panel.remove();
                trigger?.setAttribute("aria-expanded", "false");
                document.querySelector('.nav-item[data-page="cases"]')?.click();
            });
        };
        const openFlaggedInvestigations = event => {
            event?.preventDefault?.();
            const trigger = document.querySelector(".notification");
            let panel = document.getElementById("flaggedInvestigationPanel");
            if (panel) {
                window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                panel.remove();
                trigger?.setAttribute("aria-expanded", "false");
                return;
            }
            panel = document.createElement("section");
            panel.id = "flaggedInvestigationPanel";
            panel.className = "flagged-investigation-panel";
            panel.setAttribute("role", "dialog");
            panel.setAttribute("aria-label", "Recent flagged investigations");
            document.querySelector(".topbar-right")?.appendChild(panel);
            trigger?.setAttribute("aria-expanded", "true");
            renderFlaggedInvestigationPanel(panel);
            window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
        };
        window.mailtraceRefreshAlertsPanel = () => {
            const panel = document.getElementById("flaggedInvestigationPanel");
            if (panel) renderFlaggedInvestigationPanel(panel);
        };
        document.addEventListener("mailtrace:realtime-threat-update", event => {
            const events = event.detail?.events;
            if (!Array.isArray(events)) return;
            const prior = new Map((window.mailtraceInvestigations || []).map(item => [item.investigation_id || item.id, item]));
            window.mailtraceInvestigations = events.map(item => {
                const id = item.investigation_id || item.id;
                const previous = prior.get(id);
                return {
                    ...(previous || {}),
                    ...item,
                    threat_verdict: item.verdict || item.threat_verdict || previous?.threat_verdict || "UNKNOWN"
                };
            });
            window.mailtraceUpdateFlaggedNotificationBadge();
            window.mailtraceRefreshAlertsPanel?.();
            void loadPersistedSecurityAlerts();
            if (!document.hidden) {
                void loadDashboardStats();
                void loadRecentInvestigations();
                void loadDashboardCharts();
            }
        });
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) return;
            void refreshBackendStatus();
            void loadDashboardStats();
            void loadRecentInvestigations();
            void loadDashboardCharts();
        });
        document.querySelector(".notification")?.addEventListener("click", openFlaggedInvestigations);
        document.addEventListener("click", event => {
            const panel = document.getElementById("flaggedInvestigationPanel");
            if (panel && !panel.contains(event.target) && !event.target.closest(".notification")) {
                window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                panel.remove();
                document.querySelector(".notification")?.setAttribute("aria-expanded", "false");
            }
        });
        document.getElementById("viewThreatBreakdown")?.addEventListener("click", openThreatBreakdown);
        document.getElementById("viewAllReportsBtn")?.addEventListener("click", () => {
            document.querySelector('.nav-item[data-page="reports"]')?.click();
        });

        const analystMenuToggles = [document.getElementById("analystMenuToggle"), document.getElementById("topAnalystMenuToggle")].filter(Boolean);
        let analystMenu = null;
        const closeAnalystMenu = () => {
            analystMenu?.remove();
            analystMenu = null;
            analystMenuToggles.forEach(toggle => toggle.setAttribute("aria-expanded", "false"));
        };
        const toggleAnalystMenu = event => {
            event.stopPropagation();
            if (analystMenu) {
                closeAnalystMenu();
                return;
            }
            analystMenu = document.createElement("div");
            analystMenu.className = "analyst-menu";
            analystMenu.setAttribute("role", "dialog");
            analystMenu.setAttribute("aria-label", "Analyst profile");
            analystMenu.innerHTML = `<strong>Rituraj · Analyst</strong><span>Local SOC workspace</span><span>Backend authentication is not configured</span>`;
            const isTopProfile = event.currentTarget?.id === "topAnalystMenuToggle";
            analystMenu.classList.toggle("is-top-profile", isTopProfile);
            (isTopProfile ? document.querySelector(".topbar-right") : document.querySelector(".sidebar-bottom"))?.appendChild(analystMenu);
            analystMenuToggles.forEach(toggle => toggle.setAttribute("aria-expanded", "true"));
        };
        analystMenuToggles.forEach(toggle => {
            toggle.addEventListener("click", toggleAnalystMenu);
            toggle.addEventListener("keydown", event => {
                if ((event.key === "Enter" || event.key === " ") && toggle.tagName !== "BUTTON") {
                    event.preventDefault();
                    toggleAnalystMenu(event);
                }
            });
        });
        document.addEventListener("click", event => {
            if (analystMenu && !analystMenu.contains(event.target) && !analystMenuToggles.some(toggle => toggle.contains(event.target))) closeAnalystMenu();
        });
        document.addEventListener("keydown", event => {
            if (event.key === "Escape") {
                closeAnalystMenu();
                const panel = document.getElementById("flaggedInvestigationPanel");
                if (panel) {
                    window.mailtraceUpdateFlaggedNotificationBadge({ markSeen: true });
                    panel.remove();
                    document.querySelector(".notification")?.setAttribute("aria-expanded", "false");
                }
            }
        });

        /* =====================================
        VIEW ALL INVESTIGATIONS
        ===================================== */

        /* =====================================
        VIEW ALL INVESTIGATIONS
        ===================================== */

        const viewAllInvestigations =
            document.getElementById(
                "viewAllInvestigations"
            );

        if (viewAllInvestigations) {

            viewAllInvestigations.addEventListener(
                "click",
                async (event) => {

                    event.preventDefault();

                    console.log(
                        "🔥 Opening all investigations..."
                    );

                    await loadInvestigations();

                }
            );

        }
            const modal = document.getElementById("investigationModal");
            const newInvestigationBtn = document.getElementById("newInvestigationBtn");
            const closeModal = document.getElementById("closeModal");

            const uploadEmail = document.getElementById("uploadEmail");
            const uploadBox = document.getElementById("uploadBox");
            const emailFile = document.getElementById("emailFile");
            const startAnalysis = document.getElementById("startAnalysis");

            function openModal() {
                if (!modal) return;
                modal.classList.add("show");
                document.body.style.overflow = "hidden";
                closeModal?.focus();
            }

            function closeInvestigationModal() {
                if (!modal) return;
                modal.classList.remove("show");
                document.body.style.overflow = "";
                newInvestigationBtn?.focus({ preventScroll: true });
            }

            if (modal) {

            /* =====================================
            OPEN MODAL
            ===================================== */

            /* =====================================
            CLOSE MODAL
            ===================================== */


            if (newInvestigationBtn) {
                newInvestigationBtn.addEventListener(
                    "click",
                    openModal
                );
            }

            uploadEmail?.addEventListener("click", openModal);

            closeModal?.addEventListener(
                "click",
                closeInvestigationModal
            );


            /* =====================================
            CLICK OUTSIDE MODAL
            ===================================== */

            modal.addEventListener("click", (event) => {

                if (event.target === modal) {

                    closeInvestigationModal();

                }

            });


            /* =====================================
            ESC KEY
            ===================================== */

            document.addEventListener("keydown", (event) => {

                if (event.key === "Escape") {

                    closeInvestigationModal();

                }

            });


            /* =====================================
            UPLOAD BOX
            ===================================== */

            uploadBox?.addEventListener("click", () => {

                emailFile.click();

            });


            /* =====================================
            FILE SELECTED
            ===================================== */

            emailFile?.addEventListener("change", () => {

                if (!emailFile.files.length) {
                    return;
                }

                const file = emailFile.files[0];

                uploadBox.innerHTML = `
                    <div class="upload-icon">✓</div>

                    <strong>${escapeHTML(file.name)}</strong>

                    <span>
                        ${(file.size / 1024).toFixed(1)} KB
                    </span>

                    <small>
                        READY FOR ANALYSIS
                    </small>
                `;

            });


            /* =====================================
            DRAG & DROP
            ===================================== */

            ["dragenter", "dragover"].forEach(eventName => {

                uploadBox?.addEventListener(eventName, (event) => {

                    event.preventDefault();

                    uploadBox.classList.add("dragging");

                });

            });


            ["dragleave", "drop"].forEach(eventName => {

                uploadBox?.addEventListener(eventName, (event) => {

                    event.preventDefault();

                    uploadBox.classList.remove("dragging");

                });

            });


            uploadBox?.addEventListener("drop", (event) => {

                const files = event.dataTransfer.files;

                if (!files.length) {
                    return;
                }

                const file = files[0];

                if (
                    !file.name.toLowerCase().endsWith(".eml") &&
                    !file.name.toLowerCase().endsWith(".msg")
                ) {

                    alert("Please upload a .eml or .msg file.");

                    return;

                }

                emailFile.files = files;

                uploadBox.innerHTML = `
                    <div class="upload-icon">✓</div>

                    <strong>${escapeHTML(file.name)}</strong>

                    <span>
                        ${(file.size / 1024).toFixed(1)} KB
                    </span>

                    <small>
                        READY FOR ANALYSIS
                    </small>
                `;

            });


            /* =====================================
            START ANALYSIS
            ===================================== */

        startAnalysis?.addEventListener("click", async (event) => {

            event.preventDefault();


            console.log("🔥 START ANALYSIS CLICKED");

            if (!emailFile.files.length) {

                showNotification(
                    "Please upload an email first.",
                    "warning"
                );

                return;
            }

            const file = emailFile.files[0];

            // Basic file validation
            const validExtensions = [".eml", ".msg"];

            const isValid = validExtensions.some(
                extension =>
                    file.name.toLowerCase().endsWith(extension)
            );

            if (!isValid) {

                showNotification(
                    "Only .eml and .msg files are supported.",
                    "warning"
                );

                return;
            }

            // Loading state
            startAnalysis.disabled = true;

            startAnalysis.innerHTML = `
                <span class="loading-dot"></span>
                Analysing Email...
            `;

            try {

                // Create multipart form data
                const formData = new FormData();

                formData.append("file", file);

                // Send file to FastAPI
                const response = await fetch(
                    "http://127.0.0.1:8000/api/analyze-email",
                    {
                        method: "POST",
                        body: formData
                    }
                );

                // Convert response to JSON
                const data = await response.json();

                // Backend error
                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Email analysis failed."
                    );
                }

                console.log(
                    "MailTrace Analysis:",
                    data
                );

                // Save result temporarily
                localStorage.setItem(
                    "mailtrace_analysis",
                    JSON.stringify(data)
                );

                showNotification(
                    "Email analysed successfully.",
                    "success"
                );

                // Update SOC counts, alerts and recent activity immediately after analysis.
                void loadDashboardStats();
                void loadRecentInvestigations();
                void loadDashboardCharts();

                // Close modal
                closeInvestigationModal();

                // Open investigation result
                setTimeout(() => {

                    showInvestigationResult(
                        data.analysis
                    );

                }, 300);

            } catch (error) {

                console.error(
                    "Analysis Error:",
                    error
                );

                showNotification(
                    error.message ||
                    "Unable to connect to MailTrace backend.",
                    "warning"
                );

            } finally {

                startAnalysis.disabled = false;

                startAnalysis.innerHTML =
                    "Start Analysis";
            }

        });


            }

        /* =====================================
        PAGE HEADER / VIEW STATE
        ===================================== */

        /* =====================================
        SIDEBAR NAVIGATION
        ===================================== */

        const navItems =
            document.querySelectorAll(".nav-item");

        navItems.forEach(item => {

            item.addEventListener("click", async (event) => {

                event.preventDefault();

                navItems.forEach(nav => {
                    nav.classList.remove("active");
                });

                item.classList.add("active");

                const page =
                    item.dataset.page;


                    /* ==============================
                DASHBOARD
                ============================== */

            /* ==============================
        DASHBOARD
        ============================== */

        if (page === "dashboard") {

            // Dashboard is the ONLY view that renders dashboard content.
            cleanupDynamicPages();

            const dashboard =
                document.querySelector(".dashboard-content");

            if (dashboard) {
                dashboard.style.setProperty("display", "block", "important");
            }

            setPageHeader(
                "Dashboard",
                "Monitor your security operations"
            );

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

            return;
        }

        /* ==============================
                INVESTIGATIONS
                ============================== */

                if (
                    page === "investigation" ||
                    page === "investigations"
                ) {

                    setPageHeader("Investigations", "Review forensic email investigations");
                    await loadInvestigations();

                    return;
                }

                /* ==============================
                REPORTS
                ============================== */

                if (page === "reports") {
                    setPageHeader("Reports", "Review investigation reports and geolocation intelligence");
                    await loadReports();
                    return;
                }

                /* ==============================
        CASES
        ============================== */

        /* ==============================
        CASES
        ============================== */

        if (page === "cases") {

            setPageHeader("Cases", "Manage security cases and high-risk investigations");
            await loadCases();
            markCasesViewed();

            return;
        }


        /* ==============================
        CAMPAIGNS
        ============================== */

        if (page === "campaigns") {

            setPageHeader("Campaigns", "Correlate related threats into campaigns");
            await loadCampaigns();

            return;
        }

        /* ==============================
        IP INTELLIGENCE
        ============================== */

        if (
            page === "ip-intelligence" ||
            page === "ip_intelligence" ||
            page === "ip"
        ) {

            setPageHeader("IP Intelligence", "Investigate IP addresses, ownership and geolocation");
            await loadIPIntelligence();

            return;
        }

        /* ==============================
        OTHER MODULES
        ============================== */

        /* ==============================
        CAMPAIGNS
        ============================== */

                /* ==============================
                HELP & DOCS
                ============================== */

                if (page === "help-docs") {
                    setPageHeader("Help & Docs", "MailTrace-AI guidance and workflow reference");
                    await loadHelpDocs();
                    return;
                }

                /* ==============================
                OTHER MODULES
                ============================== */

                if (page) {

                    showNotification(
                        `${capitalize(page)} module is ready for backend integration.`,
                        "info"
                    );

                }

            });

        });


            /* =====================================
            QUICK ACTION BUTTONS
            ===================================== */

            document.addEventListener("click", event => {
                const actionCard = event.target.closest(".quick-card[data-action], .quick-card[data-page]");
                if (!actionCard) return;

                if (actionCard.dataset.action === "new-investigation") {
                    openModal();
                    return;
                }

                const destination = actionCard.dataset.page;
                if (destination) {
                    document.querySelector(`.nav-item[data-page="${destination}"]`)?.click();
                }
            });


            /* =====================================
            HELPER: NOTIFICATION
            ===================================== */

            function showNotification(message, type = "info") {

                const notification =
                    document.createElement("div");

                notification.className =
                    `toast toast-${type}`;

                notification.innerHTML = `
                    <span class="toast-icon">
                        ${type === "success" ? "✓" :
                        type === "warning" ? "!" : "i"}
                    </span>

                    <span>${escapeHTML(message)}</span>
                `;

                document.body.appendChild(notification);

                requestAnimationFrame(() => {

                    notification.classList.add("visible");

                });

                setTimeout(() => {

                    notification.classList.remove("visible");

                    setTimeout(() => {

                        notification.remove();

                    }, 200);

                }, 2800);

            }


            /* =====================================
            HELPER: CAPITALIZE
            ===================================== */

            function capitalize(text) {

                return text.charAt(0).toUpperCase()
                    + text.slice(1);

            }


            /* =====================================
            HELPER: ESCAPE HTML
            ===================================== */

            /* =====================================
            TOAST STYLES
            ===================================== */

            const toastStyles =
                document.createElement("style");

            toastStyles.textContent = `

                .toast {

                    position: fixed;

                    right: 25px;

                    bottom: 25px;

                    z-index: 999;

                    display: flex;

                    align-items: center;

                    gap: 10px;

                    min-width: 260px;

                    max-width: 380px;

                    padding: 12px 14px;

                    border: 1px solid #263241;

                    border-radius: 9px;
                    background: #101720;

                    color: #CBD5E1;

                    box-shadow:
                        0 15px 40px rgba(0,0,0,.35);

                    font-size: 10px;

                    transform:
                        translateY(15px);

                    opacity: 0;

                    transition:
                        opacity .2s ease,
                        transform .2s ease;

                }


                .toast.visible {

                    opacity: 1;

                    transform:
                        translateY(0);

                }


                .toast-icon {

                    width: 22px;

                    height: 22px;

                    border-radius: 6px;

                    display: grid;

                    place-items: center;

                    flex-shrink: 0;

                    font-weight: 700;

                }


                .toast-success .toast-icon {

                    color: #22C55E;

                    background:
                        rgba(34,197,94,.12);

                }


                .toast-warning .toast-icon {

                    color: #F59E0B;

                    background:
                        rgba(245,158,11,.12);

                }


                .toast-info .toast-icon {

                    color: #19B5FE;

                    background:
                        rgba(25,181,254,.12);

                }


                .loading-dot {

                    width: 10px;

                    height: 10px;

                    border: 2px solid rgba(3,19,29,.25);

                    border-top-color: #03131D;

                    border-radius: 50%;

                    display: inline-block;

                    animation:
                        spin .7s linear infinite;

                }


                @keyframes spin {

                    to {
                        transform: rotate(360deg);
                    }

                }

            `;

            document.head.appendChild(toastStyles);

        });
        function formatEmailBody(rawBody) {
            const raw = String(rawBody || "").replace(/\r\n?/g, "\n").trim();

            if (!raw) {
                return `
                    <div class="email-body-empty">
                        No plain-text body detected.
                    </div>
                `;
            }

            const lines = raw.split("\n");
            const links = raw.match(/https?:\/\/[^\s<>]+/gi) || [];
            const uniqueLinks = [...new Set(links.map(link => link.replace(/[),.;]+$/, "")))];

            const renderedLines = lines.map(line => {
                const trimmed = line.trim();
                if (!trimmed) return '<div class="email-body-spacer"></div>';

                const safe = escapeHTML(trimmed).replace(
                    /(https?:\/\/[^\s<>]+)/gi,
                    '<span class="email-body-link">$1</span>'
                );

                if (/^[A-Za-z][A-Za-z0-9 _-]{1,40}:\s+/.test(trimmed)) {
                    const splitAt = trimmed.indexOf(":");
                    const label = escapeHTML(trimmed.slice(0, splitAt));
                    const value = escapeHTML(trimmed.slice(splitAt + 1).trim());
                    return `
                        <div class="email-body-field">
                            <span>${label}</span>
                            <strong>${value}</strong>
                        </div>
                    `;
                }

                return `<div class="email-body-line">${safe}</div>`;
            }).join("");

            return `
                <div class="email-body-meta">
                    <span>PLAIN-TEXT CONTENT</span>
                    <span>${raw.length.toLocaleString()} characters</span>
                    <span>${uniqueLinks.length} link${uniqueLinks.length === 1 ? "" : "s"}</span>
                </div>
                <div class="email-body-content">
                    ${renderedLines}
                </div>
            `;
        }

        function showInvestigationResult(analysis) {

            // Result rendering lives outside the navigation scope, so define
            // its header updater locally instead of relying on a window global.
            const setPageHeader = (title, subtitle) => {
                const titleElement = document.querySelector(".page-title h1");
                const subtitleElement = document.querySelector(".page-title p");
                if (titleElement) titleElement.textContent = title;
                if (subtitleElement) subtitleElement.textContent = subtitle;
            };

            document.getElementById("resultMapHeaderAction")?.remove();

            // Show the investigation report as a standalone result.
            // The normal dashboard must not remain visible underneath it.
            const dashboard = document.querySelector(".dashboard-content");
            if (dashboard) {
                dashboard.style.setProperty("display", "none", "important");
            }

            const info =
                analysis.basic_information || {};

            const body =
                analysis.body || {};

            const urls =
                analysis.urls || [];

            // -----------------------------------------
            // URL INTELLIGENCE
            // -----------------------------------------

            // Prefer the new forensic URL analyzer.
            // Keep the legacy analyzer as a fallback.

            const forensicUrlAnalysis =
                analysis.email_forensics?.url_analysis || {};

            const forensicUrls =
                Array.isArray(forensicUrlAnalysis.urls)
                    ? forensicUrlAnalysis.urls
                    : [];

            const legacyUrlIntelligence =
                Array.isArray(analysis.url_intelligence)
                    ? analysis.url_intelligence
                    : [];

            const urlIntelligence =
                forensicUrls.length > 0
                    ? forensicUrls.map(urlInfo => {

                        const keywordFindings =
                            Array.isArray(urlInfo.findings)
                                ? urlInfo.findings.filter(
                                    finding =>
                                        finding.type === "keyword"
                                )
                                : [];

                        const suspiciousKeywords = [
                            ...(Array.isArray(
                                urlInfo.suspicious_keywords
                            )
                                ? urlInfo.suspicious_keywords
                                : []
                            ),
                            ...keywordFindings.flatMap(
                                finding =>
                                    Array.isArray(finding.matches)
                                        ? finding.matches
                                        : []
                            )
                        ];

                        return {
                            ...urlInfo,

                            domain:
                                urlInfo.domain ||
                                urlInfo.hostname ||
                                "Not available",

                            is_https:
                                Boolean(urlInfo.is_https) ||
                                String(
                                    urlInfo.scheme || ""
                                ).toLowerCase() === "https",

                            is_ip_url:
                                Boolean(
                                    urlInfo.is_ip_url ??
                                    urlInfo.is_ip_address
                                ),

                            suspicious_keywords:
                                [...new Set(
                                    suspiciousKeywords
                                )],

                            brand_indicators:
                                Array.isArray(
                                    urlInfo.brand_indicators
                                )
                                    ? urlInfo.brand_indicators
                                    : [],

                            reasons:
                                Array.isArray(
                                    urlInfo.reasons
                                )
                                    ? urlInfo.reasons
                                    : []
                        };
                    })
                    : legacyUrlIntelligence;

            const attachments =
                analysis.attachments || [];

            const authentication =
                analysis.authentication || {};

            const threat =
                analysis.threat_analysis || {};


            // -----------------------------------------
            // THREAT INTELLIGENCE / IOC CORRELATION
            // -----------------------------------------

            const threatIntelligence =
                analysis.threat_intelligence || {};

            const iocSummary =
                threatIntelligence.ioc_summary || {};

            const normalizedIOCs =
                Array.isArray(threatIntelligence.iocs)
                    ? threatIntelligence.iocs
                    : [];

            const threatIntelMatches =
                threatIntelligence.matches || {};

            const matchedIOCCount =
                Number(threatIntelligence.matched_count || 0);

            const threatIntelStatus =
    threatIntelligence.status || "no_iocs";

const iocThreatScore =
    analysis.ioc_threat_score || {};

const iocScore =
    Number(iocThreatScore.score || 0);

const iocMatchedCount =
    Number(iocThreatScore.matched_iocs || 0);

const iocEvidence =
    Array.isArray(iocThreatScore.evidence)
        ? iocThreatScore.evidence
        : [];
const iocScoreBand = iocScore >= 70 ? "high" : iocScore >= 35 ? "medium" : "low";
const iocScoreStatus = iocEvidence.length || iocMatchedCount
    ? "Evidence evaluated"
    : "No IOC matches returned";

            const scoreBreakdown =
                Array.isArray(threat.score_breakdown)
                    ? threat.score_breakdown
                    : [];

            const receivedChain =
                analysis.received_chain || [];

            const indicators =
                threat.indicators || [];

            const ipIntelligence =
            analysis.ip_intelligence || [];

            const resultScoreRaw = threat.score;
            const resultScoreAvailable = resultScoreRaw !== null &&
                resultScoreRaw !== undefined &&
                String(resultScoreRaw).trim() !== "" &&
                Number.isFinite(Number(resultScoreRaw));
            const resultRiskScore = resultScoreAvailable
                ? Math.max(0, Math.min(100, Number(resultScoreRaw)))
                : 0;
            const resultRiskBand = !resultScoreAvailable
                ? "unknown"
                : resultRiskScore >= 75
                    ? "high"
                    : resultRiskScore >= 45
                        ? "elevated"
                        : resultRiskScore >= 20
                            ? "guarded"
                            : "low";
            const resultRiskLabel = String(threat.verdict || (resultScoreAvailable ? "REVIEW REQUIRED" : "ASSESSMENT INCOMPLETE")).toUpperCase();
            const resultConfidence = String(threat.confidence || "Not available").toUpperCase();
            const resultConfidenceLabel = resultConfidence && resultConfidence !== "NOT AVAILABLE"
                ? `${resultConfidence} CONFIDENCE`
                : "CONFIDENCE NOT PROVIDED";
            const resultTopSignals = [
                ...indicators.map(item => typeof item === "string" ? item : item?.title || item?.name || item?.signal || item?.type),
                ...scoreBreakdown.map(item => item?.signal || item?.category)
            ].filter(Boolean).filter((item, index, list) => list.indexOf(item) === index).slice(0, 3);
            const resultRiskGuidance = resultRiskBand === "unknown"
                ? "A complete risk score was not returned. Review the available evidence and confirm analysis completed before deciding how to handle this message."
                : resultRiskBand === "high"
                ? "High-priority review: treat this message as potentially malicious while you validate the evidence and sender."
                : resultRiskBand === "elevated"
                    ? "Elevated concern: hold links and attachments until the sender and supporting evidence have been reviewed."
                    : resultRiskBand === "guarded"
                        ? "Review sender context and authentication results before acting on any request in the message."
                        : "The analyzer returned a low score. Keep normal email safeguards in place; a low score is not proof that a message is safe.";
            const resultNextSteps = resultRiskBand === "unknown"
                ? [
                    "Do not treat a missing score as a safe result.",
                    "Review the available email evidence and check whether the analysis completed successfully.",
                    "Retry analysis or escalate if required evidence is unavailable."
                ]
                : resultRiskBand === "high"
                ? [
                    "Keep the message and attachments isolated from end users.",
                    "Verify the sender using a trusted contact method outside this email thread.",
                    "Preserve the original message and escalate with the evidence below."
                ]
                : resultRiskBand === "elevated"
                    ? [
                        "Hold the message while an analyst reviews its indicators.",
                        "Check sender authentication and validate any requested payment or credential change.",
                        "Preserve the original email before remediation."
                    ]
                    : resultRiskBand === "guarded"
                        ? [
                            "Check sender identity and message context against a trusted source.",
                            "Review authentication results and inspect links or attachments safely.",
                            "Escalate if the request is unexpected or sensitive."
                        ]
                        : [
                            "Apply your organization’s normal email handling controls.",
                            "Verify unexpected or sensitive requests through a trusted channel.",
                            "Escalate if new evidence conflicts with this automated assessment."
                        ];

            // -----------------------------------------
// FUTURE MODULES × REAL BACKEND OUTPUTS
// -----------------------------------------

const futureHasOwn = (object, key) =>
    !!object &&
    Object.prototype.hasOwnProperty.call(object, key);

const futureIsObject = value =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);

const futureArrayify = (
    value,
    nestedKeys = []
) => {
    if (value === null || value === undefined) {
        return [];
    }

    if (Array.isArray(value)) {
        return value;
    }

    if (!futureIsObject(value)) {
        return [];
    }

    // Prefer known collection containers.
    for (const key of nestedKeys) {

        const nested = value[key];

        if (Array.isArray(nested)) {
            return nested;
        }

        if (futureIsObject(nested)) {
            const nestedValues = Object.values(nested);

            if (
                nestedValues.length > 0 &&
                nestedValues.every(item =>
                    item !== null &&
                    typeof item === "object"
                )
            ) {
                return nestedValues;
            }
        }
    }

    // A single analysis record.
    const recordKeys = [
        "raw_url",
        "url",
        "canonical_url",
        "risk_score",
        "deception_score",
        "verdict",
        "severity",
        "findings",
        "visible_text",
        "href"
    ];

    if (
        recordKeys.some(key =>
            Object.prototype.hasOwnProperty.call(value, key)
        )
    ) {
        return [value];
    }

    // Object-map fallback.
    const values = Object.values(value).filter(
        item =>
            item !== null &&
            typeof item === "object"
    );

    return values;
};

const futureObjectify = (
    value,
    nestedKeys = []
) => {

    if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    ) {
        for (const key of nestedKeys) {

            const nested = value[key];

            if (
                nested !== null &&
                typeof nested === "object" &&
                !Array.isArray(nested)
            ) {
                return nested;
            }
        }

        return value;
    }

    if (Array.isArray(value)) {
        return value.length > 0 &&
            futureIsObject(value[0])
            ? value[0]
            : {};
    }

    return {};
};


// ------------------------------------------------------------
// ADVANCED URL INTELLIGENCE
// ------------------------------------------------------------

const advancedUrlRaw =
    analysis.advanced_url_intelligence;

const advancedUrlModulePresent =
    futureHasOwn(
        analysis,
        "advanced_url_intelligence"
    );

const advancedUrlIntelligence =
    futureArrayify(
        advancedUrlRaw,
        [
            "results",
            "urls",
            "analyses",
            "items",
            "data"
        ]
    );


// ------------------------------------------------------------
// LINK DECEPTION INTELLIGENCE
// ------------------------------------------------------------

const linkDeceptionRaw =
    analysis.link_deception_intelligence;

const linkDeceptionModulePresent =
    futureHasOwn(
        analysis,
        "link_deception_intelligence"
    );

const linkDeceptionIntelligence =
    futureObjectify(
        linkDeceptionRaw,
        [
            "result",
            "analysis",
            "data"
        ]
    );

const linkDeceptionLinks =
    futureArrayify(
        linkDeceptionIntelligence.links ||
        linkDeceptionIntelligence.results ||
        linkDeceptionIntelligence.items ||
        [],
        [
            "links",
            "results",
            "items",
            "data"
        ]
    );


// ------------------------------------------------------------
// INTELLIGENCE FUSION
// ------------------------------------------------------------

const intelligenceFusionRaw =
    analysis.intelligence_fusion;

const intelligenceFusionPresent =
    futureHasOwn(
        analysis,
        "intelligence_fusion"
    );

const intelligenceFusion =
    futureObjectify(
        intelligenceFusionRaw,
        [
            "result",
            "analysis",
            "data"
        ]
    );


// ------------------------------------------------------------
// EVIDENCE GOVERNANCE
// ------------------------------------------------------------

const evidenceGovernanceRaw =
    analysis.evidence_governance;

const evidenceGovernancePresent =
    futureHasOwn(
        analysis,
        "evidence_governance"
    );

const evidenceGovernance =
    futureIsObject(evidenceGovernanceRaw) &&
    (
        futureHasOwn(evidenceGovernanceRaw, "enabled") ||
        futureHasOwn(evidenceGovernanceRaw, "evidence_id") ||
        futureHasOwn(evidenceGovernanceRaw, "classification") ||
        futureHasOwn(evidenceGovernanceRaw, "policy_id")
    )
        ? evidenceGovernanceRaw
        : futureObjectify(
            evidenceGovernanceRaw,
            [
                "result",
                "data"
            ]
        );

const evidencePreservation =
    futureObjectify(
        evidenceGovernance.preservation
    );

const evidenceCustody =
    futureObjectify(
        evidenceGovernance.custody
    );

const evidenceIntegrity =
    futureObjectify(
        evidenceGovernance.integrity_anchor
    );

const evidenceRetention =
    futureObjectify(
        evidenceGovernance.retention
    );

const evidenceGovernanceMeta =
    futureObjectify(
        evidenceGovernance.governance
    );

const evidenceCustodyVerification =
    futureObjectify(
        evidenceCustody.verification
    );

const evidenceIntegrityReceipt =
    futureObjectify(
        evidenceIntegrity.receipt
    );

const evidenceAnchorVerification =
    futureObjectify(
        evidenceIntegrity.verification
    );


// ------------------------------------------------------------
// FUSION COLLECTIONS
// ------------------------------------------------------------

const fusionCriticalSignals =
    futureArrayify(
        intelligenceFusion.critical_signals,
        [
            "items",
            "signals",
            "results",
            "data"
        ]
    );

const fusionRiskDrivers =
    futureArrayify(
        intelligenceFusion.risk_drivers,
        [
            "items",
            "drivers",
            "results",
            "data"
        ]
    );

const resultThreadIntelligence = futureObjectify(analysis.email_thread_intelligence);
const resultEmailForensics = futureObjectify(analysis.email_forensics);
const resultEmailAI = futureObjectify(analysis.email_ai);
const resultThreatIntelV2 = futureObjectify(analysis.threat_intelligence_v2);
const resultCountOf = value => Array.isArray(value)
    ? value.length
    : futureIsObject(value)
        ? Object.keys(value).length
        : 0;
const resultCompactValue = value => {
    if (value === null || value === undefined || value === "") return "Not provided";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (Array.isArray(value)) return `${value.length} records`;
    if (futureIsObject(value)) return `${Object.keys(value).length} fields`;
    return String(value);
};
const resultURLPreview = value => {
    const raw = String(value || "");
    let compact = raw;
    try {
        const parsed = new URL(raw);
        compact = `${parsed.hostname}${parsed.pathname}${parsed.hash}`;
    } catch (_) {
        // Keep non-standard URL values visible without rewriting them.
    }
    if (compact.length <= 96) return compact;
    return `${compact.slice(0, 62)}…${compact.slice(-25)}`;
};
const resultModuleCards = [
    {
        title: "Conversation & thread analysis",
        accent: "violet",
        fields: [
            ["Thread depth", resultThreadIntelligence.thread_depth],
            ["Participants", resultThreadIntelligence.participant_graph?.participant_count],
            ["Thread risk", resultThreadIntelligence.thread_risk_score],
            ["Anomalies", resultCountOf(resultThreadIntelligence.anomalies)]
        ]
    },
    {
        title: "Email header & transport forensics",
        accent: "cyan",
        fields: [
            ["Forensic status", resultEmailForensics.forensics_status],
            ["Relay hops", resultCountOf(resultEmailForensics.relay_chain)],
            ["Header findings", resultEmailForensics.header_anomaly_analysis?.finding_count],
            ["Timeline events", resultCountOf(resultEmailForensics.timeline_analysis?.timeline)]
        ]
    },
    {
        title: "AI classification & calibration",
        accent: "blue",
        fields: [
            ["Model status", resultEmailAI.status],
            ["Classification", resultEmailAI.classification?.label || resultEmailAI.classification?.class || resultEmailAI.classification],
            ["Calibrated probability", resultEmailAI.calibrated_probability],
            ["Calibration", resultEmailAI.calibration_status]
        ]
    },
    {
        title: "Correlated threat intelligence",
        accent: "amber",
        fields: [
            ["Severity", resultThreatIntelV2.overall?.severity],
            ["Unified risk", resultThreatIntelV2.overall?.risk_score],
            ["High-risk indicators", resultCountOf(resultThreatIntelV2.high_risk_indicators)],
            ["MITRE techniques", resultCountOf(resultThreatIntelV2.mitre_attack?.techniques) || resultThreatIntelV2.summary?.mitre_techniques]
        ]
    }
].filter(module => module.fields.some(([, value]) => value !== null && value !== undefined && value !== ""));

const formatAnalysisFieldLabel = value => String(value)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, character => character.toUpperCase());

const renderCompleteAnalysisValue = value => {
    if (value === null || value === undefined) {
        return '<span class="analysis-data-value is-null">Not returned</span>';
    }
    if (Array.isArray(value)) {
        if (!value.length) return '<div class="analysis-data-empty">No records returned</div>';
        if (value.every(item => item === null || ["number", "boolean"].includes(typeof item) || (typeof item === "string" && item.length <= 160))) {
            return `<div class="analysis-data-chips">${value.map(item => `<span>${escapeHTML(resultCompactValue(item))}</span>`).join("")}</div>`;
        }
        return `<div class="analysis-data-list">${value.map((item, index) => `
            <details class="analysis-data-nested">
                <summary><span>Record ${String(index + 1).padStart(2, "0")}</span><small>${futureIsObject(item) ? `${Object.keys(item).length} fields` : Array.isArray(item) ? `${item.length} values` : "Value"}</small></summary>
                <div class="analysis-data-nested-content">${renderCompleteAnalysisValue(item)}</div>
            </details>
        `).join("")}</div>`;
    }
    if (futureIsObject(value)) {
        const entries = Object.entries(value);
        if (!entries.length) return '<div class="analysis-data-empty">No fields returned</div>';
        return `<div class="analysis-data-grid">${entries.map(([key, item]) => {
            const label = escapeHTML(formatAnalysisFieldLabel(key));
            if (item !== null && typeof item === "object") {
                const count = Array.isArray(item) ? `${item.length} records` : `${Object.keys(item).length} fields`;
                return `<details class="analysis-data-nested"><summary><span>${label}</span><small>${count}</small></summary><div class="analysis-data-nested-content">${renderCompleteAnalysisValue(item)}</div></details>`;
            }
            if (typeof item === "string" && item.length > 180) {
                const preview = `${item.slice(0, 150)}…`;
                return `<details class="analysis-data-long-text"><summary><span>${label}</span><small>${item.length.toLocaleString()} characters · expand</small><code>${escapeHTML(preview)}</code></summary><pre>${escapeHTML(item)}</pre></details>`;
            }
            const className = typeof item === "boolean" ? (item ? "is-true" : "is-false") : "";
            return `<div class="analysis-data-field"><span>${label}</span><strong class="analysis-data-value ${className}">${escapeHTML(resultCompactValue(item))}</strong></div>`;
        }).join("")}</div>`;
    }
    return `<span class="analysis-data-value">${escapeHTML(resultCompactValue(value))}</span>`;
};

const completeAnalysisModuleNames = {
    basic_information: "Message metadata",
    filename: "Source file",
    source_format: "Source format",
    headers: "Raw message headers",
    received_chain: "Received relay chain",
    ip_intelligence: "IP and origin intelligence",
    body: "Message body evidence",
    urls: "Extracted URLs",
    url_intelligence: "URL threat intelligence",
    advanced_url_intelligence: "Advanced URL deception",
    link_deception_intelligence: "Rendered-link deception",
    attachments: "Attachment evidence",
    authentication: "Email authentication",
    threat_analysis: "Risk scoring and indicators",
    email_thread_intelligence: "Conversation and thread intelligence",
    email_forensics: "Email header and transport forensics",
    email_ai: "AI classification and calibration",
    threat_intelligence: "IOC threat intelligence",
    threat_intelligence_v2: "Correlated threat intelligence v2",
    intelligence_fusion: "Intelligence fusion and explainability",
    ioc_threat_score: "IOC scoring evidence",
    evidence_governance: "Evidence custody and integrity"
};
const completeAnalysisModuleMarkup = Object.entries(analysis)
    .map(([key, value]) => {
        const title = completeAnalysisModuleNames[key] || formatAnalysisFieldLabel(key);
        const count = Array.isArray(value)
            ? `${value.length} records`
            : futureIsObject(value)
                ? `${Object.keys(value).length} fields`
                : "Value";
        return `<details class="complete-analysis-module"><summary><span>${escapeHTML(title)}</span><small>${escapeHTML(count)}</small></summary><div class="complete-analysis-module-content">${renderCompleteAnalysisValue(value)}</div></details>`;
    }).join("");


// ------------------------------------------------------------
// EXISTING RESULT HANDLING
// ------------------------------------------------------------

const existingResult =
                document.getElementById(
                    "investigationResult"
                );

            if (existingResult) {
                existingResult.remove();
            }


            const resultSection =
                document.createElement("section");

            resultSection.id =
                "investigationResult";

            resultSection.className =
                "investigation-result";


            resultSection.innerHTML = `

                <!-- =================================
                    RESULT HEADER
                ================================== -->

                <div class="result-header">

                    <div>

                        <div class="eyebrow">
                            EMAIL SECURITY ASSESSMENT
                        </div>

                        <h2>
                            Analysis result
                        </h2>

                        <p>
                            ${escapeHTML(
                                analysis.filename ||
                                "Email"
                            )}
                        </p>

                        <div class="result-file-meta">
                            <span>${escapeHTML(String(analysis.source_format || "EMAIL").toUpperCase())} source</span>
                        </div>

                    </div>


                    <div class="result-header-actions">
                        <button type="button" id="resultMapHeaderAction" class="investigation-map-view-btn result-map-header-action" aria-label="View infrastructure map for this investigation">
                            <i data-lucide="map" aria-hidden="true"></i><span>View Map</span>
                        </button>
                        <div class="result-status threat-status">

                            <span class="result-status-dot"></span>

                            ${escapeHTML(
                                threat.verdict ||
                                "ANALYSIS COMPLETE"
                            )}

                        </div>

                    </div>

                </div>

                <section class="result-overview result-overview-${resultRiskBand}" aria-label="Assessment overview">
                    <div class="result-overview-score-wrap">
                        <div class="result-score-ring" style="--risk-angle:${resultRiskScore * 3.6}deg" role="img" aria-label="${resultScoreAvailable ? `Risk score ${resultRiskScore} out of 100` : "Risk score not available"}">
                            <span>${resultScoreAvailable ? resultRiskScore : "—"}</span>
                            <small>RISK SCORE</small>
                        </div>
                    </div>
                    <div class="result-overview-main">
                        <div class="result-overview-heading">
                            <div>
                                <span class="result-overview-kicker">EXECUTIVE SUMMARY</span>
                                <h3>${escapeHTML(resultRiskLabel)}</h3>
                            </div>
                            <span class="result-confidence-chip">${escapeHTML(resultConfidenceLabel)}</span>
                        </div>
                        <p>${escapeHTML(resultRiskGuidance)}</p>
                        <div class="result-message-context">
                            <div><span>SUBJECT</span><strong>${escapeHTML(info.subject || "Not available")}</strong></div>
                            <div><span>SENDER</span><strong>${escapeHTML(info.from || "Not available")}</strong></div>
                        </div>
                        <div class="result-overview-metrics" aria-label="Evidence summary">
                            <div><strong>${scoreBreakdown.length}</strong><span>Scoring factors</span></div>
                            <div><strong>${matchedIOCCount}</strong><span>Threat intel matches</span></div>
                            <div><strong>${urls.length}</strong><span>URLs extracted</span></div>
                            <div><strong>${attachments.length}</strong><span>Attachments</span></div>
                            <div><strong>${receivedChain.length}</strong><span>Relay hops</span></div>
                        </div>
                        ${resultTopSignals.length ? `
                            <div class="result-top-signals">
                                <span>TOP REPORTED SIGNALS</span>
                                <ul>${resultTopSignals.map(signal => `<li>${escapeHTML(String(signal))}</li>`).join("")}</ul>
                            </div>
                        ` : ""}
                        <div class="result-next-steps">
                            <div class="result-next-steps-heading"><span class="result-next-steps-icon" aria-hidden="true">→</span><div><span>ANALYST HANDOFF</span><strong>Recommended next steps</strong></div></div>
                            <ol>${resultNextSteps.map(step => `<li>${escapeHTML(step)}</li>`).join("")}</ol>
                        </div>
                        <p class="result-assessment-note">Automated triage support · Review the underlying evidence before making a final disposition.</p>
                    </div>
                </section>

                <!-- =================================
                    RESULT GRID
                ================================== -->

                <div class="result-grid">


                    <!-- EMAIL INFORMATION -->

                    <div class="result-card">

                        <div class="result-card-title">
                            EMAIL INFORMATION
                        </div>


                        <div class="result-row">

                            <span>
                                Subject
                            </span>

                            <strong>
                                ${escapeHTML(
                                    info.subject ||
                                    "Not available"
                                )}
                            </strong>

                        </div>


                        <div class="result-row">

                            <span>
                                From
                            </span>

                            <strong>
                                ${escapeHTML(
                                    info.from ||
                                    "Not available"
                                )}
                            </strong>

                        </div>


                        <div class="result-row">

                            <span>
                                To
                            </span>

                            <strong>
                                ${escapeHTML(
                                    info.to ||
                                    "Not available"
                                )}
                            </strong>

                        </div>

                        <div class="result-row">
                            <span>CC</span>
                            <strong>${escapeHTML(info.cc || "Not available")}</strong>
                        </div>

                        <div class="result-row">
                            <span>Date</span>
                            <strong>${escapeHTML(info.date || "Not available")}</strong>
                        </div>

                        <div class="result-row">
                            <span>Message ID</span>
                            <strong>${escapeHTML(info.message_id || "Not available")}</strong>
                        </div>


                        <div class="result-row">

                            <span>
                                Reply-To
                            </span>

                            <strong>
                                ${escapeHTML(
                                    info.reply_to ||
                                    "Not available"
                                )}
                            </strong>

                        </div>


                        <div class="result-row">

                            <span>
                                Return-Path
                            </span>

                            <strong>
                                ${escapeHTML(
                                    info.return_path ||
                                    "Not available"
                                )}
                            </strong>

                        </div>

                    </div>


                    <!-- EXTRACTED INDICATORS -->

                    <div class="result-card">

                        <div class="result-card-title">
                            EXTRACTED INDICATORS
                        </div>


                        <div class="indicator-number">

                            <strong>
                                ${urls.length}
                            </strong>

                            <span>
                                URLs detected
                            </span>

                        </div>


                        <div class="indicator-number">

                            <strong>
                                ${attachments.length}
                            </strong>

                            <span>
                                Attachments
                            </span>

                        </div>

                    </div>

                    <!-- =================================
                        THREAT INTELLIGENCE / IOC CORRELATION
                    ================================== -->

                    <div class="result-card mt-ti-card">

                        <div class="result-card-title">
                            THREAT INTELLIGENCE
                        </div>

                        <div class="mt-ti-status-row">

                            <span>
                                LOCAL THREAT INTELLIGENCE
                            </span>

                            <strong>
                                ${escapeHTML(
                                    String(threatIntelStatus).replace(
                                        /_/g,
                                        " "
                                    ).toUpperCase()
                                )}
                            </strong>

                        </div>


                        <div class="mt-ti-summary">

                            <div class="mt-ti-summary-item">

                                <div class="mt-ti-summary-value">
                                    ${normalizedIOCs.length}
                                </div>

                                <div class="mt-ti-summary-label">
                                    TOTAL IOCs
                                </div>

                            </div>


                            <div class="mt-ti-summary-item">

                                <div class="mt-ti-summary-value">
                                    ${Number(
                                        iocSummary.url || 0
                                    )}
                                </div>

                                <div class="mt-ti-summary-label">
                                    URLS
                                </div>

                            </div>


                            <div class="mt-ti-summary-item">

                                <div class="mt-ti-summary-value">
                                    ${Number(
                                        iocSummary.domain || 0
                                    )}
                                </div>

                                <div class="mt-ti-summary-label">
                                    DOMAINS
                                </div>

                            </div>


                            <div class="mt-ti-summary-item">

                                <div class="mt-ti-summary-value">
                                    ${Number(
                                        iocSummary.ip || 0
                                    )}
                                </div>

                                <div class="mt-ti-summary-label">
                                    IPs
                                </div>

                            </div>


                            <div class="mt-ti-summary-item">

                                <div class="mt-ti-summary-value">
                                    ${matchedIOCCount}
                                </div>

                                <div class="mt-ti-summary-label">
                                    MATCHES
                                </div>

                            </div>

                        </div>


                        <div class="mt-ti-section">

                            <div class="mt-ti-section-title">
                                EXTRACTED IOCs
                            </div>


                            <div class="mt-ti-ioc-list">

                                ${
                                    normalizedIOCs.length > 0
                                        ? normalizedIOCs.map(item => `
                                            <div class="mt-ti-ioc-row">

                                                <div class="mt-ti-ioc-main">

                                                    <span class="mt-ti-ioc-value">
                                                        ${escapeHTML(
                                                            String(
                                                                item.ioc ||
                                                                "Unknown IOC"
                                                            )
                                                        )}
                                                    </span>

                                                    <span class="mt-ti-ioc-type">
                                                        ${escapeHTML(
                                                            String(
                                                                item.ioc_type ||
                                                                "unknown"
                                                            ).toUpperCase()
                                                        )}
                                                    </span>

                                                </div>

                                            </div>
                                        `).join("")
                                        : `
                                            <div class="mt-ti-empty">
                                                No normalized IOCs detected.
                                            </div>
                                        `
                                }

                            </div>

                        </div>


                        <div class="mt-ti-section">

                            <div class="mt-ti-section-title">
                                THREATFOX MATCHES
                            </div>


                            <div class="mt-ti-match-list">

                                ${
                                    Object.keys(threatIntelMatches).length > 0

                                        ? Object.entries(
                                            threatIntelMatches
                                        ).flatMap(
                                            ([matchedIOC, records]) => {

                                                if (!Array.isArray(records)) {
                                                    return [];
                                                }

                                                return records.map(
                                                    record => `

                                                        <div class="mt-ti-match-card">

                                                            <div class="mt-ti-match-header">

                                                                <span class="mt-ti-match-ioc">
                                                                    ${escapeHTML(
                                                                        String(
                                                                            matchedIOC
                                                                        )
                                                                    )}
                                                                </span>

                                                                <span class="mt-ti-confidence">
                                                                    ${escapeHTML(
                                                                        String(
                                                                            record.confidence ??
                                                                            "N/A"
                                                                        )
                                                                    )}% CONFIDENCE
                                                                </span>

                                                            </div>


                                                            <div class="mt-ti-match-grid">

                                                                <div>

                                                                    <span class="mt-ti-field-label">
                                                                        SOURCE
                                                                    </span>

                                                                    <span class="mt-ti-field-value">
                                                                        ${escapeHTML(
                                                                            String(
                                                                                record.source ||
                                                                                "ThreatFox"
                                                                            )
                                                                        )}
                                                                    </span>

                                                                </div>


                                                                <div>

                                                                    <span class="mt-ti-field-label">
                                                                        IOC TYPE
                                                                    </span>

                                                                    <span class="mt-ti-field-value">
                                                                        ${escapeHTML(
                                                                            String(
                                                                                record.ioc_type ||
                                                                                "N/A"
                                                                            )
                                                                        )}
                                                                    </span>

                                                                </div>


                                                                <div>

                                                                    <span class="mt-ti-field-label">
                                                                        THREAT TYPE
                                                                    </span>

                                                                    <span class="mt-ti-field-value">
                                                                        ${escapeHTML(
                                                                            String(
                                                                                record.threat_type ||
                                                                                "N/A"
                                                                            )
                                                                        )}
                                                                    </span>

                                                                </div>


                                                                <div>

                                                                    <span class="mt-ti-field-label">
                                                                        MALWARE
                                                                    </span>

                                                                    <span class="mt-ti-field-value">
                                                                        ${escapeHTML(
                                                                            String(
                                                                                record.malware ||
                                                                                "N/A"
                                                                            )
                                                                        )}
                                                                    </span>

                                                                </div>

                                                            </div>

                                                        </div>

                                                    `
                                                );
                                            }
                                        ).join("")

                                        : `
                                            <div class="mt-ti-empty">
                                                No ThreatFox matches found for the extracted IOCs.
                                            </div>
                                        `
                                }

                            </div>

                        </div>

                    </div>



                    <!-- AUTHENTICATION -->

                    <div class="result-card">

                        <div class="result-card-title">
                            AUTHENTICATION
                        </div>


                        <div class="auth-item">

                            <span>
                                SPF
                            </span>

                            <strong class="
                                ${getAuthClass(
                                    authentication.spf
                                )}
                            ">

                                ${authentication.spf ||
                                "NOT FOUND"}

                            </strong>

                        </div>


                        <div class="auth-item">

                            <span>
                                DKIM
                            </span>

                            <strong class="
                                ${getAuthClass(
                                    authentication.dkim
                                )}
                            ">

                                ${authentication.dkim ||
                                "NOT FOUND"}

                            </strong>

                        </div>


                        <div class="auth-item">

                            <span>
                                DMARC
                            </span>

                            <strong class="
                                ${getAuthClass(
                                    authentication.dmarc
                                )}
                            ">

                                ${authentication.dmarc ||
                                "NOT FOUND"}

                            </strong>

                        </div>

                    </div>


                    <!-- THREAT ASSESSMENT -->

                    <div class="result-card threat-score-card">

                        <div class="result-card-title">
                            THREAT ASSESSMENT
                        </div>


                        <div class="threat-score">

                            <strong>
                                ${threat.score || 0}
                            </strong>

                            <span>
                                / 100
                            </span>

                        </div>


                        <div class="threat-verdict">

                            ${escapeHTML(
                                threat.verdict ||
                                "UNKNOWN"
                            )}

                        </div>


                        <div class="threat-confidence">

                            Confidence:
                            ${escapeHTML(
                                threat.confidence ||
                                "UNKNOWN"
                            )}

                        </div>

                    </div>


                </div>


                <!-- IOC SCORE SOURCE -->
                <section class="result-card body-card ioc-evidence-card">
                    <div class="result-card-title"><span>IOC SCORING EVIDENCE</span><span class="ioc-status-chip ioc-${iocScoreBand}">${escapeHTML(iocScoreStatus)}</span></div>
                    <div class="ioc-score-layout">
                        <div class="ioc-score-panel ioc-${iocScoreBand}">
                            <div class="ioc-score-heading"><span>IOC RISK SCORE</span><span>0–100</span></div>
                            <div class="ioc-score-value"><strong>${escapeHTML(String(iocScore))}</strong><span>/ 100</span></div>
                            <div class="ioc-score-track" role="img" aria-label="IOC risk score ${escapeHTML(String(iocScore))} out of 100"><span style="width:${Math.max(0, Math.min(100, iocScore))}%"></span></div>
                            <p>${iocEvidence.length || iocMatchedCount ? "Score reflects IOC evidence returned by the analysis pipeline." : "No matching IOC evidence was returned. This alone does not establish that the message is safe."}</p>
                        </div>
                        <div class="ioc-score-facts">
                            <div><span>Matched indicators</span><strong>${escapeHTML(String(iocMatchedCount))}</strong><small>Indicators matched against available threat intelligence</small></div>
                            <div><span>Evidence records</span><strong>${iocEvidence.length.toLocaleString()}</strong><small>IOC-specific reasons returned for this message</small></div>
                        </div>
                    </div>
                    ${iocEvidence.length ? `<div class="ioc-evidence-list"><div class="ioc-evidence-list-heading"><span>OBSERVED IOC EVIDENCE</span><small>${iocEvidence.length} record${iocEvidence.length === 1 ? "" : "s"}</small></div>${iocEvidence.map((item, index) => {
                        const evidenceObject = futureIsObject(item) ? item : null;
                        const evidenceText = typeof item === "string" ? item : evidenceObject?.description || evidenceObject?.reason || evidenceObject?.indicator || evidenceObject?.value || "IOC evidence record";
                        const evidenceType = evidenceObject?.type || evidenceObject?.indicator_type || evidenceObject?.source || "IOC match";
                        const confidence = evidenceObject?.confidence ?? evidenceObject?.score ?? evidenceObject?.severity;
                        return `<article class="ioc-evidence-item"><span class="ioc-evidence-index">${String(index + 1).padStart(2, "0")}</span><div class="ioc-evidence-copy"><span>${escapeHTML(formatAnalysisFieldLabel(evidenceType))}</span><strong>${escapeHTML(evidenceText)}</strong>${evidenceObject ? `<small>${Object.entries(evidenceObject).filter(([key]) => !["description", "reason", "indicator", "value", "type", "indicator_type", "source"].includes(key)).map(([key, value]) => `${escapeHTML(formatAnalysisFieldLabel(key))}: ${escapeHTML(resultCompactValue(value))}`).join(" · ")}</small>` : ""}</div>${confidence !== undefined ? `<span class="ioc-evidence-confidence">${escapeHTML(resultCompactValue(confidence))}</span>` : ""}</article>`;
                    }).join("")}</div>` : '<div class="ioc-evidence-empty"><span aria-hidden="true">◎</span><div><strong>No IOC-specific matches were returned</strong><p>The report still includes other signals such as sender authentication, URL analysis, attachments, and message context. Review the overall assessment before making a decision.</p></div></div>'}
                </section>


                <!-- ATTACHMENT EVIDENCE -->
                ${attachments.length ? `
                    <section class="result-card body-card attachment-evidence-card">
                        <div class="result-card-title"><span>ATTACHMENT EVIDENCE</span><span class="url-result-count">${attachments.length} file${attachments.length === 1 ? "" : "s"} parsed</span></div>
                        <p class="attachment-evidence-intro">File properties returned by the analysis pipeline. A listed attachment has not been declared safe unless a separate scan result says so.</p>
                        <div class="attachment-evidence-list">
                            ${attachments.map((attachment, index) => `
                                <article class="attachment-evidence-item">
                                    <div class="attachment-evidence-icon" aria-hidden="true">${String(index + 1).padStart(2, "0")}</div>
                                    <div class="attachment-evidence-main">
                                        <strong>${escapeHTML(attachment.filename || `Attachment ${index + 1}`)}</strong>
                                        <div class="attachment-evidence-meta">
                                            <span>${escapeHTML(attachment.content_type || "Type not reported")}</span>
                                            <span>${attachment.size === null || attachment.size === undefined ? "Size not reported" : `${Number(attachment.size).toLocaleString()} bytes`}</span>
                                            ${attachment.sha256 ? `<code>SHA-256 ${escapeHTML(attachment.sha256)}</code>` : ""}
                                        </div>
                                    </div>
                                    <span class="attachment-evidence-status">${escapeHTML(attachment.verdict || attachment.status || "METADATA PARSED")}</span>
                                </article>
                            `).join("")}
                        </div>
                    </section>
                ` : ""}


                <!-- =================================
                    EMAIL BODY
                ================================== -->

                <div class="result-card body-card">

                    <div class="result-card-title">
                        EMAIL BODY
                    </div>


                    <div class="email-body-preview">

                        ${formatEmailBody(body.text)}

                    </div>

                </div>
            <!-- =================================
                THREAT SCORE BREAKDOWN
            ================================== -->

            ${
                scoreBreakdown.length > 0
                ? `

                    <div class="result-card body-card">

                        <div class="result-card-title">
                            THREAT SCORE BREAKDOWN
                        </div>

                        <div class="score-breakdown-list">

                            ${scoreBreakdown.map(item => `

                                <div class="score-breakdown-item">

                                    <div class="score-breakdown-info">

                                        <span class="score-breakdown-category">
                                            ${escapeHTML(
                                                item.category ||
                                                "Security Signal"
                                            )}
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                item.signal ||
                                                "Threat indicator"
                                            )}
                                        </strong>

                                    </div>

                                    <span class="score-breakdown-points">
                                        +${escapeHTML(
                                            String(
                                                item.points ?? 0
                                            )
                                        )}
                                    </span>

                                </div>

                            `).join("")}

                        </div>

                        <div class="score-breakdown-total">

                            <span>
                                TOTAL THREAT SCORE
                            </span>

                            <strong>
                                ${escapeHTML(
                                    String(
                                        threat.score ?? 0
                                    )
                                )} / 100
                            </strong>

                        </div>

                    </div>

                `
                : ""
            }



                <!-- =================================
                    FORENSIC INDICATORS
                ================================== -->

                ${
                    indicators.length > 0
                    ? `

                        <div class="result-card body-card">

                            <div class="result-card-title">
                                FORENSIC INDICATORS
                            </div>


                            <div class="indicator-list">

                                ${indicators.map(
                                    indicator => `

                                    <div class="forensic-indicator">

                                        <div class="indicator-top">

                                            <span class="
                                                indicator-severity
                                                ${
                                                    indicator.severity ||
                                                    "info"
                                                }
                                            ">

                                                ${(
                                                    indicator.severity ||
                                                    "info"
                                                ).toUpperCase()}

                                            </span>


                                            <strong>

                                                ${escapeHTML(
                                                    indicator.title ||
                                                    "Security Indicator"
                                                )}

                                            </strong>

                                        </div>


                                        <p>

                                            ${escapeHTML(
                                                indicator.description ||
                                                "No description available."
                                            )}

                                        </p>

                                    </div>

                                `
                                ).join("")}

                            </div>

                        </div>

                    `
                    : ""
                }


            <!-- =================================
            URL THREAT INTELLIGENCE
        ================================== -->

        ${
            urlIntelligence.length > 0
            ? `

                <div class="result-card body-card url-intelligence-card">

                    <div class="result-card-title url-intelligence-title">
                        <span>URL THREAT INTELLIGENCE</span>
                        <span class="url-result-count">${urlIntelligence.length} URL${urlIntelligence.length === 1 ? "" : "s"} analyzed</span>
                    </div>
                    <p class="url-intelligence-intro">Each extracted destination is shown with its returned domain, transport, score and observed reasons. A low score does not by itself establish that a URL is safe.</p>

                    <div class="url-intelligence-list">

                        ${urlIntelligence.map(urlInfo => `

                            <div class="url-intelligence-item">

                                <!-- URL HEADER -->

                                <div class="url-intelligence-header">

                                    <div class="url-main">

                                        <span class="url-label">
                                            DETECTED URL
                                        </span>

                                        <code class="url-value">
                                            ${escapeHTML(
                                                resultURLPreview(urlInfo.url || "Unknown URL")
                                            )}
                                        </code>

                                    </div>

                                    <span class="url-risk url-risk-${escapeHTML(String(urlInfo.risk || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-"))}">
                                        ${escapeHTML(
                                            urlInfo.risk ||
                                            "UNKNOWN"
                                        )}
                                    </span>

                                </div>

                                <details class="url-full-details">
                                    <summary>Inspect full destination</summary>
                                    <code>${escapeHTML(urlInfo.url || "Unknown URL")}</code>
                                </details>


                                <!-- URL DETAILS -->

                                <div class="url-details">

                                    <div class="url-detail">

                                        <span>
                                            DOMAIN
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                urlInfo.domain ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="url-detail">

                                        <span>
                                            PROTOCOL
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                urlInfo.scheme ||
                                                "Not available"
                                            ).toUpperCase()}
                                        </strong>

                                    </div>


                                    <div class="url-detail">

                                        <span>
                                            HTTPS
                                        </span>

                                        <strong class="
                                            ${
                                                urlInfo.is_https
                                                ? "url-safe"
                                                : "url-danger"
                                            }
                                        ">
                                            ${
                                                urlInfo.is_https
                                                ? "YES"
                                                : "NO"
                                            }
                                        </strong>

                                    </div>


                                    <div class="url-detail">

                                        <span>
                                            IP-BASED URL
                                        </span>

                                        <strong class="
                                            ${
                                                urlInfo.is_ip_url
                                                ? "url-danger"
                                                : "url-safe"
                                            }
                                        ">
                                            ${
                                                urlInfo.is_ip_url
                                                ? "YES"
                                                : "NO"
                                            }
                                        </strong>

                                    </div>


                                    <div class="url-detail">

                                        <span>
                                            RISK SCORE
                                        </span>

                                        <strong>
                                            ${urlInfo.risk_score === null || urlInfo.risk_score === undefined || urlInfo.risk_score === "" ? "Not scored" : `${escapeHTML(String(urlInfo.risk_score))} / 100`}
                                        </strong>

                                    </div>

                                </div>


                                <!-- SUSPICIOUS KEYWORDS -->

                                ${
                                    urlInfo.suspicious_keywords &&
                                    urlInfo.suspicious_keywords.length > 0

                                    ? `

                                        <div class="url-section">

                                            <div class="url-section-title">
                                                SUSPICIOUS KEYWORDS
                                            </div>

                                            <div class="url-tags">

                                                ${urlInfo.suspicious_keywords
                                                    .map(keyword => `
                                                        <span class="url-tag warning">
                                                            ${escapeHTML(keyword)}
                                                        </span>
                                                    `)
                                                    .join("")
                                                }

                                            </div>

                                        </div>

                                    `

                                    : ""
                                }


                                <!-- BRAND INDICATORS -->

                                ${
                                    urlInfo.brand_indicators &&
                                    urlInfo.brand_indicators.length > 0

                                    ? `

                                        <div class="url-section">

                                            <div class="url-section-title">
                                                BRAND INDICATORS
                                            </div>

                                            <div class="url-tags">

                                                ${urlInfo.brand_indicators
                                                    .map(brand => `
                                                        <span class="url-tag brand">
                                                            ${escapeHTML(brand)}
                                                        </span>
                                                    `)
                                                    .join("")
                                                }

                                            </div>

                                        </div>

                                    `

                                    : ""
                                }


                                <!-- URL FINDINGS -->

                                ${
                                    Array.isArray(urlInfo.findings) &&
                                    urlInfo.findings.length > 0

                                    ? `

                                        <div class="url-section">

                                            <div class="url-section-title">
                                                URL FINDINGS
                                            </div>

                                            <div class="url-reasons">

                                                ${urlInfo.findings
                                                    .map(finding => {

                                                        const severity =
                                                            String(
                                                                finding.severity ||
                                                                "INFO"
                                                            ).toLowerCase();

                                                        return `
                                                            <div class="url-reason">

                                                                <span class="
                                                                    indicator-severity
                                                                    ${escapeHTML(severity)}
                                                                ">
                                                                    ${escapeHTML(
                                                                        String(
                                                                            finding.severity ||
                                                                            "INFO"
                                                                        ).toUpperCase()
                                                                    )}
                                                                </span>

                                                                <div>
                                                                    <strong>
                                                                        ${escapeHTML(
                                                                            finding.title ||
                                                                            "URL Finding"
                                                                        )}
                                                                    </strong>

                                                                    <p>
                                                                        ${escapeHTML(
                                                                            finding.description ||
                                                                            "No description available."
                                                                        )}
                                                                    </p>

                                                                    ${
                                                                        Array.isArray(finding.matches) &&
                                                                        finding.matches.length > 0
                                                                        ? `
                                                                            <div class="url-tags">
                                                                                ${finding.matches
                                                                                    .map(match => `
                                                                                        <span class="url-tag warning">
                                                                                            ${escapeHTML(match)}
                                                                                        </span>
                                                                                    `)
                                                                                    .join("")
                                                                                }
                                                                            </div>
                                                                        `
                                                                        : ""
                                                                    }
                                                                </div>

                                                            </div>
                                                        `;
                                                    })
                                                    .join("")
                                                }

                                            </div>

                                        </div>

                                    `
                                    : ""
                                }

                                <!-- ANALYSIS REASONS -->

                                ${
                                    urlInfo.reasons &&
                                    urlInfo.reasons.length > 0

                                    ? `

                                        <div class="url-section">

                                            <div class="url-section-title">
                                                ANALYSIS REASONS
                                            </div>

                                            <div class="url-reasons">

                                                ${urlInfo.reasons
                                                    .map(reason => `
                                                        <div class="url-reason">
                                                            <span>⚠</span>
                                                            <p>
                                                                ${escapeHTML(reason)}
                                                            </p>
                                                        </div>
                                                    `)
                                                    .join("")
                                                }

                                            </div>

                                        </div>

                                    `

                                    : ""
                                }

                            </div>

                        `).join("")}

                    </div>

                </div>

            `

            : (

                urls.length > 0

                ? `

                    <div class="result-card body-card">

                        <div class="result-card-title">
                            DETECTED URLS
                        </div>

                        <div class="url-list">

                            ${urls.map(url => `

                                <div class="url-item">

                                    <span>↗</span>

                                    <code>
                                        ${escapeHTML(url)}
                                    </code>

                                </div>

                            `).join("")}

                        </div>

                    </div>

                `

                : ""
            )
        }


                <!-- =================================
                    MAIL RELAY PATH
                ================================== -->

                ${
                    receivedChain.length > 0
                    ? `

                        <div class="result-card body-card">

                            <div class="result-card-title">
                                MAIL RELAY PATH
                            </div>
                            ${
            ipIntelligence.length > 0
            ? `
                <div class="result-card origin-intelligence-card">

                    <div class="result-card-title">
                        ORIGIN INTELLIGENCE
                    </div>

                    <div class="origin-intelligence-subtitle">
                        Infrastructure intelligence derived from
                        observed relay IP addresses.
                    </div>

                    <div class="origin-list">

                        ${ipIntelligence.map(ip => `

                            <div class="origin-item">

                                <div class="origin-ip-header">

                                    <div>

                                        <span class="origin-label">
                                            OBSERVED IP
                                        </span>

                                        <strong class="origin-ip">
                                            ${escapeHTML(
                                                ip.ip || "Unknown"
                                            )}
                                        </strong>

                                    </div>

                                    <span class="
                                        origin-risk
                                        ${escapeHTML(
                                            String(
                                                ip.risk ||
                                                "UNKNOWN"
                                            ).toLowerCase()
                                        )}
                                    ">
                                        ${escapeHTML(
                                            ip.risk ||
                                            "UNKNOWN"
                                        )}
                                    </span>

                                </div>


                                <div class="origin-details">

                                    <div class="origin-detail">

                                        <span>
                                            HOSTNAME
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.hostname ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            COUNTRY
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.country ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            REGION
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.region ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            CITY
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.city ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            ISP
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.isp ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            ORGANIZATION
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.organization ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            ASN
                                        </span>

                                        <strong>
                                            ${escapeHTML(
                                                ip.asn ||
                                                "Not available"
                                            )}
                                        </strong>

                                    </div>


                                    <div class="origin-detail">

                                        <span>
                                            COORDINATES
                                        </span>

                                        <strong>

                                            ${
                                                ip.latitude !== null &&
                                                ip.longitude !== null
                                                ? `${escapeHTML(
                                                    String(
                                                        ip.latitude
                                                    )
                                                )},
                                                ${escapeHTML(
                                                    String(
                                                        ip.longitude
                                                    )
                                                )}`
                                                : "Not available"
                                            }

                                        </strong>

                                    </div>

                                </div>

                            </div>

                        `).join("")}

                    </div>


                    <div class="origin-disclaimer">

                        ⚠ IP geolocation represents network
                        infrastructure location and does not
                        establish the exact physical location
                        or identity of an attacker.

                    </div>

                </div>
            `
            : ""
        }

                            <div class="relay-list">

                                ${receivedChain.map(
                                    hop => `

                                    <div class="relay-item">

                                        <div class="relay-hop">

                                            HOP ${hop.hop}

                                        </div>


                                        <div class="relay-details">

                                            ${
                                                hop.ip_addresses &&
                                                hop.ip_addresses.length
                                                ? hop.ip_addresses
                                                    .map(
                                                        ip =>
                                                            `<code>${escapeHTML(ip)}</code>`
                                                    )
                                                    .join(" ")
                                                : `
                                                    <span>
                                                        IP not detected
                                                    </span>
                                                `
                                            }

                                        </div>

                                    </div>

                                `
                                ).join("")}

                            </div>

                        </div>

                    `
                    : ""
                }


                <!-- =================================
                    ADVANCED URL DECEPTION INTELLIGENCE
                ================================== -->

                ${
                    advancedUrlModulePresent
                    ? `

                        <div class="result-card body-card mt-future-card">

                            <div class="result-card-title">
                                ADVANCED URL DECEPTION INTELLIGENCE
                            </div>

                            <div class="mt-future-subtitle">
                                Static canonicalization, parser-confusion,
                                identity and lure analysis
                            </div>

                            <div class="mt-future-list">

                                ${advancedUrlIntelligence.map((item, index) => `

                                    <div class="mt-future-item">

                                        <div class="mt-future-item-head">

                                            <div>
                                                <span class="mt-future-index">
                                                    URL ${index + 1}
                                                </span>

                                                <code class="mt-future-code">
                                                    ${escapeHTML(
                                                        String(
                                                            item.url ||
                                                            item.canonical_url ||
                                                            "Unknown URL"
                                                        )
                                                    )}
                                                </code>
                                            </div>

                                            <span class="
                                                mt-future-severity
                                                ${escapeHTML(
                                                    String(
                                                        item.severity ||
                                                        "NONE"
                                                    ).toLowerCase()
                                                )}
                                            ">
                                                ${escapeHTML(
                                                    String(
                                                        item.verdict ||
                                                        item.severity ||
                                                        "UNKNOWN"
                                                    )
                                                )}
                                            </span>

                                        </div>

                                        <div class="mt-future-grid">

                                            <div>
                                                <span>RISK SCORE</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            item.risk_score ??
                                                            0
                                                        )
                                                    )} / 100
                                                </strong>
                                            </div>

                                            <div>
                                                <span>CONFIDENCE</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            item.confidence ??
                                                            "N/A"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>DOMAIN</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            item.registrable_domain ||
                                                            item.ascii_hostname ||
                                                            item.hostname ||
                                                            "Not available"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>CANONICAL URL</span>
                                                <strong class="mt-future-wrap">
                                                    ${escapeHTML(
                                                        String(
                                                            item.canonical_url ||
                                                            "Not available"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                        </div>

                                        ${
                                            (
                                                item.punycode_detected ||
                                                item.idn_detected ||
                                                item.unicode_confusable ||
                                                item.encoded_host_detected ||
                                                item.encoded_path_detected ||
                                                item.parser_confusion ||
                                                item.userinfo_present ||
                                                item.brand_domain_mismatch
                                            )
                                            ? `

                                                <div class="mt-future-signal-row">

                                                    ${
                                                        item.punycode_detected
                                                        ? `<span class="mt-future-tag">PUNYCODE</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.idn_detected
                                                        ? `<span class="mt-future-tag">IDN</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.unicode_confusable
                                                        ? `<span class="mt-future-tag danger">UNICODE CONFUSABLE</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.encoded_host_detected
                                                        ? `<span class="mt-future-tag warning">ENCODED HOST</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.encoded_path_detected
                                                        ? `<span class="mt-future-tag warning">ENCODED PATH</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.parser_confusion
                                                        ? `<span class="mt-future-tag danger">PARSER CONFUSION</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.userinfo_present
                                                        ? `<span class="mt-future-tag danger">USERINFO</span>`
                                                        : ""
                                                    }

                                                    ${
                                                        item.brand_domain_mismatch
                                                        ? `<span class="mt-future-tag danger">BRAND DOMAIN MISMATCH</span>`
                                                        : ""
                                                    }

                                                </div>

                                            `
                                            : ""
                                        }

                                        ${
                                            Array.isArray(item.brand_candidates) &&
                                            item.brand_candidates.length > 0
                                            ? `

                                                <div class="mt-future-section">

                                                    <span class="mt-future-section-title">
                                                        BRAND SIGNALS
                                                    </span>

                                                    <div class="mt-future-tags">

                                                        ${item.brand_candidates.map(
                                                            brand => `
                                                                <span class="mt-future-tag brand">
                                                                    ${escapeHTML(String(brand))}
                                                                </span>
                                                            `
                                                        ).join("")}

                                                    </div>

                                                </div>

                                            `
                                            : ""
                                        }

                                        ${
                                            Array.isArray(item.lure_tokens) &&
                                            item.lure_tokens.length > 0
                                            ? `

                                                <div class="mt-future-section">

                                                    <span class="mt-future-section-title">
                                                        LURE TOKENS
                                                    </span>

                                                    <div class="mt-future-tags">

                                                        ${item.lure_tokens.map(
                                                            token => `
                                                                <span class="mt-future-tag warning">
                                                                    ${escapeHTML(String(token))}
                                                                </span>
                                                            `
                                                        ).join("")}

                                                    </div>

                                                </div>

                                            `
                                            : ""
                                        }

                                        ${
                                            Array.isArray(item.findings) &&
                                            item.findings.length > 0
                                            ? `

                                                <div class="mt-future-section">

                                                    <span class="mt-future-section-title">
                                                        DECEPTION FINDINGS
                                                    </span>

                                                    <div class="mt-future-findings">

                                                        ${item.findings.map(
                                                            finding => `

                                                                <div class="mt-future-finding">

                                                                    <span class="
                                                                        mt-future-severity
                                                                        ${escapeHTML(
                                                                            String(
                                                                                finding.severity ||
                                                                                "INFO"
                                                                            ).toLowerCase()
                                                                        )}
                                                                    ">
                                                                        ${escapeHTML(
                                                                            String(
                                                                                finding.severity ||
                                                                                "INFO"
                                                                            )
                                                                        )}
                                                                    </span>

                                                                    <div>

                                                                        <strong>
                                                                            ${escapeHTML(
                                                                                String(
                                                                                    finding.title ||
                                                                                    finding.rule_id ||
                                                                                    "URL Finding"
                                                                                )
                                                                            )}
                                                                        </strong>

                                                                        <p>
                                                                            ${escapeHTML(
                                                                                String(
                                                                                    finding.description ||
                                                                                    ""
                                                                                )
                                                                            )}
                                                                        </p>

                                                                    </div>

                                                                </div>

                                                            `
                                                        ).join("")}

                                                    </div>

                                                </div>

                                            `
                                            : ""
                                        }

                                    </div>

                                `).join("")}

                            </div>

                        </div>

                    `
                    : ""
                }


                <!-- =================================
                    RENDERED LINK DECEPTION
                ================================== -->

                ${
                    linkDeceptionModulePresent
                    ? `

                        <div class="result-card body-card mt-future-card">

                            <div class="result-card-title">
                                RENDERED LINK DECEPTION
                            </div>

                            <div class="mt-future-grid compact">

                                <div>
                                    <span>LINKS INSPECTED</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                linkDeceptionIntelligence.links_inspected ??
                                                linkDeceptionIntelligence.anchors_inspected ??
                                                linkDeceptionLinks.length
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>FINDINGS</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                linkDeceptionIntelligence.findings_count ??
                                                0
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>HIGH RISK</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                linkDeceptionIntelligence.high_risk_links ??
                                                0
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>CRITICAL</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                linkDeceptionIntelligence.critical_links ??
                                                0
                                            )
                                        )}
                                    </strong>
                                </div>

                            </div>

                            ${
                                linkDeceptionLinks.length > 0
                                ? `

                                    <div class="mt-future-findings">

                                        ${linkDeceptionLinks.map(
                                            (link, index) => `

                                                <div class="mt-future-item">

                                                    <div class="mt-future-item-head">

                                                        <span class="mt-future-index">
                                                            LINK ${index + 1}
                                                        </span>

                                                        <span class="
                                                            mt-future-severity
                                                            ${escapeHTML(
                                                                String(
                                                                    link.severity ||
                                                                    "NONE"
                                                                ).toLowerCase()
                                                            )}
                                                        ">
                                                            ${escapeHTML(
                                                                String(
                                                                    link.verdict ||
                                                                    link.severity ||
                                                                    "UNKNOWN"
                                                                )
                                                            )}
                                                        </span>

                                                    </div>

                                                    <div class="mt-future-grid">

                                                        <div>
                                                            <span>VISIBLE TEXT</span>
                                                            <strong class="mt-future-wrap">
                                                                ${escapeHTML(
                                                                    String(
                                                                        link.visible_text ||
                                                                        "Not available"
                                                                    )
                                                                )}
                                                            </strong>
                                                        </div>

                                                        <div>
                                                            <span>ACTUAL DESTINATION</span>
                                                            <strong class="mt-future-wrap">
                                                                ${escapeHTML(
                                                                    String(
                                                                        link.actual_destination ||
                                                                        "Not available"
                                                                    )
                                                                )}
                                                            </strong>
                                                        </div>

                                                        <div>
                                                            <span>DECEPTION SCORE</span>
                                                            <strong>
                                                                ${escapeHTML(
                                                                    String(
                                                                        link.deception_score ??
                                                                        0
                                                                    )
                                                                )}
                                                            </strong>
                                                        </div>

                                                        <div>
                                                            <span>CONFIDENCE</span>
                                                            <strong>
                                                                ${escapeHTML(
                                                                    String(
                                                                        link.confidence ??
                                                                        "N/A"
                                                                    )
                                                                )}
                                                            </strong>
                                                        </div>

                                                    </div>

                                                    ${
                                                        Array.isArray(link.findings) &&
                                                        link.findings.length > 0
                                                        ? `

                                                            <div class="mt-future-section">

                                                                <span class="mt-future-section-title">
                                                                    LINK FINDINGS
                                                                </span>

                                                                <div class="mt-future-findings">

                                                                    ${link.findings.map(
                                                                        finding => `

                                                                            <div class="mt-future-finding">

                                                                                <span class="
                                                                                    mt-future-severity
                                                                                    ${escapeHTML(
                                                                                        String(
                                                                                            finding.severity ||
                                                                                            "INFO"
                                                                                        ).toLowerCase()
                                                                                    )}
                                                                                ">
                                                                                    ${escapeHTML(
                                                                                        String(
                                                                                            finding.severity ||
                                                                                            "INFO"
                                                                                        )
                                                                                    )}
                                                                                </span>

                                                                                <div>

                                                                                    <strong>
                                                                                        ${escapeHTML(
                                                                                            String(
                                                                                                finding.title ||
                                                                                                finding.rule_id ||
                                                                                                "Link Finding"
                                                                                            )
                                                                                        )}
                                                                                    </strong>

                                                                                    <p>
                                                                                        ${escapeHTML(
                                                                                            String(
                                                                                                finding.description ||
                                                                                                ""
                                                                                            )
                                                                                        )}
                                                                                    </p>

                                                                                </div>

                                                                            </div>

                                                                        `
                                                                    ).join("")}

                                                                </div>

                                                            </div>

                                                        `
                                                        : ""
                                                    }

                                                </div>

                                            `
                                        ).join("")}

                                    </div>

                                `
                                : ""
                            }

                        </div>

                    `
                    : ""
                }


                <!-- =================================
                    INTELLIGENCE FUSION
                ================================== -->

                ${
                    intelligenceFusionPresent
                    ? `

                        <div class="result-card body-card mt-future-card">

                            <div class="result-card-title">
                                INTELLIGENCE FUSION
                            </div>

                            <div class="mt-fusion-hero">

                                <div>
                                    <span>UNIFIED RISK</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                intelligenceFusion.unified_risk_score ??
                                                0
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>RISK TIER</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                intelligenceFusion.risk_tier ||
                                                "UNKNOWN"
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>DECISION</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                intelligenceFusion.decision ||
                                                "UNKNOWN"
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>CONFIDENCE</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                intelligenceFusion.confidence ??
                                                "N/A"
                                            )
                                        )}
                                    </strong>
                                </div>

                            </div>

                            ${
                                Array.isArray(intelligenceFusion.attack_intent) &&
                                intelligenceFusion.attack_intent.length > 0
                                ? `

                                    <div class="mt-future-section">

                                        <span class="mt-future-section-title">
                                            ATTACK INTENT
                                        </span>

                                        <div class="mt-future-tags">

                                            ${intelligenceFusion.attack_intent.map(
                                                intent => `
                                                    <span class="mt-future-tag danger">
                                                        ${escapeHTML(String(intent))}
                                                    </span>
                                                `
                                            ).join("")}

                                        </div>

                                    </div>

                                `
                                : ""
                            }

                            ${
                                fusionRiskDrivers.length > 0
                                ? `

                                    <div class="mt-future-section">

                                        <span class="mt-future-section-title">
                                            TOP RISK DRIVERS
                                        </span>

                                        <div class="mt-fusion-drivers">

                                            ${fusionRiskDrivers.slice(0, 6).map(
                                                driver => `

                                                    <div class="mt-fusion-driver">

                                                        <div>
                                                            <strong>
                                                                ${escapeHTML(
                                                                    String(
                                                                        driver.category ||
                                                                        "unknown"
                                                                    )
                                                                )}
                                                            </strong>

                                                            <span>
                                                                Confidence:
                                                                ${escapeHTML(
                                                                    String(
                                                                        driver.confidence ??
                                                                        "N/A"
                                                                    )
                                                                )}
                                                            </span>

                                                        </div>

                                                        <b>
                                                            ${escapeHTML(
                                                                String(
                                                                    driver.score ??
                                                                    0
                                                                )
                                                            )}
                                                        </b>

                                                    </div>

                                                `
                                            ).join("")}

                                        </div>

                                    </div>

                                `
                                : ""
                            }

                            ${
                                fusionCriticalSignals.length > 0
                                ? `

                                    <div class="mt-future-section">

                                        <span class="mt-future-section-title">
                                            CRITICAL CORROBORATING SIGNALS
                                        </span>

                                        <div class="mt-future-findings">

                                            ${fusionCriticalSignals.slice(0, 8).map(
                                                signal => `

                                                    <div class="mt-future-finding">

                                                        <span class="mt-future-tag danger">
                                                            ${escapeHTML(
                                                                String(
                                                                    signal.category ||
                                                                    "SIGNAL"
                                                                )
                                                            )}
                                                        </span>

                                                        <div>

                                                            <strong>
                                                                ${escapeHTML(
                                                                    String(
                                                                        signal.name ||
                                                                        "Signal"
                                                                    )
                                                                )}
                                                            </strong>

                                                            <p>
                                                                ${escapeHTML(
                                                                    String(
                                                                        signal.evidence ||
                                                                        ""
                                                                    )
                                                                )}
                                                            </p>

                                                        </div>

                                                    </div>

                                                `
                                            ).join("")}

                                        </div>

                                    </div>

                                `
                                : ""
                            }

                        </div>

                    `
                    : ""
                }


                <!-- =================================
                    EVIDENCE GOVERNANCE / CUSTODY
                ================================== -->

                ${
                    evidenceGovernancePresent
                    ? `

                        <div class="result-card body-card mt-future-card">

                            <div class="result-card-title">
                                EVIDENCE GOVERNANCE & INTEGRITY
                            </div>

                            <div class="mt-future-grid compact">

                                <div>
                                    <span>EVIDENCE ID</span>
                                    <strong class="mt-future-wrap">
                                        ${escapeHTML(
                                            String(
                                                evidenceGovernance.evidence_id ||
                                                "Not available"
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>CLASSIFICATION</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                evidenceGovernance.classification ||
                                                "UNKNOWN"
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>POLICY</span>
                                    <strong>
                                        ${escapeHTML(
                                            String(
                                                evidenceGovernance.policy_id ||
                                                "Not available"
                                            )
                                        )}
                                    </strong>
                                </div>

                                <div>
                                    <span>ACQUIRED</span>
                                    <strong class="mt-future-wrap">
                                        ${escapeHTML(
                                            String(
                                                evidenceGovernance.acquired_at_utc ||
                                                "Not available"
                                            )
                                        )}
                                    </strong>
                                </div>

                            </div>

                            <div class="mt-governance-status">

                                <div class="mt-governance-status-item">

                                    <span class="mt-governance-label">
                                        PRESERVATION
                                    </span>

                                    <strong class="
                                        ${evidencePreservation.verified
                                            ? "verified"
                                            : "pending"}
                                    ">
                                        ${
                                            evidencePreservation.verified
                                            ? "VERIFIED"
                                            : "NOT VERIFIED"
                                        }
                                    </strong>

                                </div>

                                <div class="mt-governance-status-item">

                                    <span class="mt-governance-label">
                                        CUSTODY
                                    </span>

                                    <strong class="
                                        ${
                                            evidenceCustody.verified
                                            ? "verified"
                                            : evidenceCustody.registered
                                                ? "pending"
                                                : "pending"
                                        }
                                    ">
                                        ${
                                            evidenceCustody.verified
                                            ? "VERIFIED"
                                            : evidenceCustody.registered
                                                ? "REGISTERED"
                                                : "PENDING"
                                        }
                                    </strong>

                                </div>

                                <div class="mt-governance-status-item">

                                    <span class="mt-governance-label">
                                        INTEGRITY ANCHOR
                                    </span>

                                    <strong class="
                                        ${evidenceIntegrity.verified
                                            ? "verified"
                                            : "pending"}
                                    ">
                                        ${
                                            evidenceIntegrity.verified
                                            ? "VERIFIED"
                                            : evidenceIntegrity.created
                                                ? "ANCHORED"
                                                : "NOT CREATED"
                                        }
                                    </strong>

                                </div>

                                <div class="mt-governance-status-item">

                                    <span class="mt-governance-label">
                                        HOLD STATE
                                    </span>

                                    <strong>
                                        ${
                                            evidenceRetention.legal_hold
                                            ? "LEGAL HOLD"
                                            : evidenceRetention.forensic_hold
                                                ? "FORENSIC HOLD"
                                                : "NORMAL"
                                        }
                                    </strong>

                                </div>

                            </div>

                            <div class="mt-future-grid">

                                <div>
                                    <span>CUSTODY REGISTERED</span>
                                    <strong>
                                        ${
                                            evidenceCustody.registered
                                            ? "YES"
                                            : "NO"
                                        }
                                    </strong>
                                </div>

                                <div>
                                    <span>CUSTODY SEALED</span>
                                    <strong>
                                        ${
                                            evidenceCustody.sealed
                                            ? "YES"
                                            : "NO"
                                        }
                                    </strong>
                                </div>

                                <div>
                                    <span>ANCHOR CREATED</span>
                                    <strong>
                                        ${
                                            evidenceIntegrity.created
                                            ? "YES"
                                            : "NO"
                                        }
                                    </strong>
                                </div>

                                <div>
                                    <span>DERIVED VIEWS</span>
                                    <strong>
                                        ${
                                            evidenceGovernanceMeta.derived_views_only
                                            ? "YES"
                                            : "NO"
                                        }
                                    </strong>
                                </div>

                            </div>

                            ${
                                evidenceIntegrity.receipt
                                ? `

                                    <div class="mt-future-section">

                                        <span class="mt-future-section-title">
                                            INDEPENDENT INTEGRITY RECEIPT
                                        </span>

                                        <div class="mt-receipt">

                                            <div>
                                                <span>ANCHOR ID</span>
                                                <strong class="mt-future-wrap">
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceIntegrity.receipt.anchor_id ||
                                                            "Not available"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>PROVIDER</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceIntegrity.receipt.provider ||
                                                            "local"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>STATUS</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceIntegrity.receipt.status ||
                                                            "UNKNOWN"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>TRUST LEVEL</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceIntegrity.receipt.trust_level ||
                                                            "UNKNOWN"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                        </div>

                                    </div>

                                `
                                : ""
                            }

                            <!-- =================================
                                FORENSIC VERIFICATION
                            ================================== -->

                            <div class="mt-future-section mt-forensic-verification">

                                <span class="mt-future-section-title">
                                    FORENSIC VERIFICATION
                                </span>

                                <div class="mt-future-grid compact">

                                    <div>
                                        <span>SHA-256</span>
                                        <strong class="mt-future-wrap">
                                            ${
                                                escapeHTML(
                                                    String(
                                                        evidenceCustodyVerification.calculated_sha256 ||
                                                        "Not available"
                                                    )
                                                )
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>SHA-256 MATCH</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.expected_sha256 &&
                                                evidenceCustodyVerification.calculated_sha256 ===
                                                evidenceCustodyVerification.expected_sha256
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.expected_sha256 &&
                                                evidenceCustodyVerification.calculated_sha256 ===
                                                evidenceCustodyVerification.expected_sha256
                                                    ? "YES"
                                                    : "NO"
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>SHA-512</span>
                                        <strong class="mt-future-wrap">
                                            ${
                                                escapeHTML(
                                                    String(
                                                        evidenceCustodyVerification.calculated_sha512 ||
                                                        "Not available"
                                                    )
                                                )
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>SHA-512 MATCH</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.expected_sha512 &&
                                                evidenceCustodyVerification.calculated_sha512 ===
                                                evidenceCustodyVerification.expected_sha512
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.expected_sha512 &&
                                                evidenceCustodyVerification.calculated_sha512 ===
                                                evidenceCustodyVerification.expected_sha512
                                                    ? "YES"
                                                    : "NO"
                                            }
                                        </strong>
                                    </div>

                                </div>

                                <div class="mt-future-grid compact">

                                    <div>
                                        <span>EVIDENCE HASH MATCH</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.evidence_hash_match
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.evidence_hash_match
                                                    ? "YES"
                                                    : "NO"
                                            }
                                        </strong>
                                    </div>
                                    <div>
                                        <span>CUSTODY CHAIN</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.custody_chain_valid
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.custody_chain_valid
                                                    ? "VALID"
                                                    : "INVALID"
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>PRESERVATION COPY</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.preservation_copy_match
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.preservation_copy_match
                                                    ? "MATCH"
                                                    : "MISMATCH"
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>SEAL HASH</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.seal_hash_match
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.seal_hash_match
                                                    ? "MATCH"
                                                    : "MISMATCH"
                                            }
                                        </strong>
                                    </div>

                                    <div>
                                        <span>OVERALL VERIFICATION</span>
                                        <strong class="
                                            ${
                                                evidenceCustodyVerification.verified
                                                    ? "verified"
                                                    : "unverified"
                                            }
                                        ">
                                            ${
                                                evidenceCustodyVerification.verified
                                                    ? "VERIFIED"
                                                    : "FAILED"
                                            }
                                        </strong>
                                    </div>

                                </div>

                                <div class="mt-future-section">

                                    <span class="mt-future-section-title">
                                        INDEPENDENT INTEGRITY
                                    </span>

                                    <div class="mt-future-grid compact">

                                        <div>
                                            <span>ANCHOR ID</span>
                                            <strong class="mt-future-wrap">
                                                ${
                                                    escapeHTML(
                                                        String(
                                                            evidenceIntegrityReceipt.anchor_id ||
                                                            "Not available"
                                                        )
                                                    )
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>COMMITMENT SHA-256</span>
                                            <strong class="mt-future-wrap">
                                                ${
                                                    escapeHTML(
                                                        String(
                                                            evidenceIntegrityReceipt.commitment_sha256 ||
                                                            "Not available"
                                                        )
                                                    )
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>PROVIDER</span>
                                            <strong>
                                                ${
                                                    escapeHTML(
                                                        String(
                                                            evidenceIntegrityReceipt.provider ||
                                                            "Not available"
                                                        )
                                                    )
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>TRUST LEVEL</span>
                                            <strong>
                                                ${
                                                    escapeHTML(
                                                        String(
                                                            evidenceIntegrityReceipt.trust_level ||
                                                            "Not available"
                                                        )
                                                    )
                                                }
                                            </strong>
                                        </div>

                                    </div>

                                    <div class="mt-future-grid compact">

                                        <div>
                                            <span>ANCHOR STATUS</span>
                                            <strong class="
                                                ${
                                                    String(
                                                        evidenceIntegrityReceipt.status || ""
                                                    ).toUpperCase() === "ANCHORED"
                                                        ? "verified"
                                                        : "unverified"
                                                }
                                            ">
                                                ${
                                                    escapeHTML(
                                                        String(
                                                            evidenceIntegrityReceipt.status ||
                                                            "Not available"
                                                        )
                                                    )
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>COMMITMENT MATCH</span>
                                            <strong class="
                                                ${
                                                    evidenceAnchorVerification.commitment_match
                                                        ? "verified"
                                                        : "unverified"
                                                }
                                            ">
                                                ${
                                                    evidenceAnchorVerification.commitment_match
                                                        ? "YES"
                                                        : "NO"
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>PROVIDER VERIFIED</span>
                                            <strong class="
                                                ${
                                                    evidenceAnchorVerification.provider_verified
                                                        ? "verified"
                                                        : "unverified"
                                                }
                                            ">
                                                ${
                                                    evidenceAnchorVerification.provider_verified
                                                        ? "YES"
                                                        : "NO"
                                                }
                                            </strong>
                                        </div>

                                        <div>
                                            <span>TIMESTAMP</span>
                                            <strong class="
                                                ${
                                                    evidenceAnchorVerification.timestamp_present
                                                        ? "verified"
                                                        : "unverified"
                                                }
                                            ">
                                                ${
                                                    evidenceAnchorVerification.timestamp_present
                                                        ? "PRESENT"
                                                        : "MISSING"
                                                }
                                            </strong>
                                        </div>

                                    </div>

                                </div>

                            </div>
                            ${
                                evidenceRetention
                                ? `

                                    <div class="mt-future-section">

                                        <span class="mt-future-section-title">
                                            RETENTION
                                        </span>

                                        <div class="mt-receipt">

                                            <div>
                                                <span>POLICY</span>
                                                <strong>
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceRetention.policy_id ||
                                                            evidenceGovernance.policy_id ||
                                                            "Not available"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>EXPIRES</span>
                                                <strong class="mt-future-wrap">
                                                    ${escapeHTML(
                                                        String(
                                                            evidenceRetention.expires_at_utc ||
                                                            "Not available"
                                                        )
                                                    )}
                                                </strong>
                                            </div>

                                            <div>
                                                <span>LEGAL HOLD</span>
                                                <strong>
                                                    ${
                                                        evidenceRetention.legal_hold
                                                        ? "YES"
                                                        : "NO"
                                                    }
                                                </strong>
                                            </div>

                                            <div>
                                                <span>FORENSIC HOLD</span>
                                                <strong>
                                                    ${
                                                        evidenceRetention.forensic_hold
                                                        ? "YES"
                                                        : "NO"
                                                    }
                                                </strong>
                                            </div>

                                        </div>

                                    </div>

                                `
                                : ""
                            }

                            ${
                                evidenceGovernance.error
                                ? `

                                    <div class="mt-governance-error">
                                        ${escapeHTML(
                                            String(
                                                evidenceGovernance.error
                                            )
                                        )}
                                    </div>

                                `
                                : ""
                            }

                        </div>

                    `
                    : ""
                }

                <!-- =================================
                    BACK BUTTON
                ================================== -->

                ${resultModuleCards.length ? `
                    <section class="result-backend-intelligence" aria-label="Additional intelligence modules">
                        <div class="result-backend-heading">
                            <div><span>ADDITIONAL ANALYSIS ENGINES</span><h3>Cross-signal intelligence</h3></div>
                            <p>Backend modules supporting the assessment above</p>
                        </div>
                        <div class="result-backend-module-grid">${resultModuleCards.map(module => `
                            <article class="result-backend-module result-backend-${escapeHTML(module.accent)}">
                                <h4>${escapeHTML(module.title)}</h4>
                                <dl>${module.fields.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(resultCompactValue(value))}</dd></div>`).join("")}</dl>
                            </article>`).join("")}</div>
                    </section>
                ` : ""}

                <details class="complete-analysis-disclosure">
                    <summary><span><small>FORENSIC DATA</small><strong>Complete backend analysis</strong></span><span class="complete-analysis-count">${Object.keys(analysis).length} returned fields · expand for full evidence</span></summary>
                    <div class="complete-analysis-module-list">${completeAnalysisModuleMarkup || '<div class="analysis-data-empty">Backend did not return analysis modules.</div>'}</div>
                </details>

                <button
                    class="secondary-result-btn"
                    id="backToDashboard"
                >
                    ← Back to Dashboard
                </button>

            `;


            // Give long forensic reports a compact, keyboard-friendly section index.
            const reportOverview = resultSection.querySelector(".result-overview");
            if (reportOverview) {
                const reportSections = Array.from(
                    resultSection.querySelectorAll(".result-card-title")
                ).filter(title => {
                    const card = title.closest(".result-card");
                    return card &&
                        title.parentElement.closest(".result-card") === card &&
                        !card.parentElement.closest(".result-card");
                });

                if (reportSections.length > 2) {
                    const sectionNav = document.createElement("nav");
                    sectionNav.className = "result-section-nav";
                    sectionNav.setAttribute("aria-label", "Jump to a report section");
                    const links = reportSections.map((title, index) => {
                        const card = title.closest(".result-card");
                        const label = title.querySelector("span")?.textContent?.trim() || title.textContent.trim();
                        const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "section";
                        const id = `analysis-section-${slug}-${index + 1}`;
                        card.id = id;
                        return `<a href="#${id}">${escapeHTML(label)}</a>`;
                    }).join("");
                    sectionNav.innerHTML = `<span class="result-section-nav-label">REPORT SECTIONS</span><div class="result-section-nav-links">${links}</div>`;
                    reportOverview.after(sectionNav);
                }
            }


            document
                .querySelector(".page")
                .prepend(resultSection);


            resultSection.scrollIntoView({
                behavior: "smooth"
            });


            const mapAction = resultSection.querySelector("#resultMapHeaderAction");
            mapAction.addEventListener("click", () => openInvestigationMapView(ipIntelligence));
            setPageHeader("Analysis Result", "Email security assessment and forensic evidence");

            if (window.lucide?.createIcons) window.lucide.createIcons();


            document
            .getElementById("backToDashboard")
            .addEventListener(
                "click",
                () => {

                    document.querySelector('.nav-item[data-page="dashboard"]')?.click();
                    void loadDashboardStats();
                    void loadRecentInvestigations();
                    void loadDashboardCharts();

                }
            );

        }
        function escapeHTML(value) {

            if (value === null || value === undefined) {
                return "";
            }

            return String(value)
                .replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll('"', "&quot;")
                .replaceAll("'", "&#039;");
        }


        function getAuthClass(status) {

            if (!status) {
                return "auth-neutral";
            }

            const value =
                status.toUpperCase();

            if (value === "PASS") {
                return "auth-pass";
            }

            if (value === "FAIL") {
                return "auth-fail";
            }

            return "auth-neutral";
        }
        async function loadInvestigations() {

            console.log("🔥 Loading investigations...");


            /* ==============================
            SCROLL PAGE TO TOP
            ============================== */

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });


            /* ==============================
            PAGE CONTAINER
            ============================== */

            const page =
                document.querySelector(
                    ".page"
                );

            if (!page) {

                console.error(
                    "Page container not found."
                );

                return;
            }


            /* ==============================
            CLEAN OLD PAGES
            ============================== */

            cleanupDynamicPages();


            /* ==============================
            HIDE NORMAL DASHBOARD
            ============================== */

            const dashboard =
                document.querySelector(
                    ".dashboard-content"
                );

            if (dashboard) {
                dashboard.style.setProperty("display", "none", "important");
            }


            /* ==============================
            CREATE INVESTIGATIONS CONTAINER
            ============================== */

            let container =
                document.getElementById(
                    "investigationsPage"
                );


            if (!container) {

                container =
                    document.createElement(
                        "section"
                    );

                container.id =
                    "investigationsPage";

                container.className =
                    "investigations-page";

                page.prepend(
                    container
                );

            }


            /* ==============================
            LOADING STATE
            ============================== */

            container.innerHTML = `

                <div class="investigations-header">

                    <div>

                        <div class="eyebrow">
                            FORENSIC DATABASE
                        </div>

                        <h2>
                            Investigations
                        </h2>

                        <p>
                            Review previously analysed emails
                            and forensic investigations.
                        </p>

                    </div>


                    <button
                        class="secondary-result-btn"
                        id="refreshInvestigations"
                    >
                        ↻ Refresh
                    </button>

                </div>


                <div class="result-card">

                    <div class="result-card-title">
                        INVESTIGATION DATABASE
                    </div>


                    <div id="investigationsContent">

                        <div class="investigations-loading">
                            Loading investigations...
                        </div>

                    </div>

                </div>

            `;


            /* ==============================
            REFRESH BUTTON
            ============================== */

            const refreshButton =
                document.getElementById(
                    "refreshInvestigations"
                );


            if (refreshButton) {

                refreshButton.addEventListener(
                    "click",
                    loadInvestigations
                );

            }


            /* ==============================
            LOAD INVESTIGATIONS
            ============================== */

            try {

                const response =
                    await fetch(
                        "http://127.0.0.1:8000/api/investigations"
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load investigations."
                    );

                }


                console.log(
                    "🔥 INVESTIGATIONS:",
                    data
                );


                renderInvestigations(
                    data.investigations || []
                );


            }
            catch (error) {

                console.error(
                    "Investigation Load Error:",
                    error
                );


                const content =
                    document.getElementById(
                        "investigationsContent"
                    );


                if (content) {

                    content.innerHTML = `

                        <div class="investigations-error">

                            <strong>
                                Unable to load investigations
                            </strong>

                            <p>
                                ${escapeHTML(
                                    error.message ||
                                    "Backend connection failed."
                                )}
                            </p>

                        </div>

                    `;

                }

            }

        }


        /* =========================================
        RENDER INVESTIGATIONS
        ========================================= */

        function renderInvestigations(
            investigations
        ) {

            const content =
                document.getElementById(
                    "investigationsContent"
                );


            if (!content) {
                return;
            }


            /* =====================================
            STATE
            ===================================== */

            let filteredInvestigations =
                [...investigations];

            let currentPage = 1;
            const pageSize = 25;


            /* =====================================
            RENDER UI
            ===================================== */

            function renderTable() {

                const activeElementId = document.activeElement?.id || "";
                const activeSearch = activeElementId === "investigationSearch"
                    ? document.getElementById("investigationSearch")
                    : null;
                const searchCursor = activeSearch?.selectionStart ?? null;

                /* ==============================
                SEARCH
                ============================== */

                const searchInput =
                    document.getElementById(
                        "investigationSearch"
                    );


                const searchTerm =
                    searchInput
                        ? searchInput.value
                            .trim()
                            .toLowerCase()
                        : "";


                /* ==============================
                THREAT FILTER
                ============================== */

                const threatFilter =
                    document.getElementById(
                        "investigationThreatFilter"
                    );


                const selectedThreat =
                    threatFilter
                        ? threatFilter.value.toUpperCase()
                        : (window.mailTraceInitialThreatFilter || "ALL");


                /* ==============================
                SORT
                ============================== */

                const sortSelect =
                    document.getElementById(
                        "investigationSort"
                    );


                const selectedSort =
                    sortSelect
                        ? sortSelect.value
                        : "newest";

                /* ==============================
                FILTER DATA
                ============================== */

                filteredInvestigations =
                    investigations.filter(
                        investigation => {

                            const id =
                                String(
                                    investigation.investigation_id ||
                                    ""
                                ).toLowerCase();


                            const filename =
                                String(
                                    investigation.filename ||
                                    ""
                                ).toLowerCase();


                            const sender =
                                String(
                                    investigation.sender ||
                                    ""
                                ).toLowerCase();


                            const subject =
                                String(
                                    investigation.subject ||
                                    ""
                                ).toLowerCase();


                            const verdict =
                                String(
                                    investigation.threat_verdict ||
                                    ""
                                ).toUpperCase();


                            /* SEARCH MATCH */

                            const matchesSearch =
                                !searchTerm ||
                                id.includes(searchTerm) ||
                                filename.includes(searchTerm) ||
                                sender.includes(searchTerm) ||
                                subject.includes(searchTerm);


                            /* THREAT MATCH */

                            const verdictBucket = verdict === "HIGH RISK" ? "HIGH"
                                : verdict === "SUSPICIOUS" ? "MEDIUM"
                                    : verdict === "LOW" || verdict === "LEGITIMATE" || verdict === "SAFE" || verdict === "BENIGN" ? "LOW RISK"
                                        : verdict;
                            const matchesThreat = selectedThreat === "ALL"
                                || (selectedThreat === "THREATS" && ["CRITICAL", "HIGH", "HIGH RISK", "MEDIUM", "SUSPICIOUS"].includes(verdict))
                                || (selectedThreat === "UNASSESSED" && !["CRITICAL", "HIGH", "HIGH RISK", "MEDIUM", "SUSPICIOUS", "LOW", "LOW RISK", "LEGITIMATE", "SAFE", "BENIGN"].includes(verdict))
                                || (selectedThreat !== "THREATS" && selectedThreat !== "UNASSESSED" && verdictBucket === selectedThreat);


                            return (
                                matchesSearch &&
                                matchesThreat
                            );

                        }
                    );


                /* ==============================
                SORT DATA
                ============================== */

                filteredInvestigations.sort(
                    (a, b) => {

                        if (
                            selectedSort ===
                            "highest"
                        ) {

                            return (
                                Number(
                                    b.threat_score || 0
                                ) -
                                Number(
                                    a.threat_score || 0
                                )
                            );

                        }


                        if (
                            selectedSort ===
                            "lowest"
                        ) {

                            return (
                                Number(
                                    a.threat_score || 0
                                ) -
                                Number(
                                    b.threat_score || 0
                                )
                            );

                        }


                        if (
                            selectedSort ===
                            "oldest"
                        ) {

                            return (
                                new Date(
                                    a.created_at || 0
                                ) -
                                new Date(
                                    b.created_at || 0
                                )
                            );

                        }


                        /* DEFAULT: NEWEST */

                        return (
                            new Date(
                                b.created_at || 0
                            ) -
                            new Date(
                                a.created_at || 0
                            )
                        );

                    }
                );


                /* ==============================
                COUNT
                ============================== */

                const count =
                    filteredInvestigations.length;

                const pageCount = Math.max(1, Math.ceil(count / pageSize));
                currentPage = Math.min(currentPage, pageCount);
                const pageStart = (currentPage - 1) * pageSize;
                const pageInvestigations = filteredInvestigations.slice(
                    pageStart,
                    pageStart + pageSize
                );


                /* ==============================
                NO RESULTS
                ============================== */

                if (!count) {

                    content.innerHTML = `

                        <div class="investigations-toolbar">

                            <div class="investigation-search">

                                <input
                                    type="text"
                                    id="investigationSearch"
                                    placeholder="Search investigations..."
                                    value="${escapeHTML(
                                        searchTerm
                                    )}"
                                >

                            </div>


                            <select
                                id="investigationThreatFilter"
                                class="select-control"
                            >

                                <option value="ALL">
                                    All Threats
                                </option>

                                <option value="THREATS" ${selectedThreat === "THREATS" ? "selected" : ""}>
                                    Detected Threats
                                </option>

                                <option value="CRITICAL">
                                    Critical
                                </option>

                                <option value="HIGH">
                                    High
                                </option>

                                <option value="MEDIUM">
                                    Medium
                                </option>

                                <option value="LOW RISK">
                                    Low Risk
                                </option>

                                <option value="UNASSESSED">
                                    Unclassified
                                </option>

                            </select>


                            <select
                                id="investigationSort"
                                class="select-control"
                            >

                                <option value="newest">
                                    Newest First
                                </option>

                                <option value="oldest">
                                    Oldest First
                                </option>

                                <option value="highest">
                                    Highest Score
                                </option>

                                <option value="lowest">
                                    Lowest Score
                                </option>

                            </select>

                        </div>


                        <div class="investigations-count">

                            0 investigations found

                        </div>


                        <div class="investigations-empty">

                            No investigations match your filters.

                        </div>

                    `;


                    attachInvestigationFilters();
                    restoreInvestigationControl(activeElementId, searchCursor);

                    return;

                }


                /* ==============================
                TABLE
                ============================== */

                content.innerHTML = `

                    <div class="investigations-toolbar">

                        <div class="investigation-search">

                            <input
                                type="text"
                                id="investigationSearch"
                                placeholder="Search ID, filename, sender..."
                                value="${escapeHTML(
                                    searchTerm
                                )}"
                            >

                        </div>


                        <select
                            id="investigationThreatFilter"
                            class="select-control"
                        >

                            <option value="ALL"
                                ${selectedThreat === "ALL" ? "selected" : ""}>
                                All Threats
                            </option>

                            <option value="THREATS"
                                ${selectedThreat === "THREATS" ? "selected" : ""}>
                                Detected Threats
                            </option>

                            <option value="CRITICAL"
                                ${selectedThreat === "CRITICAL" ? "selected" : ""}>
                                Critical
                            </option>

                            <option value="HIGH"
                                ${selectedThreat === "HIGH" ? "selected" : ""}>
                                High
                            </option>

                            <option value="MEDIUM"
                                ${selectedThreat === "MEDIUM" ? "selected" : ""}>
                                Medium
                            </option>

                            <option value="LOW RISK"
                                ${selectedThreat === "LOW RISK" ? "selected" : ""}>
                                Low Risk
                            </option>

                            <option value="UNASSESSED"
                                ${selectedThreat === "UNASSESSED" ? "selected" : ""}>
                                Unclassified
                            </option>

                        </select>


                        <select
                            id="investigationSort"
                            class="select-control"
                        >

                            <option value="newest"
                                ${selectedSort === "newest" ? "selected" : ""}>
                                Newest First
                            </option>

                            <option value="oldest"
                                ${selectedSort === "oldest" ? "selected" : ""}>
                                Oldest First
                            </option>

                            <option value="highest"
                                ${selectedSort === "highest" ? "selected" : ""}>
                                Highest Score
                            </option>

                            <option value="lowest"
                                ${selectedSort === "lowest" ? "selected" : ""}>
                                Lowest Score
                            </option>

                        </select>

                    </div>


                    <div class="investigations-count">

                        Showing ${pageStart + 1}–${Math.min(pageStart + pageSize, count)} of ${count}
                        investigation${count === 1 ? "" : "s"}

                    </div>


                    <div class="investigations-table-wrapper">

                        <table class="investigations-table">

                            <thead>

                                <tr>

                                    <th>
                                        Investigation ID
                                    </th>

                                    <th>
                                        Filename
                                    </th>

                                    <th>
                                        Sender
                                    </th>

                                    <th>
                                        Threat
                                    </th>

                                    <th>
                                        Score
                                    </th>

                                    <th>
                                        Created
                                    </th>

                                </tr>

                            </thead>


                            <tbody>

                                ${pageInvestigations.map(
                                    investigation => `

                                    <tr
                                        class="investigation-row"
                                        data-id="${escapeHTML(
                                            investigation.investigation_id ||
                                            ""
                                        )}"
                                    >

                                        <td>

                                            <button
                                                class="investigation-id-btn"
                                                type="button"
                                            >

                                                ${escapeHTML(
                                                    investigation.investigation_id ||
                                                    "UNKNOWN"
                                                )}

                                            </button>

                                        </td>


                                        <td>

                                            ${escapeHTML(
                                                investigation.filename ||
                                                "Unknown"
                                            )}

                                        </td>


                                        <td>

                                            ${escapeHTML(
                                                investigation.sender ||
                                                "Unknown"
                                            )}

                                        </td>


                                        <td>

                                            <span class="
                                                investigation-threat
                                                ${getThreatClass(
                                                    investigation.threat_verdict
                                                )}
                                            ">

                                                ${escapeHTML(
                                                    investigation.threat_verdict ||
                                                    "UNKNOWN"
                                                )}

                                            </span>

                                        </td>


                                        <td>

                                            <strong>

                                                ${Number(
                                                    investigation.threat_score ||
                                                    0
                                                )}

                                            </strong>

                                            / 100

                                        </td>


                                        <td>

                                            ${escapeHTML(
                                                investigation.created_at ||
                                                "Unknown"
                                            )}

                                        </td>

                                    </tr>

                                `
                                ).join("")}

                            </tbody>

                        </table>

                    </div>

                    <div class="investigations-pagination" aria-label="Investigation pages">
                        <span>Page ${currentPage} of ${pageCount}</span>
                        <div>
                            <button type="button" id="investigationPagePrevious" ${currentPage <= 1 ? "disabled" : ""}>Previous</button>
                            <button type="button" id="investigationPageNext" ${currentPage >= pageCount ? "disabled" : ""}>Next</button>
                        </div>
                    </div>

                `;


                /* ==============================
                CLICK INVESTIGATION
                ============================== */

                document
                    .querySelectorAll(
                        ".investigation-row"
                    )
                    .forEach(row => {

                        row.addEventListener(
                            "click",
                            async () => {

                                const id =
                                    row.dataset.id;


                                if (!id) {
                                    return;
                                }


                                console.log(
                                    "🔥 Opening investigation:",
                                    id
                                );


                                await openInvestigation(
                                    id
                                );

                            }
                        );

                    });


                /* ==============================
                FILTER EVENTS
                ============================== */

                attachInvestigationFilters();
                restoreInvestigationControl(activeElementId, searchCursor);

                document.getElementById("investigationPagePrevious")?.addEventListener("click", () => {
                    currentPage = Math.max(1, currentPage - 1);
                    renderTable();
                });
                document.getElementById("investigationPageNext")?.addEventListener("click", () => {
                    currentPage = Math.min(pageCount, currentPage + 1);
                    renderTable();
                });

            }


            function restoreInvestigationControl(activeId, cursorPosition) {
                if (![
                    "investigationSearch",
                    "investigationThreatFilter",
                    "investigationSort",
                    "investigationPagePrevious",
                    "investigationPageNext",
                ].includes(activeId)) return;

                const nextControl = document.getElementById(activeId);
                if (!nextControl) return;
                nextControl.focus({ preventScroll: true });
                if (activeId === "investigationSearch" && cursorPosition !== null) {
                    nextControl.setSelectionRange(cursorPosition, cursorPosition);
                }
            }


            /* =====================================
            ATTACH FILTER EVENTS
            ===================================== */

            function attachInvestigationFilters() {

                const searchInput =
                    document.getElementById(
                        "investigationSearch"
                    );


                const threatFilter =
                    document.getElementById(
                        "investigationThreatFilter"
                    );


                const sortSelect =
                    document.getElementById(
                        "investigationSort"
                    );


                if (searchInput) {

                    searchInput.addEventListener(
                        "input",
                        () => {
                            currentPage = 1;
                            renderTable();
                        }
                    );

                }


                if (threatFilter) {

                    threatFilter.addEventListener(
                        "change",
                        () => {
                            currentPage = 1;
                            renderTable();
                        }
                    );

                }


                if (sortSelect) {

                    sortSelect.addEventListener(
                        "change",
                        () => {
                            currentPage = 1;
                            renderTable();
                        }
                    );

                }

            }


            /* =====================================
            INITIAL RENDER
            ===================================== */

            renderTable();
            window.mailTraceInitialThreatFilter = null;

        }


            /* =====================================
            ROW CLICK
            ===================================== */

            document
            .querySelectorAll(".investigation-id-btn")
            .forEach(button => {

                button.addEventListener("click", async (event) => {

                    event.preventDefault();
                    event.stopPropagation();

                    const row =
                        button.closest(".investigation-row");

                    if (!row) {
                        console.error("Investigation row not found.");
                        return;
                    }

                    const id =
                        row.dataset.id;

                    console.log(
                        "🔥 Investigation clicked:",
                        id
                    );

                    if (!id) {
                        showNotification(
                            "Investigation ID not found.",
                            "warning"
                        );
                        return;
                    }

                    await openInvestigation(id);

                });

            });


        /* =========================================
        OPEN SINGLE INVESTIGATION
        ========================================= */

        async function openInvestigation(investigationId) {

            console.log(
                "🔥 Opening investigation:",
                investigationId
            );

            try {

                const response =
                    await fetch(
                        `http://127.0.0.1:8000/api/investigations/${encodeURIComponent(
                            investigationId
                        )}`
                    );

                const data =
                    await response.json();

                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load investigation."
                    );

                }

                console.log(
                    "🔥 SINGLE INVESTIGATION:",
                    data
                );

                if (
                    !data.investigation ||
                    !data.investigation.analysis
                ) {

                    throw new Error(
                        "Investigation analysis data is missing."
                    );

                }

                const investigationsPage =
                    document.getElementById(
                        "investigationsPage"
                    );

                if (investigationsPage) {
                    investigationsPage.remove();
                }

                showInvestigationResult(
                    data.investigation.analysis
                );

            } catch (error) {

                console.error(
                    "Investigation Open Error:",
                    error
                );

                alert(
                    error.message ||
                    "Unable to load investigation."
                );

            }

        }


        /* =========================================
        THREAT CLASS
        ========================================= */

        function getThreatClass(
            verdict
        ) {

            const value =
                String(
                    verdict || ""
                ).toLowerCase();


            if (
                value.includes("critical")
            ) {

                return "threat-critical";

            }


            if (
                value.includes("high")
            ) {

                return "threat-high";

            }


            if (
                value.includes("medium")
            ) {

                return "threat-medium";

            }


            if (
                value.includes("low")
            ) {

                return "threat-low";

            }


            return "threat-unknown";

        }


        /* =========================================
        INVESTIGATION STYLES
        ========================================= */

        const investigationStyles =
            document.createElement("style");


        investigationStyles.textContent = `

            .investigations-page {

                margin-bottom: 30px;

            }


            .investigations-header {

                display: flex;

                justify-content: space-between;

                align-items: center;

                gap: 20px;

                margin-bottom: 24px;

            }


            .investigations-header h2 {

                margin: 5px 0;

            }


            .investigations-header p {

                margin: 0;

                color: #64748B;

            }


            .investigations-count {

                margin-bottom: 15px;

                color: #64748B;

                font-size: 13px;

            }


            .investigations-table-wrapper {

                width: 100%;

                overflow-x: auto;

            }


            .investigations-table {

                width: 100%;

                border-collapse: collapse;

                min-width: 900px;

            }


            .investigations-table th {

                text-align: left;

                padding: 14px 12px;

                border-bottom: 1px solid #263241;

                color: #64748B;

                font-size: 11px;

                text-transform: uppercase;

                letter-spacing: .06em;

            }


            .investigations-table td {

                padding: 15px 12px;

                border-bottom: 1px solid #1E293B;

                color: #CBD5E1;

                font-size: 12px;

            }


            .investigation-row {

                cursor: pointer;

                transition: background .15s ease;

            }


            .investigation-row:hover {

                background: rgba(25,181,254,.05);

            }


            .investigation-id-btn {

                border: none;

                background: transparent;

                color: #19B5FE;

                font-family: monospace;

                font-size: 12px;

                cursor: pointer;

                padding: 0;

            }


            .investigation-threat {

                display: inline-block;

                padding: 5px 8px;

                border-radius: 5px;

                font-size: 9px;

                font-weight: 700;

            }


            .threat-critical {

                color: #F87171;

                background: rgba(239,68,68,.12);

            }


            .threat-high {

                color: #FB923C;

                background: rgba(249,115,22,.12);

            }


            .threat-medium {

                color: #FBBF24;

                background: rgba(245,158,11,.12);

            }


            .threat-low {

                color: #22C55E;

                background: rgba(34,197,94,.12);

            }


            .threat-unknown {

                color: #94A3B8;

                background: rgba(148,163,184,.10);

            }


            .investigations-loading,
            .investigations-empty {

                padding: 40px;

                text-align: center;

                color: #64748B;

            }


            .investigations-error {

                padding: 30px;

                border: 1px solid rgba(239,68,68,.25);

                border-radius: 8px;

                color: #F87171;

            }


            .investigations-error p {

                color: #94A3B8;

                margin-bottom: 0;

            }

        `;


        document.head.appendChild(
            investigationStyles
        );

        /* =========================================
        LIVE DASHBOARD STATISTICS
        ========================================= */

        function setBackendStatus(state, title, detail) {
            const statusValue = document.getElementById("backendSystemStatusValue");
            const sidebarValue = document.getElementById("sidebarSystemStatusValue");
            const sidebarDetail = document.getElementById("sidebarSystemStatusDetail");

            if (statusValue) {
                statusValue.textContent = title;
                statusValue.dataset.status = state;
            }
            if (sidebarValue) {
                sidebarValue.textContent = title;
                sidebarValue.dataset.status = state;
            }
            if (sidebarDetail) sidebarDetail.textContent = detail;
            window.mailtraceSetBackendFreshness?.(state === "online");
        }

        async function refreshBackendStatus() {
            if (window.location.protocol === "file:") {
                setBackendStatus("offline", "Use local server", "Open MailTrace at http://127.0.0.1:5503");
                return;
            }

            const controller = new AbortController();
            const timeout = window.setTimeout(() => controller.abort(), 5000);
            try {
                const response = await fetch("http://127.0.0.1:8000/api/ready", {
                    cache: "no-store",
                    signal: controller.signal
                });
                const data = await response.json();
                const ready = response.ok && data.status === "ok";
                setBackendStatus(
                    ready ? "online" : "degraded",
                    ready ? "Backend Ready" : "Backend Degraded",
                    ready ? "API and database are reachable" : "Readiness check did not pass"
                );
            } catch (error) {
                setBackendStatus("offline", "Backend Offline", "Start the MailTrace backend to load live data");
            } finally {
                window.clearTimeout(timeout);
            }
        }

        function markCasesViewed() {
            const cases = window.mailtraceCases || [];
            const signature = cases.filter(item => ["OPEN", "ACTIVE", "IN PROGRESS", "INVESTIGATING"].includes(String(item.status || "OPEN").trim().toUpperCase()))
                .map(item => `${item.case_id || item.id || "case"}:${String(item.status || "OPEN").toUpperCase()}:${item.updated_at || item.last_updated || ""}`).sort().join("|");
            try { localStorage.setItem("mailtraceCasesSeenSignature", signature); } catch (_) {}
            const badge = document.getElementById("openCasesNavCount");
            if (badge) { badge.textContent = "0"; badge.hidden = true; badge.setAttribute("aria-label", "No new or changed open cases"); }
        }

        async function loadDashboardStats() {
            const endpoints = [
                "http://127.0.0.1:8000/api/investigations",
                "http://127.0.0.1:8000/api/cases",
                "http://127.0.0.1:8000/api/campaigns"
            ];

            const results = await Promise.allSettled(
                endpoints.map(async endpoint => {
                    const response = await fetch(endpoint);
                    const data = await response.json();
                    if (!response.ok) {
                        throw new Error(data.detail || `Request failed: ${response.status}`);
                    }
                    return data;
                })
            );

            document.querySelectorAll(".stat-value").forEach(value => value.setAttribute("aria-busy", "false"));

            const payloads = results.map((result, index) => {
                if (result.status === "fulfilled") return result.value;
                console.warn("Dashboard metric unavailable:", endpoints[index], result.reason);
                return null;
            });

            const investigations = payloads[0]?.investigations;
            const cases = payloads[1]?.cases;
            const campaigns = payloads[2]?.campaigns;

            if (Array.isArray(investigations)) {
                window.mailtraceInvestigations = investigations;
                const detectedVerdicts = new Set([
                    "CRITICAL", "HIGH", "HIGH RISK", "MEDIUM", "SUSPICIOUS"
                ]);
                const threats = investigations.filter(item =>
                    detectedVerdicts.has(String(item.threat_verdict || "").trim().toUpperCase())
                ).length;

                const totalElement = document.getElementById("dashboardTotalAnalysed");
                const threatsElement = document.getElementById("dashboardThreatsDetected");
                const totalContext = document.getElementById("dashboardTotalContext");
                const threatsContext = document.getElementById("dashboardThreatsContext");
                if (totalElement) totalElement.textContent = investigations.length.toLocaleString();
                if (threatsElement) threatsElement.textContent = threats.toLocaleString();
                window.mailtraceUpdateFlaggedNotificationBadge?.();
                if (totalContext) totalContext.textContent = "all investigations";
                if (threatsContext) threatsContext.textContent = "flagged investigations";
            } else {
                const totalElement = document.getElementById("dashboardTotalAnalysed");
                const threatsElement = document.getElementById("dashboardThreatsDetected");
                const totalContext = document.getElementById("dashboardTotalContext");
                const threatsContext = document.getElementById("dashboardThreatsContext");
                if (totalElement) totalElement.textContent = "—";
                if (threatsElement) threatsElement.textContent = "—";
                if (totalContext) totalContext.textContent = "data unavailable";
                if (threatsContext) threatsContext.textContent = "check backend connection";
                const flaggedCount = document.getElementById("flaggedInvestigationCount");
                if (flaggedCount) {
                    flaggedCount.textContent = "!";
                    flaggedCount.hidden = false;
                    flaggedCount.title = "Threat data unavailable";
                    flaggedCount.closest(".notification")?.setAttribute("aria-label", "Threat data unavailable");
                }
            }

            window.mailtraceRefreshAlertsPanel?.();

            if (Array.isArray(cases)) {
                const activeCases = cases.filter(item =>
                    ["OPEN", "ACTIVE", "IN PROGRESS", "INVESTIGATING"].includes(
                        String(item.status || "OPEN").trim().toUpperCase()
                    )
                ).length;
                const activeElement = document.getElementById("dashboardActiveCases");
                const casesContext = document.getElementById("dashboardCasesContext");
                const casesNavCount = document.getElementById("openCasesNavCount");
                const signature = cases.filter(item => ["OPEN", "ACTIVE", "IN PROGRESS", "INVESTIGATING"].includes(String(item.status || "OPEN").trim().toUpperCase()))
                    .map(item => `${item.case_id || item.id || "case"}:${String(item.status || "OPEN").toUpperCase()}:${item.updated_at || item.last_updated || ""}`).sort().join("|");
                window.mailtraceCases = cases;
                let seenSignature = "";
                try { seenSignature = localStorage.getItem("mailtraceCasesSeenSignature") || ""; } catch (_) {}
                if (casesNavCount) {
                    const unseenCount = signature === seenSignature ? 0 : activeCases;
                    casesNavCount.textContent = unseenCount > 99 ? "99+" : String(unseenCount);
                    casesNavCount.hidden = unseenCount === 0;
                    casesNavCount.setAttribute("aria-label", `${unseenCount} new or changed open cases`);
                }
                if (activeElement) activeElement.textContent = activeCases.toLocaleString();
                if (casesContext) casesContext.textContent = "open or active cases";
            } else {
                const activeElement = document.getElementById("dashboardActiveCases");
                const casesContext = document.getElementById("dashboardCasesContext");
                if (activeElement) activeElement.textContent = "—";
                if (casesContext) casesContext.textContent = "data unavailable";
            }

            if (Array.isArray(campaigns)) {
                const campaignsElement = document.getElementById("dashboardCampaigns");
                const campaignsContext = document.getElementById("dashboardCampaignsContext");
                if (campaignsElement) campaignsElement.textContent = campaigns.length.toLocaleString();
                if (campaignsContext) campaignsContext.textContent = "evidence-linked campaigns";

                const campaignList = document.getElementById("dashboardCampaignList");
                if (campaignList) {
                    campaignList.innerHTML = campaigns.length
                        ? campaigns.slice(0, 3).map(campaign => {
                            const severity = String(campaign.severity || "UNKNOWN").toUpperCase();
                            const severityClass = severity === "CRITICAL"
                                ? "critical"
                                : severity === "HIGH"
                                    ? "high-risk"
                                    : severity === "LOW"
                                        ? "low-risk"
                                        : "medium-risk";
                            const iconClass = severity === "CRITICAL"
                                ? "red-bg"
                                : severity === "HIGH"
                                    ? "amber-bg"
                                    : "violet-bg";
                            return `
                                <article class="campaign-item" role="button" tabindex="0"
                                    data-campaign-id="${escapeHTML(campaign.campaign_id || "")}">
                                    <div class="campaign-icon ${iconClass}" aria-hidden="true">◎</div>
                                    <div class="campaign-info">
                                        <div class="campaign-title">
                                            ${escapeHTML(campaign.campaign_id || "CAMPAIGN")}
                                            <span class="risk-pill ${severityClass}">${escapeHTML(severity)}</span>
                                        </div>
                                        <small>${escapeHTML(campaign.correlation_reason || campaign.description || "Evidence-linked activity")}</small>
                                        <div class="campaign-meta">
                                            <span>${Number(campaign.email_count || 0)} emails</span>
                                            <span aria-hidden="true">•</span>
                                            <span>${Number(campaign.indicator_count || 0)} shared indicators</span>
                                        </div>
                                    </div>
                                </article>
                            `;
                        }).join("")
                        : '<div class="campaign-loading">No evidence-linked campaigns found.</div>';

                    campaignList.querySelectorAll(".campaign-item[data-campaign-id]").forEach(item => {
                        const openDetail = () => openCampaignDetail(item.dataset.campaignId);
                        item.addEventListener("click", openDetail);
                        item.addEventListener("keydown", event => {
                            if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                openDetail();
                            }
                        });
                    });
                }
            } else {
                const campaignsElement = document.getElementById("dashboardCampaigns");
                const campaignsContext = document.getElementById("dashboardCampaignsContext");
                const campaignList = document.getElementById("dashboardCampaignList");
                if (campaignsElement) campaignsElement.textContent = "—";
                if (campaignsContext) campaignsContext.textContent = "data unavailable";
                if (campaignList) campaignList.innerHTML = '<div class="dashboard-state dashboard-state-error">Campaign data is unavailable. Check the backend connection.</div>';
            }

            document.querySelectorAll(".stat-sparkline").forEach(sparkline => sparkline.remove());
        }
        /* =========================================
        LIVE RECENT INVESTIGATIONS
        ========================================= */

        async function loadRecentInvestigations() {

            console.log("🔥 Loading recent investigations...");

            try {

                const response = await fetch(
                    "http://127.0.0.1:8000/api/investigations"
                );

                const data = await response.json();

                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load investigations."
                    );

                }

                const investigations =
                    data.investigations || [];


                console.log(
                    "🔥 Recent investigations:",
                    investigations
                );


                /* ==============================
                FIND DASHBOARD TABLE
                ============================== */

                const tbody =
                    document.querySelector(
                        ".investigations-panel tbody"
                    );


                if (!tbody) {

                    console.warn(
                        "Recent investigations table not found."
                    );

                    return;
                }


                /* ==============================
                NO DATA
                ============================== */

                if (!investigations.length) {

                    tbody.innerHTML = `
                        <tr>
                            <td
                                colspan="6"
                                class="muted"
                            >
                                No investigations found.
                            </td>
                        </tr>
                    `;

                    return;
                }


                /* ==============================
                LATEST 5 INVESTIGATIONS
                ============================== */

                const recent =
                    investigations.slice(0, 5);


                tbody.innerHTML =
                    recent.map(investigation => {

                        const verdict =
                            String(
                                investigation.threat_verdict ||
                                "UNKNOWN"
                            ).toUpperCase();


                        const score =
                            Number(
                                investigation.threat_score || 0
                            );


                        let badgeClass =
                            "warning";


                        if (
                            verdict === "CRITICAL"
                        ) {

                            badgeClass =
                                "danger";

                        }
                        else if (
                            verdict === "HIGH"
                        ) {

                            badgeClass =
                                "danger";

                        }
                        else if (
                            verdict === "LOW RISK"
                        ) {

                            badgeClass =
                                "safe";

                        }


                        return `

                            <tr
                                class="dashboard-investigation-row"
                                data-id="${escapeHTML(
                                    investigation.investigation_id
                                )}"
                            >

                                <!-- CASE -->

                                <td class="mono">

                                    ${escapeHTML(
                                        investigation.investigation_id
                                    )}

                                </td>


                                <!-- SUBJECT -->

                                <td>

                                    <div class="email-cell">

                                        <strong>

                                            ${escapeHTML(
                                                investigation.subject ||
                                                "No Subject"
                                            )}

                                        </strong>


                                        <small>

                                            ${escapeHTML(
                                                investigation.sender ||
                                                "Unknown Sender"
                                            )}

                                        </small>

                                    </div>

                                </td>


                                <!-- THREAT -->

                                <td>

                                    <span
                                        class="badge ${badgeClass}"
                                    >

                                        ${escapeHTML(
                                            verdict
                                        )}

                                    </span>

                                </td>


                                <!-- RISK -->

                                <td>

                                    <div
                                        class="risk-score ${
                                            score >= 70
                                                ? "high"
                                                : score >= 30
                                                    ? "medium"
                                                    : "low"
                                        }"
                                    >

                                        ${score}

                                    </div>

                                </td>


                                <!-- STATUS -->

                                <td>

                                    <span
                                        class="status active"
                                    >
                                        Analysed
                                    </span>

                                </td>


                                <!-- TIME -->

                                <td class="muted">

                                    ${escapeHTML(
                                        investigation.created_at ||
                                        "Unknown"
                                    )}

                                </td>

                            </tr>

                        `;

                    }).join("");


                /* ==============================
                CLICK → INVESTIGATION RESULT
                ============================== */

                document
                    .querySelectorAll(
                        ".dashboard-investigation-row"
                    )
                    .forEach(row => {

                        row.addEventListener(
                            "click",
                            async () => {

                                const id =
                                    row.dataset.id;


                                if (!id) {
                                    return;
                                }


                                console.log(
                                    "🔥 Dashboard investigation clicked:",
                                    id
                                );


                                await openInvestigation(
                                    id
                                );

                            }
                        );

                    });


            } catch (error) {

                console.error(
                    "Recent Investigations Error:",
                    error
                );

            }

        }
        /* =========================================
        LIVE DASHBOARD CHARTS
        ========================================= */

        async function loadDashboardCharts() {

            console.log("🔥 Loading live dashboard charts...");

            const setChartState = (message, isError = false) => {
                const chartArea = document.querySelector(".chart-area");
                const chartLine = document.querySelector(".chart-line");
                const chartFill = document.querySelector(".chart-area-fill");
                if (!chartArea) return;
                chartArea.dataset.ready = "true";

                chartArea.querySelector(".chart-state")?.remove();
                const state = document.createElement("div");
                state.className = `chart-state${isError ? " is-error" : ""}`;
                state.setAttribute("role", "status");
                state.textContent = message;
                chartArea.appendChild(state);
                if (isError) {
                    chartLine?.setAttribute("d", "");
                    chartFill?.setAttribute("d", "");
                }
            };

            const chartController = new AbortController();
            const chartTimeout = window.setTimeout(() => chartController.abort(), 8000);
            try {

                const response = await fetch(
                    "http://127.0.0.1:8000/api/investigations",
                    { signal: chartController.signal }
                );

                const data = await response.json();

                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load dashboard chart data."
                    );

                }

                const investigations =
                    data.investigations || [];
                window.clearTimeout(chartTimeout);
                const chartArea = document.querySelector(".chart-area");
                if (chartArea) chartArea.dataset.ready = "true";

                document.querySelector(".chart-area")?.querySelector(".chart-state")?.remove();


                console.log(
                    "🔥 Chart data:",
                    investigations
                );


                /* =====================================
                THREAT DISTRIBUTION
                ===================================== */

                const severityCounts = {

                    CRITICAL: 0,
                    HIGH: 0,
                    MEDIUM: 0,
                    "LOW RISK": 0,
                    UNCLASSIFIED: 0

                };


                investigations.forEach(item => {
                    const verdict = String(item.threat_verdict || "UNASSESSED")
                        .trim()
                        .toUpperCase();

                    if (verdict === "CRITICAL") {
                        severityCounts.CRITICAL++;
                    } else if (verdict === "HIGH" || verdict === "HIGH RISK") {
                        severityCounts.HIGH++;
                    } else if (verdict === "MEDIUM" || verdict === "SUSPICIOUS") {
                        severityCounts.MEDIUM++;
                    } else if (["LOW", "LOW RISK", "LEGITIMATE", "SAFE", "BENIGN"].includes(verdict)) {
                        severityCounts["LOW RISK"]++;
                    } else {
                        severityCounts.UNCLASSIFIED++;
                    }
                });

                const threatTotal =
                    Object.values(
                        severityCounts
                    ).reduce(
                        (sum, value) => sum + value,
                        0
                    );


                const distributionPanel =
                    document.querySelector(
                        ".distribution-panel"
                    );


                if (distributionPanel) {

                    /* ==============================
                    DONUT CENTER
                    ============================== */

                    const donutCenter =
                        distributionPanel.querySelector(
                            ".donut-center strong"
                        );


                    if (donutCenter) {

                        donutCenter.textContent =
                            threatTotal.toLocaleString();

                    }


                    /* ==============================
                    DONUT
                    ============================== */

                    const donut =
                        distributionPanel.querySelector(
                            ".donut"
                        );


                    if (donut && threatTotal > 0) {

                        const criticalPercent =
                            (
                                severityCounts.CRITICAL /
                                threatTotal
                            ) * 100;


                        const highPercent =
                            (
                                severityCounts.HIGH /
                                threatTotal
                            ) * 100;


                        const mediumPercent =
                            (
                                severityCounts.MEDIUM /
                                threatTotal
                            ) * 100;


                        const lowPercent =
                            (
                                severityCounts["LOW RISK"] /
                                threatTotal
                            ) * 100;


                        const criticalEnd =
                            criticalPercent;


                        const highEnd =
                            criticalEnd +
                            highPercent;


                        const mediumEnd =
                            highEnd +
                            mediumPercent;

                        const lowEnd = mediumEnd + lowPercent;


                        donut.style.background =
                            `conic-gradient(
                                #ff4545 0% ${criticalEnd}%,
                                #ff9f1c ${criticalEnd}% ${highEnd}%,
                                #7c6cff ${highEnd}% ${mediumEnd}%,
                                #19b5fe ${mediumEnd}% ${lowEnd}%,
                                #64748b ${lowEnd}% 100%
                            )`;

                    }


                    /* ==============================
                    LEGEND
                    ============================== */

                    const legendRows =
                        distributionPanel.querySelectorAll(
                            ".legend-row"
                        );


                    const distributionItems = [

                        {
                            name: "Critical",
                            value: severityCounts.CRITICAL,
                            className: "phishing"
                        },

                        {
                            name: "High",
                            value: severityCounts.HIGH,
                            className: "impersonation"
                        },

                        {
                            name: "Medium",
                            value: severityCounts.MEDIUM,
                            className: "bec"
                        },

                        {
                            name: "Low Risk",
                            value: severityCounts["LOW RISK"],
                            className: "malware"
                        },

                        {
                            name: "Unclassified",
                            value: severityCounts.UNCLASSIFIED,
                            className: "unclassified"
                        }

                    ];


                    legendRows.forEach(
                        (row, index) => {

                            const item =
                                distributionItems[index];


                            if (!item) {
                                return;
                            }


                            const label =
                                row.querySelector(
                                    "span"
                                );


                            const percentage =
                                row.querySelector(
                                    "strong"
                                );

                            const name =
                                row.querySelector(
                                    ".legend-name"
                                );

                            const dot =
                                row.querySelector(
                                    ".legend-dot"
                                );

                            if (name) {
                                name.textContent = item.name;
                            }

                            if (dot) {
                                dot.className = `legend-dot ${item.className}`;
                            }

                            if (percentage) {

                                const percent =
                                    threatTotal > 0
                                        ? Math.round(
                                            (
                                                item.value /
                                                threatTotal
                                            ) * 100
                                        )
                                        : 0;

                                const count =
                                    percentage.querySelector(
                                        ".legend-count"
                                    );

                                const percentText =
                                    percentage.querySelector(
                                        ".legend-percent"
                                    );

                                if (count) {
                                    count.textContent =
                                        item.value.toLocaleString();
                                }

                                if (percentText) {
                                    percentText.textContent =
                                        `(${percent}%)`;
                                } else {
                                    percentage.textContent =
                                        `${item.value.toLocaleString()} (${percent}%)`;
                                }

                            }

                        }
                    );

                }


                /* =====================================
        THREAT ACTIVITY — DYNAMIC RANGE
        ===================================== */

        const chartLine =
            document.querySelector(".chart-line");

        const chartFill =
            document.querySelector(".chart-area-fill");

        const rangeSelector =
            document.getElementById(
                "threatActivityRange"
            );
        const threatActivitySubtitle =
            document.querySelector(
                ".threat-panel .panel-header p"
            );


        function updateThreatActivityChart(days) {

    if (!chartLine || !chartFill) {
        return;
    }


    /* ==============================
       NORMALIZE RANGE
       ============================== */

    days = Number(days);

    if (![7, 30, 90].includes(days)) {
        days = 30;
    }


    /* ==============================
       UPDATE SUBTITLE
       ============================== */

    if (threatActivitySubtitle) {

        threatActivitySubtitle.textContent =
            `Email threats detected over the last ${days} days`;

    }


    /* ==============================
       CREATE DATE RANGE
       ============================== */

    const now = new Date();

    now.setHours(
        0,
        0,
        0,
        0
    );


    const dailyCounts = [];


    for (
        let i = days - 1;
        i >= 0;
        i--
    ) {

        const date =
            new Date(now);

        date.setDate(
            date.getDate() - i
        );


        dailyCounts.push({
            date: date,
            count: 0
        });

    }


    /* ==============================
       COUNT LIVE THREATS
       ============================== */

    investigations.forEach(
        investigation => {

            const verdict =
                String(
                    investigation.threat_verdict ||
                    ""
                )
                    .trim()
                    .toUpperCase();


            const isThreat = [
                "CRITICAL", "HIGH", "HIGH RISK", "MEDIUM", "SUSPICIOUS"
            ].includes(verdict);


            if (!isThreat) {
                return;
            }


            const createdAt =
                String(
                    investigation.created_at ||
                    ""
                ).trim();


            if (!createdAt) {
                return;
            }


            /*
            Backend commonly returns:

            YYYY-MM-DD HH:mm:ss
            YYYY-MM-DDTHH:mm:ss
            ISO timestamp
            */

            const normalizedDate =
                createdAt.includes("T")
                    ? createdAt
                    : createdAt.replace(
                        " ",
                        "T"
                    );


            const emailDate =
                new Date(
                    normalizedDate
                );


            if (
                Number.isNaN(
                    emailDate.getTime()
                )
            ) {
                return;
            }


            emailDate.setHours(
                0,
                0,
                0,
                0
            );


            const matchingDay =
                dailyCounts.find(
                    day =>
                        day.date.getTime() ===
                        emailDate.getTime()
                );


            if (matchingDay) {
                matchingDay.count++;
            }

        }
    );


    /* ==============================
       CHART DIMENSIONS
       ============================== */

    const chartWidth = 800;

    const chartHeight = 240;

    const chartBaseY = 240;

    const chartPlotHeight = 190;


    /* ==============================
       DYNAMIC Y SCALE
       ============================== */

    const highestCount =
        Math.max(
            ...dailyCounts.map(
                item => item.count
            ),
            0
        );

    if (highestCount === 0) {
        setChartState(`No threat detections in the last ${days} days.`);
    } else {
        document.querySelector(".chart-area")?.querySelector(".chart-state")?.remove();
    }


    const maxValue =
        highestCount <= 5
            ? 5
            : Math.ceil(
                highestCount / 5
            ) * 5;


    /* ==============================
       CREATE POINTS
       ============================== */

    const denominator =
        Math.max(
            dailyCounts.length - 1,
            1
        );


    const points =
        dailyCounts.map(
            (item, index) => {

                const x =
                    (
                        index /
                        denominator
                    ) *
                    chartWidth;


                const y =
                    chartBaseY -
                    (
                        item.count /
                        maxValue
                    ) *
                    chartPlotHeight;


                return {
                    x,
                    y
                };

            }
        );


    /* ==============================
       CREATE SVG PATH
       ============================== */

    let linePath = "";


    points.forEach(
        (point, index) => {

            if (index === 0) {

                linePath =
                    `M${point.x},${point.y}`;

            }
            else {

                linePath +=
                    ` L${point.x},${point.y}`;

            }

        }
    );


    const firstPoint =
        points[0];

    const lastPoint =
        points[
            points.length - 1
        ];


    if (
        !firstPoint ||
        !lastPoint
    ) {
        return;
    }


    /* ==============================
       AREA FILL
       ============================== */

    const fillPath =
        `${linePath}
        L${lastPoint.x},${chartBaseY}
        L${firstPoint.x},${chartBaseY}
        Z`;


    chartLine.setAttribute(
        "d",
        linePath
    );


    chartFill.setAttribute(
        "d",
        fillPath
    );


    /* ==============================
       X AXIS
       ============================== */

    const xAxis =
        document.querySelector(
            ".chart-x-axis"
        );


    if (xAxis) {

        let indexes;


        if (days === 7) {

            indexes = [
                0,
                1,
                2,
                3,
                4,
                5,
                6
            ];

        }
        else if (days === 30) {

            indexes = [
                0,
                7,
                14,
                21,
                29
            ];

        }
        else {

            indexes = [
                0,
                22,
                44,
                67,
                89
            ];

        }


        xAxis.innerHTML =
            indexes
                .filter(
                    index =>
                        dailyCounts[index]
                )
                .map(
                    index => {

                        const item =
                            dailyCounts[
                                index
                            ];


                        const day =
                            String(
                                item.date.getDate()
                            ).padStart(
                                2,
                                "0"
                            );


                        const month =
                            item.date.toLocaleString(
                                "en-US",
                                {
                                    month:
                                        "short"
                                }
                            );


                        return `
                            <span>
                                ${day} ${month}
                            </span>
                        `;

                    }
                )
                .join("");

    }


    /* ==============================
       Y AXIS
       ============================== */

    const yAxis =
        document.querySelector(
            ".chart-y-axis"
        );


    if (yAxis) {

        const yValues = [
            maxValue,
            Math.round(
                maxValue * 0.75
            ),
            Math.round(
                maxValue * 0.50
            ),
            Math.round(
                maxValue * 0.25
            ),
            0
        ];


        yAxis.innerHTML =
            yValues
                .map(
                    value =>
                        `<span>${value}</span>`
                )
                .join("");

    }

}


        /* ==============================
        INITIAL CHART
        ============================== */

        updateThreatActivityChart(30);


        /* ==============================
        DROPDOWN CHANGE
        ============================== */

        if (rangeSelector) {

            rangeSelector.addEventListener(
                "change",
                () => {

                    const days =
                        Number(
                            rangeSelector.value
                        );


                    updateThreatActivityChart(
                        days
                    );

                }
            );

        }


                console.log(
                    "✅ Dashboard charts updated successfully."
                );


            } catch (error) {
                window.clearTimeout(chartTimeout);

                console.error(
                    "Dashboard Charts Error:",
                    error
                );

                setChartState("Threat activity is unavailable. Check the backend connection and refresh.", true);

            }

        }/* =========================================
        CASES MODULE
        ========================================= */

        /* =========================================
        PAGE CLEANUP
        ========================================= */

        /* =========================================
        PAGE CLEANUP
        ========================================= */

        /* =========================================
        REPORTS MODULE + REPORT-SPECIFIC MAP VIEW
        ========================================= */

        function escapeHtml(value) {
            return String(value ?? "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        async function loadReports() {
            const page = document.querySelector(".page");
            if (!page) return;

            cleanupDynamicPages();

            const dashboard = document.querySelector(".dashboard-content");
            if (dashboard) dashboard.style.setProperty("display", "none", "important");

            const container = document.createElement("section");
            container.id = "reportsPage";
            container.className = "reports-page";
            page.prepend(container);

            container.innerHTML = `
                <div class="reports-header">
                    <div>
                        <div class="eyebrow">FORENSIC REPORTING</div>
                        <h2>Reports</h2>
                        <p>Open a completed investigation report and view its available geolocation intelligence from the MAP VIEW control.</p>
                    </div>
                    <button class="report-refresh-btn" id="refreshReports">↻ Refresh</button>
                </div>
                <div id="reportsContent" class="reports-content-state">Loading reports...</div>
            `;

            document.getElementById("refreshReports")?.addEventListener("click", loadReports);

            try {
                const response = await fetch("http://127.0.0.1:8000/api/investigations");
                const data = await response.json();
                if (!response.ok) throw new Error(data.detail || "Failed to load reports.");

                const reports = data.investigations || [];
                const content = document.getElementById("reportsContent");
                if (!content) return;

                if (!reports.length) {
                    content.className = "reports-empty-state";
                    content.textContent = "No investigation reports are available yet.";
                    return;
                }

                content.className = "reports-list";
                let reportPage = 1;
                const pageSize = 20;
                const renderReportPage = () => {
                    const start = (reportPage - 1) * pageSize;
                    const pageReports = reports.slice(start, start + pageSize);
                    content.innerHTML = `${pageReports.map(report => `
                    <article class="report-card">
                        <div class="report-card-top">
                            <div>
                                <div class="report-id">${escapeHtml(report.investigation_id || "REPORT")}</div>
                                <h3>${escapeHtml(report.subject || report.filename || "Untitled Investigation")}</h3>
                            </div>
                            <div class="report-card-actions">
                                <button type="button" class="report-open-btn" data-report-open="${escapeHtml(report.investigation_id || "")}">OPEN REPORT</button>
                                <button type="button" class="map-view-btn" data-investigation-id="${escapeHtml(report.investigation_id || "")}">VIEW MAP</button>
                            </div>
                        </div>
                        <div class="report-meta">
                            <span>FROM: ${escapeHtml(report.sender || "Unknown")}</span>
                            <span class="report-verdict">${escapeHtml(report.threat_verdict || "UNASSESSED")}</span>
                            <span>RISK: ${escapeHtml(report.threat_score ?? 0)}/100</span>
                            <span>${escapeHtml(report.created_at || "")}</span>
                        </div>
                    </article>
                `).join("")}
                    <div class="reports-pagination">
                        <span>Showing ${start + 1}–${Math.min(start + pageSize, reports.length)} of ${reports.length} reports</span>
                        <div class="reports-pagination-actions">
                            <button type="button" class="reports-page-btn" data-page-action="previous" ${reportPage === 1 ? "disabled" : ""}>Previous</button>
                            <span>Page ${reportPage} of ${Math.ceil(reports.length / pageSize)}</span>
                            <button type="button" class="reports-page-btn" data-page-action="next" ${start + pageSize >= reports.length ? "disabled" : ""}>Next</button>
                        </div>
                    </div>`;

                    content.querySelector('[data-page-action="previous"]')?.addEventListener("click", () => {
                        if (reportPage > 1) { reportPage -= 1; renderReportPage(); }
                    });
                    content.querySelector('[data-page-action="next"]')?.addEventListener("click", () => {
                        if (reportPage * pageSize < reports.length) { reportPage += 1; renderReportPage(); }
                    });

                    content.querySelectorAll(".report-open-btn").forEach(button => {
                        button.addEventListener("click", () => openInvestigation(button.dataset.reportOpen));
                    });
                    content.querySelectorAll(".map-view-btn").forEach(button => {
                        button.addEventListener("click", () => openReportMap(button.dataset.investigationId));
                    });
                };
                renderReportPage();
            } catch (error) {
                const content = document.getElementById("reportsContent");
                if (content) {
                    content.className = "reports-content-state";
                    content.textContent = `Unable to load reports: ${error.message}`;
                }
            }
        }

        function openInvestigationMapView(ipIntelligence) {

            const nodes = Array.isArray(ipIntelligence)
                ? ipIntelligence
                    .map(item => ({
                        ip: item.ip || item.observed_ip || item.address || "Observed IP",
                        city: item.city || "",
                        region: item.region || "",
                        country: item.country || "",
                        country_code: item.country_code || "",
                        type: item.type || "",
                        risk: item.risk || "",
                        risk_score: item.risk_score ?? null,
                        isp: item.isp || item.organization || item.org || "",
                        latitude: Number(
                            item.latitude ?? item.lat ??
                            (Array.isArray(item.coordinates) ? item.coordinates[0] : NaN)
                        ),
                        longitude: Number(
                            item.longitude ?? item.lon ??
                            (Array.isArray(item.coordinates) ? item.coordinates[1] : NaN)
                        )
                    }))
                : [];

            disposeReportMapModal();

            const modal = document.createElement("div");
            modal.id = "reportMapModal";
            modal.className = "report-map-modal open";
            modal.innerHTML = `
                <div class="report-map-dialog" role="dialog" aria-modal="true" aria-labelledby="investigationMapTitle">
                    <button class="report-map-close" aria-label="Close">×</button>
                    <div class="report-map-title">
                        <div class="eyebrow">GEOLOCATION INTELLIGENCE</div>
                        <h2 id="investigationMapTitle">Map View</h2>
                        <p>Infrastructure locations derived from this investigation's observed relay intelligence.</p>
                    </div>
                    <div class="report-map-canvas" id="reportMapCanvas">
                        <div class="report-map-grid"></div>
                        <div class="report-map-loading">Loading investigation geolocation evidence...</div>
                    </div>
                    <div class="report-map-details" id="reportMapDetails"></div>
                </div>
            `;

            document.body.appendChild(modal);

            const close = () => disposeReportMapModal();
            modal.querySelector(".report-map-close")?.addEventListener("click", close);
            modal.__closeOnEscape = event => { if (event.key === "Escape") close(); };
            document.addEventListener("keydown", modal.__closeOnEscape);
            modal.querySelector(".report-map-close")?.focus();
            modal.addEventListener("click", event => {
                if (event.target === modal) close();
            });

            renderReportMap(nodes);
        }


        async function openReportMap(investigationId) {
            if (!investigationId) return;

            disposeReportMapModal();

            const modal = document.createElement("div");
            modal.id = "reportMapModal";
            modal.className = "report-map-modal open";
            modal.innerHTML = `
                <div class="report-map-dialog" role="dialog" aria-modal="true" aria-labelledby="reportMapTitle">
                    <button class="report-map-close" aria-label="Close">×</button>
                    <div class="report-map-title">
                        <div class="eyebrow">GEOLOCATION INTELLIGENCE</div>
                        <h2 id="reportMapTitle">Report Map View</h2>
                        <p>${escapeHtml(investigationId)}</p>
                    </div>
                    <div class="report-map-canvas" id="reportMapCanvas">
                        <div class="report-map-grid"></div>
                        <div class="report-map-loading">Loading report geolocation evidence...</div>
                    </div>
                    <div class="report-map-details" id="reportMapDetails"></div>
                </div>
            `;
            document.body.appendChild(modal);

            const close = () => disposeReportMapModal();
            modal.querySelector(".report-map-close").addEventListener("click", close);
            modal.__closeOnEscape = event => { if (event.key === "Escape") close(); };
            document.addEventListener("keydown", modal.__closeOnEscape);
            modal.querySelector(".report-map-close")?.focus();
            modal.addEventListener("click", event => { if (event.target === modal) close(); });

            try {
                const response = await fetch(`http://127.0.0.1:8000/api/reports/map-view/${encodeURIComponent(investigationId)}`);
                const data = await response.json();
                if (!response.ok) throw new Error(data.detail || "Unable to load map data.");

                if (!modal.isConnected || document.getElementById("reportMapModal") !== modal) return;
                renderReportMap(data.nodes || []);
            } catch (error) {
                if (!modal.isConnected || document.getElementById("reportMapModal") !== modal) return;
                const canvas = modal.querySelector("#reportMapCanvas");
                if (canvas) {
                    canvas.innerHTML = `<div class="map-request-error" role="alert">
                        <strong>Map data could not be loaded</strong>
                        <span>${escapeHtml(error.message || "The backend did not return map data.")}</span>
                        <button type="button" class="map-request-retry">Try again</button>
                    </div>`;
                    canvas.querySelector(".map-request-retry")?.addEventListener("click", () => openReportMap(investigationId));
                }
            }
        }

        function disposeReportMapModal() {
            const existingModal = document.getElementById("reportMapModal");
            if (existingModal?.__closeOnEscape) {
                document.removeEventListener("keydown", existingModal.__closeOnEscape);
            }
            if (window.currentReportLeafletMap) {
                try {
                    window.currentReportLeafletMap.remove();
                } catch (error) {
                    console.warn("Map cleanup:", error);
                }
                window.currentReportLeafletMap = null;
            }

            document.getElementById("reportMapModal")?.remove();
        }

        function loadMapAsset(url, assetId, isStyleSheet = false) {
            return new Promise((resolve, reject) => {
                const existing = document.getElementById(assetId);
                if (existing?.dataset.loaded === "true") {
                    resolve();
                    return;
                }

                const asset = existing || document.createElement(isStyleSheet ? "link" : "script");
                asset.id = assetId;
                if (isStyleSheet) {
                    asset.rel = "stylesheet";
                    asset.href = url;
                } else {
                    asset.src = url;
                    asset.async = true;
                }

                const timeout = window.setTimeout(() => {
                    asset.remove();
                    reject(new Error("Map library request timed out."));
                }, 10000);

                asset.onload = () => {
                    window.clearTimeout(timeout);
                    asset.dataset.loaded = "true";
                    resolve();
                };
                asset.onerror = () => {
                    window.clearTimeout(timeout);
                    asset.remove();
                    reject(new Error("Map library could not be downloaded."));
                };

                if (!existing) document.head.appendChild(asset);
            });
        }

        function ensureMapLibreLeaflet() {
            if (window.maplibregl && window.L?.maplibreGL) return Promise.resolve();
            if (window.mailTraceMapLibreLoad) return window.mailTraceMapLibreLoad;

            window.mailTraceMapLibreLoad = Promise.all([
                loadMapAsset(
                    "https://unpkg.com/maplibre-gl@5/dist/maplibre-gl.css",
                    "mailtrace-maplibre-css",
                    true
                ),
                loadMapAsset(
                    "https://unpkg.com/maplibre-gl@5/dist/maplibre-gl.js",
                    "mailtrace-maplibre-js"
                )
            ]).then(() => loadMapAsset(
                "https://unpkg.com/@maplibre/maplibre-gl-leaflet@0.1.4/dist/leaflet-maplibre-gl.js",
                "mailtrace-maplibre-leaflet-js"
            )).then(() => {
                if (!window.maplibregl || !window.L?.maplibreGL) {
                    throw new Error("Map renderer did not initialize.");
                }
            }).catch(error => {
                window.mailTraceMapLibreLoad = null;
                throw error;
            });

            return window.mailTraceMapLibreLoad;
        }

        function drawStaticMapFallback(canvas, nodes) {
            if (!canvas) return;
            canvas.innerHTML = `<div class="map-fallback" role="img" aria-label="Offline world map with observed infrastructure locations">
                ${nodes.map(node => {
                    const lat = Number(node.latitude);
                    const lng = Number(node.longitude);
                    const x = Math.max(2, Math.min(98, ((lng + 180) / 360) * 100));
                    const y = Math.max(4, Math.min(96, ((90 - lat) / 180) * 100));
                    const label = `${node.ip || "Observed IP"} — ${[node.city, node.region, node.country].filter(Boolean).join(", ") || "Unknown location"}`;
                    return `<span class="map-fallback-marker" style="left:${x}%;top:${y}%" title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"></span>`;
                }).join("")}
                <span class="map-fallback-caption">Offline map preview · approximate locations</span>
            </div>`;
        }

        function renderReportMap(nodes) {

    const canvas = document.getElementById("reportMapCanvas");
    const details = document.getElementById("reportMapDetails");

    if (!canvas || !details) return;

    const safeNodes = Array.isArray(nodes) ? nodes : [];
    const validNodes = safeNodes.filter(node => {
        const lat = Number(node.latitude);
        const lng = Number(node.longitude);
        return Number.isFinite(lat) && Number.isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
    });

    const renderMapNodeDetail = node => {
        const location = [node.city, node.region, node.country].filter(Boolean).join(", ");
        const lat = Number(node.latitude);
        const lng = Number(node.longitude);
        const coordinates = Number.isFinite(lat) && Number.isFinite(lng)
            ? `${lat.toFixed(4)}, ${lng.toFixed(4)}`
            : "Coordinates unavailable";
        return `
            <article class="map-node-detail">
                <div class="map-node-detail-heading"><strong>${escapeHtml(node.ip || "Observed IP")}</strong><span>${escapeHtml(node.country_code || node.type || "RELAY")}</span></div>
                <span>${escapeHtml(location || "Location unavailable")}</span>
                <small>${escapeHtml(coordinates)}</small>
                ${node.isp ? `<small>${escapeHtml(node.isp)}</small>` : ""}
                ${node.risk ? `<small class="map-node-risk">${escapeHtml(node.risk)} infrastructure score ${escapeHtml(String(node.risk_score ?? "—"))}</small>` : ""}
            </article>
        `;
    };

    details.innerHTML = safeNodes.length
        ? safeNodes.map(renderMapNodeDetail).join("")
        : '<div class="map-no-data">No IP geolocation evidence was returned for this investigation.</div>';

    if (validNodes.length === 0) {

        canvas.innerHTML = `
            <div class="map-canvas-message">
                No valid geolocation coordinates are available for this investigation.
            </div>
        `;

        return;
    }

    canvas.innerHTML = '<div id="leafletReportMap" class="leaflet-report-map"></div>';

    const mapElement = document.getElementById("leafletReportMap");

    if (!window.L) {
        drawStaticMapFallback(canvas, validNodes);
        Promise.all([
            loadMapAsset("https://unpkg.com/leaflet@1.9.4/dist/leaflet.css", "mailtrace-leaflet-css", true),
            loadMapAsset("https://unpkg.com/leaflet@1.9.4/dist/leaflet.js", "mailtrace-leaflet-js")
        ]).then(() => {
            if (canvas.isConnected) renderReportMap(safeNodes);
        }).catch(error => {
            console.warn("Interactive map unavailable; keeping the offline map preview:", error);
        });
        return;
    }

    if (window.currentReportLeafletMap) {

        try {
            window.currentReportLeafletMap.remove();
        } catch (error) {
            console.warn("Previous map cleanup:", error);
        }

        window.currentReportLeafletMap = null;
    }

    const firstNode = validNodes[0];

    const map = L.map(mapElement, {
        zoomControl: true,
        attributionControl: true
    });

    window.currentReportLeafletMap = map;

        const basemapStatus = document.createElement("div");
        basemapStatus.className = "report-map-basemap-status";
        basemapStatus.textContent = "Loading map…";
        canvas.appendChild(basemapStatus);

        let basemapLoaded = false;
        let fallbackRendered = false;
        const showOfflineMap = () => {
            if (fallbackRendered || !mapElement.isConnected || window.currentReportLeafletMap !== map) return;
            fallbackRendered = true;
            map.remove();
            window.currentReportLeafletMap = null;
            drawStaticMapFallback(canvas, validNodes);
        };
        const basemapTimeout = window.setTimeout(showOfflineMap, 12000);

        ensureMapLibreLeaflet().then(() => {
            if (!mapElement.isConnected || window.currentReportLeafletMap !== map) return;

        const basemap = L.maplibreGL({
            style: "https://tiles.openfreemap.org/styles/dark",
            interactive: false
            }).addTo(map);
            const vectorMap = basemap.getMaplibreMap();

            vectorMap.once("load", () => {
                basemapLoaded = true;
                window.clearTimeout(basemapTimeout);
                basemapStatus.remove();
            });
            vectorMap.on("error", () => {
                if (!basemapLoaded) {
                    console.warn("Map tiles are unavailable; switching to the offline map preview.");
                    showOfflineMap();
                    return;
                }
                basemapStatus.textContent = "Some basemap tiles are unavailable; location details and markers remain available.";
                basemapStatus.classList.add("is-visible");
            });
        }).catch(error => {
            console.warn("Map basemap failed to load:", error);
            window.clearTimeout(basemapTimeout);
            showOfflineMap();
        });

    const markers = [];

    validNodes.forEach((node, index) => {

        const lat = Number(node.latitude);
        const lng = Number(node.longitude);

        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;

        const locationParts = [
            node.city,
            node.region,
            node.country
        ].filter(Boolean);

        const location = locationParts.join(", ") || "Unknown location";

        const marker = L.circleMarker(
            [lat, lng],
            {
                radius: 9,
                color: "#00d9ff",
                weight: 2,
                fillColor: "#062235",
                fillOpacity: 1
            }
        ).addTo(map);

        marker.bindPopup(`
            <div class="map-popup">
                <strong>${escapeHtml(node.ip || "Observed IP")}</strong>
                <span>${escapeHtml(location)}</span>
                <small>
                    ${lat.toFixed(4)}, ${lng.toFixed(4)}
                </small>
                ${
                    node.isp
                        ? `<small>${escapeHtml(node.isp)}</small>`
                        : ""
                }
            </div>
        `);

        markers.push([lat, lng]);
    });

    if (markers.length === 1) {

        map.setView(markers[0], 7);

    } else if (markers.length > 1) {

        const bounds = L.latLngBounds(markers);

        map.fitBounds(bounds, {
            padding: [60, 60],
            maxZoom: 8
        });

    } else {

        map.setView(
            [
                Number(firstNode.latitude) || 20,
                Number(firstNode.longitude) || 0
            ],
            2
        );
    }

    setTimeout(() => map.invalidateSize(), 150);

}


        async function loadHelpDocs() {
            const page = document.querySelector(".page");
            if (!page) return;

            cleanupDynamicPages();

            const dashboard = document.querySelector(".dashboard-content");
            if (dashboard) {
                dashboard.style.setProperty("display", "none", "important");
            }

            const container = document.createElement("section");
            container.id = "helpDocsPage";
            container.className = "investigations-page";
            container.innerHTML = `
                <div class="investigations-header"><div><div class="eyebrow">MAILTRACE-AI DOCUMENTATION</div><h2>Help &amp; Docs</h2><p>Navigation guidance and workflow reference for email threat analysis.</p></div></div>
                <div class="result-card"><div class="result-card-title">QUICK START</div><div class="help-docs-grid">
                <button type="button" class="quick-card" data-action="new-investigation"><span class="quick-card-icon">+</span><h4>Start an Investigation</h4><p>Upload an EML or MSG file and start forensic analysis.</p></button>
                <button type="button" class="quick-card" data-page="ip-intelligence"><span class="quick-card-icon">IP</span><h4>Investigate an IP</h4><p>Review reputation, network ownership and available geolocation.</p></button>
                <button type="button" class="quick-card" data-page="cases"><span class="quick-card-icon">CASE</span><h4>Review Cases</h4><p>Track active incident work and investigation outcomes.</p></button>
                <button type="button" class="quick-card" data-page="campaigns"><span class="quick-card-icon">IOC</span><h4>Explore Campaigns</h4><p>Review related investigations and their correlation evidence.</p></button></div></div>
                <div class="result-card help-workspace-guide"><div class="result-card-title">WORKSPACE GUIDE</div><p class="help-guide-intro">Move from an email signal to a documented analyst decision using these workspaces.</p><div class="help-guide-grid">
                <article><span>01</span><h3>Dashboard</h3><p>Monitor analyzed mail, threat verdicts, open cases and campaign activity. Use metric cards and charts to identify work needing review.</p></article>
                <article><span>02</span><h3>Investigations</h3><p>Search analyzed email and inspect verdict, authentication, headers, URLs, attachments and forensic evidence. Open a record for the full result.</p></article>
                <article><span>03</span><h3>Cases</h3><p>Track active incident work, evidence and disposition. Open a case to review linked investigations and current status.</p></article>
                <article><span>04</span><h3>Campaigns</h3><p>Explore related investigations grouped by shared infrastructure or indicators. Review correlation evidence before inferring a common actor.</p></article>
                <article><span>05</span><h3>Reports</h3><p>Open a completed investigation report for its full analysis. Use View Map to inspect available relay or IP geolocation evidence.</p></article>
                <article><span>06</span><h3>IP Intelligence</h3><p>Submit an IP to review network ownership, reputation, risk signals and geolocation. Private or reserved addresses may not have coordinates.</p></article>
                <article><span>07</span><h3>Help &amp; Docs</h3><p>Use this guide to navigate MailTrace and verify findings against source evidence.</p></article>
                </div><div class="help-workflow"><strong>Recommended workflow</strong><span>Analyze email</span><i>&#8594;</i><span>Review evidence</span><i>&#8594;</i><span>Enrich IPs</span><i>&#8594;</i><span>Track a case</span><i>&#8594;</i><span>Review report</span></div><p class="help-guide-footnote">MailTrace supports analyst triage. Confirm findings against source evidence and your organization&apos;s response procedures.</p></div>
            `;
            page.prepend(container);
            window.scrollTo({ top: 0, behavior: "smooth" });
        }


        function cleanupDynamicPages() {

            document.getElementById("resultMapHeaderAction")?.remove();

            const pages = [
                "investigationsPage",
                "casesPage",
                "caseDetailPage",
                "campaignsPage",
                "campaignDetailPage",
                "investigationResult",
                "ipIntelligencePage",
                "reportsPage",
                "helpDocsPage"
            ];

            pages.forEach((id) => {

                const element =
                    document.getElementById(id);

                if (element) {
                    element.remove();
                }

            });

        }


        /* =========================================
        CASES MODULE
        ========================================= */


        async function loadSlaAlerts() {
            const host = document.getElementById("socSlaAlertsContent");
            const statusFilter = document.getElementById("socSlaAlertStatus");
            if (!host) return;
            const status = String(statusFilter?.value || "OPEN").toUpperCase();
            host.setAttribute("aria-busy", "true");
            host.innerHTML = '<div class="investigations-loading">Loading persisted SLA alerts?</div>';
            try {
                const response = await fetch(
                    "http://127.0.0.1:8000/api/soc/routing/alerts?status=" + encodeURIComponent(status) + "&limit=100",
                    { headers: { "Accept": "application/json" }, cache: "no-store" }
                );
                const payload = await response.json().catch(() => ({}));
                if (!response.ok) {
                    const detail = typeof payload.detail === "string" ? payload.detail : "";
                    if (response.status === 401 || response.status === 403) throw new Error("Sign in with an authorized SOC account to view tenant-scoped SLA alerts.");
                    throw new Error(detail || ("SLA alerts request failed (" + response.status + ")."));
                }
                const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
                if (!alerts.length) {
                    const label = status === "ALL" ? "" : status.toLowerCase() + " ";
                    host.innerHTML = '<div class="case-empty-state">No ' + escapeHTML(label) + 'SLA alerts returned for this tenant.</div>';
                    return;
                }
                const overdueCount = alerts.filter(item => Number(item.overdue) === 1).length;
                const total = Number(payload.count || alerts.length);
                host.innerHTML =
                    '<div class="soc-alert-summary" role="status"><span><strong>' + total + '</strong> alert' + (total === 1 ? '' : 's') + '</span><span><strong>' + overdueCount + '</strong> overdue</span><span>Live data ? server persisted</span></div>' +
                    '<div class="investigations-table-wrapper"><table class="investigations-table soc-alert-table"><thead><tr><th>CASE</th><th>SEVERITY / PRIORITY</th><th>SLA DEADLINE</th><th>ASSIGNEE</th><th>ROUTING</th><th>ESCALATIONS</th><th>ALERT STATUS</th></tr></thead><tbody>' +
                    alerts.map(item => {
                        const statusText = String(item.status || "Unknown");
                        const count = Number(item.escalation_count);
                        return '<tr class="' + (Number(item.overdue) === 1 ? 'soc-case-overdue' : '') + '">' +
                            '<td><strong>' + escapeHTML(item.case_id || "Unknown case") + '</strong><small>' + escapeHTML(item.title || item.alert_type || "SLA alert") + '</small></td>' +
                            '<td><span class="investigation-threat ' + escapeHTML(getThreatClass(item.severity || "MEDIUM")) + '">' + escapeHTML(item.severity || "Unknown") + '</span><small>' + escapeHTML(item.priority || "Unprioritized") + '</small></td>' +
                            '<td><strong class="' + (Number(item.overdue) === 1 ? 'soc-sla-overdue' : '') + '">' + escapeHTML(item.sla_deadline || "Not set") + '</strong><small>' + (Number(item.overdue) === 1 ? 'SLA OVERDUE' : 'Deadline not passed') + '</small></td>' +
                            '<td>' + escapeHTML(item.assigned_analyst || "Unassigned") + '</td>' +
                            '<td><span class="soc-routing-status">' + escapeHTML(item.routing_status || "Unknown") + '</span></td>' +
                            '<td>' + (Number.isFinite(count) ? count : 0) + '</td>' +
                            '<td><span class="soc-alert-status soc-alert-status-' + escapeHTML(statusText.toLowerCase()) + '">' + escapeHTML(statusText) + '</span><small>Updated ' + escapeHTML(item.last_seen_at || "unknown") + '</small></td></tr>';
                    }).join("") + '</tbody></table></div>';
            } catch (error) {
                host.innerHTML = '<div class="investigations-error"><strong>Unable to load SLA alerts</strong><p>' + escapeHTML(error.message || "The alerts service could not be reached.") + '</p><button type="button" class="secondary-result-btn" id="retrySocSlaAlerts">Retry alerts</button></div>';
                document.getElementById("retrySocSlaAlerts")?.addEventListener("click", loadSlaAlerts, { once: true });
            } finally {
                host.setAttribute("aria-busy", "false");
            }
        }

async function loadCases() {

            console.log("🔥 Loading cases...");


            /* ==============================
            GET PAGE
            ============================== */

            const page =
                document.querySelector(".page");


            if (!page) {

                console.error(
                    "Page container not found."
                );

                return;
            }


            /* ==============================
            CLEAN OLD DYNAMIC PAGES
            ============================== */

            cleanupDynamicPages();


            /* ==============================
            HIDE NORMAL DASHBOARD
            ============================== */

            const dashboard =
                document.querySelector(
                    ".dashboard-content"
                );


            if (dashboard) {

                dashboard.style.setProperty(
                    "display",
                    "none",
                    "important"
                );

            }


            /* ==============================
            CREATE / GET CASES PAGE
            ============================== */

            let container =
                document.getElementById(
                    "casesPage"
                );


            if (!container) {

                container =
                    document.createElement(
                        "section"
                    );


                container.id =
                    "casesPage";


                container.className =
                    "investigations-page";


                page.prepend(
                    container
                );

            }


            /* ==============================
            LOADING UI
            ============================== */

            container.innerHTML = `

                <div class="investigations-header">

                    <div>

                        <div class="eyebrow">
                            SECURITY CASE MANAGEMENT
                        </div>

                        <h2>
                            Cases
                        </h2>

                        <p>
                            Review ownership, routing priority, SLA deadlines, and claim status.
                        </p>

                    </div>


                    <button
                        class="secondary-result-btn"
                        id="refreshCases"
                    >
                        ↻ Refresh
                    </button>

                </div>


                <section class="result-card soc-sla-alerts-panel" aria-labelledby="socSlaAlertsTitle">
                    <div class="soc-alerts-heading">
                        <div>
                            <div class="result-card-title" id="socSlaAlertsTitle">SOC SLA ALERTS</div>
                            <p>Persisted escalation alerts for the authenticated tenant. Alert status is read-only until lifecycle actions are available in the API.</p>
                        </div>
                        <div class="soc-alerts-controls">
                            <label class="sr-only" for="socSlaAlertStatus">Alert status filter</label>
                            <select id="socSlaAlertStatus" class="select-control">
                                <option value="OPEN">Open alerts</option><option value="ACKNOWLEDGED">Acknowledged</option>
                                <option value="RESOLVED">Resolved</option><option value="ALL">All statuses</option>
                            </select>
                            <button type="button" class="secondary-result-btn" id="refreshSocSlaAlerts">Refresh alerts</button>
                        </div>
                    </div>
                    <div id="socSlaAlertsContent" aria-live="polite" aria-busy="true">
                        <div class="investigations-loading">SLA alerts will load from the backend?</div>
                    </div>
                </section>

                <div class="result-card">

                    <div class="result-card-title">
                        CASE DATABASE
                    </div>


                    <div id="casesContent">

                        <div class="investigations-loading">
                            Loading cases...
                        </div>

                    </div>

                </div>

            `;


            /* ==============================
            FETCH CASES
            ============================== */

            try {

                const response =
                    await fetch(
                        "http://127.0.0.1:8000/api/soc/routing/queue"
                    );


                const data =
                    await response.json();


                /* ==============================
                CHECK RESPONSE
                ============================== */

                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load cases."
                    );

                }


                console.log(
                    "🔥 CASES:",
                    data
                );


                /* ==============================
                RENDER CASES
                ============================== */

                renderCases(
                    data.cases || [],
                    data
                );


            } catch (error) {

                console.error(
                    "Cases Load Error:",
                    error
                );


                const content =
                    document.getElementById(
                        "casesContent"
                    );


                if (content) {

                    content.innerHTML = `

                        <div class="investigations-error">

                            <strong>
                                Unable to load cases
                            </strong>

                            <p>
                                ${escapeHTML(
                                    error.message ||
                                    "Backend connection failed."
                                )}
                            </p>

                        </div>

                    `;

                }

            }


            /* Load persisted SLA alerts even if the case queue itself failed. */
            await loadSlaAlerts();
            document.getElementById("refreshSocSlaAlerts")?.addEventListener("click", loadSlaAlerts);
            document.getElementById("socSlaAlertStatus")?.addEventListener("change", loadSlaAlerts);

            /* ==============================
            REFRESH BUTTON
            ============================== */

            const refreshButton =
                document.getElementById(
                    "refreshCases"
                );


            if (refreshButton) {

                refreshButton.addEventListener(
                    "click",
                    loadCases
                );

            }

        }
        /* =========================================
        LIVE CAMPAIGNS
        ========================================= */

        async function loadCampaigns() {

            console.log("🔥 Loading campaigns...");

            const page = document.querySelector(".page");

            if (!page) {
                console.error("Page container not found.");
                return;
            }

            /* ==============================
        CLEAN OLD PAGES
        ============================== */

        cleanupDynamicPages();


        /* ==============================
        HIDE DASHBOARD
        ============================== */

        const dashboard =
            document.querySelector(
                ".dashboard-content"
            );

        if (dashboard) {
            dashboard.style.setProperty("display", "none", "important");
        }


            /* ==============================
            CREATE CAMPAIGNS PAGE
            ============================== */

            const container =
                document.createElement("section");

            container.id =
                "campaignsPage";

            container.className =
                "campaigns-page";


            container.innerHTML = `

                <div class="investigations-header">

                    <div>

                        <div class="eyebrow">
                            THREAT INTELLIGENCE
                        </div>

                        <h2>
                            Campaigns
                        </h2>

                        <p>
                            Correlated threat activity detected
                            across analysed emails.
                        </p>

                    </div>


                    <button
                        class="secondary-result-btn"
                        id="refreshCampaigns"
                    >
                        ↻ Refresh
                    </button>

                </div>


                <div class="result-card">

                    <div class="result-card-title">
                        ACTIVE CAMPAIGNS
                    </div>


                    <div id="campaignsContent">

                        <div class="investigations-loading">
                            Loading campaigns...
                        </div>

                    </div>

                </div>

            `;


            page.prepend(container);
            container.querySelector("#refreshCampaigns")?.addEventListener("click", loadCampaigns);

            /* ==============================
            FETCH CAMPAIGNS
            ============================== */

            try {

                const response =
                    await fetch(
                        "http://127.0.0.1:8000/api/campaigns"
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load campaigns."
                    );

                }


                console.log(
                    "🔥 CAMPAIGNS:",
                    data
                );


                renderCampaigns(
                    data.campaigns || []
                );


            } catch (error) {

                console.error(
                    "Campaign Load Error:",
                    error
                );


                const content =
                    document.getElementById(
                        "campaignsContent"
                    );


                if (content) {

                    content.innerHTML = `

                        <div class="investigations-error">

                            <strong>
                                Unable to load campaigns
                            </strong>

                            <p>
                                ${escapeHTML(
                                    error.message ||
                                    "Backend connection failed."
                                )}
                            </p>

                        </div>

                    `;

                }

            }

        }

        /* =========================================
        RENDER CAMPAIGNS
        ========================================= */

        function renderCampaigns(campaigns) {

            const content =
                document.getElementById(
                    "campaignsContent"
                );


            if (!content) {

                console.error(
                    "Campaigns content container not found."
                );

                return;

            }


            /* ==============================
            NO CAMPAIGNS
            ============================== */

            if (!campaigns.length) {

                content.innerHTML = `

                    <div class="investigations-empty">

                        No active campaigns found.

                    </div>

                `;

                return;

            }


            /* ==============================
            CAMPAIGN CARDS
            ============================== */

            content.innerHTML = `

                <div class="campaigns-count">

                    ${campaigns.length}
                    campaign${campaigns.length === 1 ? "" : "s"}

                </div>


                <div class="campaign-grid">

                    ${campaigns.map(
                        campaign => {

                            const severity =
                                String(
                                    campaign.severity ||
                                    "UNKNOWN"
                                ).toUpperCase();


                            let severityClass =
                                "medium";


                            if (
                                severity === "CRITICAL"
                            ) {

                                severityClass =
                                    "critical";

                            }
                            else if (
                                severity === "HIGH"
                            ) {

                                severityClass =
                                    "high";

                            }
                            else if (
                                severity === "LOW"
                            ) {

                                severityClass =
                                    "low";

                            }


                            return `

                                <article
                                    class="campaign-card"
                                    data-campaign-id="${escapeHTML(
                                        campaign.campaign_id ||
                                        ""
                                    )}"
                                >

                                    <div class="campaign-card-header">

                                        <div>

                                            <div class="campaign-id">

                                                ${escapeHTML(
                                                    campaign.campaign_id ||
                                                    "UNKNOWN"
                                                )}

                                            </div>


                                            <h3>

                                                ${escapeHTML(
                                                    campaign.name ||
                                                    "Unknown Campaign"
                                                )}

                                            </h3>

                                        </div>


                                        <span
                                            class="campaign-severity ${severityClass}"
                                        >

                                            ${escapeHTML(
                                                severity
                                            )}

                                        </span>

                                    </div>


                                    <p class="campaign-description">

                                        ${escapeHTML(
                                            campaign.description ||
                                            "No campaign description available."
                                        )}

                                    </p>


                                    <div class="campaign-stats">

                                        <div>

                                            <span>
                                                EMAILS
                                            </span>

                                            <strong>
                                                ${Number(
                                                    campaign.email_count ||
                                                    0
                                                )}
                                            </strong>

                                        </div>


                                        <div>

                                            <span>
                                                INDICATORS
                                            </span>

                                            <strong>
                                                ${Number(
                                                    campaign.indicator_count ||
                                                    0
                                                )}
                                            </strong>

                                        </div>


                                        <div>

                                            <span>
                                                SCORE
                                            </span>

                                            <strong>
                                                ${Number(
                                                    campaign.threat_score ||
                                                    0
                                                )}
                                                /100
                                            </strong>

                                        </div>

                                    </div>


                                    <div class="campaign-card-footer">

                                        <span class="status active">

                                            ${escapeHTML(
                                                campaign.status ||
                                                "ACTIVE"
                                            )}

                                        </span>


                                        <span class="campaign-date">

                                            ${escapeHTML(
                                                campaign.created_at ||
                                                "Unknown"
                                            )}

                                        </span>

                                    </div>

                                </article>

                            `;



                        }
                    ).join("")}

                </div>

            `;

                /* ==============================
            CAMPAIGN CARD CLICK
            ============================== */

            /* ==============================
        CAMPAIGN CARD CLICK
        ============================== */

        document
            .querySelectorAll(".campaign-card")
            .forEach(card => {

                card.addEventListener(
                    "click",
                    async () => {

                        const campaignId =
                            card.dataset.campaignId;


                        if (!campaignId) {

                            console.warn(
                                "Campaign ID not found."
                            );

                            return;

                        }


                        console.log(
                            "🔥 Opening campaign detail:",
                            campaignId
                        );


                        await openCampaignDetail(
                            campaignId
                        );

                    }
                );

            });

        }

        /* =========================================
        CAMPAIGN DETAIL
        ========================================= */

        async function openCampaignDetail(
            campaignId
        ) {

            console.log(
                "🔥 Opening campaign:",
                campaignId
            );


            try {

                const response =
                    await fetch(
                        `http://127.0.0.1:8000/api/campaigns/${encodeURIComponent(
                            campaignId
                        )}`
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load campaign."
                    );

                }


                console.log(
                    "🔥 CAMPAIGN DETAIL:",
                    data
                );


                renderCampaignDetail(
                    data.campaign
                );


            } catch (error) {

                console.error(
                    "Campaign Detail Error:",
                    error
                );


                showNotification(
                    error.message ||
                    "Unable to load campaign.",
                    "warning"
                );

            }

        }

        /* =========================================
        RENDER CAMPAIGN DETAIL
        ========================================= */

        function renderCampaignDetail(
            campaign
        ) {

            const page =
                document.querySelector(".page");


            if (!page || !campaign) {
                return;
            }


            /* ==============================
            CLEAN OLD PAGES
            ============================== */

            cleanupDynamicPages();


            /* ==============================
            HIDE DASHBOARD
            ============================== */

            const dashboard =
                document.querySelector(
                    ".dashboard-content"
                );

            if (dashboard) {
                dashboard.style.setProperty("display", "none", "important");
            }


            /* ==============================
            REMOVE EXISTING DETAIL PAGE
            ============================== */

            const oldDetail =
                document.getElementById(
                    "campaignDetailPage"
                );

            if (oldDetail) {
                oldDetail.remove();
            }


            const investigations =
                campaign.investigations || [];


            const severity =
                String(
                    campaign.severity ||
                    "UNKNOWN"
                ).toUpperCase();


            let severityClass =
                "medium";


            if (severity === "CRITICAL") {

                severityClass =
                    "critical";

            }
            else if (severity === "HIGH") {

                severityClass =
                    "high";

            }
            else if (severity === "LOW") {

                severityClass =
                    "low";

            }


            const container =
                document.createElement(
                    "section"
                );


            container.id =
                "campaignDetailPage";


            container.className =
                "campaign-detail-page";


            container.innerHTML = `

                <div class="investigations-header">

                    <div>

                        <div class="eyebrow">
                            CAMPAIGN INTELLIGENCE
                        </div>

                        <h2>
                            ${escapeHTML(
                                campaign.name ||
                                "Unknown Campaign"
                            )}
                        </h2>

                        <p>
                            ${escapeHTML(
                                campaign.campaign_id ||
                                ""
                            )}
                        </p>

                    </div>


                    <button
                        class="secondary-result-btn"
                        id="backToCampaigns"
                    >
                        ← Back to Campaigns
                    </button>

                </div>


                <div class="campaign-detail-summary">

                    <div class="campaign-detail-stat">

                        <span>
                            SEVERITY
                        </span>

                        <strong
                            class="campaign-severity ${severityClass}"
                        >
                            ${escapeHTML(
                                severity
                            )}
                        </strong>

                    </div>


                    <div class="campaign-detail-stat">

                        <span>
                            STATUS
                        </span>

                        <strong>
                            ${escapeHTML(
                                campaign.status ||
                                "ACTIVE"
                            )}
                        </strong>

                    </div>


                    <div class="campaign-detail-stat">

                        <span>
                            EMAILS
                        </span>

                        <strong>
                            ${Number(
                                campaign.email_count ||
                                0
                            )}
                        </strong>

                    </div>


                    <div class="campaign-detail-stat">

                        <span>
                            MAX THREAT SCORE
                        </span>

                        <strong>
                            ${Number(
                                campaign.threat_score ||
                                0
                            )}
                            /100
                        </strong>

                    </div>

                </div>


                <div class="result-card campaign-evidence-card">

                    <div class="result-card-title">
                        CORRELATION EVIDENCE
                    </div>

                    <p>
                        ${escapeHTML(
                            campaign.correlation_reason ||
                            campaign.description ||
                            "No correlation explanation available."
                        )}
                    </p>

                    ${
                        Array.isArray(campaign.shared_indicators) &&
                        campaign.shared_indicators.length
                        ? `<div class="campaign-shared-indicators">
                            ${campaign.shared_indicators.map(indicator => `
                                <span class="campaign-shared-indicator">
                                    <strong>${escapeHTML(indicator.value || "Unknown indicator")}</strong>
                                    <small>${escapeHTML(indicator.type || "IOC")}</small>
                                </span>
                            `).join("")}
                        </div>`
                        : ""
                    }

                </div>


                <div class="result-card">

                    <div class="result-card-title">
                        RELATED INVESTIGATIONS
                    </div>


                    <div
                        id="campaignInvestigations"
                        class="campaign-investigations"
                    >

                        ${
                            investigations.length
                            ? investigations.map(
                                investigation => `

                                    <div
                                        class="campaign-investigation-row"
                                        data-investigation-id="${escapeHTML(
                                            investigation.investigation_id ||
                                            ""
                                        )}"
                                    >

                                        <div>

                                            <strong>
                                                ${escapeHTML(
                                                    investigation.subject ||
                                                    "No Subject"
                                                )}
                                            </strong>

                                            <small>
                                                ${escapeHTML(
                                                    investigation.sender ||
                                                    "Unknown Sender"
                                                )}
                                            </small>

                                        </div>


                                        <div>

                                            <span class="mono">
                                                ${escapeHTML(
                                                    investigation.investigation_id ||
                                                    ""
                                                )}
                                            </span>

                                        </div>


                                        <div>

                                            <strong>
                                                ${Number(
                                                    investigation.threat_score ||
                                                    0
                                                )}
                                                /100
                                            </strong>

                                        </div>


                                        <div>

                                            <span
                                                class="investigation-threat ${getThreatClass(
                                                    investigation.threat_verdict
                                                )}"
                                            >
                                                ${escapeHTML(
                                                    investigation.threat_verdict ||
                                                    "UNKNOWN"
                                                )}
                                            </span>

                                        </div>

                                    </div>

                                `
                            ).join("")
                            :
                            `
                                <div class="investigations-empty">
                                    No related investigations found.
                                </div>
                            `
                        }

                    </div>

                </div>

            `;


            page.prepend(
                container
            );


            /* ==============================
            BACK BUTTON
            ============================== */

            document
            .getElementById(
                "backToCampaigns"
            )
            .addEventListener(
                "click",
                async () => {

                    container.remove();

                    await loadCampaigns();

                }
            );


            /* ==============================
            INVESTIGATION CLICK
            ============================== */

            document
                .querySelectorAll(
                    ".campaign-investigation-row"
                )
                .forEach(row => {

                    row.addEventListener(
                        "click",
                        async () => {

                            const id =
                                row.dataset
                                    .investigationId;


                            if (!id) {
                                return;
                            }


                            await openInvestigation(
                                id
                            );

                        }
                    );

                });

        }

        /* =========================================
        RENDER CASES
        ========================================= */

        /* =========================================
        RENDER CASES
        ========================================= */

        function renderCases(cases, queueSummary = {}) {

            const content =
                document.getElementById(
                    "casesContent"
                );

            if (!content) {
                console.error(
                    "Cases content container not found."
                );
                return;
            }


            /* =====================================
            STATE
            ===================================== */

            let filteredCases = [...cases];


            /* =====================================
            RENDER TABLE
            ===================================== */

            function renderTable() {

                /* ==============================
                SEARCH
                ============================== */

                const searchInput =
                    document.getElementById(
                        "caseSearch"
                    );

                const searchTerm =
                    searchInput
                        ? searchInput.value
                            .trim()
                            .toLowerCase()
                        : "";


                /* ==============================
                THREAT FILTER
                ============================== */

                const threatFilter =
                    document.getElementById(
                        "caseThreatFilter"
                    );

                const selectedThreat =
                    threatFilter
                        ? threatFilter.value.toUpperCase()
                        : "ALL";


                /* ==============================
                STATUS FILTER
                ============================== */

                const statusFilter =
                    document.getElementById(
                        "caseStatusFilter"
                    );

                const selectedStatus =
                    statusFilter
                        ? statusFilter.value.toUpperCase()
                        : "ALL";


                /* ==============================
                SORT
                ============================== */

                const sortSelect =
                    document.getElementById(
                        "caseSort"
                    );

                const selectedSort =
                    sortSelect
                        ? sortSelect.value
                        : "newest";


                /* ==============================
                FILTER DATA
                ============================== */

                filteredCases =
                    cases.filter(caseItem => {

                        const caseId =
                            String(
                                caseItem.case_id || ""
                            ).toLowerCase();


                        const investigationId =
                            String(
                                caseItem.investigation_id || ""
                            ).toLowerCase();


                        const subject =
                            String(
                                caseItem.subject || caseItem.title || ""
                            ).toLowerCase();


                        const sender =
                            String(
                                caseItem.sender || [caseItem.region_key, caseItem.team_key].filter(Boolean).join(" ") || ""
                            ).toLowerCase();


                        const verdict =
                            String(
                                caseItem.severity || caseItem.threat_verdict || ""
                            ).toUpperCase();


                        const status =
                            String(
                                caseItem.case_status || caseItem.status || "OPEN"
                            ).toUpperCase();


                        /* SEARCH MATCH */

                        const matchesSearch =
                            !searchTerm ||
                            caseId.includes(searchTerm) ||
                            investigationId.includes(searchTerm) ||
                            subject.includes(searchTerm) ||
                            sender.includes(searchTerm);


                        /* THREAT MATCH */

                        const matchesThreat =
                            selectedThreat === "ALL" ||
                            verdict === selectedThreat;


                        /* STATUS MATCH */

                        const matchesStatus =
                            selectedStatus === "ALL" ||
                            status === selectedStatus;


                        return (
                            matchesSearch &&
                            matchesThreat &&
                            matchesStatus
                        );

                    });


                /* =================================
                SORT DATA
                ================================= */

                filteredCases.sort(
                    (a, b) => {

                        /* HIGH SCORE */

                        if (
                            selectedSort === "highest"
                        ) {

                            return (
                                Number(
                                    b.threat_score || 0
                                ) -
                                Number(
                                    a.threat_score || 0
                                )
                            );

                        }


                        /* LOW SCORE */

                        if (
                            selectedSort === "lowest"
                        ) {

                            return (
                                Number(
                                    a.threat_score || 0
                                ) -
                                Number(
                                    b.threat_score || 0
                                )
                            );

                        }


                        /* OLDEST */

                        if (
                            selectedSort === "oldest"
                        ) {

                            return (
                                new Date(
                                    a.created_at || 0
                                ) -
                                new Date(
                                    b.created_at || 0
                                )
                            );

                        }


                        /* DEFAULT = NEWEST */

                        return (
                            new Date(
                                b.created_at || 0
                            ) -
                            new Date(
                                a.created_at || 0
                            )
                        );

                    }
                );


                /* =================================
                COUNT
                ================================= */

                const count =
                    filteredCases.length;


                /* =================================
                NO RESULTS
                ================================= */

                if (!count) {

                    content.innerHTML = `

                        <div class="cases-toolbar">

                            <div class="case-search">

                                <input
                                    type="text"
                                    id="caseSearch"
                                    placeholder="Search case ID, investigation ID, subject, sender..."
                                    value="${escapeHTML(
                                        searchTerm
                                    )}"
                                >

                            </div>


                            <select
                                id="caseThreatFilter"
                                class="select-control"
                            >

                                <option value="ALL">
                                    All Threats
                                </option>

                                <option value="CRITICAL">
                                    Critical
                                </option>

                                <option value="HIGH">
                                    High
                                </option>

                                <option value="MEDIUM">
                                    Medium
                                </option>

                                <option value="LOW RISK">
                                    Low Risk
                                </option>

                            </select>


                            <select
                                id="caseStatusFilter"
                                class="select-control"
                            >

                                <option value="ALL">
                                    All Status
                                </option>

                                <option value="OPEN">
                                    Open
                                </option>

                                <option value="CLOSED">
                                    Closed
                                </option>

                            </select>


                            <select
                                id="caseSort"
                                class="select-control"
                            >

                                <option value="newest">
                                    Newest First
                                </option>

                                <option value="oldest">
                                    Oldest First
                                </option>

                                <option value="highest">
                                    Highest Score
                                </option>

                                <option value="lowest">
                                    Lowest Score
                                </option>

                            </select>

                        </div>


                        <div class="soc-queue-summary">
                        <span><strong>${Number(queueSummary.count || 0)}</strong> active cases</span>
                        <span><strong>${Number(queueSummary.unassigned_count || 0)}</strong> unassigned</span>
                        <span class="${Number(queueSummary.overdue_count || 0) ? "soc-sla-overdue" : ""}"><strong>${Number(queueSummary.overdue_count || 0)}</strong> overdue</span>
                        <span><strong>${Number(queueSummary.escalations_created || 0)}</strong> escalations this refresh</span>
                    </div>

                    <div class="investigations-count">

                            0 cases found

                        </div>


                        <div class="investigations-empty">

                            No SOC cases match these filters or are currently queued.

                        </div>

                    `;


                    attachCaseFilters();

                    return;

                }


                /* =================================
                TABLE
                ================================= */

                content.innerHTML = `

                    <div class="cases-toolbar">

                        <div class="case-search">

                            <input
                                type="text"
                                id="caseSearch"
                                placeholder="Search case ID, investigation ID, subject, sender..."
                                value="${escapeHTML(
                                    searchTerm
                                )}"
                            >

                        </div>


                        <select
                            id="caseThreatFilter"
                            class="select-control"
                        >

                            <option
                                value="ALL"
                                ${selectedThreat === "ALL"
                                    ? "selected"
                                    : ""}
                            >
                                All Threats
                            </option>

                            <option
                                value="CRITICAL"
                                ${selectedThreat === "CRITICAL"
                                    ? "selected"
                                    : ""}
                            >
                                Critical
                            </option>

                            <option
                                value="HIGH"
                                ${selectedThreat === "HIGH"
                                    ? "selected"
                                    : ""}
                            >
                                High
                            </option>

                            <option
                                value="MEDIUM"
                                ${selectedThreat === "MEDIUM"
                                    ? "selected"
                                    : ""}
                            >
                                Medium
                            </option>

                            <option
                                value="LOW RISK"
                                ${selectedThreat === "LOW RISK"
                                    ? "selected"
                                    : ""}
                            >
                                Low Risk
                            </option>

                        </select>


                        <select
                            id="caseStatusFilter"
                            class="select-control"
                        >

                            <option
                                value="ALL"
                                ${selectedStatus === "ALL"
                                    ? "selected"
                                    : ""}
                            >
                                All Status
                            </option>

                            <option
                                value="OPEN"
                                ${selectedStatus === "OPEN"
                                    ? "selected"
                                    : ""}
                            >
                                Open
                            </option>

                            <option
                                value="CLOSED"
                                ${selectedStatus === "CLOSED"
                                    ? "selected"
                                    : ""}
                            >
                                Closed
                            </option>

                        </select>


                        <select
                            id="caseSort"
                            class="select-control"
                        >

                            <option
                                value="newest"
                                ${selectedSort === "newest"
                                    ? "selected"
                                    : ""}
                            >
                                Newest First
                            </option>

                            <option
                                value="oldest"
                                ${selectedSort === "oldest"
                                    ? "selected"
                                    : ""}
                            >
                                Oldest First
                            </option>

                            <option
                                value="highest"
                                ${selectedSort === "highest"
                                    ? "selected"
                                    : ""}
                            >
                                Highest Score
                            </option>

                            <option
                                value="lowest"
                                ${selectedSort === "lowest"
                                    ? "selected"
                                    : ""}
                            >
                                Lowest Score
                            </option>

                        </select>

                    </div>


                    <div class="soc-queue-summary">
                        <span><strong>${Number(queueSummary.count || 0)}</strong> active cases</span>
                        <span><strong>${Number(queueSummary.unassigned_count || 0)}</strong> unassigned</span>
                        <span class="${Number(queueSummary.overdue_count || 0) ? "soc-sla-overdue" : ""}"><strong>${Number(queueSummary.overdue_count || 0)}</strong> overdue</span>
                        <span><strong>${Number(queueSummary.escalations_created || 0)}</strong> escalations this refresh</span>
                    </div>

                    <div class="investigations-count">

                        ${count}
                        case${count === 1 ? "" : "s"}

                    </div>


                    <div class="investigations-table-wrapper">

                        <table class="investigations-table">

                            <thead>
                                <tr>
                                    <th>CASE ID</th>
                                    <th>CASE</th>
                                    <th>SEVERITY</th>
                                    <th>PRIORITY</th>
                                    <th>ASSIGNEE / TEAM / REGION</th>
                                    <th>CLAIM OWNER / EXPIRY</th>
                                    <th>SLA DEADLINE</th>
                                    <th>ROUTING STATUS</th>
                                    <th>LAST ACTIVITY</th>
                                    <th>ACTIONS</th>
                                </tr>
                            </thead>


                            <tbody>

                                ${filteredCases.map(
                                    caseItem => `
                                    <tr class="case-row ${caseItem.overdue ? "soc-case-overdue" : ""}" data-case-id="${escapeHTML(caseItem.case_id || "")}">
                                        <td><button class="investigation-id-btn" type="button">${escapeHTML(caseItem.case_id || "UNKNOWN")}</button></td>
                                        <td><div class="email-cell"><strong>${escapeHTML(caseItem.title || caseItem.subject || "Untitled case")}</strong><small>${escapeHTML(caseItem.case_status || "OPEN")}</small></div></td>
                                        <td><span class="investigation-threat ${getThreatClass(caseItem.severity || "LOW")}">${escapeHTML(caseItem.severity || "LOW")}</span><small>${Number(caseItem.threat_score || 0)}/100</small></td>
                                        <td><span class="soc-priority soc-priority-${escapeHTML(String(caseItem.priority || "P3").toLowerCase())}">${escapeHTML(caseItem.priority || "P3")}</span></td>
                                        <td><strong>${escapeHTML(caseItem.assigned_analyst || "Unassigned")}</strong><small>${escapeHTML([caseItem.team_key, caseItem.region_key].filter(Boolean).join(" / ") || "Central queue")}</small></td>
                                        <td><strong>${escapeHTML(caseItem.claim_owner || "Unclaimed")}</strong><small>${caseItem.claim_expired ? "CLAIM EXPIRED" : caseItem.claim_expires_at ? `Expires ${escapeHTML(caseItem.claim_expires_at)}` : "No active claim"}</small></td>
                                        <td><strong class="${caseItem.overdue ? "soc-sla-overdue" : ""}">${escapeHTML(caseItem.sla_deadline || "Not set")}</strong><small>${caseItem.overdue ? "SLA OVERDUE" : "Within SLA"}</small></td>
                                        <td><span class="soc-routing-status">${escapeHTML(caseItem.routing_status || "QUEUED")}</span>${caseItem.routing_reason && !caseItem.assigned_analyst ? `<small>${escapeHTML(caseItem.routing_reason)}</small>` : ""}</td>
                                        <td>${escapeHTML(caseItem.last_activity_at || caseItem.updated_at || caseItem.created_at || "Unknown")}</td>
                                        <td>${window.mailtraceAuth?.hasRole(["soc_lead", "tenant_admin", "platform_admin", "admin"]) ? '<button class="soc-reassign-btn" type="button">Reassign</button>' : '<span>Lead only</span>'}</td>
                                    </tr>
                                `                                ).join("")}

                            </tbody>

                        </table>

                    </div>

                `;


                /* =================================
    CASE ROW CLICK
    ================================= */

    document
        .querySelectorAll(".case-row")
        .forEach(row => {

            row.querySelector(".soc-reassign-btn")?.addEventListener("click", async event => {
                event.stopPropagation();
                const button = event.currentTarget;
                const caseId = row.dataset.caseId;
                if (!caseId) return;
                button.disabled = true;
                try {
                    const rosterResponse = await fetch("http://127.0.0.1:8000/api/soc/routing/analysts");
                    const rosterPayload = await rosterResponse.json().catch(() => ({}));
                    if (!rosterResponse.ok) throw new Error(rosterPayload.detail || "Unable to load the authorized analyst roster.");
                    const activeAnalysts = (rosterPayload.analysts || []).filter(item => item.active);
                    if (!activeAnalysts.length) throw new Error("No active analysts are configured for this tenant.");
                    const rosterText = activeAnalysts.map(item => `${item.subject_id} - ${item.availability}, ${item.region_key}/${item.team_key || "general"}, load ${item.open_load}/${item.max_open_cases}`).join("\n");
                    const analystSubject = (window.prompt(`Reassign case ${caseId} to an active analyst subject ID:\n\n${rosterText}`) || "").trim();
                    if (!analystSubject) return;
                    const reason = (window.prompt("Required audit reason for manual reassignment:", "SLA/workload balancing") || "").trim();
                    if (reason.length < 5) throw new Error("A reassignment reason of at least 5 characters is required.");
                    const response = await fetch(`http://127.0.0.1:8000/api/soc/routing/cases/${encodeURIComponent(caseId)}/assign`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ analyst_subject: analystSubject, reason })
                    });
                    const result = await response.json().catch(() => ({}));
                    if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "Manual reassignment was rejected by the server.");
                    await loadCases();
                } catch (error) {
                    alert(error.message || "Unable to reassign this case.");
                } finally {
                    button.disabled = false;
                }
            });

            row.addEventListener(
                "click",
                async () => {

                    const caseId =
                        row.dataset.caseId;

                    if (!caseId) {

                        console.error(
                            "Case ID missing from row."
                        );

                        return;

                    }

                    console.log(
                        "Opening case:",
                        caseId
                    );

                    await openCase(
                        caseId
                    );

                }
            );

        });


    /* =================================
    FILTER EVENTS
                ================================= */

                attachCaseFilters();

            }


            /* =====================================
            ATTACH FILTER EVENTS
            ===================================== */

            function attachCaseFilters() {

                const searchInput =
                    document.getElementById(
                        "caseSearch"
                    );


                const threatFilter =
                    document.getElementById(
                        "caseThreatFilter"
                    );


                const statusFilter =
                    document.getElementById(
                        "caseStatusFilter"
                    );


                const sortSelect =
                    document.getElementById(
                        "caseSort"
                    );


                if (searchInput) {

                    searchInput.addEventListener(
                        "input",
                        renderTable
                    );

                }


                if (threatFilter) {

                    threatFilter.addEventListener(
                        "change",
                        renderTable
                    );

                }


                if (statusFilter) {

                    statusFilter.addEventListener(
                        "change",
                        renderTable
                    );

                }


                if (sortSelect) {

                    sortSelect.addEventListener(
                        "change",
                        renderTable
                    );

                }

            }


            /* =====================================
            INITIAL RENDER
            ===================================== */

            renderTable();

        }

        /* =========================================
        CASE DETAIL
        ========================================= */

        async function openCase(caseId) {

            console.log(
                "Opening case:",
                caseId
            );

            if (!caseId) {
                alert("Invalid case ID.");
                return;
            }

            try {

                const response = await fetch(
                    `http://127.0.0.1:8000/api/cases/${encodeURIComponent(caseId)}`
                );

                const data = await response.json();

                if (!response.ok) {

                    throw new Error(
                        data.detail ||
                        "Failed to load case."
                    );

                }

                if (!data.case) {

                    throw new Error(
                        "Case data is missing."
                    );

                }

                let routing = null;
                try {
                    const routingResponse = await fetch(
                        `http://127.0.0.1:8000/api/soc/routing/cases/${encodeURIComponent(caseId)}`
                    );
                    if (routingResponse.ok) {
                        const routingPayload = await routingResponse.json();
                        routing = routingPayload.routing || null;
                    }
                } catch (_) {
                    // Routing may be pending reconciliation; the case remains viewable to its tenant.
                }

                renderCaseDetail({
                    ...data.case,
                    routing,
                    investigations: data.investigations || [],
                    notes: data.notes || [],
                    evidence: data.evidence || []
                });

            } catch (error) {

                console.error(
                    "Case Detail Error:",
                    error
                );

                alert(
                    error.message ||
                    "Unable to load case."
                );

            }

        }


        function renderCaseDetail(caseData) {

            cleanupDynamicPages();

            const page =
                document.querySelector(".page");

            if (!page) {
                console.error(
                    "Page container not found."
                );
                return;
            }

            const investigations =
                Array.isArray(
                    caseData.investigations
                )
                    ? caseData.investigations
                    : [];

            const notes =
                Array.isArray(
                    caseData.notes
                )
                    ? caseData.notes
                    : [];

            const evidence =
                Array.isArray(
                    caseData.evidence
                )
                    ? caseData.evidence
                    : [];

            const score =
                Number(
                    caseData.threat_score || 0
                );

            const severity =
                String(
                    caseData.severity || "LOW"
                ).toUpperCase();

            const status =
                String(
                    caseData.status || "OPEN"
                ).toUpperCase();
            const assignmentExpired = Boolean(caseData.claim_expired);
            const assignmentActive = caseData.assignment_status === "ACTIVE" && !assignmentExpired;
            const assignmentMine = Boolean(caseData.assignment_mine) && assignmentActive;
            const assignmentOwner = caseData.assigned_analyst || "Unclaimed";
            const routing = caseData.routing || {};
            const routingPriority = routing.priority || "Not routed";
            const routingStatus = routing.status || "Not routed";


            const detail =
                document.createElement("div");

            detail.id =
                "caseDetailPage";

            detail.className =
                "case-detail-page";


            detail.innerHTML = `

                <div class="case-detail-header">

                    <div>

                        <button
                            type="button"
                            id="backToCasesBtn"
                            class="case-detail-back-btn"
                        >
                            &larr; Back to Cases
                        </button>

                        <div class="case-detail-kicker">
                            CASE MANAGEMENT
                        </div>

                        <h1>
                            ${escapeHTML(
                                caseData.title ||
                                caseData.case_id ||
                                "Untitled Case"
                            )}
                        </h1>

                        <p>
                            ${escapeHTML(
                                caseData.description ||
                                "No description available."
                            )}
                        </p>

                    </div>


                    <div class="case-detail-meta">

                        <span class="case-detail-id">
                            ${escapeHTML(
                                caseData.case_id ||
                                "UNKNOWN"
                            )}
                        </span>

                        <span>
                            ${escapeHTML(
                                severity
                            )}
                        </span>

                    </div>

                </div>


                <div class="case-detail-stats">

                    <div class="case-detail-stat">
                        <span>THREAT SCORE</span>
                        <strong>
                            ${escapeHTML(
                                String(score)
                            )} / 100
                        </strong>
                    </div>


                    <div class="case-detail-stat">
                        <span>STATUS</span>
                        <strong>
                            ${escapeHTML(status)}
                        </strong>
                    </div>


                    <div class="case-detail-stat">
                        <span>INVESTIGATIONS</span>
                        <strong>
                            ${investigations.length}
                        </strong>
                    </div>


                    <div class="case-detail-stat">
                        <span>EVIDENCE</span>
                        <strong>
                            ${evidence.length}
                        </strong>
                    </div>

                </div>


                <section class="case-claim-controls" aria-label="Case ownership">
                    <div>
                        <span class="case-claim-label">CLAIM OWNER (LEASE)</span>
                        <strong>${escapeHTML(assignmentOwner)}</strong>
                        <small>${assignmentExpired ? `Claim expired ${escapeHTML(caseData.lease_expires_at || "recently")} - safe reclaim available` : assignmentActive ? `Claim expires ${escapeHTML(caseData.lease_expires_at || "soon")}` : "No active claim lease"}</small>
                    </div>
                    <div class="case-claim-actions">
                        <button type="button" id="caseClaimToggle" ${assignmentActive && !assignmentMine ? "disabled" : ""}>${assignmentMine ? "Release case" : assignmentActive ? "Claim held" : assignmentExpired ? "Reclaim expired claim" : "Claim case"}</button>
                        ${assignmentMine ? `<button type="button" id="caseClaimRenew">Renew lease</button>` : ""}
                        <button type="button" id="caseClaimHistoryBtn">Assignment history</button>
                    </div>
                </section>

                <section class="result-card body-card soc-case-routing-meta">
                    <div class="result-card-title">SOC ROUTING & SLA</div>
                    <div class="case-detail-fields">
                        <div><span>QUEUE / REGION</span><strong>${escapeHTML(routing.queue_id || "Pending route")} / ${escapeHTML(routing.region_key || "Unknown")}</strong></div>
                        <div><span>TEAM / ROUTING ASSIGNEE</span><strong>${escapeHTML([routing.team_key, routing.assigned_analyst || "Unassigned"].filter(Boolean).join(" / "))}</strong><small>Separate from the claim owner above; queued cases can remain unassigned until an eligible analyst is configured.</small></div>
                        <div><span>PRIORITY / STATUS</span><strong>${escapeHTML(routingPriority)} / ${escapeHTML(routingStatus)}</strong></div>
                        <div><span>SLA DEADLINE</span><strong class="${routing.sla_deadline && new Date(routing.sla_deadline).getTime() < Date.now() ? "soc-sla-overdue" : ""}">${escapeHTML(routing.sla_deadline || "Not set")}</strong></div>
                    </div>
                </section>
                <section id="caseAssignmentHistory" class="result-card body-card soc-assignment-history" hidden>
                    <div class="result-card-title">CLAIM & ROUTING AUDIT HISTORY</div>
                    <div class="case-empty-state">Click Assignment history to load the tenant-scoped audit trail.</div>
                </section>


                <div class="case-detail-grid">


                    <section class="result-card body-card">

                        <div class="result-card-title">
                            CASE OVERVIEW
                        </div>

                        <div class="case-detail-fields">

                            <div>
                                <span>CASE ID</span>
                                <strong>
                                    ${escapeHTML(
                                        caseData.case_id ||
                                        "UNKNOWN"
                                    )}
                                </strong>
                            </div>

                            <div>
                                <span>CREATED</span>
                                <strong>
                                    ${escapeHTML(
                                        caseData.created_at ||
                                        "Unknown"
                                    )}
                                </strong>
                            </div>

                            <div>
                                <span>UPDATED</span>
                                <strong>
                                    ${escapeHTML(
                                        caseData.updated_at ||
                                        "Unknown"
                                    )}
                                </strong>
                            </div>

                            <div>
                                <span>STATUS</span>
                                <strong>
                                    ${escapeHTML(status)}
                                </strong>
                            </div>

                        </div>

                    </section>


                    <section class="result-card body-card">

                        <div class="result-card-title">
                            INVESTIGATIONS
                        </div>

                        ${
                            investigations.length
                                ? investigations.map(
                                    investigation => `

                                        <button
                                            type="button"
                                            class="case-investigation-btn"
                                            data-investigation-id="${escapeHTML(
                                                investigation.investigation_id ||
                                                ""
                                            )}"
                                        >

                                            <span>
                                                ${escapeHTML(
                                                    investigation.subject ||
                                                    investigation.investigation_id ||
                                                    "Investigation"
                                                )}
                                            </span>

                                            <strong>
                                                ${escapeHTML(
                                                    String(
                                                        investigation.threat_score ??
                                                        0
                                                    )
                                                )}
                                            </strong>

                                        </button>

                                    `
                                ).join("")
                                : `
                                    <div class="case-empty-state">
                                        No investigations attached.
                                    </div>
                                `
                        }

                    </section>


                    <section class="result-card body-card">

                        <div class="result-card-title">
                            EVIDENCE
                        </div>

                        ${
                            evidence.length
                                ? evidence.map(
                                    item => `

                                        <div class="case-evidence-item">

                                            <strong>
                                                ${escapeHTML(
                                                    item.evidence_type ||
                                                    "Evidence"
                                                )}
                                            </strong>

                                            <p>
                                                ${escapeHTML(
                                                    item.description ||
                                                    ""
                                                )}
                                            </p>

                                            <code>
                                                ${escapeHTML(
                                                    item.value ||
                                                    ""
                                                )}
                                            </code>

                                        </div>

                                    `
                                ).join("")
                                : `
                                    <div class="case-empty-state">
                                        No evidence recorded.
                                    </div>
                                `
                        }

                    </section>


                    <section class="result-card body-card">

                        <div class="result-card-title">
                            ANALYST NOTES
                        </div>

                        ${
                            notes.length
                                ? notes.map(
                                    note => `

                                        <div class="case-note-item">

                                            <p>
                                                ${escapeHTML(
                                                    note.note ||
                                                    ""
                                                )}
                                            </p>

                                            <span>
                                                ${escapeHTML(
                                                    note.author ||
                                                    "Analyst"
                                                )}
                                                ·
                                                ${escapeHTML(
                                                    note.created_at ||
                                                    ""
                                                )}
                                            </span>

                                        </div>

                                    `
                                ).join("")
                                : `
                                    <div class="case-empty-state">
                                        No analyst notes recorded.
                                    </div>
                                `
                        }

                    </section>


                </div>

            `;


            page.appendChild(detail);

            detail.querySelector("#caseClaimToggle")?.addEventListener("click", async event => {
                const button = event.currentTarget;
                if (button.disabled) return;
                button.disabled = true;
                const action = assignmentMine ? "release" : "claim";
                const reason = action === "release"
                    ? (window.prompt("Reason for releasing this case claim:", "handoff to SOC queue") || "").trim()
                    : "claim requested from case detail";
                if (action === "release" && !reason) { button.disabled = false; return; }
                try {
                    const response = await fetch(
                        `http://127.0.0.1:8000/api/cases/${encodeURIComponent(caseData.case_id)}/${action}`,
                        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason }) }
                    );
                    const payload = await response.json().catch(() => ({}));
                    if (!response.ok) {
                        const detailMessage = typeof payload.detail === "string"
                            ? payload.detail
                            : payload.detail?.message || (payload.detail?.assignment?.assigned_analyst
                                ? `Current owner: ${payload.detail.assignment.assigned_analyst}`
                                : "Unable to update case ownership.");
                        throw new Error(detailMessage);
                    }
                    await openCase(caseData.case_id);
                } catch (error) {
                    button.disabled = false;
                    alert(error.message || "Unable to update case ownership.");
                }
            });

            detail.querySelector("#caseClaimRenew")?.addEventListener("click", async event => {
                const button = event.currentTarget;
                button.disabled = true;
                try {
                    const response = await fetch(
                        `http://127.0.0.1:8000/api/cases/${encodeURIComponent(caseData.case_id)}/renew`,
                        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: "owner renewal from case detail" }) }
                    );
                    const payload = await response.json().catch(() => ({}));
                    if (!response.ok) {
                        const message = typeof payload.detail === "string" ? payload.detail : payload.detail?.message || "Claim renewal failed; another analyst may own the case.";
                        throw new Error(message);
                    }
                    await openCase(caseData.case_id);
                } catch (error) {
                    button.disabled = false;
                    alert(error.message || "Unable to renew the claim.");
                }
            });

            detail.querySelector("#caseClaimHistoryBtn")?.addEventListener("click", async event => {
                const button = event.currentTarget;
                const panel = detail.querySelector("#caseAssignmentHistory");
                if (!panel) return;
                button.disabled = true;
                panel.hidden = false;
                panel.querySelector(".result-card-title + .case-empty-state")?.replaceChildren(document.createTextNode("Loading audit history?"));
                try {
                    const base = `http://127.0.0.1:8000`;
                    const [claimResponse, routingResponse] = await Promise.all([
                        fetch(`${base}/api/cases/${encodeURIComponent(caseData.case_id)}/history`),
                        fetch(`${base}/api/soc/routing/cases/${encodeURIComponent(caseData.case_id)}/history`)
                    ]);
                    const claimPayload = claimResponse.ok ? await claimResponse.json() : { events: [] };
                    const routingPayload = routingResponse.ok ? await routingResponse.json() : { events: [] };
                    const events = [
                        ...(claimPayload.events || []).map(item => ({ ...item, audit_type: "CLAIM" })),
                        ...(routingPayload.events || []).map(item => ({ ...item, audit_type: "ROUTING" }))
                    ].sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")));
                    panel.innerHTML = `<div class="result-card-title">CLAIM & ROUTING AUDIT HISTORY</div>` + (events.length
                        ? `<div class="soc-audit-list">${events.map(item => { let details = {}; try { details = JSON.parse(item.details_json || "{}"); } catch (_) {} return `<div class="soc-audit-item"><strong>${escapeHTML(item.action || "EVENT")} | ${escapeHTML(item.audit_type)}</strong><span>${escapeHTML(item.created_at || "")}</span><small>Actor: ${escapeHTML(item.actor_subject || "system")} | Reason: ${escapeHTML(details.reason || item.reason || "not recorded")}</small></div>`; }).join("")}</div>`
                        : `<div class="case-empty-state">No assignment audit events recorded yet.</div>`);
                } catch (error) {
                    panel.innerHTML = `<div class="result-card-title">CLAIM & ROUTING AUDIT HISTORY</div><div class="case-empty-state">${escapeHTML(error.message || "Unable to load assignment history.")}</div>`;
                } finally {
                    button.disabled = false;
                }
            });


            const backButton =
                document.getElementById(
                    "backToCasesBtn"
                );

            if (backButton) {

                backButton.addEventListener(
                    "click",
                    async () => {

                        detail.remove();

                        await loadCases();

                    }
                );

            }


            document
                .querySelectorAll(
                    ".case-investigation-btn"
                )
                .forEach(button => {

                    button.addEventListener(
                        "click",
                        async event => {

                            event.stopPropagation();

                            const investigationId =
                                button.dataset
                                    .investigationId;

                            if (investigationId) {

                                await openInvestigation(
                                    investigationId
                                );

                            }

                        }
                    );

                });

        }



        /* =========================================
        IP INTELLIGENCE MODULE
        ========================================= */

        async function loadIPIntelligence() {

            console.log("🔥 Loading IP Intelligence...");

            const page =
                document.querySelector(".page");

            if (!page) {

                console.error(
                    "Page container not found."
                );

                return;
            }


            /* ==============================
            CLEAN OLD DYNAMIC PAGES
            ============================== */

            cleanupDynamicPages();


            /* ==============================
            HIDE DASHBOARD
            ============================== */

            const dashboard =
                document.querySelector(
                    ".dashboard-content"
                );

            if (dashboard) {

                dashboard.style.setProperty(
                    "display",
                    "none",
                    "important"
                );

            }


            /* ==============================
            CREATE IP INTELLIGENCE PAGE
            ============================== */

            const container =
                document.createElement(
                    "section"
                );

            container.id =
                "ipIntelligencePage";

            container.className =
                "investigations-page";


            page.prepend(
                container
            );


            /* ==============================
            PAGE UI
            ============================== */

            container.innerHTML = `

                <div class="investigations-header">

                    <div>

                        <div class="eyebrow">
                            NETWORK INTELLIGENCE
                        </div>

                        <h2>
                            IP Intelligence
                        </h2>

                        <p>
                            Investigate IP addresses, network ownership,
                            geolocation and risk indicators.
                        </p>

                    </div>

                </div>


                <!-- ==========================
                    SEARCH
                ========================== -->

                <div class="result-card ip-search-card">

                    <div class="result-card-title">
                        IP INVESTIGATION
                    </div>


                    <div class="ip-search-wrapper">

                        <input
                            type="text"
                            id="ipAddressInput"
                            class="ip-input"
                            placeholder="Enter IP address e.g. 8.8.8.8"
                            autocomplete="off"
                        >


                        <button
                            type="button"
                            class="primary-btn"
                            id="analyzeIPButton"
                        >
                            Analyze IP
                        </button>

                    </div>


                    <div
                        id="ipAnalysisError"
                        class="ip-analysis-error"
                        style="display:none;"
                    ></div>

                </div>


                <!-- ==========================
                    RESULTS
                ========================== -->

                <div
                    id="ipIntelligenceResults"
                >

                    <div class="result-card">

                        <div class="investigations-loading">
                            Enter an IP address to begin analysis.
                        </div>

                    </div>

                </div>

            `;


            /* ==============================
            INPUT
            ============================== */

            const input =
                document.getElementById(
                    "ipAddressInput"
                );


            const button =
                document.getElementById(
                    "analyzeIPButton"
                );


            if (!input || !button) {
                return;
            }


            /* ==============================
            BUTTON CLICK
            ============================== */

            button.addEventListener(
                "click",
                analyzeIPAddress
            );


            /* ==============================
            ENTER KEY
            ============================== */

            input.addEventListener(
                "keydown",
                event => {

                    if (
                        event.key === "Enter"
                    ) {

                        analyzeIPAddress();

                    }

                }
            );


            input.focus();


            /* ==============================
            ANALYZE FUNCTION
            ============================== */

            async function analyzeIPAddress() {

                const ip =
                    input.value.trim();


                const errorBox =
                    document.getElementById(
                        "ipAnalysisError"
                    );


                const results =
                    document.getElementById(
                        "ipIntelligenceResults"
                    );


                if (!ip) {

                    showIPError(
                        "Please enter an IP address."
                    );

                    return;
                }


                /* ==========================
                LOADING
                ========================== */

                errorBox.style.display =
                    "none";


                results.innerHTML = `

                    <div class="result-card">

                        <div class="investigations-loading">

                            Analyzing
                            <span class="mono">
                                ${escapeHTML(ip)}
                            </span>
                            ...

                        </div>

                    </div>

                `;


                button.disabled = true;

                button.textContent =
                    "Analyzing...";


                try {

                    const response =
                        await fetch(
                            "http://127.0.0.1:8000/api/ip-intelligence",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body: JSON.stringify({
                                    ip: ip
                                })
                            }
                        );


                    const data =
                        await response.json();


                    if (!response.ok) {

                        throw new Error(
                            data.detail ||
                            "IP intelligence analysis failed."
                        );

                    }


                    console.log(
                        "🔥 IP INTELLIGENCE:",
                        data
                    );


                    renderIPIntelligence(
                        data.result
                    );


                }
                catch (error) {

                    console.error(
                        "IP Intelligence Error:",
                        error
                    );


                    showIPError(
                        error.message ||
                        "Unable to analyze IP address."
                    );

                }
                finally {

                    button.disabled = false;

                    button.textContent =
                        "Analyze IP";

                }

            }


            /* ==============================
            ERROR
            ============================== */

            function showIPError(
                message
            ) {

                const errorBox =
                    document.getElementById(
                        "ipAnalysisError"
                    );


                if (!errorBox) {
                    return;
                }


                errorBox.textContent =
                    message;


                errorBox.style.display =
                    "block";

            }

        }


        /* =========================================
        RENDER IP INTELLIGENCE
        ========================================= */

        function renderIPIntelligence(
            result
        ) {

            const container =
                document.getElementById(
                    "ipIntelligenceResults"
                );


            if (!container || !result) {
                return;
            }


            const risk =
                String(
                    result.risk ||
                    "UNKNOWN"
                ).toUpperCase();


        let riskClass = "unknown";


    if (risk === "PUBLIC") {
        riskClass = "public";
    }

    else if (risk === "INTERNAL") {
        riskClass = "internal";
    }

    else if (risk === "LOCAL") {
        riskClass = "local";
    }

    else if (risk === "DOCUMENTATION") {
        riskClass = "documentation";
    }

    else if (risk === "RESERVED") {
        riskClass = "reserved";
    }

    else if (risk === "LOW") {
        riskClass = "low";
    }

    else if (risk === "MEDIUM") {
        riskClass = "medium";
    }

    else if (risk === "HIGH") {
        riskClass = "high";
    }

    else if (risk === "CRITICAL") {
        riskClass = "critical";
    }

    else if (risk === "UNKNOWN") {
        riskClass = "unknown";
    }

            const score =
                Number(
                    result.risk_score ||
                    0
                );


            container.innerHTML = `
                <div class="ip-result-toolbar">
                    <div><span class="eyebrow">IP REPUTATION ASSESSMENT</span><strong>Investigation result</strong></div>
                    <button type="button" class="secondary-result-btn" id="ipResultViewMap">View map</button>
                </div>

                <!-- ==========================
                    SUMMARY
                ========================== -->

                <div class="ip-summary-grid">

                    <div class="ip-summary-card">

                        <span>
                            IP ADDRESS
                        </span>

                        <strong class="mono">
                            ${escapeHTML(
                                result.ip ||
                                "Unknown"
                            )}
                        </strong>

                    </div>


                    <div class="ip-summary-card">

                        <span>
                            RISK
                        </span>

                        <strong
                            class="ip-risk ${riskClass}"
                        >
                            ${escapeHTML(
                                risk
                            )}
                        </strong>

                    </div>


                    <div class="ip-summary-card">

                        <span>
                            RISK SCORE
                        </span>

                        <strong>
                            ${score}/100
                        </strong>

                    </div>


                    <div class="ip-summary-card">

                        <span>
                            IP TYPE
                        </span>

                        <strong>
                            ${escapeHTML(
                                result.type ||
                                "UNKNOWN"
                            )}
                        </strong>

                    </div>

                </div>


                <!-- ==========================
                    GEOLOCATION
                ========================== -->

                <div class="ip-intelligence-grid">

                    <div class="result-card">

                        <div class="result-card-title">
                            GEOLOCATION
                        </div>


                        <div class="ip-detail-list">

                            <div class="ip-detail-row">

                                <span>
                                    Country
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.country ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Country Code
                                </span>

                                <strong class="mono">
                                    ${escapeHTML(
                                        result.country_code ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Region
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.region ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    City
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.city ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Postal
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.postal ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Timezone
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.timezone ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>

                        </div>

                    </div>


                    <!-- ==========================
                        NETWORK
                    ========================== -->

                    <div class="result-card">

                        <div class="result-card-title">
                            NETWORK INTELLIGENCE
                        </div>


                        <div class="ip-detail-list">

                            <div class="ip-detail-row">

                                <span>
                                    Hostname
                                </span>

                                <strong class="mono">
                                    ${escapeHTML(
                                        result.hostname ||
                                        "Not found"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    ASN
                                </span>

                                <strong class="mono">
                                    ${escapeHTML(
                                        result.asn ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    ISP
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.isp ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Organization
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.organization ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Continent
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        result.continent ||
                                        "Unknown"
                                    )}
                                </strong>

                            </div>


                            <div class="ip-detail-row">

                                <span>
                                    Coordinates
                                </span>

                                <strong class="mono">

                                    ${
                                        result.latitude !== null &&
                                        result.longitude !== null

                                        ? `${escapeHTML(
                                            result.latitude
                                        )},
                                        ${escapeHTML(
                                            result.longitude
                                        )}`

                                        : "Unknown"
                                    }

                                </strong>

                            </div>

                        </div>

                    </div>

                </div>


                <!-- ==========================
                    FLAGS
                ========================== -->

                <div class="result-card ip-flags-card">

                    <div class="result-card-title">
                        NETWORK FLAGS
                    </div>


                    <div class="ip-flags">

                        <div class="ip-flag">

                            <span>
                                Private
                            </span>

                            <strong>
                                ${result.is_private ? "YES" : "NO"}
                            </strong>

                        </div>


                        <div class="ip-flag">

                            <span>
                                Loopback
                            </span>

                            <strong>
                                ${result.is_loopback ? "YES" : "NO"}
                            </strong>

                        </div>


                        <div class="ip-flag">

                            <span>
                                Reserved
                            </span>

                            <strong>
                                ${result.is_reserved ? "YES" : "NO"}
                            </strong>

                        </div>


                        <div class="ip-flag">

                            <span>
                                Proxy
                            </span>

                            <strong>
                                ${
                                    result.is_proxy === null
                                    ? "UNKNOWN"
                                    : result.is_proxy
                                        ? "YES"
                                        : "NO"
                                }
                            </strong>

                        </div>


                        <div class="ip-flag">

                            <span>
                                Hosting
                            </span>

                            <strong>
                                ${
                                    result.is_hosting === null
                                    ? "UNKNOWN"
                                    : result.is_hosting
                                        ? "YES"
                                        : "NO"
                                }
                            </strong>

                        </div>

                    </div>

                </div>


                <!-- ==========================
                    NOTES
                ========================== -->

                <div class="result-card">

                    <div class="result-card-title">
                        INTELLIGENCE NOTES
                    </div>


                    <div class="ip-notes">

                        ${
                            Array.isArray(result.notes) &&
                            result.notes.length

                            ? result.notes.map(
                                note => `

                                    <div class="ip-note">

                                        <span>
                                            ✓
                                        </span>

                                        <p>
                                            ${escapeHTML(
                                                note
                                            )}
                                        </p>

                                    </div>

                                `
                            ).join("")

                            :

                            `
                                <div class="ip-note">

                                    <span>
                                        ✓
                                    </span>

                                    <p>
                                        No additional intelligence notes.
                                    </p>

                                </div>
                            `
                        }

                    </div>

                </div>

            `;
            container.querySelector("#ipResultViewMap")?.addEventListener("click", () => openInvestigationMapView([{
                ip: result.ip, city: result.city, region: result.region, country: result.country,
                country_code: result.country_code, type: result.type, risk, risk_score: score,
                isp: result.isp || result.organization, latitude: result.latitude, longitude: result.longitude
            }]));

        }

    /* ============================================================
    MAILTRACE_FORENSIC_SIGNAL_BUILD
    Premium forensic-system startup.
    No mouse tracking.
    No drops.
    No rings.
    No grid.
    ============================================================ */

    (function MailTraceForensicStartup() {

        function launchStartup() {

            if (
                document.querySelector(
                    ".mailtrace-forensic-startup"
                )
            ) {
                return;
            }

            const boot =
                document.createElement("div");

            boot.className =
                "mailtrace-forensic-startup";

            boot.innerHTML = `

                <div class="forensic-core-glow"></div>

                <div class="forensic-network">

                    <div class="network-path path-a"></div>
                    <div class="network-path path-b"></div>
                    <div class="network-path path-c"></div>
                    <div class="network-path path-d"></div>
                    <div class="network-path path-e"></div>

                    <span class="network-node n-a"></span>
                    <span class="network-node n-b"></span>
                    <span class="network-node n-c"></span>
                    <span class="network-node n-d"></span>
                    <span class="network-node n-e"></span>
                    <span class="network-node n-f"></span>

                    <div class="network-core"></div>

                    <div class="assembled-logo">

                        <svg
                            viewBox="0 0 64 64"
                            aria-hidden="true"
                        >

                            <path
                                class="assembled-shield"
                                d="
                                    M32 5
                                    L51 12
                                    V28
                                    C51 41 43 52 32 59
                                    C21 52 13 41 13 28
                                    V12
                                    Z
                                "
                            />

                            <path
                                class="assembled-envelope"
                                d="
                                    M21 25
                                    H43
                                    V40
                                    H21
                                    Z
                                "
                            />

                            <path
                                class="assembled-fold"
                                d="
                                    M21 26
                                    L32 34
                                    L43 26
                                "
                            />

                            <path
                                class="assembled-trace"
                                d="
                                    M24 47
                                    H29
                                    L32 43
                                    L36 47
                                    H41
                                "
                            />

                        </svg>

                        <div class="logo-scan-beam"></div>

                    </div>

                </div>


                <div class="startup-brand">

                    <div class="startup-name">
                        Mail<span>Trace</span>
                    </div>

                    <div class="startup-tag">
                        AI FORENSICS
                    </div>

                    <div class="startup-status">
                        <span class="status-light"></span>
                        SECURE FORENSIC ENGINE
                    </div>

                </div>


                <div class="startup-footer">
                    SYSTEM READY
                </div>
            `;


            const style =
                document.createElement("style");

            style.textContent = `

                .mailtrace-forensic-startup {

                    position: fixed;

                    inset: 0;

                    z-index: 999999;

                    display: flex;

                    align-items: center;

                    justify-content: center;

                    overflow: hidden;

                    background:
                        radial-gradient(
                            circle at 50% 48%,
                            #091A27 0%,
                            #050C13 35%,
                            #02060B 75%,
                            #010308 100%
                        );

                    color: #ECF7FF;

                    font-family:
                        Inter,
                        system-ui,
                        -apple-system,
                        BlinkMacSystemFont,
                        "Segoe UI",
                        sans-serif;
                }


                .forensic-core-glow {

                    position: absolute;

                    left: 50%;
                    top: 49%;

                    width: 360px;
                    height: 360px;

                    transform:
                        translate(-50%, -50%);

                    border-radius: 50%;

                    background:
                        radial-gradient(
                            circle,
                            rgba(0,212,255,.11),
                            rgba(0,212,255,.035) 38%,
                            transparent 72%
                        );

                    filter:
                        blur(14px);

                    opacity: .45;

                    animation:
                        coreGlow
                        3.2s
                        ease-in-out
                        infinite;
                }


                @keyframes coreGlow {

                    0%,
                    100% {
                        opacity: .34;
                        transform:
                            translate(-50%, -50%)
                            scale(.88);
                    }

                    50% {
                        opacity: .72;
                        transform:
                            translate(-50%, -50%)
                            scale(1.08);
                    }
                }


                .forensic-network {

                    position: absolute;

                    left: 50%;
                    top: 46%;

                    width: 540px;
                    height: 360px;

                    transform:
                        translate(-50%, -50%);
                }


                /* =================================================
                NETWORK PATHS
                ================================================= */

                .network-path {

                    position: absolute;

                    height: 1px;

                    transform-origin:
                        left center;

                    opacity: 0;

                    background:
                        linear-gradient(
                            90deg,
                            transparent,
                            rgba(0,212,255,.35),
                            #00D4FF,
                            rgba(0,212,255,.12),
                            transparent
                        );

                    box-shadow:
                        0 0 7px
                        rgba(0,212,255,.20);
                }


                .path-a {
                    width: 245px;
                    left: 6px;
                    top: 97px;
                    transform:
                        rotate(24deg)
                        scaleX(0);
                    animation:
                        buildPath .65s
                        cubic-bezier(.16,1,.3,1)
                        .05s forwards;
                }


                .path-b {
                    width: 280px;
                    right: 0;
                    top: 106px;
                    transform-origin: right center;
                    transform:
                        rotate(-20deg)
                        scaleX(0);
                    animation:
                        buildPathRight .68s
                        cubic-bezier(.16,1,.3,1)
                        .12s forwards;
                }


                .path-c {
                    width: 220px;
                    left: 30px;
                    top: 236px;
                    transform:
                        rotate(-12deg)
                        scaleX(0);
                    animation:
                        buildPath .62s
                        cubic-bezier(.16,1,.3,1)
                        .22s forwards;
                }


                .path-d {
                    width: 190px;
                    right: 36px;
                    top: 252px;
                    transform-origin: right center;
                    transform:
                        rotate(13deg)
                        scaleX(0);
                    animation:
                        buildPathRight .62s
                        cubic-bezier(.16,1,.3,1)
                        .30s forwards;
                }


                .path-e {
                    width: 290px;
                    left: 124px;
                    top: 177px;
                    transform:
                        rotate(2deg)
                        scaleX(0);
                    opacity: .35;
                    animation:
                        buildPath .55s
                        cubic-bezier(.16,1,.3,1)
                        .38s forwards;
                }


                @keyframes buildPath {

                    from {
                        opacity: 0;
                        transform:
                            rotate(24deg)
                            scaleX(0);
                    }

                    35% {
                        opacity: 1;
                    }

                    to {
                        opacity: .58;
                        transform:
                            rotate(24deg)
                            scaleX(1);
                    }
                }


                @keyframes buildPathRight {

                    from {
                        opacity: 0;
                        transform:
                            rotate(-20deg)
                            scaleX(0);
                    }

                    35% {
                        opacity: 1;
                    }

                    to {
                        opacity: .58;
                        transform:
                            rotate(-20deg)
                            scaleX(1);
                    }
                }


                /* =================================================
                NODES
                ================================================= */

                .network-node {

                    position: absolute;

                    width: 5px;
                    height: 5px;

                    border-radius: 50%;

                    background:
                        #BDF7FF;

                    box-shadow:
                        0 0 8px
                        rgba(0,212,255,.70);

                    opacity: 0;

                    animation:
                        nodeIn
                        .42s
                        ease-out
                        forwards;
                }


                .n-a {
                    left: 92px;
                    top: 134px;
                    animation-delay: .40s;
                }

                .n-b {
                    left: 153px;
                    top: 158px;
                    animation-delay: .49s;
                }

                .n-c {
                    left: 361px;
                    top: 143px;
                    animation-delay: .56s;
                }

                .n-d {
                    left: 406px;
                    top: 126px;
                    animation-delay: .63s;
                }

                .n-e {
                    left: 91px;
                    top: 219px;
                    animation-delay: .69s;
                }

                .n-f {
                    left: 422px;
                    top: 226px;
                    animation-delay: .76s;
                }


                @keyframes nodeIn {

                    from {
                        opacity: 0;
                        transform:
                            scale(.2);
                    }

                    55% {
                        opacity: 1;
                        transform:
                            scale(1.45);
                    }

                    to {
                        opacity: .72;
                        transform:
                            scale(1);
                    }
                }


                /* =================================================
                CORE
                ================================================= */

                .network-core {

                    position: absolute;

                    left: 50%;
                    top: 50%;

                    width: 8px;
                    height: 8px;

                    border-radius: 50%;

                    background:
                        #E5FCFF;

                    box-shadow:
                        0 0 10px #00D4FF,
                        0 0 28px rgba(0,212,255,.62),
                        0 0 58px rgba(0,212,255,.20);

                    transform:
                        translate(-50%, -50%)
                        scale(0);

                    opacity: 0;

                    animation:
                        igniteCore
                        .62s
                        cubic-bezier(.16,1,.3,1)
                        .78s forwards;
                }


                @keyframes igniteCore {

                    0% {
                        opacity: 0;
                        transform:
                            translate(-50%, -50%)
                            scale(0);
                    }

                    35% {
                        opacity: 1;
                        transform:
                            translate(-50%, -50%)
                            scale(1.8);
                    }

                    100% {
                        opacity: 1;
                        transform:
                            translate(-50%, -50%)
                            scale(1);
                    }
                }


                /* =================================================
                LOGO
                ================================================= */

                .assembled-logo {

                    position: absolute;

                    left: 50%;
                    top: 50%;

                    width: 92px;
                    height: 92px;

                    display: grid;
                    place-items: center;

                    transform:
                        translate(-50%, -50%)
                        scale(.72);

                    opacity: 0;

                    border-radius: 26px;

                    background:
                        rgba(5,17,28,.82);

                    border:
                        1px solid
                        rgba(0,212,255,.22);

                    box-shadow:
                        0 0 28px
                        rgba(0,212,255,.10),

                        inset 0 0 25px
                        rgba(0,212,255,.025);

                    animation:
                        logoForm
                        .78s
                        cubic-bezier(.16,1,.3,1)
                        1.12s forwards;
                }


                .assembled-logo svg {

                    width: 61px;
                    height: 61px;

                    overflow: visible;
                }


                .assembled-shield {

                    fill:
                        rgba(0,212,255,.025);

                    stroke:
                        #00D4FF;

                    stroke-width:
                        1.7;

                    stroke-linejoin:
                        round;

                    stroke-dasharray:
                        170;

                    stroke-dashoffset:
                        170;

                    animation:
                        drawShield
                        .78s
                        cubic-bezier(.16,1,.3,1)
                        1.17s forwards;
                }


                .assembled-envelope {

                    fill:
                        rgba(2,9,15,.62);

                    stroke:
                        #E4F9FF;

                    stroke-width:
                        1.5;

                    stroke-linejoin:
                        round;

                    opacity: 0;

                    animation:
                        innerMark
                        .32s
                        ease-out
                        1.56s forwards;
                }


                .assembled-fold {

                    fill: none;

                    stroke:
                        #E4F9FF;

                    stroke-width:
                        1.5;

                    stroke-linecap:
                        round;

                    stroke-linejoin:
                        round;

                    stroke-dasharray:
                        42;

                    stroke-dashoffset:
                        42;

                    animation:
                        drawFold
                        .38s
                        ease-out
                        1.56s forwards;
                }


                .assembled-trace {

                    fill: none;

                    stroke:
                        #00D4FF;

                    stroke-width:
                        1.5;

                    stroke-linecap:
                        round;

                    stroke-linejoin:
                        round;

                    stroke-dasharray:
                        30;

                    stroke-dashoffset:
                        30;

                    animation:
                        drawTrace
                        .36s
                        ease-out
                        1.72s forwards;
                }


                @keyframes logoForm {

                    from {
                        opacity: 0;
                        transform:
                            translate(-50%, -50%)
                            scale(.72);
                        filter:
                            blur(5px);
                    }

                    to {
                        opacity: 1;
                        transform:
                            translate(-50%, -50%)
                            scale(1);
                        filter:
                            blur(0);
                    }
                }


                @keyframes drawShield {

                    to {
                        stroke-dashoffset: 0;
                    }
                }


                @keyframes innerMark {

                    from {
                        opacity: 0;
                    }

                    to {
                        opacity: 1;
                    }
                }


                @keyframes drawFold {

                    to {
                        stroke-dashoffset: 0;
                    }
                }


                @keyframes drawTrace {

                    to {
                        stroke-dashoffset: 0;
                    }
                }


                /* =================================================
                LOGO SCAN
                ================================================= */

                .logo-scan-beam {

                    position: absolute;

                    left: 5px;

                    width: 82px;

                    height: 1px;

                    top: 17px;

                    opacity: 0;

                    background:
                        linear-gradient(
                            90deg,
                            transparent,
                            #E5FCFF,
                            #00D4FF,
                            transparent
                        );

                    box-shadow:
                        0 0 8px
                        rgba(0,212,255,.55);

                    animation:
                        scanLogo
                        .58s
                        ease-in-out
                        1.92s forwards;
                }


                @keyframes scanLogo {

                    0% {
                        opacity: 0;
                        transform:
                            translateY(0);
                    }

                    15% {
                        opacity: 1;
                    }

                    85% {
                        opacity: .85;
                    }

                    100% {
                        opacity: 0;
                        transform:
                            translateY(58px);
                    }
                }


                /* =================================================
                WORDMARK
                ================================================= */

                .startup-brand {

                    position: relative;

                    z-index: 8;

                    margin-top: 222px;

                    display: flex;

                    flex-direction: column;

                    align-items: center;

                    opacity: 0;

                    transform:
                        translateY(12px);

                    animation:
                        wordmarkIn
                        .72s
                        cubic-bezier(.16,1,.3,1)
                        2.00s forwards;
                }


                .startup-name {

                    font-size: 32px;

                    line-height: 36px;

                    font-weight: 750;

                    letter-spacing: -1px;

                    color:
                        #EDF7FF;
                }


                .startup-name span {

                    color:
                        #00D4FF;

                    text-shadow:
                        0 0 16px
                        rgba(0,212,255,.28);
                }


                .startup-tag {

                    margin-top: 4px;

                    color:
                        #00D4FF;

                    font-size: 8px;

                    line-height: 11px;

                    font-weight: 700;

                    letter-spacing: 3px;
                }


                .startup-status {

                    margin-top: 18px;

                    display: flex;

                    align-items: center;

                    gap: 7px;

                    color:
                        #536C7E;

                    font-family:
                        Consolas,
                        "SFMono-Regular",
                        monospace;

                    font-size: 7px;

                    letter-spacing: 1.7px;
                }


                .status-light {

                    width: 5px;
                    height: 5px;

                    border-radius: 50%;

                    background:
                        #00E6A8;

                    box-shadow:
                        0 0 8px
                        rgba(0,230,168,.60);

                    animation:
                        statusPulse
                        1s
                        ease-in-out
                        infinite;
                }


                @keyframes statusPulse {

                    0%,
                    100% {
                        opacity: .55;
                    }

                    50% {
                        opacity: 1;
                    }
                }


                @keyframes wordmarkIn {

                    from {
                        opacity: 0;
                        transform:
                            translateY(12px);
                        filter:
                            blur(5px);
                    }

                    to {
                        opacity: 1;
                        transform:
                            translateY(0);
                        filter:
                            blur(0);
                    }
                }


                /* =================================================
                FOOTER STATUS
                ================================================= */

                .startup-footer {

                    position: absolute;

                    left: 50%;
                    bottom: 40px;

                    transform:
                        translateX(-50%);

                    color:
                        #3F596B;

                    font-family:
                        Consolas,
                        monospace;

                    font-size: 7px;

                    letter-spacing: 2px;

                    opacity: 0;

                    animation:
                        footerIn
                        .5s
                        ease-out
                        2.25s forwards;
                }


                @keyframes footerIn {

                    from {
                        opacity: 0;
                    }

                    to {
                        opacity: .85;
                    }
                }


                /* =================================================
                EXIT
                ================================================= */

                .mailtrace-forensic-startup.boot-exit {

                    animation:
                        bootExit
                        .65s
                        cubic-bezier(.7,0,.84,.2)
                        forwards;
                }


                @keyframes bootExit {

                    from {
                        opacity: 1;
                    }

                    to {
                        opacity: 0;
                        transform:
                            scale(1.018);
                    }
                }


                /* =================================================
                ACCESSIBILITY
                ================================================= */

                @media (
                    prefers-reduced-motion: reduce
                ) {

                    .mailtrace-forensic-startup * {
                        animation: none !important;
                    }

                    .assembled-logo,
                    .startup-brand,
                    .startup-footer {
                        opacity: 1 !important;
                    }
                }

            `;


            document.head.appendChild(style);

            document.body.appendChild(boot);


            /* =====================================================
            FINAL REVEAL
            ===================================================== */

            setTimeout(
                function () {

                    boot.classList.add(
                        "boot-exit"
                    );

                    setTimeout(
                        function () {

                            boot.remove();

                            style.remove();

                        },
                        700
                    );

                },
                3300
            );
        }


        if (
            document.readyState ===
            "loading"
        ) {

            document.addEventListener(
                "DOMContentLoaded",
                launchStartup,
                { once: true }
            );

        } else {

            launchStartup();
        }

    })();

    /* ============================================================
    MAILTRACE_HEADER_ENTRANCE_ANIMATION
    Premium static-page entrance.
    No mouse tracking.
    No layout shifting.
    ============================================================ */

    (function MailTraceHeaderAnimation() {

        function animateHeader() {

            const header =
                document.querySelector(".topbar");

            if (!header) {
                return;
            }

            const menu =
                header.querySelector(".menu-toggle");

            const brand =
                header.querySelector(".brand-mini");

            const title =
                header.querySelector(".page-title");

            const search =
                header.querySelector(".search-wrapper");

            const actions =
                header.querySelector(".topbar-right");

            const items = [
                menu,
                brand,
                title,
                search,
                actions
            ].filter(Boolean);


            /* ------------------------------------------------------
            INITIAL APPEARANCE
            ------------------------------------------------------ */

            items.forEach((item) => {

                item.style.opacity = "0";

                item.style.transform =
                    "translateY(-7px)";

                item.style.willChange =
                    "transform, opacity";
            });


            /* ------------------------------------------------------
            STAGGERED REVEAL
            ------------------------------------------------------ */

            items.forEach((item, index) => {

                item.animate(
                    [
                        {
                            opacity: 0,

                            transform:
                                "translateY(-7px)"
                        },
                        {
                            opacity: 1,

                            transform:
                                "translateY(0)"
                        }
                    ],
                    {
                        duration: 520,

                        delay:
                            80 + (index * 75),

                        easing:
                            "cubic-bezier(.16,1,.3,1)",

                        fill: "forwards"
                    }
                );
            });


            /* ------------------------------------------------------
            LOGO POWER-ON
            ------------------------------------------------------ */

            const logo =
                header.querySelector(
                    ".mailtrace-logo-svg"
                );

            const logoBox =
                header.querySelector(
                    ".mailtrace-logo"
                );

            if (logo && logoBox) {

                setTimeout(
                    function () {

                        logoBox.animate(
                            [
                                {
                                    transform:
                                        "scale(.94)",

                                    boxShadow:
                                        "0 0 8px rgba(0,212,255,.03)"
                                },

                                {
                                    transform:
                                        "scale(1.045)",

                                    boxShadow:
                                        "0 0 24px rgba(0,212,255,.16)"
                                },

                                {
                                    transform:
                                        "scale(1)",

                                    boxShadow:
                                        "0 0 14px rgba(0,212,255,.05)"
                                }
                            ],
                            {
                                duration: 720,

                                easing:
                                    "cubic-bezier(.16,1,.3,1)"
                            }
                        );


                        /* --------------------------------------------------
                        LOGO LIGHT SWEEP
                        -------------------------------------------------- */

                        const sweep =
                            document.createElement(
                                "span"
                            );

                        sweep.className =
                            "logo-light-sweep";

                        Object.assign(
                            sweep.style,
                            {
                                position: "absolute",
                                top: "3px",
                                left: "-26px",
                                width: "14px",
                                height: "36px",
                                borderRadius: "50%",
                                transform: "rotate(18deg)",
                                opacity: "0",
                                pointerEvents: "none",
                                background:
                                    "linear-gradient(90deg, transparent, rgba(220,250,255,.72), transparent)",
                                filter:
                                    "blur(2px)"
                            }
                        );

                        logoBox.appendChild(
                            sweep
                        );

                        sweep.animate(
                            [
                                {
                                    left: "-26px",
                                    opacity: 0
                                },
                                {
                                    left: "54px",
                                    opacity: .8
                                },
                                {
                                    left: "65px",
                                    opacity: 0
                                }
                            ],
                            {
                                duration: 680,

                                delay: 120,

                                easing: "ease-in-out"
                            }
                        ).finished.then(
                            function () {

                                sweep.remove();
                            }
                        );

                    },
                    520
                );


                /* --------------------------------------------------
                VERY SUBTLE IDLE BREATH
                -------------------------------------------------- */

                setTimeout(
                    function () {

                        logo.animate(
                            [
                                {
                                    filter:
                                        "drop-shadow(0 0 2px rgba(0,212,255,.08))"
                                },

                                {
                                    filter:
                                        "drop-shadow(0 0 5px rgba(0,212,255,.20))"
                                },

                                {
                                    filter:
                                        "drop-shadow(0 0 2px rgba(0,212,255,.08))"
                                }
                            ],
                            {
                                duration: 3200,

                                iterations: Infinity,

                                easing: "ease-in-out"
                            }
                        );

                    },
                    1300
                );
            }


            /* ------------------------------------------------------
            SEARCH INITIAL GLOW
            ------------------------------------------------------ */

            if (search) {

                setTimeout(
                    function () {

                        search.animate(
                            [
                                {
                                    boxShadow:
                                        "0 0 0 rgba(0,212,255,0)"
                                },

                                {
                                    boxShadow:
                                        "0 0 22px rgba(0,212,255,.065)"
                                },

                                {
                                    boxShadow:
                                        "0 0 0 rgba(0,212,255,0)"
                                }
                            ],
                            {
                                duration: 750,

                                easing:
                                    "ease-out"
                            }
                        );

                    },
                    620
                );
            }


            /* ------------------------------------------------------
            CLEAN INLINE ANIMATION PROPERTIES
            ------------------------------------------------------ */

            setTimeout(
                function () {

                    items.forEach((item) => {

                        item.style.willChange =
                            "auto";
                    });

                },
                1100
            );
        }


        if (
            document.readyState ===
            "loading"
        ) {

            document.addEventListener(
                "DOMContentLoaded",
                animateHeader,
                { once: true }
            );

        } else {

            animateHeader();
        }

    })();





/* MAILTRACE_OBSERVED_INFRA_JS_START */

(function () {

    "use strict";


    // =====================================================
    // IP VALIDATION
    // =====================================================

    function extractIPv4(value) {

        if (!value) return "";

        var match = value.match(
            /\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\b/
        );

        return match ? match[0] : "";

    }


    function extractCoordinates(value) {

        if (!value) return "";

        var match = value.match(
            /-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+/
        );

        return match ? match[0] : "";

    }


    // =====================================================
    // COUNTRY FLAG DETECTION
    // =====================================================

    function getCountryFlag(country) {

        if (!country) return "🌐";

        var value = country.toLowerCase().trim();


        var flags = {

            "united states": "🇺🇸",
            "usa": "🇺🇸",
            "us": "🇺🇸",

            "india": "🇮🇳",

            "united kingdom": "🇬🇧",
            "england": "🇬🇧",
            "uk": "🇬🇧",

            "singapore": "🇸🇬",

            "canada": "🇨🇦",

            "germany": "🇩🇪",

            "france": "🇫🇷",

            "japan": "🇯🇵",

            "china": "🇨🇳",

            "australia": "🇦🇺",

            "russia": "🇷🇺",

            "brazil": "🇧🇷",

            "netherlands": "🇳🇱",

            "ireland": "🇮🇪",

            "sweden": "🇸🇪",

            "switzerland": "🇨🇭",

            "south korea": "🇰🇷",

            "korea": "🇰🇷",

            "uae": "🇦🇪",

            "united arab emirates": "🇦🇪"

        };


        for (var key in flags) {

            if (
                value === key ||
                value.indexOf(key) !== -1
            ) {

                return flags[key];

            }

        }


        return "🌐";

    }


    // =====================================================
    // COUNTRY EXTRACTION
    // =====================================================

    function extractCountry(location) {

        if (!location) return "";

        var parts = location
            .split(",")
            .map(function (item) {
                return item.trim();
            })
            .filter(Boolean);


        if (parts.length >= 1) {

            return parts[parts.length - 1];

        }


        return "";

    }


    // =====================================================
    // FIND GEO DATA CARDS
    // =====================================================

    function findGeoData() {

        var mapContainer =
            document.getElementById("leafletReportMap");


        if (!mapContainer) {

            return [];

        }


        var parent =
            mapContainer.parentElement;


        if (!parent) {

            return [];

        }


        var allElements =
            parent.querySelectorAll("div");


        var results = [];

        var seenIPs = {};


        for (
            var i = 0;
            i < allElements.length;
            i++
        ) {

            var element =
                allElements[i];


            if (
                element.id ===
                "observedInfrastructurePanel"
            ) {

                continue;

            }


            if (
                element === parent ||
                element === mapContainer
            ) {

                continue;

            }


            var text =
                (element.innerText || "").trim();


            if (
                !text ||
                text.length > 450
            ) {

                continue;

            }


            var ip =
                extractIPv4(text);


            if (!ip) {

                continue;

            }


            if (seenIPs[ip]) {

                continue;

            }


            var lines =
                text
                .split(/\n+/)
                .map(function (line) {

                    return line.trim();

                })
                .filter(function (line) {

                    return line.length > 0;

                });


            var coordinates = "";

            var location = "";

            var organization = "";


            for (
                var j = 0;
                j < lines.length;
                j++
            ) {

                var line =
                    lines[j];


                if (
                    line === ip
                ) {

                    continue;

                }


                if (
                    !coordinates &&
                    /-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+/.test(line)
                ) {

                    coordinates =
                        extractCoordinates(line);

                    continue;

                }


                if (
                    !location &&
                    line !== ip &&
                    !extractIPv4(line) &&
                    !/-?\d{1,3}\.\d+\s*,\s*-?\d{1,3}\.\d+/.test(line)
                ) {

                    location =
                        line;

                    continue;

                }


                if (
                    !organization &&
                    line !== location &&
                    line !== coordinates
                ) {

                    organization =
                        line;

                }

            }


            if (location) {

                seenIPs[ip] = true;


                results.push({

                    ip: ip,

                    location: location,

                    country:
                        extractCountry(location),

                    coordinates:
                        coordinates,

                    organization:
                        organization,

                    sourceElement:
                        element

                });

            }

        }


        return results;

    }


    // =====================================================
    // CREATE OBSERVED INFRASTRUCTURE PANEL
    // =====================================================

    function createInfrastructurePanel(data) {

        var mapContainer =
            document.getElementById("leafletReportMap");


        if (!mapContainer) return;


        var parent =
            mapContainer.parentElement;


        if (!parent) return;


        var existing =
            document.getElementById(
                "observedInfrastructurePanel"
            );


        if (existing) {

            existing.remove();

        }


        var panel =
            document.createElement("div");


        panel.id =
            "observedInfrastructurePanel";


        panel.className =
            "observed-infrastructure-panel";


        var cards = "";


        if (!data.length) {

            cards = `
                <div class="observed-infrastructure-empty">
                    No infrastructure geolocation evidence available.
                </div>
            `;

        }

        else {

            data.forEach(function (item) {

                var flag =
                    getCountryFlag(
                        item.country
                    );


                var locationParts =
                    item.location
                    .split(",")
                    .map(function (part) {

                        return part.trim();

                    });


                var cityRegion =
                    item.location;


                var country =
                    item.country;


                if (
                    locationParts.length >= 2
                ) {

                    country =
                        locationParts[
                            locationParts.length - 1
                        ];


                    cityRegion =
                        locationParts
                        .slice(
                            0,
                            locationParts.length - 1
                        )
                        .join(", ");

                }


                cards += `

                    <div class="observed-infrastructure-card">

                        <div class="observed-ip-row">

                            <span class="observed-status-dot"></span>

                            <span class="observed-ip-address">
                                ${item.ip}
                            </span>

                        </div>


                        <div class="observed-location-row">

                            <div class="observed-country-flag">
                                ${flag}
                            </div>


                            <div>

                                <div class="observed-location-text">
                                    ${cityRegion}
                                </div>


                                <div class="observed-country-text">
                                    ${country}
                                </div>

                            </div>

                        </div>


                        <div class="observed-coordinates">

                            ${
                                item.coordinates ||
                                "Coordinates unavailable"
                            }

                        </div>

                    </div>

                `;

            });

        }


        panel.innerHTML = `

            <div class="observed-infrastructure-header">

                <div class="observed-location-icon">
                    📍
                </div>


                <div class="observed-infrastructure-title">

                    Observed Infrastructure

                    <span class="observed-infrastructure-count">
                        (${data.length})
                    </span>

                </div>

            </div>


            <div class="observed-infrastructure-grid">

                ${cards}

            </div>

        `;


        // Insert directly after map

        if (
            mapContainer.nextSibling
        ) {

            parent.insertBefore(
                panel,
                mapContainer.nextSibling
            );

        }

        else {

            parent.appendChild(panel);

        }


        // Hide old raw information cards
        // but NEVER hide the map itself

        data.forEach(function (item) {

            if (
                item.sourceElement &&
                item.sourceElement !== panel
            ) {

                item.sourceElement.style.display =
                    "none";

            }

        });

    }


    // =====================================================
    // UPGRADE FUNCTION
    // =====================================================

    function upgradeObservedInfrastructure() {

        var map =
            document.getElementById(
                "leafletReportMap"
            );


        if (!map) return;


        var data =
            findGeoData();


        if (!data.length) return;


        createInfrastructurePanel(data);

    }


    // =====================================================
    // WATCH DYNAMIC REPORT CONTENT
    // =====================================================

    var timer = null;


    function scheduleUpgrade() {

        clearTimeout(timer);


        timer = setTimeout(
            upgradeObservedInfrastructure,
            300
        );

    }


    function startObservedInfrastructure() {

        scheduleUpgrade();


        var observer =
            new MutationObserver(function () {

                scheduleUpgrade();

            });


        observer.observe(
            document.body,
            {

                childList: true,

                subtree: true

            }

        );

    }


    if (
        document.readyState === "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            startObservedInfrastructure
        );

    }

    else {

        startObservedInfrastructure();

    }


})();

/* MAILTRACE_OBSERVED_INFRA_JS_END */






/* ============================================================
   MAILTRACE-AI — LIVE DIGITAL CLOCK
   ============================================================ */
(function initMailTraceDigitalClock() {
    function updateClock() {
        var timeEl = document.getElementById("mailtraceClockTime");
        var dateEl = document.getElementById("mailtraceClockDate");
        if (!timeEl || !dateEl) return;

        var now = new Date();

        timeEl.textContent = now.toLocaleTimeString("en-IN", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false
        });

        dateEl.textContent = now.toLocaleDateString("en-IN", {
            weekday: "short",
            day: "2-digit",
            month: "short",
            year: "numeric"
        });
    }

    function startClock() {
        updateClock();
        window.setInterval(updateClock, 1000);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", startClock, { once: true });
    } else {
        startClock();
    }
})();
