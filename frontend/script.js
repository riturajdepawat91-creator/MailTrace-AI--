    console.log("ðŸ”¥ MAILTRACE JS LOADED");

    /* =========================================
    MAILTRACE AI
    FRONTEND INTERACTIONS
    ========================================= */

    document.addEventListener("DOMContentLoaded", () => {
        
    loadDashboardStats();
    loadRecentInvestigations();
    loadDashboardCharts();

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
                    "ðŸ”¥ Opening all investigations..."
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
        

        /* =====================================
        OPEN MODAL
        ===================================== */

        function openModal() {
            modal.classList.add("show");
            document.body.style.overflow = "hidden";
        }


        /* =====================================
        CLOSE MODAL
        ===================================== */

        function closeInvestigationModal() {
            modal.classList.remove("show");
            document.body.style.overflow = "";
        }


        newInvestigationBtn.addEventListener("click", openModal);

        uploadEmail.addEventListener("click", openModal);

        closeModal.addEventListener(
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

        uploadBox.addEventListener("click", () => {

            emailFile.click();

        });


        /* =====================================
        FILE SELECTED
        ===================================== */

        emailFile.addEventListener("change", () => {

            if (!emailFile.files.length) {
                return;
            }

            const file = emailFile.files[0];

            uploadBox.innerHTML = `
                <div class="upload-icon">âœ“</div>

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

            uploadBox.addEventListener(eventName, (event) => {

                event.preventDefault();

                uploadBox.classList.add("dragging");

            });

        });


        ["dragleave", "drop"].forEach(eventName => {

            uploadBox.addEventListener(eventName, (event) => {

                event.preventDefault();

                uploadBox.classList.remove("dragging");

            });

        });


        uploadBox.addEventListener("drop", (event) => {

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
                <div class="upload-icon">âœ“</div>

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

    startAnalysis.addEventListener("click", async (event) => {

        event.preventDefault();


        console.log("ðŸ”¥ START ANALYSIS CLICKED");

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

        /* ==============================
        REMOVE INVESTIGATIONS PAGE
        ============================== */

        const investigationsPage =
            document.getElementById("investigationsPage");

        if (investigationsPage) {
            investigationsPage.remove();
        }


        /* ==============================
        REMOVE CASES PAGE
        ============================== */

        const casesPage =
            document.getElementById("casesPage");

        if (casesPage) {
            casesPage.remove();
        }


        /* ==============================
        REMOVE CAMPAIGNS PAGE
        ============================== */

        const campaignsPage =
            document.getElementById("campaignsPage");

        if (campaignsPage) {
            campaignsPage.remove();
        }


        /* ==============================
        REMOVE CAMPAIGN DETAIL
        ============================== */

        const campaignDetailPage =
            document.getElementById("campaignDetailPage");

        if (campaignDetailPage) {
            campaignDetailPage.remove();
        }


        /* ==============================
        REMOVE INVESTIGATION RESULT
        ============================== */

        const investigationResult =
            document.getElementById("investigationResult");

        if (investigationResult) {
            investigationResult.remove();
        }


        /* ==============================
        SHOW NORMAL DASHBOARD
        ============================== */

        const dashboard =
            document.querySelector(".dashboard-content");

        if (dashboard) {
            dashboard.style.display = "";
        }


        /* ==============================
        SCROLL TOP
        ============================== */

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

                await loadInvestigations();

                return;
            }

            /* ==============================
    CASES
    ============================== */

    /* ==============================
    CASES
    ============================== */

    if (page === "cases") {

        await loadCases();

        return;
    }


    /* ==============================
    CAMPAIGNS
    ============================== */

    if (page === "campaigns") {

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

        document.querySelectorAll(".quick-card")
            .forEach((button, index) => {

                button.addEventListener("click", () => {

                    if (index === 0) {

                        openModal();

                    } else if (index === 1) {

                        showNotification(
                            "Campaign intelligence module selected.",
                            "info"
                        );

                    } else {

                        showNotification(
                            "Forensic reporting module selected.",
                            "info"
                        );

                    }

                });

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
                    ${type === "success" ? "âœ“" :
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
    function showInvestigationResult(analysis) {

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
                        LIVE EMAIL ANALYSIS
                    </div>

                    <h2>
                        Investigation Result
                    </h2>

                    <p>
                        ${escapeHTML(
                            analysis.filename ||
                            "Email"
                        )}
                    </p>

                </div>


                <div class="result-status threat-status">

                    <span class="result-status-dot"></span>

                    ${escapeHTML(
                        threat.verdict ||
                        "ANALYSIS COMPLETE"
                    )}

                </div>

            </div>


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


            <!-- =================================
                EMAIL BODY
            ================================== -->

            <div class="result-card body-card">

                <div class="result-card-title">
                    EMAIL BODY
                </div>


                <div class="email-body-preview">

                    ${escapeHTML(
                        body.text ||
                        "No plain-text body detected."
                    )}

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

            <div class="result-card body-card">

                <div class="result-card-title">
                    URL THREAT INTELLIGENCE
                </div>

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
                                            urlInfo.url ||
                                            "Unknown URL"
                                        )}
                                    </code>

                                </div>

                                <span class="
                                    url-risk
                                    ${escapeHTML(
                                        String(
                                            urlInfo.risk ||
                                            "UNKNOWN"
                                        ).toLowerCase()
                                    )}
                                ">
                                    ${escapeHTML(
                                        urlInfo.risk ||
                                        "UNKNOWN"
                                    )}
                                </span>

                            </div>


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
                                        ${escapeHTML(
                                            String(
                                                urlInfo.risk_score ??
                                                0
                                            )
                                        )} / 100
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

                                <span>â†—</span>

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
                BACK BUTTON
            ================================== -->

            <button
                class="secondary-result-btn"
                id="backToDashboard"
            >
                â† Back to Dashboard
            </button>

        `;


        document
            .querySelector(".page")
            .prepend(resultSection);


        resultSection.scrollIntoView({
            behavior: "smooth"
        });


        document
        .getElementById("backToDashboard")
        .addEventListener(
            "click",
            () => {

                /* ==============================
                CLEAN ALL DYNAMIC PAGES
                ============================== */

                cleanupDynamicPages();


                /* ==============================
                SCROLL TO TOP
                ============================== */

                window.scrollTo({
                    top: 0,
                    behavior: "smooth"
                });

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

        console.log("ðŸ”¥ Loading investigations...");


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

            dashboard.style.display =
                "none";

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
                    â†» Refresh
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
                "ðŸ”¥ INVESTIGATIONS:",
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


        /* =====================================
        RENDER UI
        ===================================== */

        function renderTable() {

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
                    ? threatFilter.value
                        .toUpperCase()
                    : "ALL";


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

                        const matchesThreat =
                            selectedThreat === "ALL" ||
                            verdict === selectedThreat;


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

                    ${count}
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

                            ${filteredInvestigations.map(
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
                                "ðŸ”¥ Opening investigation:",
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
                    renderTable
                );

            }


            if (threatFilter) {

                threatFilter.addEventListener(
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
                    "ðŸ”¥ Investigation clicked:",
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
            "ðŸ”¥ Opening investigation:",
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
                "ðŸ”¥ SINGLE INVESTIGATION:",
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

    async function loadDashboardStats() {

        console.log(
            "ðŸ”¥ Loading dashboard statistics..."
        );

        try {

            /* =====================================
            FETCH INVESTIGATIONS + CASES
            ===================================== */

            const [
                investigationsResponse,
                casesResponse
            ] = await Promise.all([

                fetch(
                    "http://127.0.0.1:8000/api/investigations"
                ),

                fetch(
                    "http://127.0.0.1:8000/api/cases"
                )

            ]);


            const investigationsData =
                await investigationsResponse.json();

            const casesData =
                await casesResponse.json();


            /* =====================================
            CHECK RESPONSES
            ===================================== */

            if (!investigationsResponse.ok) {

                throw new Error(
                    investigationsData.detail ||
                    "Failed to load investigations."
                );

            }


            if (!casesResponse.ok) {

                throw new Error(
                    casesData.detail ||
                    "Failed to load cases."
                );

            }


            /* =====================================
            GET DATA
            ===================================== */

            const investigations =
                investigationsData.investigations || [];


            const cases =
                casesData.cases || [];


            /* =====================================
            CALCULATE STATISTICS
            ===================================== */

            const total =
                investigations.length;


            const threats =
                investigations.filter(
                    item => {

                        const verdict =
                            String(
                                item.threat_verdict || ""
                            ).toUpperCase();

                        return (
                            verdict === "CRITICAL" ||
                            verdict === "HIGH"
                        );

                    }
                ).length;


            /* =====================================
            ACTIVE CASES
            ===================================== */

            const activeCases =
                cases.filter(
                    caseItem => {

                        const status =
                            String(
                                caseItem.status || "OPEN"
                            ).toUpperCase();

                        return (
                            status === "OPEN" ||
                            status === "ACTIVE"
                        );

                    }
                ).length;


            /* =====================================
            DEBUG
            ===================================== */

            console.log(
                "ðŸ”¥ DASHBOARD STATS:",
                {
                    total,
                    threats,
                    activeCases,
                    investigations:
                        investigations.length,
                    cases:
                        cases.length
                }
            );


            /* =====================================
            FIND DASHBOARD STAT CARDS
            ===================================== */

            const statCards =
                document.querySelectorAll(
                    ".stat-value"
                );


            console.log(
                "Dashboard stat cards found:",
                statCards.length
            );


            /* =====================================
            CARD 1
            TOTAL ANALYSED
            ===================================== */

            if (statCards[0]) {

                statCards[0].textContent =
                    total.toLocaleString();

            }


            /* =====================================
            CARD 2
            THREATS DETECTED
            ===================================== */

            if (statCards[1]) {

                statCards[1].textContent =
                    threats.toLocaleString();

            }


            /* =====================================
            CARD 3
            ACTIVE CASES
            ===================================== */

            if (statCards[2]) {

                statCards[2].textContent =
                    activeCases.toLocaleString();

            }


            /* =====================================
            CARD 4
            CAMPAIGNS

            Currently no backend endpoint
            connected for campaigns.
            ===================================== */


            console.log(
                "âœ… Dashboard statistics updated."
            );


        } catch (error) {

            console.error(
                "Dashboard Statistics Error:",
                error
            );

        }

    }
    /* =========================================
    LIVE RECENT INVESTIGATIONS
    ========================================= */

    async function loadRecentInvestigations() {

        console.log("ðŸ”¥ Loading recent investigations...");

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
                "ðŸ”¥ Recent investigations:",
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
            CLICK â†’ INVESTIGATION RESULT
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
                                "ðŸ”¥ Dashboard investigation clicked:",
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

        console.log("ðŸ”¥ Loading live dashboard charts...");

        try {

            const response = await fetch(
                "http://127.0.0.1:8000/api/investigations"
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


            console.log(
                "ðŸ”¥ Chart data:",
                investigations
            );


            /* =====================================
            THREAT DISTRIBUTION
            ===================================== */

            const severityCounts = {

                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                "LOW RISK": 0

            };


            investigations.forEach(item => {

                const verdict =
                    String(
                        item.threat_verdict || ""
                    ).toUpperCase();


                if (
                    Object.prototype.hasOwnProperty.call(
                        severityCounts,
                        verdict
                    )
                ) {

                    severityCounts[verdict]++;

                }

            });
            const totalThreats =
        investigations.filter(item => {

            const verdict =
                String(
                    item.threat_verdict || ""
                ).toUpperCase();

            return (
                verdict === "CRITICAL" ||
                verdict === "HIGH" ||
                verdict === "MEDIUM"
            );

        }).length;


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
        totalThreats.toLocaleString();

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


                    const criticalEnd =
                        criticalPercent;


                    const highEnd =
                        criticalEnd +
                        highPercent;


                    const mediumEnd =
                        highEnd +
                        mediumPercent;


                    donut.style.background =
                        `conic-gradient(
                            #ff4545 0% ${criticalEnd}%,
                            #ff9f1c ${criticalEnd}% ${highEnd}%,
                            #7c6cff ${highEnd}% ${mediumEnd}%,
                            #19b5fe ${mediumEnd}% 100%
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


                        if (label) {

                            label.innerHTML = `

                                <i
                                    class="legend-dot ${item.className}"
                                ></i>

                                ${item.name}

                            `;

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


                            percentage.textContent =
                                `${percent}%`;

                        }

                    }
                );

            }


            /* =====================================
    THREAT ACTIVITY â€” DYNAMIC RANGE
    ===================================== */

    const chartLine =
        document.querySelector(".chart-line");

    const chartFill =
        document.querySelector(".chart-area-fill");

    const rangeSelector =
        document.getElementById(
            "threatActivityRange"
        );


    function updateThreatActivityChart(days) {

        if (!chartLine || !chartFill) {
            return;
        }


        /* ==============================
        CREATE DATE RANGE
        ============================== */

        const now = new Date();

        const dailyCounts = [];


        for (
            let i = days - 1;
            i >= 0;
            i--
        ) {

            const date =
                new Date(now);

            date.setHours(
                0,
                0,
                0,
                0
            );

            date.setDate(
                date.getDate() - i
            );


            dailyCounts.push({

                date: date,

                count: 0

            });

        }


        /* ==============================
        COUNT THREATS
        ============================== */

        investigations.forEach(
            investigation => {

                const verdict =
                    String(
                        investigation.threat_verdict ||
                        ""
                    ).toUpperCase();


                const isThreat =
                    verdict === "CRITICAL" ||
                    verdict === "HIGH" ||
                    verdict === "MEDIUM";


                if (!isThreat) {
                    return;
                }


                const createdAt =
                    String(
                        investigation.created_at ||
                        ""
                    );


                if (!createdAt) {
                    return;
                }


                const emailDate =
                    new Date(
                        createdAt.replace(
                            " ",
                            "T"
                        )
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


        const maxValue =
            Math.max(
                ...dailyCounts.map(
                    item => item.count
                ),
                5
            );


        /* ==============================
        CREATE POINTS
        ============================== */

        const points =
            dailyCounts.map(
                (item, index) => {

                    const x =
                        (
                            index /
                            Math.max(
                                dailyCounts.length - 1,
                                1
                            )
                        ) *
                        chartWidth;


                    const y =
                        chartHeight -
                        (
                            item.count /
                            maxValue
                        ) *
                        190;


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


        if (!firstPoint || !lastPoint) {
            return;
        }


        const fillPath =
            `${linePath}
            L${lastPoint.x},240
            L${firstPoint.x},240
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
                "âœ… Dashboard charts updated successfully."
            );


        } catch (error) {

            console.error(
                "Dashboard Charts Error:",
                error
            );

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

    function cleanupDynamicPages() {

        const pages = [
            "investigationsPage",
            "casesPage",
            "campaignsPage",
            "campaignDetailPage",
            "investigationResult",
            "ipIntelligencePage"
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

    async function loadCases() {

        console.log("ðŸ”¥ Loading cases...");


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
                        Review high-risk email investigations.
                    </p>

                </div>


                <button
                    class="secondary-result-btn"
                    id="refreshCases"
                >
                    â†» Refresh
                </button>

            </div>


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
                    "http://127.0.0.1:8000/api/cases"
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
                "ðŸ”¥ CASES:",
                data
            );


            /* ==============================
            RENDER CASES
            ============================== */

            renderCases(
                data.cases || []
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

        console.log("ðŸ”¥ Loading campaigns...");

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
                    â†» Refresh
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
                "ðŸ”¥ CAMPAIGNS:",
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
                        "ðŸ”¥ Opening campaign detail:",
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
            "ðŸ”¥ Opening campaign:",
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
                "ðŸ”¥ CAMPAIGN DETAIL:",
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

            dashboard.style.display = "none";

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
                    â† Back to Campaigns
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

    function renderCases(cases) {

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
                            caseItem.subject || ""
                        ).toLowerCase();


                    const sender =
                        String(
                            caseItem.sender || ""
                        ).toLowerCase();


                    const verdict =
                        String(
                            caseItem.threat_verdict || ""
                        ).toUpperCase();


                    const status =
                        String(
                            caseItem.status || "OPEN"
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


                    <div class="investigations-count">

                        0 cases found

                    </div>


                    <div class="investigations-empty">

                        No cases match your filters.

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


                <div class="investigations-count">

                    ${count}
                    case${count === 1 ? "" : "s"}

                </div>


                <div class="investigations-table-wrapper">

                    <table class="investigations-table">

                        <thead>

                            <tr>

                                <th>
                                    CASE ID
                                </th>

                                <th>
                                    INVESTIGATION ID
                                </th>

                                <th>
                                    SUBJECT
                                </th>

                                <th>
                                    SENDER
                                </th>

                                <th>
                                    THREAT
                                </th>

                                <th>
                                    SCORE
                                </th>

                                <th>
                                    STATUS
                                </th>

                                <th>
                                    CREATED
                                </th>

                            </tr>

                        </thead>


                        <tbody>

                            ${filteredCases.map(
                                caseItem => `

                                <tr
                                    class="case-row"
                                    data-case-id="${escapeHTML(caseItem.case_id || "")}"
                                >

                                    <td>

                                        <button
                                            class="investigation-id-btn"
                                            type="button"
                                        >

                                            ${escapeHTML(
                                                caseItem.case_id ||
                                                "UNKNOWN"
                                            )}

                                        </button>

                                    </td>


                                    <td>

                                        <span class="mono">

                                            ${escapeHTML(
                                                caseItem.investigation_id ||
                                                "UNKNOWN"
                                            )}

                                        </span>

                                    </td>


                                    <td>

                                        <div class="email-cell">

                                            <strong>

                                                ${escapeHTML(
                                                    caseItem.subject ||
                                                    "No Subject"
                                                )}

                                            </strong>

                                        </div>

                                    </td>


                                    <td>

                                        ${escapeHTML(
                                            caseItem.sender ||
                                            "Unknown Sender"
                                        )}

                                    </td>


                                    <td>

                                        <span class="
                                            investigation-threat
                                            ${getThreatClass(
                                                caseItem.threat_verdict
                                            )}
                                        ">

                                            ${escapeHTML(
                                                caseItem.threat_verdict ||
                                                "UNKNOWN"
                                            )}

                                        </span>

                                    </td>


                                    <td>

                                        <strong>

                                            ${Number(
                                                caseItem.threat_score || 0
                                            )}

                                        </strong>

                                        / 100

                                    </td>


                                    <td>

                                        <span class="status active">

                                            ${escapeHTML(
                                                caseItem.status ||
                                                "OPEN"
                                            )}

                                        </span>

                                    </td>


                                    <td>

                                        ${escapeHTML(
                                            caseItem.created_at ||
                                            "Unknown"
                                        )}

                                    </td>

                                </tr>

                            `
                            ).join("")}

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

            renderCaseDetail(
                data.case
            );

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
                        ← Back to Cases
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

        console.log("ðŸ”¥ Loading IP Intelligence...");

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
                    "ðŸ”¥ IP INTELLIGENCE:",
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
                                        âœ“
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
                                    âœ“
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

    }








