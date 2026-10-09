/* =========================================================
   MAILTRACE AI — REAL-TIME THREAT INTELLIGENCE ENGINE
   STEP 4 — API → UI CONNECTION
   ========================================================= */

(function () {

    "use strict";

    const API_URL =
        "http://127.0.0.1:8000/api/threat-intelligence/live";

    const STREAM_URL =
        "http://127.0.0.1:8000/api/threat-intelligence/stream";

    const REFRESH_INTERVAL = 5000;

    let refreshTimer = null;
    let eventStream = null;
    let lastEvents = [];
    let isFetching = false;


    /* =========================================================
       DOM HELPERS
       ========================================================= */

    function getElement(id) {
        return document.getElementById(id);
    }


    /* =========================================================
       THREAT LEVEL
       ========================================================= */

    function calculateThreatLevel(events) {

        events = Array.isArray(events) ? events : [];

        if (!Array.isArray(events) || events.length === 0) {
            return {
                label: "Low",
                score: 0,
                severity: "LOW"
            };
        }

        let highestScore = 0;
        let highestSeverity = "LOW";

        events.forEach(function (event) {

            const score = Number(event.threat_score || 0);

            const severity =
                String(event.severity || "LOW").toUpperCase();

            if (score > highestScore) {
                highestScore = score;
            }

            const rank = {
                LOW: 1,
                MEDIUM: 2,
                HIGH: 3,
                CRITICAL: 4
            };

            if (
                (rank[severity] || 1) >
                (rank[highestSeverity] || 1)
            ) {
                highestSeverity = severity;
            }

        });

        let label = "Low";

        if (highestSeverity === "CRITICAL" || highestScore >= 90) {
            label = "Critical";
        }
        else if (highestSeverity === "HIGH" || highestScore >= 70) {
            label = "High";
        }
        else if (highestSeverity === "MEDIUM" || highestScore >= 40) {
            label = "Medium";
        }

        return {
            label: label,
            score: highestScore,
            severity: highestSeverity
        };
    }


    /* =========================================================
       UPDATE THREAT LEVEL CARD
       ========================================================= */

    function updateThreatLevel(events) {

        const valueElement =
            getElement("threatLevelValue");

        const updatedElement =
            getElement("threatLastUpdated");

        const statusDot =
            document.querySelector(
                ".threat-level-status .status-dot"
            );

        const level =
            calculateThreatLevel(events);

        if (valueElement) {
            valueElement.textContent = level.label;
        }

        if (updatedElement) {
            updatedElement.textContent = "just now";
        }

        if (statusDot) {
            statusDot.style.background = "#20e6a0";
            statusDot.style.boxShadow =
                "0 0 7px rgba(32, 230, 160, 0.8)";
        }

        console.log(
            "[MailTrace] Threat level updated:",
            level
        );
    }


    /* =========================================================
       UPDATE MAP NODES
       ========================================================= */

    function updateMapNodes(events) {

        const nodes =
            document.querySelectorAll(
                ".map-threat-node"
            );

        if (!nodes.length) {
            return;
        }

        const safeEvents =
            Array.isArray(events)
                ? events
                : [];

        /*
         * Reset nodes first.
         */

        nodes.forEach(function (node) {

            node.classList.remove(
                "threat-low",
                "threat-medium",
                "threat-high",
                "threat-critical"
            );

            node.style.background = "#00d9ff";

            node.style.boxShadow =
                "0 0 5px #00d9ff, " +
                "0 0 13px rgba(0, 217, 255, 0.85)";
        });


        /*
         * Use the first six live events as
         * visual threat activity indicators.
         */

        const activeEvents =
            safeEvents.slice(0, nodes.length);

        activeEvents.forEach(function (event, index) {

            const node = nodes[index];

            if (!node) {
                return;
            }

            const score =
                Number(event.threat_score || 0);

            const severity =
                String(event.severity || "LOW")
                    .toUpperCase();

            let state = "low";

            if (
                severity === "CRITICAL" ||
                score >= 90
            ) {
                state = "critical";

                node.style.background = "#ff3158";

                node.style.boxShadow =
                    "0 0 6px #ff3158, " +
                    "0 0 16px rgba(255,49,88,0.95)";
            }
            else if (
                severity === "HIGH" ||
                score >= 70
            ) {
                state = "high";

                node.style.background = "#ff7a00";

                node.style.boxShadow =
                    "0 0 6px #ff7a00, " +
                    "0 0 16px rgba(255,122,0,0.9)";
            }
            else if (
                severity === "MEDIUM" ||
                score >= 40
            ) {
                state = "medium";

                node.style.background = "#ffab00";

                node.style.boxShadow =
                    "0 0 6px #ffab00, " +
                    "0 0 16px rgba(255,171,0,0.9)";
            }

            node.classList.add(
                "threat-" + state
            );

            node.setAttribute(
                "data-threat-score",
                String(score)
            );

            node.setAttribute(
                "data-severity",
                severity
            );

            node.setAttribute(
                "data-investigation-id",
                event.investigation_id || ""
            );

            node.setAttribute(
                "title",
                (event.subject || "Threat event") +
                " — " +
                severity +
                " — Score " +
                score
            );
        });


        /*
         * Pulse active nodes.
         */

        nodes.forEach(function (node, index) {

            if (index < activeEvents.length) {

                node.style.animation =
                    "mailtraceThreatPulse 1.8s " +
                    "ease-in-out infinite";

            }
            else {

                node.style.animation = "none";

            }

        });


        console.log(
            "[MailTrace] Map nodes updated:",
            activeEvents.length
        );
    }


    /* =========================================================
       UPDATE LAST UPDATED STATE
       ========================================================= */

    function updateLastUpdated() {

        const element =
            getElement("threatLastUpdated");

        if (!element) {
            return;
        }

        element.textContent = "just now";
    }


    /* =========================================================
       ERROR STATE
       ========================================================= */

    function showErrorState() {

        const valueElement =
            getElement("threatLevelValue");

        const updatedElement =
            getElement("threatLastUpdated");

        const statusDot =
            document.querySelector(
                ".threat-level-status .status-dot"
            );

        if (valueElement) {
            valueElement.textContent = "Offline";
        }

        if (updatedElement) {
            updatedElement.textContent =
                "connection error";
        }

        if (statusDot) {
            statusDot.style.background = "#ff3158";

            statusDot.style.boxShadow =
                "0 0 7px rgba(255,49,88,0.8)";
        }
    }


    /* =========================================================
       FETCH LIVE THREAT INTELLIGENCE
       ========================================================= */

    function applyLiveThreatData(data) {
        if (!data || data.success !== true) {
            throw new Error("Invalid live threat intelligence response.");
        }

        const events = Array.isArray(data.events) ? data.events : [];
        lastEvents = events;
        window.MailTraceRealtimeThreats = {
            success: true,
            status: data.status || "operational",
            count: Number(data.count || events.length),
            events: events,
            updatedAt: new Date().toISOString()
        };

        updateThreatLevel(events);
        updateMapNodes(events);
        updateLastUpdated();
        document.dispatchEvent(new CustomEvent(
            "mailtrace:realtime-threat-update",
            { detail: window.MailTraceRealtimeThreats }
        ));
    }

    async function fetchLiveThreatIntelligence() {

        if (isFetching) {
            return;
        }

        isFetching = true;

        try {

            const response =
                await fetch(API_URL, {
                    method: "GET",

                    headers: {
                        "Accept": "application/json"
                    },

                    cache: "no-store"
                });


            if (!response.ok) {

                throw new Error(
                    "Live threat API returned HTTP " +
                    response.status
                );

            }


            const data =
                await response.json();


            applyLiveThreatData(data);


            console.log(
                "[MailTrace] Live threat intelligence updated:",
                {
                    count: window.MailTraceRealtimeThreats.count,
                    status: data.status,
                    latest:
                        window.MailTraceRealtimeThreats.events[0] || null
                }
            );

        }
        catch (error) {

            console.error(
                "[MailTrace] Real-time threat intelligence error:",
                error
            );


            window.MailTraceRealtimeThreats = {

                success: false,

                status: "error",

                count: 0,

                events: [],

                error: error.message,

                updatedAt:
                    new Date().toISOString()

            };


            showErrorState();


            document.dispatchEvent(
                new CustomEvent(
                    "mailtrace:realtime-threat-error",
                    {
                        detail:
                            window.MailTraceRealtimeThreats
                    }
                )
            );

        }
        finally {

            isFetching = false;

        }

    }


    /* =========================================================
       START MONITORING
       ========================================================= */

    function startRealtimeThreatMonitoring() {

        stopRealtimeThreatMonitoring();


        /*
         * Initial live request.
         */

        fetchLiveThreatIntelligence();

        if ("EventSource" in window) {
            eventStream = new EventSource(STREAM_URL);
            eventStream.onmessage = function (message) {
                try {
                    applyLiveThreatData(JSON.parse(message.data));
                } catch (error) {
                    console.error("[MailTrace] Invalid live event:", error);
                }
            };
            eventStream.onopen = function () {
                if (refreshTimer !== null) {
                    clearInterval(refreshTimer);
                    refreshTimer = null;
                }
            };
            eventStream.onerror = function () {
                if (refreshTimer === null) {
                    refreshTimer = setInterval(
                        fetchLiveThreatIntelligence,
                        REFRESH_INTERVAL
                    );
                }
            };
        } else {
            refreshTimer = setInterval(
                fetchLiveThreatIntelligence,
                REFRESH_INTERVAL
            );
        }


        console.log(
            "[MailTrace] Real-time threat monitoring started."
        );

    }


    /* =========================================================
       STOP MONITORING
       ========================================================= */

    function stopRealtimeThreatMonitoring() {

        if (eventStream !== null) {
            eventStream.close();
            eventStream = null;
        }

        if (refreshTimer !== null) {

            clearInterval(refreshTimer);

            refreshTimer = null;

        }

    }


    /* =========================================================
       PUBLIC API
       ========================================================= */

    window.MailTraceRealtimeThreatEngine = {

        start:
            startRealtimeThreatMonitoring,

        stop:
            stopRealtimeThreatMonitoring,

        refresh:
            fetchLiveThreatIntelligence,

        getEvents:
            function () {
                return lastEvents;
            }

    };


    /* =========================================================
       CSS ANIMATION
       ========================================================= */

    if (
        !document.getElementById(
            "mailtraceRealtimeThreatAnimation"
        )
    ) {

        const style =
            document.createElement("style");

        style.id =
            "mailtraceRealtimeThreatAnimation";

        style.textContent = `
            @keyframes mailtraceThreatPulse {
                0%, 100% {
                    transform: scale(1);
                    opacity: 0.85;
                }

                50% {
                    transform: scale(1.45);
                    opacity: 1;
                }
            }
        `;

        document.head.appendChild(style);

    }


    /* =========================================================
       AUTO START
       ========================================================= */

    document.addEventListener(
        "DOMContentLoaded",
        function () {

            startRealtimeThreatMonitoring();

        }
    );


    /* =========================================================
       CLEANUP
       ========================================================= */

    window.addEventListener(
        "beforeunload",
        function () {

            stopRealtimeThreatMonitoring();

        }
    );


})();
