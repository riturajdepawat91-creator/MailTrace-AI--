/* ============================================================
   MAILTRACE AI - SOC MAP INTELLIGENCE ENGINE
   Phase 2
   This module DOES NOT replace existing map functionality.
   It enhances already working investigation maps.
============================================================ */

(function () {
    "use strict";

    const SOC_MAP_VERSION = "2.0.0";

    const state = {
        initialized: false,
        activeMapElement: null,
        observer: null,
        refreshTimer: null
    };

    // --------------------------------------------------------
    // SAFE TEXT EXTRACTION
    // --------------------------------------------------------

    function cleanText(value) {
        return String(value || "")
            .replace(/\s+/g, " ")
            .trim();
    }

    function escapeHtml(value) {
        return String(value || "")
            .replace(/[&<>"']/g, function (character) {
                return {
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#039;"
                }[character];
            });
    }

    // --------------------------------------------------------
    // FIND ACTIVE MAP
    // --------------------------------------------------------

    function findMapElement() {

        const selectors = [
            ".ip-intelligence-leaflet-map",
            ".ip-location-map",
            ".leaflet-container",
            ".report-map-canvas"
        ];

        for (const selector of selectors) {

            const elements = document.querySelectorAll(selector);

            for (const element of elements) {

                if (
                    element.offsetWidth > 100 &&
                    element.offsetHeight > 100
                ) {
                    return element;
                }

            }

        }

        return null;
    }

    // --------------------------------------------------------
    // FIND MAP MODAL / CONTAINER
    // --------------------------------------------------------

    function findMapContainer(mapElement) {

        if (!mapElement) return null;

        return (
            mapElement.closest(
                ".ip-intelligence-map-modal"
            ) ||
            mapElement.closest(
                ".ip-map-modal"
            ) ||
            mapElement.closest(
                ".modal"
            ) ||
            mapElement.parentElement
        );
    }

    // --------------------------------------------------------
    // EXTRACT INTELLIGENCE
    // --------------------------------------------------------

    function extractIntelligence(container) {

        const text = cleanText(
            container ? container.innerText : document.body.innerText
        );

        const ipMatch = text.match(
            /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/
        );

        const coordinateMatch = text.match(
            /(-?\d{1,2}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)/
        );

        let ip = ipMatch ? ipMatch[0] : "Unknown";

        let coordinates = "Unavailable";

        if (coordinateMatch) {
            coordinates =
                coordinateMatch[1] +
                ", " +
                coordinateMatch[2];
        }

        let location = "Unknown location";

        const locationCandidates = [
            /(?:Location|City)\s*[:\-]?\s*([A-Za-z\s,\-]+)/i,
            /([A-Za-z\s]+,\s*[A-Za-z\s]+,\s*[A-Za-z\s]+)/i
        ];

        for (const pattern of locationCandidates) {

            const match = text.match(pattern);

            if (match && cleanText(match[1]).length > 2) {
                location = cleanText(match[1]);
                break;
            }

        }

        return {
            ip,
            coordinates,
            location
        };
    }

    // --------------------------------------------------------
    // IP CLASSIFICATION
    // --------------------------------------------------------

    function classifyIp(ip) {

        if (!ip || ip === "Unknown") {
            return {
                type: "UNKNOWN",
                severity: "UNKNOWN",
                score: 0,
                label: "Unknown"
            };
        }

        if (
            ip === "127.0.0.1" ||
            ip.startsWith("127.")
        ) {
            return {
                type: "LOOPBACK",
                severity: "LOW",
                score: 0,
                label: "Loopback Infrastructure"
            };
        }

        if (
            ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
        ) {
            return {
                type: "PRIVATE",
                severity: "LOW",
                score: 5,
                label: "Private Infrastructure"
            };
        }

        return {
            type: "PUBLIC",
            severity: "LOW",
            score: 10,
            label: "Public Internet Infrastructure"
        };
    }

    // --------------------------------------------------------
    // COPY TO CLIPBOARD
    // --------------------------------------------------------

    async function copyValue(value, button) {

        try {

            await navigator.clipboard.writeText(value);

            const original = button.textContent;

            button.textContent = "Copied";

            setTimeout(function () {
                button.textContent = original;
            }, 1400);

        } catch (error) {

            console.warn(
                "[SOC MAP] Clipboard copy failed",
                error
            );

        }

    }

    // --------------------------------------------------------
    // CREATE HUD
    // --------------------------------------------------------

    function createHud(container, intelligence, classification) {

        if (!container) return;

        const existing = container.querySelector(
            ".mailtrace-soc-map-hud"
        );

        if (existing) {

            existing.remove();

        }

        const hud = document.createElement("section");

        hud.className = "mailtrace-soc-map-hud";

        hud.setAttribute(
            "data-soc-map-version",
            SOC_MAP_VERSION
        );

        hud.innerHTML = `
            <div class="soc-map-hud-header">

                <div class="soc-map-hud-title">

                    <span class="soc-map-live-dot"></span>

                    <div>

                        <span class="soc-map-eyebrow">
                            SOC GEOLOCATION INTELLIGENCE
                        </span>

                        <strong>
                            Investigation Context
                        </strong>

                    </div>

                </div>

                <div class="soc-map-status">
                    LIVE ANALYSIS
                </div>

            </div>

            <div class="soc-map-grid">

                <article class="soc-map-card">

                    <span>OBSERVED IP</span>

                    <strong>
                        ${escapeHtml(intelligence.ip)}
                    </strong>

                    <button
                        type="button"
                        class="soc-map-copy"
                        data-copy="${escapeHtml(intelligence.ip)}"
                    >
                        Copy IP
                    </button>

                </article>

                <article class="soc-map-card">

                    <span>INFRASTRUCTURE TYPE</span>

                    <strong>
                        ${escapeHtml(classification.type)}
                    </strong>

                    <small>
                        ${escapeHtml(classification.label)}
                    </small>

                </article>

                <article class="soc-map-card">

                    <span>RISK BASELINE</span>

                    <strong class="soc-risk-${classification.severity.toLowerCase()}">
                        ${escapeHtml(classification.severity)}
                    </strong>

                    <small>
                        Score ${classification.score}/100
                    </small>

                </article>

                <article class="soc-map-card">

                    <span>GEOLOCATION</span>

                    <strong>
                        ${escapeHtml(intelligence.location)}
                    </strong>

                    <small>
                        ${escapeHtml(intelligence.coordinates)}
                    </small>

                </article>

            </div>

            <div class="soc-map-actions">

                <button
                    type="button"
                    class="soc-map-action"
                    data-soc-copy-ip
                >
                    Copy IOC
                </button>

                <button
                    type="button"
                    class="soc-map-action"
                    data-soc-copy-coordinates
                >
                    Copy Coordinates
                </button>

                <button
                    type="button"
                    class="soc-map-action"
                    data-soc-refresh-map
                >
                    Refresh Map
                </button>

            </div>

            <div class="soc-map-footer">

                <span>
                    Intelligence Version ${SOC_MAP_VERSION}
                </span>

                <span>
                    Source: Investigation Geolocation Data
                </span>

                <span>
                    Confidence: Location-level enrichment
                </span>

            </div>
        `;

        const mapElement = findMapElement();

        if (
            mapElement &&
            mapElement.parentElement
        ) {

            mapElement.parentElement.insertBefore(
                hud,
                mapElement
            );

        } else {

            container.prepend(hud);

        }

        bindHudEvents(
            hud,
            intelligence,
            mapElement
        );

    }

    // --------------------------------------------------------
    // HUD EVENTS
    // --------------------------------------------------------

    function bindHudEvents(
        hud,
        intelligence,
        mapElement
    ) {

        const copyButtons = hud.querySelectorAll(
            "[data-copy]"
        );

        copyButtons.forEach(function (button) {

            button.addEventListener(
                "click",
                function () {

                    copyValue(
                        button.dataset.copy,
                        button
                    );

                }
            );

        });

        const copyIpButton = hud.querySelector(
            "[data-soc-copy-ip]"
        );

        if (copyIpButton) {

            copyIpButton.addEventListener(
                "click",
                function () {

                    copyValue(
                        intelligence.ip,
                        copyIpButton
                    );

                }
            );

        }

        const copyCoordinatesButton =
            hud.querySelector(
                "[data-soc-copy-coordinates]"
            );

        if (copyCoordinatesButton) {

            copyCoordinatesButton.addEventListener(
                "click",
                function () {

                    copyValue(
                        intelligence.coordinates,
                        copyCoordinatesButton
                    );

                }
            );

        }

        const refreshButton =
            hud.querySelector(
                "[data-soc-refresh-map]"
            );

        if (refreshButton) {

            refreshButton.addEventListener(
                "click",
                function () {

                    window.dispatchEvent(
                        new Event("resize")
                    );

                    if (mapElement) {

                        mapElement.style.display = "none";

                        requestAnimationFrame(
                            function () {

                                mapElement.style.display = "";

                                window.dispatchEvent(
                                    new Event("resize")
                                );

                            }
                        );

                    }

                    const original =
                        refreshButton.textContent;

                    refreshButton.textContent =
                        "Refreshed";

                    setTimeout(function () {

                        refreshButton.textContent =
                            original;

                    }, 1000);

                }
            );

        }

    }

    // --------------------------------------------------------
    // ENHANCE MAP
    // --------------------------------------------------------

    function enhanceMap() {

        const mapElement = findMapElement();

        if (!mapElement) return;

        if (
            state.activeMapElement === mapElement &&
            mapElement.dataset.socEnhanced === "true"
        ) {
            return;
        }

        const container =
            findMapContainer(mapElement);

        if (!container) return;

        const intelligence =
            extractIntelligence(container);

        const classification =
            classifyIp(intelligence.ip);

        createHud(
            container,
            intelligence,
            classification
        );

        mapElement.dataset.socEnhanced = "true";

        state.activeMapElement = mapElement;

        requestAnimationFrame(function () {

            window.dispatchEvent(
                new Event("resize")
            );

        });

        console.info(
            "[MAILTRACE SOC MAP] Enhanced",
            intelligence
        );

    }

    // --------------------------------------------------------
    // WATCH DOM FOR MAP OPENING
    // --------------------------------------------------------

    function startObserver() {

        if (state.observer) {

            state.observer.disconnect();

        }

        state.observer =
            new MutationObserver(function () {

                clearTimeout(state.refreshTimer);

                state.refreshTimer =
                    setTimeout(
                        enhanceMap,
                        120
                    );

            });

        state.observer.observe(
            document.body,
            {
                childList: true,
                subtree: true
            }
        );

    }

    // --------------------------------------------------------
    // ESC KEY SUPPORT
    // --------------------------------------------------------

    function installKeyboardSupport() {

        document.addEventListener(
            "keydown",
            function (event) {

                if (event.key !== "Escape") return;

                const closeButton =
                    document.querySelector(
                        ".ip-map-close, .map-close, .modal-close"
                    );

                if (
                    closeButton &&
                    closeButton.offsetParent !== null
                ) {

                    closeButton.click();

                }

            }
        );

    }

    // --------------------------------------------------------
    // INITIALIZE
    // --------------------------------------------------------

    function initialize() {

        if (state.initialized) return;

        state.initialized = true;

        startObserver();

        installKeyboardSupport();

        setTimeout(
            enhanceMap,
            500
        );

        console.info(
            "[MAILTRACE SOC MAP] Phase 2 initialized"
        );

    }

    if (
        document.readyState === "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            initialize
        );

    } else {

        initialize();

    }

    window.MailTraceSOCMap = {
        version: SOC_MAP_VERSION,
        enhance: enhanceMap,
        getState: function () {
            return {
                version: SOC_MAP_VERSION,
                initialized: state.initialized,
                activeMap: Boolean(
                    state.activeMapElement
                )
            };
        }
    };

})();