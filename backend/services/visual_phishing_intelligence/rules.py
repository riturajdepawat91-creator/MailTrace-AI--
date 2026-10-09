ANALYSIS_VERSION = "1.3.0"

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_WIDTH = 8000
MAX_HEIGHT = 8000
MAX_PIXELS = 40_000_000

MAX_QR_RESULTS = 20
MAX_PAYLOAD_CHARS = 8192
MAX_EVIDENCE = 100

MAX_URL_ANALYSES = 20
MAX_URL_FINDINGS = 20
MAX_URL_EVIDENCE_CHARS = 2048

# Visual-analysis bounds
MAX_COMPONENTS = 5000
MAX_CONTOURS = 2000
MAX_VISUAL_SIGNAL_SCORE = 40.0

VERDICT_CLEAN = "NO_VISUAL_THREAT_INDICATORS"
VERDICT_QR_PRESENT = "QR_CONTENT_DETECTED"
VERDICT_URL_CORRELATED = "QR_URL_THREAT_CORRELATED"
VERDICT_HIGH_RISK_QR = "HIGH_RISK_QR_PHISHING"
VERDICT_VISUAL_SUSPICION = "VISUAL_PHISHING_SIGNALS_DETECTED"
VERDICT_COMBINED_VISUAL_RISK = "COMBINED_VISUAL_PHISHING_RISK"
VERDICT_ANALYSIS_LIMITED = "ANALYSIS_LIMITED"
VERDICT_ERROR = "ANALYSIS_ERROR"

ACTION_REVIEW_QR_PAYLOAD = (
    "Review decoded QR payload with URL/IOC intelligence before any user interaction."
)

ACTION_REVIEW_VISUAL = (
    "Review the image as potential visual-phishing content."
)

ACTION_REVIEW_URL = (
    "Review the decoded QR URL and correlated URL-deception findings."
)

ACTION_REVIEW_VISUAL_SIGNALS = (
    "Review the image layout and visual phishing indicators manually."
)

ACTION_LIMITED = (
    "Treat the result as incomplete because one or more analysis limits were reached."
)

ACTION_CORRELATION_FAILURE = (
    "Review the QR payload manually because URL intelligence correlation failed."
)

SEVERITY_RANK = {
    "NONE": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}
