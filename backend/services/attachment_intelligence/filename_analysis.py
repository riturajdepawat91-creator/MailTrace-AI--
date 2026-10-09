"""
Attachment Intelligence Engine - Advanced Filename Analysis

Static filename intelligence for deceptive naming, Unicode manipulation,
extension masquerading, social-engineering cues, platform-specific tricks,
and filename-level risk correlation.

This module is intentionally non-executing: it inspects the filename only.
"""

from __future__ import annotations

import math
import os
import re
import unicodedata
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".jar", ".reg", ".lnk", ".application", ".gadget",
    ".psm1", ".psd1", ".psc1", ".msc", ".msix", ".appx", ".appxbundle",
    ".vxd", ".sys", ".ocx", ".scrx",
}

SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".psc1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp",
    ".jar", ".lnk", ".application", ".gadget", ".msix", ".appx", ".sys",
    ".ocx", ".vxd",
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".rtf", ".csv", ".odt", ".ods", ".odp", ".pages", ".numbers",
    ".key", ".epub", ".xps",
}

MACRO_CAPABLE_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".xlam", ".xltm", ".potm", ".dotm",
    ".ppsm", ".ppam",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz",
    ".tbz2", ".iso", ".img", ".cab", ".arj", ".zst",
}

SUSPICIOUS_KEYWORDS = {
    "invoice", "payment", "urgent", "password", "verify", "verification",
    "account", "bank", "statement", "receipt", "salary", "payroll",
    "confidential", "security", "update", "document", "scan", "shared",
    "refund", "transaction", "wire", "transfer", "tax", "claim", "notice",
    "overdue", "locked", "suspend", "suspended", "login", "credential",
    "reset", "unlock", "signature", "esign", "contract", "purchase",
}

MULTILINGUAL_KEYWORD_ALIASES = {
    "factura": "invoice", "pago": "payment", "urgente": "urgent",
    "contraseña": "password", "cuenta": "account", "banco": "bank",
    "verificar": "verify", "seguridad": "security", "recibo": "receipt",
    "reembolso": "refund", "impuesto": "tax",
    "facture": "invoice", "paiement": "payment", "urgent": "urgent",
    "motdepasse": "password", "compte": "account", "verifier": "verify",
    "securite": "security",
    "rechnung": "invoice", "zahlung": "payment", "passwort": "password",
    "konto": "account", "sicherheit": "security", "quittung": "receipt",
    "factura": "invoice", "pagamento": "payment", "senha": "password",
    "conta": "account", "verificar": "verify", "seguranca": "security",
    "contabil": "account",
}

# High-signal combinations; unlike simple keyword matching these require context.
SOCIAL_ENGINEERING_PHRASES = {
    "urgent_payment": ("urgent", "payment"),
    "verify_account": ("verify", "account"),
    "password_reset": ("password", "reset"),
    "account_locked": ("account", "locked"),
    "security_update": ("security", "update"),
    "overdue_invoice": ("overdue", "invoice"),
    "tax_notice": ("tax", "notice"),
    "refund_claim": ("refund", "claim"),
    "wire_transfer": ("wire", "transfer"),
    "payment_receipt": ("payment", "receipt"),
}

# Common high-value brands/entities seen in enterprise phishing. Matching is
# deliberately conservative: it fires on a brand token plus a deceptive cue.
BRAND_TOKENS = {
    "microsoft", "office365", "office", "outlook", "onedrive", "sharepoint",
    "adobe", "docusign", "dropbox", "google", "gmail", "apple", "icloud",
    "paypal", "amazon", "linkedin", "microsoft365", "zoom", "slack",
    "teams", "github", "gitlab", "dhl", "fedex", "ups",
}

DECEPTIVE_CUES = {
    "login", "signin", "verify", "verification", "password", "security",
    "account", "reset", "unlock", "secure", "update", "invoice", "payment",
    "document", "shared", "download", "signature", "notification",
}

RTL_OVERRIDE_CHARACTERS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

ZERO_WIDTH_CHARACTERS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
}

# A compact confusable set aimed at common Latin-lookalike attacks.
CONFUSABLES = {
    # Cyrillic lookalikes
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0438": "n", "\u0458": "j", "\u043a": "k", "\u043c": "m",
    "\u0442": "t", "\u0432": "b", "\u043d": "h", "\u043b": "l",
    "\u0491": "g", "\u04cf": "p", "\u04bb": "h",
    # Latin lookalikes
    "\u0131": "i", "\u017f": "s",
    # Greek lookalikes
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    "\u03c7": "x", "\u03c5": "y", "\u03bd": "v", "\u03ba": "k",
    "\u03bc": "m", "\u03c4": "t", "\u03b9": "i",
    # Full-width Latin
    "\uff45": "e", "\uff4f": "o", "\uff41": "a", "\uff49": "i",
}

LEET_TRANSLATION = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g",
})

WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

# Unicode / control categories that are useful to expose separately.
INVISIBLE_CATEGORIES = {"Cf", "Cc", "Cs", "Co"}
SEPARATOR_PATTERN = re.compile(r"[\u0020\t\u00a0\u1680\u180e\u2000-\u200a\u202f\u205f\u3000]+")
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
DOMAIN_LIKE_PATTERN = re.compile(r"(?:[a-z0-9-]+\.){1,8}[a-z]{2,63}$", re.I)
KNOWN_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "ai", "app",
    "dev", "info", "biz", "me", "in", "uk", "de", "fr", "jp", "cn",
    "au", "ca", "us", "xyz", "online", "site", "tech", "cloud",
}

COMMON_BUSINESS_TERMS = {
    "normal", "business", "report", "document", "documents", "quarterly",
    "annual", "monthly", "weekly", "summary", "statement", "meeting",
    "minutes", "project", "proposal", "contract", "purchase", "order",
    "invoice", "receipt", "letter", "schedule", "calendar", "budget",
    "financial", "finance", "audit", "policy", "presentation", "research",
    "draft", "final", "version", "backup", "archive", "export", "data",
    "results", "analysis", "form", "application", "resume", "cv", "notes",
    "photo", "image", "scan", "shared", "team",
}

SCRIPT_MARKERS = {
    "LATIN": "Latin", "CYRILLIC": "Cyrillic", "GREEK": "Greek",
    "ARABIC": "Arabic", "HEBREW": "Hebrew", "DEVANAGARI": "Devanagari",
    "BENGALI": "Bengali", "THAI": "Thai", "HIRAGANA": "Hiragana",
    "KATAKANA": "Katakana", "HANGUL": "Hangul", "ARMENIAN": "Armenian",
    "GEORGIAN": "Georgian",
}

NONCHARACTER_RANGES = ((0xFDD0, 0xFDEF), (0xFFFE, 0xFFFF))


@dataclass
class FilenameFinding:
    """Represents one suspicious filename characteristic."""

    rule_id: str
    title: str
    description: str
    severity: str
    score: float
    evidence: Dict[str, object] = field(default_factory=dict)
    confidence: float = 0.0
    category: str = "filename"

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": round(float(self.score), 2),
            "confidence": round(float(self.confidence), 3),
            "category": self.category,
            "evidence": self.evidence,
        }


@dataclass
class FilenameAnalysisResult:
    """Complete result of filename intelligence analysis."""

    original_filename: str
    normalized_filename: str
    extension: str
    findings: List[FilenameFinding] = field(default_factory=list)
    risk_score: float = 0.0
    normalized_for_comparison: str = ""
    metadata: Dict[str, object] = field(default_factory=dict)
    analysis_version: str = "5.0.0"

    def add_finding(self, finding: FilenameFinding) -> None:
        finding.score = max(0.0, min(100.0, float(finding.score)))
        finding.confidence = max(0.0, min(1.0, float(finding.confidence)))
        self.findings.append(finding)
        self.risk_score = min(100.0, self.risk_score + finding.score)

    def to_dict(self) -> Dict[str, object]:
        return {
            "analysis_version": self.analysis_version,
            "original_filename": self.original_filename,
            "normalized_filename": self.normalized_filename,
            "normalized_for_comparison": self.normalized_for_comparison,
            "extension": self.extension,
            "risk_score": round(self.risk_score, 2),
            "metadata": self.metadata,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def normalize_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")
    return unicodedata.normalize("NFKC", filename).strip()


def get_extension(filename: str) -> str:
    """Return the final extension, normalized for benign trailing-dot/space tricks."""
    if not isinstance(filename, str):
        raise TypeError("filename must be a string")
    basename = os.path.basename(filename)
    # Windows commonly ignores trailing spaces and dots in legacy path APIs.
    trimmed = basename.rstrip(" .\t\r\n")
    return os.path.splitext(trimmed)[1].lower()


def get_all_extensions(filename: str) -> List[str]:
    basename = os.path.basename(filename).rstrip(" .\t\r\n")
    parts = basename.split(".")
    if len(parts) <= 1:
        return []
    return [f".{part.lower()}" for part in parts[1:] if part]


def contains_rtl_override(filename: str) -> List[str]:
    return [character for character in filename if character in RTL_OVERRIDE_CHARACTERS]


def contains_control_characters(filename: str) -> List[str]:
    suspicious: List[str] = []
    for character in filename:
        category = unicodedata.category(character)
        if category.startswith("C") and character not in ("\n", "\r", "\t"):
            suspicious.append(character)
    return suspicious


def _unicode_confusables(filename: str) -> List[Dict[str, str]]:
    return [
        {"character": char, "codepoint": f"U+{ord(char):04X}", "maps_to": CONFUSABLES[char]}
        for char in filename if char in CONFUSABLES
    ]


def _comparison_form(filename: str) -> str:
    """Approximate ASCII comparison form for evasive naming analysis."""
    normalized = unicodedata.normalize("NFKC", filename).casefold()
    normalized = "".join(CONFUSABLES.get(ch, ch) for ch in normalized)
    normalized = normalized.translate(LEET_TRANSLATION)
    return normalized


def _tokenize(filename: str) -> List[str]:
    return TOKEN_PATTERN.findall(_comparison_form(filename))


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_mostly_random(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]", "", value.casefold())
    if len(compact) < 16:
        return False
    digits = sum(ch.isdigit() for ch in compact)
    letters = sum(ch.isalpha() for ch in compact)
    unique_ratio = len(set(compact)) / len(compact)
    entropy = _shannon_entropy(compact)
    alpha_chunks = [
        chunk for chunk in TOKEN_PATTERN.findall(value.casefold())
        if chunk.isalpha() and len(chunk) >= 4
    ]
    return (
        unique_ratio >= 0.68
        and entropy >= 3.55
        and digits >= 4
        and letters >= 2
        and len(alpha_chunks) <= 1
        and (not alpha_chunks or len(alpha_chunks[0]) <= 4)
    )


def _stem_tokens(filename: str) -> List[str]:
    stem = os.path.splitext(filename.rstrip(" .\t\r\n"))[0]
    return TOKEN_PATTERN.findall(_comparison_form(stem))


def _script_groups(filename: str) -> List[str]:
    groups = set()
    for char in filename:
        if not unicodedata.category(char).startswith("L"):
            continue
        name = unicodedata.name(char, "")
        for marker, label in SCRIPT_MARKERS.items():
            if marker in name:
                groups.add(label)
                break
    return sorted(groups)


def _is_noncharacter(char: str) -> bool:
    cp = ord(char)
    return any(start <= cp <= end for start, end in NONCHARACTER_RANGES) or (cp & 0xFFFF) in (0xFFFE, 0xFFFF)


def _fuzzy_brand_match(tokens: List[str]) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    for token in tokens:
        if len(token) < 5:
            continue
        for brand in BRAND_TOKENS:
            if token == brand:
                continue
            ratio = SequenceMatcher(None, token, brand).ratio()
            if 0.84 <= ratio < 1.0:
                matches.append({"token": token, "brand": brand, "similarity": round(ratio, 3)})
    return sorted(matches, key=lambda item: (-float(item["similarity"]), str(item["brand"])))


def _extension_chain(filename: str) -> List[str]:
    return get_all_extensions(filename)


def _unicode_skeleton(filename: str) -> str:
    """Build a conservative comparison skeleton for lookalike analysis."""
    normalized = unicodedata.normalize("NFKD", filename).casefold()
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    normalized = "".join(CONFUSABLES.get(ch, ch) for ch in normalized)
    return normalized.translate(LEET_TRANSLATION)


def _has_path_traversal(filename: str) -> bool:
    return bool(re.search(r"(?:^|[\\/])\.\.(?:[\\/]|$)", filename))


def _has_device_namespace(filename: str) -> bool:
    lowered = filename.casefold()
    return lowered.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./"))


def _shell_meta_characters(filename: str) -> List[str]:
    return sorted(set(ch for ch in filename if ch in "|&;<>()$`"))


def _semantic_business_context(tokens: List[str]) -> List[str]:
    return sorted({token for token in tokens if token in COMMON_BUSINESS_TERMS})


def _risk_recommendation(severity: str) -> str:
    return {
        "CRITICAL": "QUARANTINE_AND_ANALYST_REVIEW",
        "HIGH": "HOLD_FOR_SECURITY_REVIEW",
        "MEDIUM": "ENHANCED_CONTENT_INSPECTION",
        "LOW": "MONITOR_WITH_CONTEXT",
    }.get(severity.upper(), "NO_ADDITIONAL_ACTION")


def _add(
    result: FilenameAnalysisResult,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    score: float,
    confidence: float,
    evidence: Dict[str, object],
    category: str = "filename",
) -> None:
    result.add_finding(FilenameFinding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        score=score,
        confidence=confidence,
        evidence=evidence,
        category=category,
    ))


def analyze_filename(filename: str) -> FilenameAnalysisResult:
    """Perform layered, static filename intelligence analysis."""
    normalized = normalize_filename(filename)
    raw_basename = os.path.basename(filename)
    basename = os.path.basename(normalized)
    extension = get_extension(normalized)
    comparison = _comparison_form(basename)
    tokens = _tokenize(basename)
    token_set = set(tokens)
    chain = _extension_chain(basename)
    raw_casefold = filename.casefold()
    url_scheme_like = bool(re.match(r"^(?:https?|ftp)://", raw_casefold))
    www_like = bool(re.match(r"^www\.", raw_casefold))
    domain_marker_like = bool(
        re.search(r"\b[a-z0-9-]+\.[a-z]{2,63}(?:\b|\.)", raw_casefold)
    )

    result = FilenameAnalysisResult(
        original_filename=filename,
        normalized_filename=normalized,
        extension=extension,
        normalized_for_comparison=comparison,
        metadata={
            "basename_length": len(basename),
            "raw_basename_length": len(raw_basename),
            "unicode_codepoints": len(basename),
            "extension_count": len(chain),
            "token_count": len(tokens),
            "entropy": round(_shannon_entropy(basename), 3),
            "utf16_code_units": len(basename.encode("utf-16-le", errors="surrogatepass")) // 2,
        },
    )

    # 0. Input integrity and canonicalization anomalies.
    if "\x00" in filename:
        _add(result, "FILENAME_NUL_BYTE", "NUL byte embedded in filename",
             "NUL bytes are invalid in ordinary filesystem path components and can cause truncation or parser discrepancies.",
             "CRITICAL", 35.0, 0.999, {"count": filename.count("\x00")}, "platform")

    surrogate_chars = [c for c in filename if 0xD800 <= ord(c) <= 0xDFFF]
    if surrogate_chars:
        _add(result, "FILENAME_INVALID_SURROGATE", "Unpaired Unicode surrogate detected",
             "Surrogate code points are not valid standalone Unicode characters and may break parsing, logging, or normalization boundaries.",
             "HIGH", 24.0, 0.995, {"codepoints": [f"U+{ord(c):04X}" for c in surrogate_chars]}, "unicode")

    noncharacters = [c for c in filename if _is_noncharacter(c)]
    if noncharacters:
        _add(result, "FILENAME_UNICODE_NONCHARACTER", "Unicode noncharacter detected",
             "Unicode noncharacters are reserved code points that may be mishandled by parsers and transport systems.",
             "MEDIUM", 16.0, 0.97, {"codepoints": [f"U+{ord(c):04X}" for c in noncharacters]}, "unicode")

    if filename != filename.lstrip(" \t"):
        _add(result, "FILENAME_LEADING_WHITESPACE", "Leading whitespace detected",
             "Leading whitespace can reduce visual clarity and create discrepancies between displayed and canonical names.",
             "LOW", 5.0, 0.92, {"count": len(filename) - len(filename.lstrip(" \t"))}, "platform")

    result.metadata["normalization_changed"] = normalized != filename
    if normalized != filename:
        raw_ext = get_extension(filename)
        normalized_ext = get_extension(normalized)
        normalization_security_change = (
            raw_ext != normalized_ext
            or len(contains_rtl_override(filename)) != len(contains_rtl_override(normalized))
            or any(ch in filename for ch in ZERO_WIDTH_CHARACTERS)
        )
        if normalization_security_change:
            _add(result, "FILENAME_UNICODE_NORMALIZATION_CHANGE", "Unicode normalization changes security-relevant filename structure",
                 "Canonical Unicode normalization changes security-relevant filename structure and may create parser or comparison discrepancies.",
                 "MEDIUM", 10.0, 0.90, {"original": filename, "normalized": normalized, "raw_extension": raw_ext, "normalized_extension": normalized_ext}, "unicode")

    script_groups = _script_groups(filename)
    result.metadata["script_groups"] = script_groups

    # 1. Path / platform anomalies.
    if any(separator in filename for separator in ("/", "\\")):
        _add(result, "FILENAME_PATH_SEPARATOR", "Path separator present in supplied filename",
             "The filename contains path separators and should be treated as untrusted path input.",
             "MEDIUM", 12.0, 0.98, {"separators": [c for c in filename if c in "/\\"]}, "platform")

    if ":" in basename and re.search(r"^[A-Za-z]:", basename) is None:
        _add(result, "FILENAME_NTFS_ADS_PATTERN", "Alternate-data-stream style colon detected",
             "A colon in a Windows filename can be associated with alternate-data-stream semantics and path confusion.",
             "MEDIUM", 14.0, 0.90, {"filename": basename}, "platform")

    stripped_windows = raw_basename.rstrip(" .\t\r\n")
    if stripped_windows != raw_basename:
        _add(result, "FILENAME_TRAILING_SPACE_DOT", "Windows trailing space/dot trick detected",
             "Trailing spaces or dots may be ignored by Windows path handling and can create display/lookup discrepancies.",
             "HIGH", 22.0, 0.99, {"original_basename": raw_basename, "canonical_basename": stripped_windows}, "platform")

    stem = os.path.splitext(stripped_windows)[0].rstrip(" .").casefold()
    if stem in WINDOWS_RESERVED_NAMES:
        _add(result, "FILENAME_WINDOWS_RESERVED_NAME", "Windows reserved device name detected",
             "The stem matches a Windows reserved device name and is unusual for a legitimate attachment.",
             "HIGH", 20.0, 0.97, {"reserved_name": stem}, "platform")

    # 2. Unicode deception.
    rtl_chars = contains_rtl_override(filename)
    if rtl_chars:
        _add(result, "FILENAME_RTL_OVERRIDE", "Unicode bidirectional control detected",
             "Bidirectional controls can alter visual ordering and disguise the apparent filename or extension.",
             "CRITICAL", 38.0, 0.995, {"characters": [RTL_OVERRIDE_CHARACTERS[c] for c in rtl_chars],
                                      "codepoints": [f"U+{ord(c):04X}" for c in rtl_chars]})

    zero_width = [c for c in filename if c in ZERO_WIDTH_CHARACTERS]
    if zero_width:
        _add(result, "FILENAME_ZERO_WIDTH_CHARACTERS", "Zero-width characters detected",
             "Invisible Unicode characters may split tokens, conceal extensions, or defeat naive security checks.",
             "HIGH", 24.0, 0.98, {"characters": [ZERO_WIDTH_CHARACTERS[c] for c in zero_width],
                                  "count": len(zero_width)})

    controls = contains_control_characters(filename)
    if controls:
        non_whitespace_controls = [c for c in controls if c not in ZERO_WIDTH_CHARACTERS and c not in RTL_OVERRIDE_CHARACTERS]
        if non_whitespace_controls:
            _add(result, "FILENAME_CONTROL_CHARACTERS", "Hidden Unicode control characters detected",
                 "The filename contains Unicode control characters that can interfere with display or parsing.",
                 "MEDIUM", min(20.0, 5.0 + 2.0 * len(non_whitespace_controls)), 0.97,
                 {"count": len(non_whitespace_controls), "codepoints": [f"U+{ord(c):04X}" for c in non_whitespace_controls]})

    confusables = _unicode_confusables(filename)
    if confusables:
        _add(result, "FILENAME_UNICODE_CONFUSABLES", "Unicode confusable characters detected",
             "Characters visually similar to common Latin characters may be used to imitate trusted filenames or brands.",
             "HIGH", min(28.0, 12.0 + 4.0 * len(confusables)), 0.94, {"matches": confusables}, "unicode")

    # Compare a confusable-normalized token stream against known brands.
    comparison_tokens = set(TOKEN_PATTERN.findall(comparison))
    confusable_brands = sorted(BRAND_TOKENS.intersection(comparison_tokens))
    if confusable_brands and confusables:
        _add(result, "FILENAME_CONFUSABLE_BRAND_LOOKALIKE",
             "Confusable brand lookalike detected",
             "Unicode confusable normalization produces a recognizable brand token, increasing the likelihood of intentional impersonation.",
             "HIGH", 24.0, 0.95,
             {"brands": confusable_brands, "matches": confusables},
             "impersonation")

    fuzzy_brands = _fuzzy_brand_match(tokens)
    if fuzzy_brands:
        _add(result, "FILENAME_FUZZY_BRAND_LOOKALIKE",
             "Near-match brand lookalike detected",
             "The filename contains a token highly similar to a known brand name, consistent with typo-squatting or character substitution.",
             "HIGH", 20.0, 0.90, {"matches": fuzzy_brands[:5]}, "impersonation")

    non_ascii = [c for c in filename if ord(c) > 127]
    result.metadata["non_ascii_count"] = len(non_ascii)
    if len(script_groups) >= 2:
        _add(result, "FILENAME_MIXED_SCRIPT", "Mixed-script filename detected",
             "Multiple writing systems appear in the filename; mixed scripts can increase lookalike and impersonation risk.",
             "MEDIUM", 14.0, 0.92, {"non_ascii_count": len(non_ascii), "script_groups": script_groups}, "unicode")

    # 3. Extension and masquerade intelligence.
    dangerous = extension in DANGEROUS_EXTENSIONS
    executable = extension in EXECUTABLE_EXTENSIONS
    macro = extension in MACRO_CAPABLE_EXTENSIONS
    archive = extension in ARCHIVE_EXTENSIONS

    if dangerous:
        severity = "HIGH" if executable else "MEDIUM"
        _add(result, "FILENAME_DANGEROUS_EXTENSION", "Potentially dangerous attachment extension",
             f"The attachment uses a potentially dangerous extension: {extension}",
             severity, 30.0 if executable else 24.0, 0.98, {"extension": extension}, "extension")

    if extension in SCRIPT_EXTENSIONS:
        _add(result, "FILENAME_SCRIPT_EXTENSION", "Script-capable attachment extension",
             "The extension can represent a script or script-hosted content and warrants additional inspection.",
             "HIGH", 24.0, 0.98, {"extension": extension}, "extension")

    if macro:
        _add(result, "FILENAME_MACRO_DOCUMENT", "Macro-capable Office document",
             "The attachment format can contain executable Office macro content.",
             "MEDIUM", 15.0, 0.97, {"extension": extension}, "extension")

    if archive:
        _add(result, "FILENAME_ARCHIVE_CONTAINER", "Archive or disk-image attachment",
             "Container formats can hide embedded payloads from simple filename inspection.",
             "INFO", 3.0, 0.95, {"extension": extension}, "extension")

    if chain:
        prior_extensions = chain[:-1]
        if len(chain) >= 2:
            if chain[-2] in DOCUMENT_EXTENSIONS and dangerous:
                _add(result, "FILENAME_DOUBLE_EXTENSION_MASQUERADE", "Document disguised with dangerous extension",
                     "A document-like extension precedes a dangerous final extension, a common masquerading pattern.",
                     "CRITICAL", 45.0, 0.995, {"extensions": chain}, "masquerade")
            elif chain[-2] in ARCHIVE_EXTENSIONS and dangerous:
                _add(result, "FILENAME_ARCHIVE_EXECUTABLE_MASQUERADE", "Archive name followed by dangerous extension",
                     "An archive-like suffix is followed by a dangerous executable/script suffix.",
                     "CRITICAL", 42.0, 0.99, {"extensions": chain}, "masquerade")
            elif dangerous and any(ext in DOCUMENT_EXTENSIONS for ext in prior_extensions):
                _add(result, "FILENAME_NESTED_DOCUMENT_MASQUERADE", "Nested document masquerade pattern",
                     "A document-like extension appears earlier in an extension chain ending in a dangerous type.",
                     "HIGH", 32.0, 0.96, {"extensions": chain}, "masquerade")
            elif len(chain) >= 3:
                _add(result, "FILENAME_COMPLEX_EXTENSION_CHAIN", "Complex extension chain detected",
                     "Multiple suffixes make the effective file type harder to interpret and can support masquerading.",
                     "LOW", 7.0, 0.82, {"extensions": chain}, "extension")
            else:
                _add(result, "FILENAME_MULTIPLE_EXTENSIONS", "Multiple file extensions detected",
                     "The filename contains multiple extension-like segments and warrants content-based verification.",
                     "LOW", 5.0, 0.80, {"extensions": chain}, "extension")

    if re.search(r"\s+\.(?:exe|scr|bat|cmd|js|vbs|vbe|ps1|lnk)$", normalized.casefold()):
        _add(result, "FILENAME_WHITESPACE_MASQUERADE", "Whitespace-based extension masquerade",
             "Whitespace appears before a dangerous extension and may reduce visual salience of the true suffix.",
             "HIGH", 25.0, 0.97, {"filename": normalized}, "masquerade")

    if re.search(r"\.{2,}[^.]+$", basename):
        _add(result, "FILENAME_SEPARATOR_ABUSE", "Repeated separator pattern near extension",
             "Repeated dots can conceal or visually separate a deceptive suffix.",
             "MEDIUM", 10.0, 0.86, {"filename": basename}, "masquerade")

    if len(chain) >= 2 and any(ext in DANGEROUS_EXTENSIONS for ext in chain[:-1]):
        _add(result, "FILENAME_HIDDEN_DANGEROUS_EXTENSION", "Dangerous extension hidden earlier in chain",
             "A dangerous extension occurs before the final suffix, which can be used to bypass simplistic extension checks.",
             "HIGH", 28.0, 0.96, {"extensions": chain}, "masquerade")

    # 4. Character-shape, entropy, and generated-name analysis.
    compact = re.sub(r"[^a-z0-9]", "", comparison)
    entropy = _shannon_entropy(compact)
    digit_ratio = sum(ch.isdigit() for ch in compact) / len(compact) if compact else 0.0
    alpha_ratio = sum(ch.isalpha() for ch in compact) / len(compact) if compact else 0.0
    unique_ratio = len(set(compact)) / len(compact) if compact else 0.0
    result.metadata.update({
        "comparison_entropy": round(entropy, 3),
        "digit_ratio": round(digit_ratio, 3),
        "alpha_ratio": round(alpha_ratio, 3),
        "unique_ratio": round(unique_ratio, 3),
    })

    stem_tokens = _stem_tokens(basename)
    stem_source = os.path.splitext(basename)[0]
    compact_stem = re.sub(r"[^a-z0-9]", "", _comparison_form(stem_source))
    semantic_stem_tokens = [t for t in stem_tokens if t in COMMON_BUSINESS_TERMS]
    randomized_candidate = (
        _is_mostly_random(stem_source)
        and bool(compact_stem)
        and len(stem_tokens) <= 1
        and not semantic_stem_tokens
        and "-" not in stem_source
        and "_" not in stem_source
    )
    if randomized_candidate:
        _add(result, "FILENAME_RANDOMIZED_NAME", "High-randomness filename detected",
             "The filename has a high-entropy, mixed alphanumeric structure with limited semantic content, consistent with generated or randomized naming.",
             "MEDIUM", 11.0, 0.84,
             {
                 "entropy": round(_shannon_entropy(compact_stem), 3),
                 "unique_ratio": round(len(set(compact_stem)) / len(compact_stem), 3),
                 "digit_ratio": round(sum(ch.isdigit() for ch in compact_stem) / len(compact_stem), 3),
                 "stem": stem_source,
             },
             "anomaly")

    if re.search(r"(.)\1{4,}", compact):
        _add(result, "FILENAME_REPEATED_CHARACTER_ANOMALY", "Repeated-character anomaly",
             "Unusually long repeated-character runs can indicate generated, padded, or evasive filenames.",
             "LOW", 6.0, 0.75, {"matches": re.findall(r"(.)\1{4,}", compact)}, "anomaly")

    if len(compact) >= 10 and digit_ratio >= 0.55:
        _add(result, "FILENAME_NUMERIC_HEAVY", "Numeric-heavy filename",
             "An unusually high proportion of digits can indicate generated identifiers or obfuscation.",
             "LOW", 5.0, 0.70, {"digit_ratio": round(digit_ratio, 3)}, "anomaly")

    # 5. Social engineering cues, with context-aware scoring.
    alias_matches = sorted({MULTILINGUAL_KEYWORD_ALIASES[token] for token in token_set if token in MULTILINGUAL_KEYWORD_ALIASES})
    matched_keywords = sorted((set(SUSPICIOUS_KEYWORDS).intersection(token_set)) | set(alias_matches))
    if matched_keywords:
        base = min(9.0, 2.0 * len(matched_keywords))
        _add(result, "FILENAME_SOCIAL_ENGINEERING_KEYWORDS", "Social engineering keywords detected",
             "The attachment name contains terms associated with common phishing lures; context is considered separately.",
             "LOW", base, 0.72, {"keywords": matched_keywords}, "social_engineering")

    phrase_matches: List[str] = []
    semantic_token_set = set(token_set) | {MULTILINGUAL_KEYWORD_ALIASES[t] for t in token_set if t in MULTILINGUAL_KEYWORD_ALIASES}
    for phrase_name, terms in SOCIAL_ENGINEERING_PHRASES.items():
        if all(term in semantic_token_set for term in terms):
            phrase_matches.append(phrase_name)
    if phrase_matches:
        _add(result, "FILENAME_SOCIAL_ENGINEERING_PHRASE", "High-signal social engineering phrase",
             "Multiple lure-related terms occur together, producing a stronger filename-level social-engineering signal.",
             "MEDIUM", min(18.0, 8.0 + 3.0 * len(phrase_matches)), 0.91,
             {"phrases": phrase_matches}, "social_engineering")

    # 6. Brand impersonation / lookalike context.
    brands = sorted(BRAND_TOKENS.intersection(token_set))
    cues = sorted(DECEPTIVE_CUES.intersection(token_set))
    if brands and cues:
        _add(result, "FILENAME_BRAND_IMPERSONATION_CUE", "Brand impersonation cue detected",
             "A recognizable enterprise/service brand appears alongside a deceptive action or access term.",
             "HIGH", 22.0, 0.88, {"brands": brands, "deceptive_cues": cues}, "impersonation")

    # 7. Domain-like / URL-like names.
    domain_candidate = basename.rstrip(" .").casefold()
    domain_parts = domain_candidate.split(".")
    domain_like = (
        len(domain_parts) >= 2
        and extension not in (
            DOCUMENT_EXTENSIONS
            | DANGEROUS_EXTENSIONS
            | ARCHIVE_EXTENSIONS
            | MACRO_CAPABLE_EXTENSIONS
        )
        and all(part and re.fullmatch(r"[a-z0-9-]+", part) for part in domain_parts)
        and domain_parts[-1] in KNOWN_TLDS
        and DOMAIN_LIKE_PATTERN.fullmatch(domain_candidate)
    )
    if domain_like:
        _add(result, "FILENAME_DOMAIN_LIKE", "Domain-like filename detected",
             "The filename resembles a DNS domain and may be intended to visually resemble a website identity.",
             "MEDIUM", 12.0, 0.82, {"filename": basename}, "impersonation")

    if url_scheme_like or www_like or re.search(r"(?:https?|www)[-_:.]", comparison):
        _add(result, "FILENAME_URL_LIKE", "URL-like filename token detected",
             "The filename contains URL-like markers that can be used in social-engineering lures.",
             "MEDIUM", 10.0, 0.90,
             {
                 "filename": basename,
                 "scheme_like": url_scheme_like,
                 "www_like": www_like,
                 "domain_marker_like": domain_marker_like,
             },
             "social_engineering")

    if brands and dangerous and (url_scheme_like or www_like or domain_marker_like):
        _add(result, "FILENAME_BRAND_DOMAIN_IMPERSONATION",
             "Brand/domain impersonation with dangerous suffix",
             "A recognizable brand appears in a URL/domain-like filename that also ends in a dangerous extension.",
             "CRITICAL", 28.0, 0.97,
             {
                 "brands": brands,
                 "extension": extension,
                 "url_scheme_like": url_scheme_like,
                 "www_like": www_like,
                 "domain_marker_like": domain_marker_like,
             },
             "impersonation")

    # 8. Length / extension edge cases.
    if len(basename) > 180:
        _add(result, "FILENAME_EXCESSIVE_LENGTH", "Unusually long filename",
             "The filename is unusually long and may obscure the effective suffix or relevant content.",
             "LOW", 5.0, 0.98, {"length": len(basename)}, "anomaly")

    if len(basename) > 255:
        _add(result, "FILENAME_EXTREME_LENGTH", "Extreme filename length",
             "The filename exceeds common single-component filesystem limits and should be handled as untrusted input.",
             "HIGH", 18.0, 0.995, {"length": len(basename)}, "platform")

    if not extension:
        _add(result, "FILENAME_NO_EXTENSION", "Attachment has no visible extension",
             "Files without a visible extension require content-based identification.",
             "INFO", 2.0, 0.98, {}, "extension")

    # 9. Correlation: only add a small bounded bonus so one filename cannot
    # independently overwhelm the central risk engine.
    finding_ids = {finding.rule_id for finding in result.findings}
    correlation_reasons: List[str] = []
    correlation_bonus = 0.0
    if "FILENAME_RTL_OVERRIDE" in finding_ids and dangerous:
        correlation_reasons.append("unicode_direction_control + dangerous_extension")
        correlation_bonus += 14.0
    if "FILENAME_ZERO_WIDTH_CHARACTERS" in finding_ids and len(chain) >= 2:
        correlation_reasons.append("zero_width + extension_chain")
        correlation_bonus += 8.0
    if "FILENAME_BRAND_IMPERSONATION_CUE" in finding_ids and dangerous:
        correlation_reasons.append("brand_cue + dangerous_extension")
        correlation_bonus += 12.0
    if "FILENAME_FUZZY_BRAND_LOOKALIKE" in finding_ids and dangerous:
        correlation_reasons.append("fuzzy_brand_lookalike + dangerous_extension")
        correlation_bonus += 10.0
    if "FILENAME_BRAND_DOMAIN_IMPERSONATION" in finding_ids:
        correlation_reasons.append("brand_domain_impersonation")
        correlation_bonus += 8.0
    if "FILENAME_SOCIAL_ENGINEERING_PHRASE" in finding_ids and dangerous:
        correlation_reasons.append("social_engineering_phrase + dangerous_extension")
        correlation_bonus += 10.0
    if correlation_bonus:
        _add(result, "FILENAME_CORRELATED_RISK", "Correlated filename deception indicators",
             "Multiple independent filename indicators reinforce the same deception hypothesis.",
             "CRITICAL" if correlation_bonus >= 20 else "HIGH", min(20.0, correlation_bonus), 0.93,
             {"reasons": correlation_reasons, "bonus": min(20.0, correlation_bonus)}, "correlation")

    result.risk_score = min(100.0, result.risk_score)
    result.metadata["finding_count"] = len(result.findings)
    result.metadata["highest_severity"] = _highest_severity(result.findings)
    result.metadata["risk_score"] = round(result.risk_score, 2)
    result.metadata["extension_chain"] = chain
    result.metadata["brand_matches"] = sorted(set(brands + confusable_brands + [m["brand"] for m in fuzzy_brands]))

    # 10. SOC-grade post-processing and evidence normalization.
    skeleton = _unicode_skeleton(basename)
    result.metadata["unicode_skeleton"] = skeleton
    result.metadata["business_context_terms"] = _semantic_business_context(tokens)
    result.metadata["path_traversal_detected"] = _has_path_traversal(filename)
    result.metadata["device_namespace_detected"] = _has_device_namespace(filename)

    if _has_path_traversal(filename):
        _add(result, "FILENAME_PATH_TRAVERSAL_PATTERN", "Path traversal pattern detected",
             "The supplied attachment name contains a relative path traversal sequence and must be treated as untrusted path input.",
             "HIGH", 20.0, 0.995, {"filename": filename}, "platform")

    if _has_device_namespace(filename):
        _add(result, "FILENAME_WINDOWS_DEVICE_NAMESPACE", "Windows device namespace pattern detected",
             "The filename resembles a Windows device or extended-path namespace and can cause path-handling ambiguity.",
             "HIGH", 20.0, 0.99, {"filename": filename}, "platform")

    shell_meta = _shell_meta_characters(filename)
    if shell_meta:
        shell_severity = "HIGH" if dangerous else "LOW"
        shell_score = 14.0 if dangerous else 3.0
        _add(result, "FILENAME_SHELL_META_CHARACTERS", "Shell metacharacters detected",
             "Shell metacharacters are unusual in ordinary attachment names and can increase parser or workflow ambiguity.",
             shell_severity, shell_score, 0.90, {"characters": shell_meta}, "platform")

    if len(chain) >= 3 and sum(1 for ext in chain if ext in DANGEROUS_EXTENSIONS) >= 2:
        _add(result, "FILENAME_MULTIPLE_DANGEROUS_SUFFIXES", "Multiple dangerous suffixes detected",
             "More than one dangerous suffix occurs in the extension chain, materially increasing masquerading risk.",
             "CRITICAL", 18.0, 0.98, {"extensions": chain}, "masquerade")

    repeated_separator_count = len(re.findall(r"\.{2,}", basename))
    result.metadata["repeated_separator_count"] = repeated_separator_count
    result.metadata["shell_meta_characters"] = shell_meta

    # Produce a compact, deterministic analyst summary without replacing the central risk engine.
    finding_severity = _highest_severity(result.findings)
    result.metadata["risk_score"] = round(min(100.0, result.risk_score), 2)
    result.metadata["analyst_action"] = _risk_recommendation(finding_severity)
    result.metadata["risk_factors"] = [
        finding.title for finding in sorted(
            result.findings, key=lambda f: (-float(f.score), f.rule_id)
        )[:8]
    ]
    result.metadata["confidence_summary"] = round(
        sum(float(f.confidence) for f in result.findings) / len(result.findings), 3
    ) if result.findings else 1.0
    result.metadata["attack_categories"] = sorted({
        f.category for f in result.findings if f.category
    })

    result.risk_score = min(100.0, result.risk_score)
    result.metadata["finding_count"] = len(result.findings)
    result.metadata["highest_severity"] = _highest_severity(result.findings)
    return result


def _highest_severity(findings: List[FilenameFinding]) -> str:
    rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: rank.get(f.severity.upper(), 0)).severity


__all__ = [
    "FilenameFinding",
    "FilenameAnalysisResult",
    "normalize_filename",
    "get_extension",
    "get_all_extensions",
    "contains_rtl_override",
    "contains_control_characters",
    "analyze_filename",
]
