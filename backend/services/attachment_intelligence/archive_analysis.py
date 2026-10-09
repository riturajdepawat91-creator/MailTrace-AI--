"""
MailTrace-AI Attachment Intelligence - Archive Analysis
SOC-oriented static ZIP inspection with bounded, non-executing analysis.

Backward-compatible public API:
- ArchiveFinding
- ArchiveAnalysisResult
- get_archive_extension
- is_zip_archive
- get_compression_ratio
- analyze_zip_archive

The analyzer never extracts archive members to disk and never executes them.
"""

from __future__ import annotations

import re
import zipfile

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union


DANGEROUS_ARCHIVE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".mjs", ".wsf", ".wsh", ".hta",
    ".jar", ".lnk", ".msi", ".msix", ".msixbundle", ".reg",
}

SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".mjs", ".wsf", ".wsh", ".hta", ".sh", ".bash", ".zsh", ".py",
    ".pl", ".rb", ".php", ".psd1",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".jar", ".apk", ".whl", ".ipa", ".epub", ".xpi",
    ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
}

LURE_TERMS = {
    "invoice", "payment", "receipt", "refund", "salary", "payroll",
    "statement", "tax", "document", "documents", "report", "scan",
    "urgent", "important", "secure", "password", "credential",
    "login", "verify", "verification", "account", "update", "notice",
    "delivery", "shipping", "order", "resume", "cv", "quotation",
    "proposal", "contract", "bank", "wallet", "crypto",
}

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

MAX_RECOMMENDED_FILES = 1000
HIGH_COMPRESSION_RATIO = 100.0

MAX_MEMBERS_TO_INSPECT = 5000
MAX_MEMBER_PREFIX_BYTES = 65536
MAX_TOTAL_PREFIX_BYTES = 2 * 1024 * 1024
MAX_SINGLE_UNCOMPRESSED_MEMBER = 512 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
EXTREME_MEMBER_COMPRESSION_RATIO = 1000.0
HIGH_MEMBER_COMPRESSION_RATIO = 100.0
MAX_SUSPICIOUS_FILES_REPORTED = 50

_MAGIC_SIGNATURES: Tuple[Tuple[bytes, str], ...] = (
    (b"MZ", "PE/Windows executable"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP container"),
    (b"PK\x05\x06", "ZIP empty archive"),
    (b"PK\x07\x08", "ZIP spanned marker"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/Compound File"),
    (b"\x1f\x8b\x08", "GZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"Rar!\x1a\x07\x00", "RAR"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:($|[\\/])")
_WINDOWS_UNC_RE = re.compile(r"^(\\\\|//)")


@dataclass
class ArchiveFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    score: float
    evidence: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "evidence": self.evidence,
        }


@dataclass
class ArchiveAnalysisResult:
    filename: str
    archive_type: str = "ZIP"

    file_count: int = 0
    compressed_size: int = 0
    uncompressed_size: int = 0
    compression_ratio: float = 0.0

    suspicious_files: List[str] = field(default_factory=list)
    findings: List[ArchiveFinding] = field(default_factory=list)
    risk_score: float = 0.0

    encrypted_files: List[str] = field(default_factory=list)
    nested_archives: List[str] = field(default_factory=list)
    duplicate_files: List[str] = field(default_factory=list)
    traversal_files: List[str] = field(default_factory=list)
    absolute_path_files: List[str] = field(default_factory=list)
    suspicious_name_files: List[str] = field(default_factory=list)
    symlink_files: List[str] = field(default_factory=list)
    hidden_files: List[str] = field(default_factory=list)
    lure_dangerous_files: List[str] = field(default_factory=list)
    content_mismatch_files: List[str] = field(default_factory=list)

    inspection_limited: bool = False
    members_inspected: int = 0
    prefix_bytes_inspected: int = 0
    analysis_version: str = "2.0.0"
    static_only: bool = True

    def add_finding(self, finding: ArchiveFinding) -> None:
        self.findings.append(finding)
        self.risk_score = min(100.0, self.risk_score + finding.score)

    def to_dict(self) -> Dict[str, object]:
        return {
            "filename": self.filename,
            "archive_type": self.archive_type,
            "file_count": self.file_count,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "compression_ratio": round(self.compression_ratio, 2),
            "suspicious_files": self.suspicious_files,
            "risk_score": round(self.risk_score, 2),
            "findings": [f.to_dict() for f in self.findings],
            "encrypted_files": self.encrypted_files,
            "nested_archives": self.nested_archives,
            "duplicate_files": self.duplicate_files,
            "traversal_files": self.traversal_files,
            "absolute_path_files": self.absolute_path_files,
            "suspicious_name_files": self.suspicious_name_files,
            "symlink_files": self.symlink_files,
            "hidden_files": self.hidden_files,
            "lure_dangerous_files": self.lure_dangerous_files,
            "content_mismatch_files": self.content_mismatch_files,
            "inspection_limited": self.inspection_limited,
            "members_inspected": self.members_inspected,
            "prefix_bytes_inspected": self.prefix_bytes_inspected,
            "analysis_version": self.analysis_version,
            "static_only": self.static_only,
        }


def get_archive_extension(filename: str) -> str:
    return Path(filename).suffix.lower()


def is_zip_archive(file_path: Union[str, Path]) -> bool:
    return zipfile.is_zipfile(file_path)


def get_compression_ratio(compressed_size: int, uncompressed_size: int) -> float:
    if compressed_size <= 0:
        return 0.0
    return uncompressed_size / compressed_size


def _normalized_member_name(name: str) -> str:
    return name.replace("\\", "/")


def _path_flags(name: str) -> Dict[str, bool]:
    normalized = _normalized_member_name(name)
    parts = [p for p in normalized.split("/") if p]
    return {
        "traversal": any(p == ".." for p in parts),
        "absolute": (
            normalized.startswith("/")
            or normalized.startswith("\\")
            or bool(_DRIVE_PATH_RE.match(normalized))
            or bool(_WINDOWS_UNC_RE.match(name))
        ),
        "control": bool(_CONTROL_RE.search(name)),
        "trailing_dot_space": any(
            segment.endswith((" ", "."))
            for segment in parts
            if segment
        ),
        "reserved": (
            bool(parts)
            and parts[-1].split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
        ),
        "unicode_trick": any(
            ord(ch) in {
                0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
                0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                0x2066, 0x2067, 0x2069,
            }
            for ch in name
        ),
        "hidden": any(
            segment.startswith(".") and segment not in {".", ".."}
            for segment in parts
        ),
    }


def _member_extension(name: str) -> str:
    return Path(name.replace("\\", "/")).suffix.lower()


def _double_extension(name: str) -> bool:
    base = Path(name.replace("\\", "/")).name
    suffixes = Path(base).suffixes
    return (
        len(suffixes) >= 2
        and suffixes[-1].lower() in (DANGEROUS_ARCHIVE_EXTENSIONS | SCRIPT_EXTENSIONS)
    )


def _has_lure_term(name: str) -> bool:
    tokens = re.findall(r"[a-z0-9]+", name.casefold())
    return any(token in LURE_TERMS for token in tokens)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def _magic_name(prefix: bytes) -> Optional[str]:
    for signature, label in _MAGIC_SIGNATURES:
        if prefix.startswith(signature):
            return label
    return None


def _expected_magic_for_extension(ext: str, prefix: bytes) -> Optional[str]:
    if not prefix:
        return None
    checks = {
        ".pdf": (b"%PDF-", "PDF"),
        ".exe": (b"MZ", "PE/Windows executable"),
        ".dll": (b"MZ", "PE/Windows executable"),
        ".scr": (b"MZ", "PE/Windows executable"),
        ".png": (b"\x89PNG\r\n\x1a\n", "PNG"),
        ".jpg": (b"\xff\xd8\xff", "JPEG"),
        ".jpeg": (b"\xff\xd8\xff", "JPEG"),
        ".gif": ((b"GIF87a", b"GIF89a"), "GIF"),
        ".zip": ((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"), "ZIP"),
        ".gz": (b"\x1f\x8b\x08", "GZIP"),
        ".gzip": (b"\x1f\x8b\x08", "GZIP"),
        ".7z": (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        ".rar": ((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"), "RAR"),
    }
    check = checks.get(ext)
    if not check:
        return None
    signature, label = check
    valid = prefix.startswith(signature) if isinstance(signature, bytes) else prefix.startswith(signature)
    return None if valid else label


def _add_unique(items: List[str], value: str, limit: int = MAX_SUSPICIOUS_FILES_REPORTED) -> None:
    if value not in items and len(items) < limit:
        items.append(value)


def _safe_prefix(archive: zipfile.ZipFile, info: zipfile.ZipInfo, budget_left: int) -> bytes:
    amount = min(MAX_MEMBER_PREFIX_BYTES, max(0, budget_left))
    if amount <= 0 or info.file_size <= 0:
        return b""
    try:
        with archive.open(info, "r") as member:
            return member.read(amount)
    except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile):
        return b""


def _finding(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    score: float,
    evidence: Optional[Dict[str, object]] = None,
) -> ArchiveFinding:
    return ArchiveFinding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        score=score,
        evidence=evidence or {},
    )


def analyze_zip_archive(
    file_path: Union[str, Path],
    filename: Optional[str] = None,
) -> ArchiveAnalysisResult:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    result = ArchiveAnalysisResult(filename=filename or path.name)

    if not is_zip_archive(path):
        result.add_finding(_finding(
            "ARCHIVE_INVALID_ZIP",
            "Invalid ZIP archive",
            "The file does not contain a valid ZIP archive structure.",
            "MEDIUM",
            20.0,
        ))
        return result

    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()
            result.file_count = len(members)
            result.compressed_size = sum(max(0, m.compress_size) for m in members)
            result.uncompressed_size = sum(max(0, m.file_size) for m in members)
            result.compression_ratio = get_compression_ratio(
                result.compressed_size,
                result.uncompressed_size,
            )

            if not members:
                result.add_finding(_finding(
                    "ARCHIVE_EMPTY",
                    "Empty archive",
                    "The archive contains no files.",
                    "INFO",
                    1.0,
                ))

            if result.file_count > MAX_RECOMMENDED_FILES:
                result.add_finding(_finding(
                    "ARCHIVE_EXCESSIVE_FILE_COUNT",
                    "Archive contains unusually large number of files",
                    "Large member counts can complicate inspection and may indicate resource-exhaustion abuse.",
                    "MEDIUM",
                    15.0,
                    {"file_count": result.file_count},
                ))

            if result.file_count > MAX_MEMBERS_TO_INSPECT:
                result.inspection_limited = True
                result.add_finding(_finding(
                    "ARCHIVE_INSPECTION_MEMBER_LIMIT",
                    "Archive inspection was bounded",
                    "The archive contains more members than the static inspection ceiling; only a bounded subset is analyzed.",
                    "MEDIUM",
                    8.0,
                    {
                        "file_count": result.file_count,
                        "max_members_to_inspect": MAX_MEMBERS_TO_INSPECT,
                    },
                ))

            if result.uncompressed_size > MAX_TOTAL_UNCOMPRESSED:
                result.add_finding(_finding(
                    "ARCHIVE_TOTAL_EXPANSION_LIMIT",
                    "Archive has excessive declared expansion size",
                    "The declared total uncompressed size exceeds the static analysis safety ceiling.",
                    "HIGH",
                    30.0,
                    {
                        "uncompressed_size": result.uncompressed_size,
                        "max_total_uncompressed": MAX_TOTAL_UNCOMPRESSED,
                    },
                ))

            if result.compression_ratio >= HIGH_COMPRESSION_RATIO:
                result.add_finding(_finding(
                    "ARCHIVE_HIGH_COMPRESSION_RATIO",
                    "Unusually high compression ratio",
                    "The archive expands to a size significantly larger than its compressed representation.",
                    "HIGH",
                    30.0,
                    {
                        "compressed_size": result.compressed_size,
                        "uncompressed_size": result.uncompressed_size,
                        "compression_ratio": round(result.compression_ratio, 2),
                    },
                ))

            seen: Set[str] = set()
            prefix_budget = MAX_TOTAL_PREFIX_BYTES
            dangerous_count = 0
            suspicious: List[str] = []

            for index, member in enumerate(members):
                if index >= MAX_MEMBERS_TO_INSPECT:
                    result.inspection_limited = True
                    continue

                result.members_inspected += 1
                name = member.filename
                normalized = _normalized_member_name(name)
                ext = _member_extension(name)

                key = normalized.casefold()
                if key in seen:
                    _add_unique(result.duplicate_files, name)
                seen.add(key)

                flags = _path_flags(name)
                if flags["traversal"]:
                    _add_unique(result.traversal_files, name)
                if flags["absolute"]:
                    _add_unique(result.absolute_path_files, name)
                if flags["control"] or flags["trailing_dot_space"] or flags["reserved"] or flags["unicode_trick"]:
                    _add_unique(result.suspicious_name_files, name)
                if flags["hidden"]:
                    _add_unique(result.hidden_files, name)
                if _is_symlink(member):
                    _add_unique(result.symlink_files, name)

                dangerous = ext in DANGEROUS_ARCHIVE_EXTENSIONS or ext in SCRIPT_EXTENSIONS
                if dangerous:
                    dangerous_count += 1
                    _add_unique(suspicious, name)
                    if _has_lure_term(name):
                        _add_unique(result.lure_dangerous_files, name)
                    if _double_extension(name):
                        _add_unique(result.suspicious_name_files, name)

                nested_by_name = ext in ARCHIVE_EXTENSIONS
                if nested_by_name:
                    _add_unique(result.nested_archives, name)

                member_ratio = get_compression_ratio(
                    max(0, member.compress_size),
                    max(0, member.file_size),
                )
                if member.file_size > MAX_SINGLE_UNCOMPRESSED_MEMBER:
                    result.add_finding(_finding(
                        "ARCHIVE_MEMBER_SIZE_LIMIT",
                        "Archive member exceeds per-file size ceiling",
                        "A member declares a very large uncompressed size and warrants controlled handling.",
                        "HIGH",
                        20.0,
                        {
                            "file": name,
                            "file_size": member.file_size,
                            "max_single_uncompressed_member": MAX_SINGLE_UNCOMPRESSED_MEMBER,
                        },
                    ))

                if member_ratio >= EXTREME_MEMBER_COMPRESSION_RATIO:
                    result.add_finding(_finding(
                        "ARCHIVE_MEMBER_EXTREME_COMPRESSION",
                        "Archive member has extreme compression ratio",
                        "A single member expands by an unusually large factor and may indicate compression-bomb behavior.",
                        "HIGH",
                        25.0,
                        {
                            "file": name,
                            "compressed_size": member.compress_size,
                            "uncompressed_size": member.file_size,
                            "compression_ratio": round(member_ratio, 2),
                        },
                    ))
                elif member_ratio >= HIGH_MEMBER_COMPRESSION_RATIO:
                    result.add_finding(_finding(
                        "ARCHIVE_MEMBER_HIGH_COMPRESSION",
                        "Archive member has high compression ratio",
                        "A single member expands by a high factor and should receive additional scrutiny.",
                        "MEDIUM",
                        12.0,
                        {
                            "file": name,
                            "compressed_size": member.compress_size,
                            "uncompressed_size": member.file_size,
                            "compression_ratio": round(member_ratio, 2),
                        },
                    ))

                prefix = _safe_prefix(archive, member, prefix_budget)
                result.prefix_bytes_inspected += len(prefix)
                prefix_budget -= len(prefix)

                magic = _magic_name(prefix)
                expected = _expected_magic_for_extension(ext, prefix)
                if expected:
                    expected_ok = (
                        (expected == "PDF" and magic == "PDF")
                        or (expected == "PE/Windows executable" and magic == "PE/Windows executable")
                        or (expected == "PNG" and magic == "PNG")
                        or (expected == "JPEG" and magic == "JPEG")
                        or (expected == "GIF" and magic == "GIF")
                        or (expected == "ZIP" and magic in {"ZIP container", "ZIP empty archive", "ZIP spanned marker"})
                        or (expected == "GZIP" and magic == "GZIP")
                        or (expected == "7-Zip" and magic == "7-Zip")
                        or (expected == "RAR" and magic == "RAR")
                    )
                    if not expected_ok:
                        _add_unique(result.content_mismatch_files, name)

                if magic in {"ZIP container", "GZIP", "7-Zip", "RAR"}:
                    _add_unique(result.nested_archives, name)

                if prefix_budget <= 0 and index + 1 < len(members):
                    result.inspection_limited = True

            result.suspicious_files = suspicious[:MAX_SUSPICIOUS_FILES_REPORTED]

            if dangerous_count:
                result.add_finding(_finding(
                    "ARCHIVE_DANGEROUS_CONTENT",
                    "Potentially dangerous files inside archive",
                    "The archive contains executable, installer, link, or script-like members.",
                    "HIGH",
                    min(55.0, 25.0 + dangerous_count * 5.0),
                    {"count": dangerous_count, "files": result.suspicious_files},
                ))

            encrypted = [
                member.filename
                for member in members[:MAX_MEMBERS_TO_INSPECT]
                if member.flag_bits & 0x1
            ]
            result.encrypted_files = encrypted[:MAX_SUSPICIOUS_FILES_REPORTED]

            if result.encrypted_files:
                result.add_finding(_finding(
                    "ARCHIVE_ENCRYPTED_MEMBERS",
                    "Archive contains encrypted members",
                    "Encrypted members limit static visibility into their contents and should be treated as reduced-confidence inspection.",
                    "MEDIUM",
                    18.0,
                    {
                        "count": len(encrypted),
                        "files": result.encrypted_files,
                    },
                ))

            if result.lure_dangerous_files:
                result.add_finding(_finding(
                    "ARCHIVE_LURE_DANGEROUS_CONTENT",
                    "Social-engineering lure paired with dangerous content",
                    "Dangerous members use filenames associated with invoices, payments, credentials, urgent notices, or similar lures.",
                    "HIGH",
                    18.0,
                    {"files": result.lure_dangerous_files},
                ))

            if result.duplicate_files:
                result.add_finding(_finding(
                    "ARCHIVE_DUPLICATE_MEMBERS",
                    "Archive contains duplicate member names",
                    "Duplicate names can create extraction ambiguity and differing overwrite behavior across tooling.",
                    "MEDIUM",
                    10.0,
                    {"count": len(result.duplicate_files), "files": result.duplicate_files},
                ))

            if result.traversal_files:
                result.add_finding(_finding(
                    "ARCHIVE_PATH_TRAVERSAL",
                    "Archive contains path traversal entries",
                    "Member names contain parent-directory traversal components that can escape an extraction root in unsafe tooling.",
                    "CRITICAL",
                    45.0,
                    {"count": len(result.traversal_files), "files": result.traversal_files},
                ))

            if result.absolute_path_files:
                result.add_finding(_finding(
                    "ARCHIVE_ABSOLUTE_PATH",
                    "Archive contains absolute or drive-qualified paths",
                    "Member names use absolute, UNC, or drive-qualified path forms that are unsafe for naive extraction.",
                    "HIGH",
                    25.0,
                    {"count": len(result.absolute_path_files), "files": result.absolute_path_files},
                ))

            if result.suspicious_name_files:
                result.add_finding(_finding(
                    "ARCHIVE_SUSPICIOUS_MEMBER_NAMES",
                    "Archive contains suspicious member names",
                    "Member names contain Unicode control tricks, Windows-reserved names, trailing-dot/space forms, or extension deception indicators.",
                    "MEDIUM",
                    15.0,
                    {"count": len(result.suspicious_name_files), "files": result.suspicious_name_files},
                ))

            if result.symlink_files:
                result.add_finding(_finding(
                    "ARCHIVE_SYMLINK_MEMBER",
                    "Archive contains symbolic-link members",
                    "Symbolic links can redirect extraction or post-extraction processing outside the intended directory.",
                    "HIGH",
                    25.0,
                    {"count": len(result.symlink_files), "files": result.symlink_files},
                ))

            if result.hidden_files:
                result.add_finding(_finding(
                    "ARCHIVE_HIDDEN_MEMBERS",
                    "Archive contains hidden-style member names",
                    "One or more members use dot-prefixed path components; this is contextual evidence rather than a malware verdict.",
                    "LOW",
                    4.0,
                    {"count": len(result.hidden_files), "files": result.hidden_files},
                ))

            if result.nested_archives:
                result.add_finding(_finding(
                    "ARCHIVE_NESTED_ARCHIVE",
                    "Archive contains nested archive content",
                    "Nested containers reduce static visibility and can conceal secondary payloads or bypass shallow inspection.",
                    "MEDIUM",
                    15.0,
                    {"count": len(result.nested_archives), "files": result.nested_archives},
                ))

            if result.content_mismatch_files:
                result.add_finding(_finding(
                    "ARCHIVE_MEMBER_CONTENT_MISMATCH",
                    "Member content conflicts with its filename extension",
                    "Bounded magic-byte inspection found one or more members whose leading bytes conflict with the claimed extension.",
                    "HIGH",
                    22.0,
                    {"count": len(result.content_mismatch_files), "files": result.content_mismatch_files},
                ))

            if result.inspection_limited:
                result.add_finding(_finding(
                    "ARCHIVE_INSPECTION_BOUNDED",
                    "Archive inspection was partially bounded",
                    "Static inspection stopped at configured member or prefix ceilings; findings represent observed evidence only.",
                    "INFO",
                    0.0,
                    {
                        "members_inspected": result.members_inspected,
                        "prefix_bytes_inspected": result.prefix_bytes_inspected,
                        "max_members_to_inspect": MAX_MEMBERS_TO_INSPECT,
                        "max_total_prefix_bytes": MAX_TOTAL_PREFIX_BYTES,
                    },
                ))

            result.add_finding(_finding(
                "ARCHIVE_STATIC_ANALYSIS_PROFILE",
                "Static archive analysis profile",
                "Archive inspection used metadata, bounded member-prefix reads, and structural heuristics only; no member was extracted to disk or executed.",
                "INFO",
                0.0,
                {
                    "analysis_version": result.analysis_version,
                    "static_only": result.static_only,
                    "members_total": result.file_count,
                    "members_inspected": result.members_inspected,
                    "prefix_bytes_inspected": result.prefix_bytes_inspected,
                },
            ))

    except zipfile.BadZipFile:
        result.add_finding(_finding(
            "ARCHIVE_CORRUPTED",
            "Corrupted ZIP archive",
            "The archive structure could not be safely parsed.",
            "MEDIUM",
            20.0,
        ))
    except (OSError, EOFError, RuntimeError, ValueError) as error:
        result.add_finding(_finding(
            "ARCHIVE_ANALYSIS_ERROR",
            "Archive analysis error",
            "An I/O or parsing error occurred while inspecting the archive.",
            "INFO",
            0.0,
            {"error": str(error)},
        ))
    except Exception as error:
        result.add_finding(_finding(
            "ARCHIVE_ANALYSIS_ERROR",
            "Archive analysis error",
            "An unexpected error occurred while inspecting the archive.",
            "INFO",
            0.0,
            {"error": str(error)},
        ))

    return result


__all__ = [
    "DANGEROUS_ARCHIVE_EXTENSIONS",
    "MAX_RECOMMENDED_FILES",
    "HIGH_COMPRESSION_RATIO",
    "ArchiveFinding",
    "ArchiveAnalysisResult",
    "get_archive_extension",
    "is_zip_archive",
    "get_compression_ratio",
    "analyze_zip_archive",
]
