"""
MailTrace-AI Attachment Intelligence Engine
SOC-grade File Type Intelligence

Static, non-executing analysis of attachment bytes and filename context.
The module identifies file formats from magic bytes, detects extension/type
mismatches, common polyglot/embedded signatures, truncation and structural
anomalies, executable/container characteristics, and produces explainable
findings suitable for downstream SOC correlation.

Compatibility goals:
- Preserve common public names from the original module.
- Keep analysis non-executing and bounded.
- Avoid optional third-party dependencies.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union


MAX_HEADER_READ = 65536
MAX_EMBEDDED_SCAN = 256 * 1024
MAX_FINDINGS = 100


@dataclass(frozen=True)
class SignatureDefinition:
    type_name: str
    category: str
    signatures: Tuple[Tuple[int, bytes], ...]
    extensions: Tuple[str, ...] = ()
    mime_types: Tuple[str, ...] = ()
    executable: bool = False
    archive: bool = False
    document: bool = False
    container: bool = False
    description: str = ""


@dataclass
class FileTypeFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    score: float
    evidence: Dict[str, object] = field(default_factory=dict)
    confidence: float = 0.0
    category: str = "file_type"

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
class FileTypeAnalysisResult:
    original_filename: str
    extension: str
    detected_type: Optional[str] = None
    detected_category: Optional[str] = None
    mime_type: Optional[str] = None
    header_hex: str = ""
    file_size: int = 0
    findings: List[FileTypeFinding] = field(default_factory=list)
    risk_score: float = 0.0
    metadata: Dict[str, object] = field(default_factory=dict)
    analysis_version: str = "17.0.0"

    def add_finding(self, finding: FileTypeFinding) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            return
        finding.score = max(0.0, min(100.0, float(finding.score)))
        finding.confidence = max(0.0, min(1.0, float(finding.confidence)))
        self.findings.append(finding)
        self.risk_score = min(100.0, self.risk_score + finding.score)

    def to_dict(self) -> Dict[str, object]:
        return {
            "analysis_version": self.analysis_version,
            "original_filename": self.original_filename,
            "extension": self.extension,
            "detected_type": self.detected_type,
            "detected_category": self.detected_category,
            "mime_type": self.mime_type,
            "header_hex": self.header_hex,
            "file_size": self.file_size,
            "risk_score": round(self.risk_score, 2),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Signature knowledge base
# ---------------------------------------------------------------------------


def _sig(type_name: str, category: str, *pairs: Tuple[int, bytes], **kwargs: object) -> SignatureDefinition:
    return SignatureDefinition(type_name, category, tuple(pairs), **kwargs)


SIGNATURES: Tuple[SignatureDefinition, ...] = (
    _sig("PDF", "document", (0, b"%PDF-"), extensions=(".pdf",), mime_types=("application/pdf",), document=True, description="PDF document"),
    _sig("ZIP", "archive", (0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08"), extensions=(".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp", ".epub", ".msix", ".appx", ".appxbundle"), mime_types=("application/zip",), archive=True, container=True, description="ZIP-based container"),
    _sig("GZIP", "archive", (0, b"\x1f\x8b\x08"), extensions=(".gz", ".tgz"), mime_types=("application/gzip",), archive=True, container=True, description="GZIP stream"),
    _sig("BZIP2", "archive", (0, b"BZh"), extensions=(".bz2",), mime_types=("application/x-bzip2",), archive=True, description="BZIP2 stream"),
    _sig("XZ", "archive", (0, b"\xfd7zXZ\x00"), extensions=(".xz",), mime_types=("application/x-xz",), archive=True, description="XZ stream"),
    _sig("7-ZIP", "archive", (0, b"7z\xbc\xaf\x27\x1c"), extensions=(".7z",), mime_types=("application/x-7z-compressed",), archive=True, container=True, description="7-Zip archive"),
    _sig("RAR4", "archive", (0, b"Rar!\x1a\x07\x00"), extensions=(".rar",), mime_types=("application/vnd.rar",), archive=True, description="RAR 4.x archive"),
    _sig("RAR5", "archive", (0, b"Rar!\x1a\x07\x01\x00"), extensions=(".rar",), mime_types=("application/vnd.rar",), archive=True, description="RAR 5.x archive"),
    _sig("ELF", "executable", (0, b"\x7fELF"), extensions=("",), mime_types=("application/x-elf",), executable=True, description="ELF executable"),
    _sig("PE/COFF", "executable", (0, b"MZ"), extensions=(".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx"), mime_types=("application/vnd.microsoft.portable-executable",), executable=True, description="Windows PE family; DOS stub begins with MZ"),
    _sig("Mach-O 32", "executable", (0, b"\xfe\xed\xfa\xce"), extensions=(), mime_types=("application/x-mach-binary",), executable=True, description="Mach-O 32-bit big-endian"),
    _sig("Mach-O 64", "executable", (0, b"\xfe\xed\xfa\xcf"), extensions=(), mime_types=("application/x-mach-binary",), executable=True, description="Mach-O 64-bit big-endian"),
    _sig("Mach-O 32 LE", "executable", (0, b"\xce\xfa\xed\xfe"), extensions=(), mime_types=("application/x-mach-binary",), executable=True, description="Mach-O 32-bit little-endian"),
    _sig("Mach-O 64 LE", "executable", (0, b"\xcf\xfa\xed\xfe"), extensions=(), mime_types=("application/x-mach-binary",), executable=True, description="Mach-O 64-bit little-endian"),
    _sig("FAT Mach-O", "executable", (0, b"\xca\xfe\xba\xbe"), (0, b"\xbe\xba\xfe\xca"), extensions=(), mime_types=("application/x-mach-binary",), executable=True, description="Universal/FAT Mach-O binary"),
    _sig("Windows Cabinet", "archive", (0, b"MSCF\x00\x00\x00"), extensions=(".cab",), mime_types=("application/vnd.ms-cab-compressed",), archive=True, container=True, description="Microsoft Cabinet"),
    _sig("RAR-like legacy", "archive", (0, b"\x60\xea"), extensions=(), archive=True, description="Legacy compression signature"),
    _sig("PNG", "image", (0, b"\x89PNG\r\n\x1a\n"), extensions=(".png",), mime_types=("image/png",), description="PNG image"),
    _sig("JPEG", "image", (0, b"\xff\xd8\xff"), extensions=(".jpg", ".jpeg", ".jpe"), mime_types=("image/jpeg",), description="JPEG image"),
    _sig("GIF", "image", (0, b"GIF87a"), (0, b"GIF89a"), extensions=(".gif",), mime_types=("image/gif",), description="GIF image"),
    _sig("BMP", "image", (0, b"BM"), extensions=(".bmp",), mime_types=("image/bmp",), description="BMP image"),
    _sig("TIFF LE", "image", (0, b"II*\x00"), extensions=(".tif", ".tiff"), mime_types=("image/tiff",), description="TIFF little-endian"),
    _sig("TIFF BE", "image", (0, b"MM\x00*"), extensions=(".tif", ".tiff"), mime_types=("image/tiff",), description="TIFF big-endian"),
    _sig("WEBP", "image", (0, b"RIFF"), extensions=(".webp",), mime_types=("image/webp",), description="RIFF container; validated as WEBP using RIFF form type"),
    _sig("WAV/RIFF", "audio", (0, b"RIFF"), extensions=(".wav",), mime_types=("audio/wav",), description="RIFF container; form type distinguishes WAV"),
    _sig("AVI/RIFF", "video", (0, b"RIFF"), extensions=(".avi",), mime_types=("video/x-msvideo",), description="RIFF container; form type distinguishes AVI"),
    _sig("MP3 ID3", "audio", (0, b"ID3"), extensions=(".mp3",), mime_types=("audio/mpeg",), description="MP3 with ID3 tag"),
    _sig("MP3 frame", "audio", (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2"), extensions=(".mp3",), mime_types=("audio/mpeg",), description="MP3 MPEG audio frame"),
    _sig("FLAC", "audio", (0, b"fLaC"), extensions=(".flac",), mime_types=("audio/flac",), description="FLAC audio"),
    _sig("OGG", "audio", (0, b"OggS"), extensions=(".ogg", ".oga", ".ogv"), mime_types=("application/ogg",), description="Ogg container"),
    _sig("WASM", "executable", (0, b"\x00asm\x01\x00\x00\x00"), extensions=(".wasm",), mime_types=("application/wasm",), executable=True, description="WebAssembly module"),
    _sig("Java class", "executable", (0, b"\xca\xfe\xba\xbe"), extensions=(".class",), mime_types=("application/java-vm",), executable=True, description="Java class file"),
    _sig("SQLite3", "database", (0, b"SQLite format 3\x00"), extensions=(".db", ".sqlite", ".sqlite3"), mime_types=("application/vnd.sqlite3",), container=True, description="SQLite 3 database"),
    _sig("Microsoft Compound File", "container", (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), extensions=(".doc", ".xls", ".ppt", ".msg", ".ole"), mime_types=("application/x-ole-storage",), container=True, document=True, description="OLE/Compound File Binary Format"),
    _sig("WIM", "container", (0, b"MSWIM\x00\x00\x00"), extensions=(".wim",), container=True, archive=True, description="Windows Imaging Format"),
    _sig("ISO9660", "disk", (0, b"CD001",), extensions=(".iso",), mime_types=("application/x-iso9660-image",), archive=True, container=True, description="ISO 9660 volume descriptor signature at offset 32769"),
    _sig("AR", "archive", (0, b"!<arch>\n"), extensions=(".ar", ".deb"), mime_types=("application/x-archive",), archive=True, container=True, description="Unix ar archive"),
    _sig("ARJ", "archive", (0, b"\x60\xea"), extensions=(".arj",), archive=True, description="ARJ archive signature"),
    _sig("TAR ustar", "archive", (257, b"ustar\x00"), extensions=(".tar", ".tgz", ".tbz", ".tbz2"), archive=True, container=True, description="POSIX tar header"),
)


EXTENSION_ALIASES: Dict[str, str] = {
    ".jpeg": ".jpg",
    ".jpe": ".jpg",
    ".tif": ".tiff",
    ".htm": ".html",
    ".tgz": ".tar.gz",
    ".tbz": ".tar.bz2",
    ".tbz2": ".tar.bz2",
}


# Common internal/embedded markers that are useful even when the outer format
# is valid. Offsets are deliberately broad but bounded by MAX_EMBEDDED_SCAN.
EMBEDDED_MARKERS: Tuple[Tuple[str, bytes], ...] = (
    ("PDF_MAGIC", b"%PDF-"),
    ("OLE_CFBF", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("PE_MZ", b"MZ"),
    ("ELF", b"\x7fELF"),
    ("ZIP_LOCAL", b"PK\x03\x04"),
    ("ZIP_EOCD", b"PK\x05\x06"),
    ("RAR", b"Rar!\x1a\x07"),
    ("7ZIP", b"7z\xbc\xaf\x27\x1c"),
    ("GZIP", b"\x1f\x8b\x08"),
)


DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".pages", ".numbers", ".key",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx", ".com", ".pif", ".msi", ".msp",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".jar", ".class", ".wasm", ".appx", ".msix", ".lnk",
}

PACKAGE_EXTENSIONS = {
    ".jar", ".apk", ".msix", ".appx", ".appxbundle",
}


ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz", ".tbz2", ".iso", ".cab", ".arj", ".ar",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _basename(filename: str) -> str:
    return os.path.basename(filename or "")


def normalize_extension(extension: Optional[str]) -> str:
    if not extension:
        return ""
    ext = extension.strip().casefold()
    if ext and not ext.startswith("."):
        ext = "." + ext
    return EXTENSION_ALIASES.get(ext, ext)


def get_extension(filename: str) -> str:
    """Return the final filename extension in lowercase."""
    base = _basename(filename).rstrip(" .\t\r\n")
    return os.path.splitext(base)[1].casefold()


def read_header(path: Union[str, Path], size: int = 4096) -> bytes:
    """Read a bounded prefix without executing or parsing the file."""
    limit = max(1, min(int(size), MAX_HEADER_READ))
    with open(path, "rb") as handle:
        return handle.read(limit)


def _read_bounded(path: Union[str, Path], size: int = MAX_HEADER_READ) -> bytes:
    return read_header(path, size)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts if n)


def _ascii_strings(data: bytes, min_len: int = 6, max_count: int = 200) -> List[str]:
    output: List[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % max(2, min_len), data):
        try:
            value = match.group().decode("ascii", "ignore")
        except Exception:
            continue
        output.append(value)
        if len(output) >= max_count:
            break
    return output


def _add(
    result: FileTypeAnalysisResult,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    score: float,
    confidence: float,
    evidence: Optional[Dict[str, object]] = None,
    category: str = "file_type",
) -> None:
    result.add_finding(
        FileTypeFinding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            score=score,
            confidence=confidence,
            evidence=evidence or {},
            category=category,
        )
    )


def _severity_rank(value: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def _highest_severity(findings: Sequence[FileTypeFinding]) -> str:
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: _severity_rank(f.severity)).severity.upper()


# ---------------------------------------------------------------------------
# Signature detection
# ---------------------------------------------------------------------------


def _validate_riff(data: bytes) -> Optional[str]:
    if len(data) < 12 or data[:4] != b"RIFF":
        return None
    form = data[8:12]
    return {
        b"WEBP": "WEBP",
        b"WAVE": "WAV/RIFF",
        b"AVI ": "AVI/RIFF",
        b"RF64": "RF64/RIFF",
    }.get(form)


def _validate_iso_at_32769(data: bytes) -> bool:
    # Offset 32768 is the first byte of the standard volume descriptor;
    # the signature CD001 begins 1 byte into that descriptor.
    return len(data) >= 32774 and data[32769:32774] == b"CD001"


def _detect_html_signature(data: bytes) -> Optional[Dict[str, object]]:
    if not data:
        return None
    sample = data[:65536].lstrip().lower()
    if sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return {
            "type": "HTML",
            "category": "web_document",
            "mime_type": "text/html",
            "executable": False,
            "archive": False,
            "description": "HTML document",
            "offset": 0,
        }
    return None


def _detect_cafebabe_format(data: bytes) -> Optional[Dict[str, object]]:
    """Disambiguate Java class files from FAT Mach-O using structural header cues."""
    if len(data) < 8:
        return None
    magic = data[:4]

    # Java class: CAFEBABE + minor_version + major_version.
    if magic == b"\xca\xfe\xba\xbe":
        minor = int.from_bytes(data[4:6], "big")
        major = int.from_bytes(data[6:8], "big")
        if 45 <= major <= 70:
            return {
                "type": "Java class",
                "category": "executable",
                "mime_type": "application/java-vm",
                "executable": True,
                "archive": False,
                "description": "Java class file",
                "offset": 0,
                "java_minor_version": minor,
                "java_major_version": major,
            }

        # FAT Mach-O: CAFEBABE + nfat_arch (big endian), followed by
        # architecture entries (20 bytes each). Keep the structural test
        # conservative to avoid class-file false positives.
        nfat = int.from_bytes(data[4:8], "big")
        if 1 <= nfat <= 32 and len(data) >= 8 + 20 * nfat:
            return {
                "type": "FAT Mach-O",
                "category": "executable",
                "mime_type": "application/x-mach-binary",
                "executable": True,
                "archive": False,
                "description": "Universal/FAT Mach-O binary",
                "offset": 0,
                "fat_arch_count": nfat,
            }

    if magic == b"\xbe\xba\xfe\xca":
        # Swapped-endian FAT header.
        nfat = int.from_bytes(data[4:8], "little")
        if 1 <= nfat <= 32 and len(data) >= 8 + 20 * nfat:
            return {
                "type": "FAT Mach-O",
                "category": "executable",
                "mime_type": "application/x-mach-binary",
                "executable": True,
                "archive": False,
                "description": "Universal/FAT Mach-O binary",
                "offset": 0,
                "fat_arch_count": nfat,
            }
    return None


def detect_file_signature(data: bytes) -> Optional[Dict[str, object]]:
    """Identify a format from magic bytes without attempting execution."""
    if not data:
        return None

    html = _detect_html_signature(data)
    if html:
        return html

    cafebabe = _detect_cafebabe_format(data)
    if cafebabe:
        return cafebabe

    riff = _validate_riff(data)
    if riff:
        definition = next((s for s in SIGNATURES if s.type_name == riff), None)
        return {
            "type": riff,
            "category": definition.category if definition else "container",
            "mime_type": definition.mime_types[0] if definition and definition.mime_types else None,
            "executable": bool(definition.executable) if definition else False,
            "archive": bool(definition.archive) if definition else False,
            "description": definition.description if definition else "RIFF-derived container",
            "offset": 0,
        }

    if _validate_iso_at_32769(data):
        return {
            "type": "ISO9660",
            "category": "disk",
            "mime_type": "application/x-iso9660-image",
            "executable": False,
            "archive": True,
            "description": "ISO 9660 volume descriptor",
            "offset": 32769,
        }

    for definition in SIGNATURES:
        for offset, magic in definition.signatures:
            end = offset + len(magic)
            if offset >= 0 and len(data) >= end and data[offset:end] == magic:
                return {
                    "type": definition.type_name,
                    "category": definition.category,
                    "mime_type": definition.mime_types[0] if definition.mime_types else None,
                    "executable": definition.executable,
                    "archive": definition.archive,
                    "description": definition.description,
                    "offset": offset,
                }
    return None


def detect_file_type(path: Union[str, Path], max_read: int = MAX_HEADER_READ) -> Optional[Dict[str, object]]:
    """Detect file type from a bounded prefix."""
    data = _read_bounded(path, min(max_read, MAX_HEADER_READ))
    return detect_file_signature(data)


# ---------------------------------------------------------------------------
# Deep static characteristics
# ---------------------------------------------------------------------------


def _parse_pe_header(data: bytes) -> Dict[str, object]:
    result: Dict[str, object] = {}
    if len(data) < 64 or data[:2] != b"MZ":
        return result
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    result["pe_header_offset"] = pe_offset
    if pe_offset < 0 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        result["valid_pe_signature_in_prefix"] = False
        return result

    result["valid_pe_signature_in_prefix"] = True
    machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
    sections = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    timestamp = int.from_bytes(data[pe_offset + 8:pe_offset + 12], "little")
    optional_magic = int.from_bytes(data[pe_offset + 24:pe_offset + 26], "little") if pe_offset + 26 <= len(data) else None
    result.update({
        "machine": f"0x{machine:04x}",
        "section_count": sections,
        "pe_timestamp_raw": timestamp,
        "optional_header_magic": f"0x{optional_magic:04x}" if optional_magic is not None else None,
        "architecture": {
            0x014C: "x86",
            0x8664: "x64",
            0x01C0: "ARM",
            0x01C4: "ARM Thumb-2",
            0xAA64: "ARM64",
        }.get(machine, "unknown"),
        "pe_format": {0x10B: "PE32", 0x20B: "PE32+"}.get(optional_magic, "unknown"),
    })
    return result


def _parse_elf_header(data: bytes) -> Dict[str, object]:
    result: Dict[str, object] = {}
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return result
    elf_class = data[4]
    endian = data[5]
    machine = int.from_bytes(data[18:20], "little" if endian == 1 else "big")
    result.update({
        "elf_class": {1: "ELF32", 2: "ELF64"}.get(elf_class, "unknown"),
        "endianness": {1: "little", 2: "big"}.get(endian, "unknown"),
        "machine": machine,
        "architecture": {
            3: "x86",
            62: "x86_64",
            40: "ARM",
            183: "AArch64",
            8: "MIPS",
            20: "PowerPC",
            21: "PowerPC64",
            243: "RISC-V",
        }.get(machine, "unknown"),
    })
    return result


def _parse_ole(data: bytes) -> Dict[str, object]:
    result: Dict[str, object] = {}
    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return result
    result["compound_file"] = True
    if len(data) >= 32:
        minor = int.from_bytes(data[24:26], "little")
        major = int.from_bytes(data[26:28], "little")
        byte_order = int.from_bytes(data[28:30], "little")
        sector_shift = int.from_bytes(data[30:32], "little")
        result.update({
            "version_minor": minor,
            "version_major": major,
            "byte_order": f"0x{byte_order:04x}",
            "sector_size": 1 << sector_shift if 9 <= sector_shift <= 16 else None,
        })
    return result


def _zip_container_identity(data: bytes) -> Dict[str, object]:
    """Infer common ZIP-based container subtypes from entry names only.

    This is bounded metadata inspection: no extraction and no decompression.
    """
    names: List[str] = []
    scan = data[:MAX_EMBEDDED_SCAN]
    offset = 0
    while len(names) < 256:
        idx = scan.find(b"PK\x03\x04", offset)
        if idx < 0 or idx + 30 > len(scan):
            break
        name_len = int.from_bytes(scan[idx + 26:idx + 28], "little")
        extra_len = int.from_bytes(scan[idx + 28:idx + 30], "little")
        start = idx + 30
        end = start + name_len
        if end > len(scan):
            break
        raw_name = scan[start:end]
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            name = raw_name.decode("cp437", "replace")
        if name not in names:
            names.append(name)
        offset = end + extra_len

    lower_names = {n.casefold() for n in names}
    subtype = None
    confidence = 0.0
    markers: List[str] = []

    if "[content_types].xml" in lower_names:
        if "word/document.xml" in lower_names:
            subtype, confidence = "OOXML Word document", 0.99
            markers = ["[Content_Types].xml", "word/document.xml"]
        elif "xl/workbook.xml" in lower_names:
            subtype, confidence = "OOXML Excel workbook", 0.99
            markers = ["[Content_Types].xml", "xl/workbook.xml"]
        elif "ppt/presentation.xml" in lower_names:
            subtype, confidence = "OOXML PowerPoint presentation", 0.99
            markers = ["[Content_Types].xml", "ppt/presentation.xml"]

    if subtype is None and "meta-inf/manifest.mf" in lower_names:
        subtype, confidence = "JAR archive", 0.96
        markers = ["META-INF/MANIFEST.MF"]

    if subtype is None and "androidmanifest.xml" in lower_names:
        subtype, confidence = "Android APK-like container", 0.97
        markers = ["AndroidManifest.xml"]

    if subtype is None and "meta-inf/container.xml" in lower_names and "mimetype" in lower_names:
        subtype, confidence = "EPUB-like container", 0.95
        markers = ["mimetype", "META-INF/container.xml"]

    return {
        "entry_name_count": len(names),
        "entry_names_sample": names[:64],
        "subtype": subtype,
        "confidence": confidence,
        "markers": markers,
    }


def _parse_zip_local_headers(data: bytes) -> Dict[str, object]:
    result: Dict[str, object] = {}
    matches = [m.start() for m in re.finditer(re.escape(b"PK\x03\x04"), data)]
    eocd = data.find(b"PK\x05\x06")
    result["local_header_count_in_prefix"] = len(matches)
    result["eocd_in_prefix"] = eocd >= 0
    result["zip_entry_signatures"] = matches[:32]
    return result


def _polyglot_indicators(data: bytes, primary_type: Optional[str]) -> List[Dict[str, object]]:
    found: List[Dict[str, object]] = []
    scan = data[:MAX_EMBEDDED_SCAN]
    same_family = {
        "PDF_MAGIC": {"PDF"},
        "PE_MZ": {"PE/COFF"},
        "ELF": {"ELF"},
        "ZIP_LOCAL": {"ZIP"},
        "ZIP_EOCD": {"ZIP"},
        "OLE_CFBF": {"Microsoft Compound File"},
        "RAR": {"RAR4", "RAR5", "RAR-like legacy"},
        "7ZIP": {"7-ZIP"},
        "GZIP": {"GZIP"},
    }
    for marker_name, marker in EMBEDDED_MARKERS:
        offset = scan.find(marker)
        while offset >= 0:
            if offset != 0 and primary_type not in same_family.get(marker_name, set()):
                found.append({"marker": marker_name, "offset": offset})
                break
            offset = scan.find(marker, offset + 1)
    return found[:32]


def _structural_integrity_findings(result: FileTypeAnalysisResult, detected: Dict[str, object], data: bytes, size: int) -> None:
    """Add conservative structural checks that distinguish malformed/truncated data from malware."""
    dtype = str(detected.get("type") or "")

    if dtype == "PNG":
        if len(data) < 24:
            _add(result, "FILE_TYPE_PNG_TRUNCATED_HEADER", "PNG header is incomplete",
                 "The PNG signature is present, but the inspected data is shorter than the minimum header/chunk structure.",
                 "LOW", 5.0, 0.97, {"bytes_available": len(data)}, "integrity")
        elif data[12:16] != b"IHDR":
            _add(result, "FILE_TYPE_PNG_INVALID_IHDR", "PNG IHDR structure is inconsistent",
                 "The PNG signature is present but the first expected chunk is not IHDR.",
                 "MEDIUM", 8.0, 0.92, {"first_chunk": data[12:16].decode("ascii", "replace")}, "integrity")

    elif dtype == "JPEG":
        if size < 2 or b"\xff\xd9" not in data:
            _add(result, "FILE_TYPE_JPEG_EOI_MISSING", "JPEG end-of-image marker not observed",
                 "The JPEG header is present but the bounded inspection window does not contain the expected end marker; the file may be truncated.",
                 "LOW", 4.0, 0.82, {"bytes_inspected": len(data)}, "integrity")

    elif dtype == "GIF":
        if len(data) < 13:
            _add(result, "FILE_TYPE_GIF_TRUNCATED_HEADER", "GIF header is incomplete",
                 "The GIF signature is present but the logical screen descriptor is incomplete.",
                 "LOW", 4.0, 0.96, {"bytes_available": len(data)}, "integrity")
        elif b"\x3b" not in data:
            _add(result, "FILE_TYPE_GIF_TRAILER_MISSING", "GIF trailer not observed",
                 "The GIF signature is present but the expected trailer byte was not observed in the inspected data.",
                 "LOW", 3.0, 0.80, {"bytes_inspected": len(data)}, "integrity")

    elif dtype in {"WAV/RIFF", "AVI/RIFF", "WEBP"} and len(data) >= 8:
        declared = int.from_bytes(data[4:8], "little")
        if declared + 8 > size and size >= 12:
            _add(result, "FILE_TYPE_RIFF_TRUNCATED", "RIFF container appears truncated",
                 "The RIFF declared size extends beyond the actual file size.",
                 "LOW", 5.0, 0.88, {"declared_size": declared + 8, "actual_size": size}, "integrity")

    elif dtype == "ELF":
        elf = _parse_elf_header(data)
        result.metadata["elf"] = elf
        if elf.get("elf_class") == "unknown" or elf.get("endianness") == "unknown":
            _add(result, "FILE_TYPE_ELF_INVALID_IDENT", "ELF identification fields are invalid",
                 "The ELF magic is present but the class or byte-order field is outside the recognized ELF values.",
                 "MEDIUM", 8.0, 0.97, elf, "integrity")


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:65536]
    nul_count = sample.count(0)
    if nul_count > max(2, len(sample) // 100):
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / max(1, len(sample)) >= 0.85


def _looks_html(data: bytes) -> bool:
    sample = data[:65536].lstrip().lower()
    return sample.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _extension_compatible(extension: str, detected: Optional[Dict[str, object]]) -> bool:
    if not extension or not detected:
        return True
    detected_type = str(detected.get("type") or "")
    for definition in SIGNATURES:
        if definition.type_name == detected_type:
            if not definition.extensions:
                return True
            return normalize_extension(extension) in {normalize_extension(e) for e in definition.extensions}
    return True


def _expected_category(extension: str) -> Optional[str]:
    ext = normalize_extension(extension)
    # Package formats such as JAR/APK/MSIX are containers whose outer bytes
    # are normally ZIP rather than raw executable images. Treat them as
    # archive/container expectations so legitimate packages are not
    # penalized merely because they can ultimately launch executable code.
    if ext in PACKAGE_EXTENSIONS:
        return "archive"
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in DOCUMENT_EXTENSIONS:
        return "document"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    return None



def _infer_zip_subtype(data: bytes, extension: str) -> Dict[str, object]:
    """Infer common ZIP-based package/document subtypes from bounded local headers.

    This never extracts or executes content. It only inspects entry names present in
    the bounded byte window. A subtype is reported only when strong structural
    markers are observed.
    """
    names = _parse_zip_local_headers.__name__  # keep helper local and deterministic
    scan = data[:MAX_EMBEDDED_SCAN]
    entry_names: List[str] = []
    offset = 0
    while len(entry_names) < 512:
        idx = scan.find(b"PK\x03\x04", offset)
        if idx < 0 or idx + 30 > len(scan):
            break
        name_len = int.from_bytes(scan[idx + 26:idx + 28], "little")
        extra_len = int.from_bytes(scan[idx + 28:idx + 30], "little")
        start = idx + 30
        end = start + name_len
        if end > len(scan):
            break
        raw = scan[start:end]
        try:
            entry = raw.decode("utf-8")
        except UnicodeDecodeError:
            entry = raw.decode("cp437", "replace")
        if entry and entry not in entry_names:
            entry_names.append(entry)
        offset = max(end + extra_len, idx + 4)

    lower = {name.casefold() for name in entry_names}
    ext = normalize_extension(extension)
    subtype = None
    confidence = 0.0
    markers: List[str] = []

    if "word/document.xml" in lower and "[content_types].xml" in lower:
        subtype, confidence = "OOXML Word document", 0.995
        markers = ["[Content_Types].xml", "word/document.xml"]
    elif "xl/workbook.xml" in lower and "[content_types].xml" in lower:
        subtype, confidence = "OOXML Excel workbook", 0.995
        markers = ["[Content_Types].xml", "xl/workbook.xml"]
    elif "ppt/presentation.xml" in lower and "[content_types].xml" in lower:
        subtype, confidence = "OOXML PowerPoint presentation", 0.995
        markers = ["[Content_Types].xml", "ppt/presentation.xml"]
    elif "meta-inf/manifest.mf" in lower:
        subtype, confidence = "JAR archive", 0.98
        markers = ["META-INF/MANIFEST.MF"]
    elif "androidmanifest.xml" in lower:
        subtype, confidence = "Android APK-like container", 0.98
        markers = ["AndroidManifest.xml"]
    elif "meta-inf/container.xml" in lower and "mimetype" in lower:
        subtype, confidence = "EPUB-like container", 0.97
        markers = ["mimetype", "META-INF/container.xml"]
    elif "mimetype" in lower and ext == ".epub":
        # EPUB files commonly contain a mandatory mimetype entry.  The
        # presence of the entry plus an .epub suffix is strong enough for a
        # semantic subtype, while the physical magic identity remains ZIP.
        subtype, confidence = "EPUB-like container", 0.90
        markers = ["mimetype", "extension:.epub"]
    elif ext == ".docx" and "word/document.xml" in lower:
        subtype, confidence = "OOXML Word document", 0.96
        markers = ["word/document.xml", "extension:.docx"]
    elif ext == ".xlsx" and "xl/workbook.xml" in lower:
        subtype, confidence = "OOXML Excel workbook", 0.96
        markers = ["xl/workbook.xml", "extension:.xlsx"]
    elif ext == ".pptx" and "ppt/presentation.xml" in lower:
        subtype, confidence = "OOXML PowerPoint presentation", 0.96
        markers = ["ppt/presentation.xml", "extension:.pptx"]

    if subtype is None and ext in PACKAGE_EXTENSIONS:
        subtype_map = {
            ".jar": ("JAR archive", 0.65),
            ".apk": ("Android APK-like container", 0.65),
            ".msix": ("MSIX-like ZIP package", 0.65),
            ".appx": ("APPX-like ZIP package", 0.65),
            ".appxbundle": ("APPX bundle-like ZIP package", 0.65),
            ".epub": ("EPUB-like container", 0.78),
        }
        if ext in subtype_map:
            subtype, confidence = subtype_map[ext]
            markers = [f"extension:{ext}"]

    return {
        "subtype": subtype,
        "confidence": confidence,
        "markers": markers,
        "entry_name_count": len(entry_names),
        "entry_names_sample": entry_names[:64],
    }


def _expected_mime_for_extension(extension: str) -> Optional[str]:
    ext = normalize_extension(extension)
    mapping = {
        ".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg", ".gif": "image/gif", ".zip": "application/zip",
        ".gz": "application/gzip", ".bz2": "application/x-bzip2",
        ".xz": "application/x-xz", ".7z": "application/x-7z-compressed",
        ".rar": "application/vnd.rar", ".jar": "application/java-archive",
        ".apk": "application/vnd.android.package-archive",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".html": "text/html", ".htm": "text/html",
        ".class": "application/java-vm", ".wasm": "application/wasm",
        ".doc": "application/msword", ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
        ".txt": "text/plain", ".csv": "text/csv", ".rtf": "application/rtf",
        ".bmp": "image/bmp", ".tif": "image/tiff", ".tiff": "image/tiff", ".webp": "image/webp",
        ".mp3": "audio/mpeg", ".flac": "audio/flac", ".ogg": "application/ogg",
        ".cab": "application/vnd.ms-cab-compressed", ".iso": "application/x-iso9660-image",
    }
    return mapping.get(ext)


def _inferred_text_mime(data: bytes) -> Optional[str]:
    """Infer plain-text MIME conservatively for otherwise-unidentified text."""
    if not data or not _looks_text(data):
        return None
    sample = data[:65536]
    lowered = sample.lower()
    if _looks_html(sample):
        return "text/html"
    if b"," in sample and b"\n" in sample:
        return "text/csv"
    if b"\r\n" in sample or b"\n" in sample or b"\r" in sample:
        return "text/plain"
    return "text/plain"


def _semantic_expected_extensions(semantic_type: Optional[str], detected_category: Optional[str]) -> Optional[set[str]]:
    mapping = {
        "PDF": {".pdf"}, "HTML": {".html", ".htm"},
        "PNG": {".png"}, "JPEG": {".jpg", ".jpeg", ".jpe"},
        "GIF": {".gif"}, "BMP": {".bmp"},
        "TIFF LE": {".tif", ".tiff"}, "TIFF BE": {".tif", ".tiff"},
        "WEBP": {".webp"}, "WAV/RIFF": {".wav"}, "AVI/RIFF": {".avi"},
        "MP3 ID3": {".mp3"}, "MP3 frame": {".mp3"}, "FLAC": {".flac"},
        "OGG": {".ogg", ".oga", ".ogv"}, "WASM": {".wasm"},
        "Java class": {".class"}, "SQLite3": {".db", ".sqlite", ".sqlite3"},
        "Microsoft Compound File": {".doc", ".xls", ".ppt", ".msg", ".ole"},
        "Windows Cabinet": {".cab"}, "WIM": {".wim"}, "AR": {".ar", ".deb"},
        "ARJ": {".arj"}, "GZIP": {".gz", ".tgz"}, "BZIP2": {".bz2"},
        "XZ": {".xz"}, "7-ZIP": {".7z"}, "RAR4": {".rar"}, "RAR5": {".rar"},
        "ZIP": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".epub", ".odt", ".ods", ".odp", ".msix", ".appx", ".appxbundle"},
        "JAR archive": {".jar"},
        "Android APK-like container": {".apk"},
        "EPUB-like container": {".epub"},
        "OOXML Word document": {".docx"},
        "OOXML Excel workbook": {".xlsx"},
        "OOXML PowerPoint presentation": {".pptx"},
        "MSIX-like ZIP package": {".msix"},
        "APPX-like ZIP package": {".appx"},
        "APPX bundle-like ZIP package": {".appxbundle"},
        "PE/COFF": {".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx", ".com", ".pif", ".msi", ".msp"},
    }
    return mapping.get(str(semantic_type))




# ---------------------------------------------------------------------------
# V17 advanced static hardening
# ---------------------------------------------------------------------------

SCRIPT_FAMILY_MARKERS: Tuple[Tuple[str, Tuple[bytes, ...]], ...] = (
    ("PowerShell", (b"powershell", b"pwsh", b"invoke-expression", b"iex ")),
    ("Windows batch", (b"@echo off", b"set ", b"cmd.exe", b"%~dp")),
    ("VBScript", (b"createobject(", b"wscript.", b"vbscript")),
    ("JavaScript", (b"javascript:", b"function ", b"eval(", b"document.cookie")),
    ("Shell script", (b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env bash", b"#!/usr/bin/env sh")),
)


def _entropy_window_profile(data: bytes, window: int = 4096, max_windows: int = 16) -> Dict[str, object]:
    """Compute bounded entropy statistics across a few non-overlapping windows."""
    if not data:
        return {"window_size": window, "windows_analyzed": 0, "max_entropy": 0.0, "min_entropy": 0.0, "mean_entropy": 0.0, "high_entropy_windows": []}
    entropies: List[float] = []
    high: List[Dict[str, object]] = []
    limit = min(len(data), window * max_windows)
    for offset in range(0, limit, window):
        chunk = data[offset:offset + window]
        if not chunk:
            break
        e = round(_shannon_entropy(chunk), 3)
        entropies.append(e)
        if e >= 7.8:
            high.append({"offset": offset, "length": len(chunk), "entropy": e})
    return {
        "window_size": window,
        "windows_analyzed": len(entropies),
        "max_entropy": max(entropies) if entropies else 0.0,
        "min_entropy": min(entropies) if entropies else 0.0,
        "mean_entropy": round(sum(entropies) / len(entropies), 3) if entropies else 0.0,
        "high_entropy_windows": high[:16],
    }


def _content_script_profile(data: bytes) -> Dict[str, object]:
    """Conservatively classify script-like content without executing anything."""
    sample = data[:MAX_EMBEDDED_SCAN].lower()
    matches: List[Dict[str, object]] = []
    for family, markers in SCRIPT_FAMILY_MARKERS:
        hits = [m.decode("ascii", "ignore") for m in markers if m in sample]
        if hits:
            matches.append({"family": family, "markers": hits[:8]})
    shebang = None
    first_line = sample.splitlines()[0][:160] if sample.splitlines() else b""
    if first_line.startswith(b"#!"):
        try:
            shebang = first_line.decode("utf-8", "replace")
        except Exception:
            shebang = repr(first_line)
    return {
        "script_like": bool(matches or shebang),
        "families": matches,
        "shebang": shebang,
    }


def _magic_candidate_set(data: bytes) -> List[Dict[str, object]]:
    """Return all signatures matching at their declared offsets in the bounded prefix."""
    candidates: List[Dict[str, object]] = []
    for definition in SIGNATURES:
        for offset, magic in definition.signatures:
            end = offset + len(magic)
            if offset >= 0 and len(data) >= end and data[offset:end] == magic:
                candidates.append({
                    "type": definition.type_name,
                    "category": definition.category,
                    "mime_type": definition.mime_types[0] if definition.mime_types else None,
                    "executable": definition.executable,
                    "archive": definition.archive,
                    "offset": offset,
                    "magic_length": len(magic),
                })
                break
    return candidates


def _v17_identity_hardening(result: FileTypeAnalysisResult, detected: Optional[Dict[str, object]], data: bytes, size: int, extension: str) -> None:
    """Add deeper deterministic identity/conflict/format heuristics within File Type scope."""
    candidates = _magic_candidate_set(data)
    result.metadata["magic_candidates"] = candidates[:24]
    result.metadata["magic_candidate_count"] = len(candidates)

    if len(candidates) > 1:
        distinct = {str(c["type"]) for c in candidates}
        result.metadata["multiple_primary_candidates"] = len(distinct) > 1
        if len(distinct) > 1 and not any(f.rule_id == "FILE_TYPE_MULTIPLE_MAGIC_IDENTITIES" for f in result.findings):
            _add(result, "FILE_TYPE_MULTIPLE_MAGIC_IDENTITIES",
                 "Multiple file-format signatures match the same prefix",
                 "More than one known format signature matched within the bounded prefix, creating an identity ambiguity that requires contextual resolution.",
                 "HIGH", 18.0, 0.94,
                 {"candidates": sorted(distinct)[:12]}, "identity_conflict")
    else:
        result.metadata["multiple_primary_candidates"] = False

    entropy_profile = _entropy_window_profile(data)
    result.metadata["entropy_profile"] = entropy_profile
    if entropy_profile["high_entropy_windows"] and len(entropy_profile["high_entropy_windows"]) >= 2:
        _add(result, "FILE_TYPE_MULTIPLE_HIGH_ENTROPY_REGIONS",
             "Multiple high-entropy regions detected",
             "Several bounded regions exhibit very high byte entropy; this can be consistent with packed, encrypted, or compressed content and should be correlated with the detected file type.",
             "MEDIUM", 8.0, 0.78,
             {"regions": entropy_profile["high_entropy_windows"][:8]}, "anomaly")

    script_profile = _content_script_profile(data)
    result.metadata["script_profile"] = script_profile
    if script_profile.get("script_like") and (not detected or detected.get("category") not in {"executable", "archive"}):
        result.metadata["content_behavior_class"] = "script_like"
        _add(result, "FILE_TYPE_SCRIPT_LIKE_CONTENT",
             "Script-like content detected",
             "The bounded content contains markers consistent with a script family. This identifies executable-like content characteristics but does not execute or confirm malware.",
             "MEDIUM", 12.0, 0.90,
             script_profile, "active_content")
    else:
        result.metadata.setdefault("content_behavior_class", "binary_or_document")

    # PDF structural confidence improves when multiple canonical sections exist.
    if detected and detected.get("type") == "PDF":
        pdf_markers = {
            "header": data[:16].startswith(b"%PDF-"),
            "eof": b"%%EOF" in data,
            "catalog": b"/Type /Catalog" in data,
            "xref": b"xref" in data,
        }
        result.metadata["pdf_structure_profile"] = pdf_markers
        if not pdf_markers["eof"] and size >= MAX_HEADER_READ:
            result.metadata["pdf_eof_status"] = "not_observed_within_bounded_prefix"

    # Identity matrix for SOC consumers.
    expected_category = _expected_category(extension)
    actual_category = str(detected.get("category") or "") if detected else None
    semantic_type = result.metadata.get("semantic_file_type") or result.detected_type
    conflict_reasons: List[str] = []
    if expected_category and actual_category and expected_category != actual_category:
        conflict_reasons.append("extension_category_vs_detected_category")
    if result.metadata.get("semantic_extension_consistent") is False:
        conflict_reasons.append("semantic_extension_mismatch")
    if result.metadata.get("mime_consistency") is False:
        conflict_reasons.append("mime_mismatch")
    if result.metadata.get("multiple_primary_candidates"):
        conflict_reasons.append("multiple_magic_candidates")
    result.metadata["identity_confidence_factors"] = {
        "magic_match": bool(detected),
        "semantic_identity": bool(semantic_type),
        "extension_present": bool(extension),
        "conflict_reasons": conflict_reasons[:12],
    }
    result.metadata["identity_conflict_score"] = min(100.0, float(len(conflict_reasons) * 25))
    if conflict_reasons:
        result.metadata["identity_conflict"] = True
    result.metadata["analysis_depth"] = {
        "magic_signature": True,
        "semantic_container_identity": bool(result.metadata.get("semantic_file_type")),
        "structural_checks": True,
        "polyglot_scan": True,
        "entropy_profile": True,
        "script_profile": True,
        "static_only": True,
    }


def _soc_type_postprocess(result: FileTypeAnalysisResult, detected: Optional[Dict[str, object]], extension: str, data: bytes) -> None:
    """Add SOC-oriented identity, correlation and verdict semantics without claiming malware.

    File type analysis establishes file characteristics; it does not prove maliciousness.
    """
    result.metadata["malware_confirmed"] = False
    result.metadata["analysis_scope"] = "static_file_type_and_structure"
    result.metadata["identity_confidence"] = 0.0 if not detected else 0.99
    result.metadata["inferred_mime_type"] = detected.get("mime_type") if detected else _inferred_text_mime(data)
    result.metadata["expected_mime_type"] = _expected_mime_for_extension(extension)
    result.metadata["content_is_text_like"] = bool(_looks_text(data))

    if detected and detected.get("type") == "ZIP":
        package = _infer_zip_subtype(data, extension)
        subtype = package.get("subtype")
        result.metadata["container_subtype"] = subtype
        result.metadata["container_subtype_confidence"] = package.get("confidence", 0.0)
        result.metadata["container_markers"] = package.get("markers", [])
        result.metadata["container_entry_count"] = package.get("entry_name_count", 0)
        result.metadata["container_entry_names_sample"] = package.get("entry_names_sample", [])
        if subtype:
            result.metadata["identity_confidence"] = float(package.get("confidence", 0.0))
            # Keep the physical magic identity (ZIP) while exposing the stronger
            # semantic identity separately for SOC/UI consumers.
            result.metadata["semantic_file_type"] = subtype
            result.metadata["container_identity_basis"] = package.get("markers", [])
            subtype_mime = {
                "OOXML Word document": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "OOXML Excel workbook": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "OOXML PowerPoint presentation": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                "JAR archive": "application/java-archive",
                "Android APK-like container": "application/vnd.android.package-archive",
                "EPUB-like container": "application/epub+zip",
                "MSIX-like ZIP package": "application/vnd.ms-appx",
                "APPX-like ZIP package": "application/vnd.ms-appx",
                "APPX bundle-like ZIP package": "application/vnd.ms-appx-bundle",
            }
            result.metadata["semantic_mime_type"] = subtype_mime.get(str(subtype))
        else:
            result.metadata["semantic_file_type"] = "Generic ZIP container"
            result.metadata["semantic_mime_type"] = "application/zip"

    expected_mime = result.metadata.get("expected_mime_type")
    observed_mime = result.metadata.get("inferred_mime_type")
    if expected_mime and observed_mime and expected_mime != observed_mime:
        # ZIP-based office/package formats intentionally use specialized MIME values.
        specialized = {
            ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".msix", ".appx", ".appxbundle"
        }
        if normalize_extension(extension) not in specialized:
            _add(result, "FILE_TYPE_MIME_EXTENSION_CONFLICT",
                 "Inferred MIME type conflicts with filename extension",
                 "The magic-byte-derived MIME type does not align with the MIME type normally associated with the filename extension.",
                 "MEDIUM", 10.0, 0.90,
                 {"extension": extension, "expected_mime": expected_mime, "observed_mime": observed_mime}, "masquerade")

    # Normalize semantic MIME and type consistency for downstream SOC consumers.
    semantic_type = result.metadata.get("semantic_file_type") or result.detected_type
    semantic_mime = result.metadata.get("semantic_mime_type") or result.mime_type
    expected_mime = result.metadata.get("expected_mime_type")
    result.metadata["semantic_mime_type"] = semantic_mime
    result.metadata["mime_consistency"] = (
        None if not expected_mime or not semantic_mime else expected_mime == semantic_mime
    )
    result.metadata["identity_confidence"] = round(float(result.metadata.get("identity_confidence", 0.0)), 3)
    result.metadata["type_consistency"] = result.metadata.get("semantic_extension_consistent")
    if result.metadata.get("semantic_extension_consistent") is False and extension and result.detected_type:
        result.metadata["identity_conflict"] = True
        result.metadata["identity_conflict_basis"] = {
            "extension": extension,
            "detected_type": result.detected_type,
            "semantic_type": semantic_type,
            "inferred_mime": result.mime_type,
            "expected_mime": expected_mime,
        }
    else:
        result.metadata["identity_conflict"] = False
    result.metadata["identity_evidence"] = {
        "extension": extension or None,
        "magic_type": result.detected_type,
        "semantic_type": semantic_type,
        "inferred_mime": result.mime_type,
        "semantic_mime": semantic_mime,
        "expected_mime": expected_mime,
    }

    if detected and detected.get("executable"):
        result.metadata["malware_confirmed"] = False
        result.metadata["maliciousness_basis"] = "executable_content_or_executable_format_detected; malware_not_confirmed_by_file_type_only"
    elif detected:
        result.metadata["maliciousness_basis"] = "file_type_and_structure_only"
    else:
        result.metadata["maliciousness_basis"] = "unknown_file_type"

    semantic_type = result.metadata.get("semantic_file_type") or result.detected_type
    semantic_mime = result.metadata.get("semantic_mime_type") or result.mime_type
    result.metadata["three_way_identity"] = {
        "filename_extension": extension or None,
        "magic_type": result.detected_type,
        "semantic_type": semantic_type,
        "inferred_mime": result.mime_type,
        "expected_mime": result.metadata.get("expected_mime_type"),
    }
    if extension and semantic_type:
        expected_extensions = _semantic_expected_extensions(str(semantic_type), result.detected_category)
        if expected_extensions is None:
            if result.detected_category == "executable":
                result.metadata["semantic_extension_consistent"] = extension in EXECUTABLE_EXTENSIONS
            elif result.detected_category == "archive":
                result.metadata["semantic_extension_consistent"] = extension in ARCHIVE_EXTENSIONS
            elif result.detected_category == "document":
                result.metadata["semantic_extension_consistent"] = extension in DOCUMENT_EXTENSIONS
            else:
                result.metadata["semantic_extension_consistent"] = None
        else:
            result.metadata["semantic_extension_consistent"] = extension in {normalize_extension(e) for e in expected_extensions}
    elif extension and not semantic_type:
        result.metadata["semantic_extension_consistent"] = None
    else:
        result.metadata["semantic_extension_consistent"] = None
    result.metadata["detection_summary"] = {
        "detected_type": result.detected_type,
        "detected_category": result.detected_category,
        "semantic_file_type": semantic_type,
        "semantic_mime_type": semantic_mime,
        "extension": extension,
        "mime_type": result.mime_type,
        "malware_confirmed": False,
        "semantic_extension_consistent": result.metadata.get("semantic_extension_consistent"),
        "mime_consistency": result.metadata.get("mime_consistency"),
        "identity_conflict": result.metadata.get("identity_conflict", False),
    }

# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


def analyze_file_type(
    file_path: Union[str, Path],
    filename: Optional[str] = None,
    header: Optional[bytes] = None,
) -> FileTypeAnalysisResult:
    """Run bounded static file-type intelligence."""
    path = Path(file_path)
    display_name = filename or path.name
    extension = get_extension(display_name)
    size = path.stat().st_size
    data = header if header is not None else _read_bounded(path, MAX_HEADER_READ)

    detected = detect_file_signature(data)
    result = FileTypeAnalysisResult(
        original_filename=display_name,
        extension=extension,
        detected_type=str(detected["type"]) if detected else None,
        detected_category=str(detected["category"]) if detected else None,
        mime_type=str(detected["mime_type"]) if detected and detected.get("mime_type") else None,
        header_hex=data[:64].hex(),
        file_size=size,
        metadata={
            "header_bytes_read": len(data),
            "header_entropy": round(_shannon_entropy(data), 3),
            "signature_offset": detected.get("offset") if detected else None,
            "extension_category": _expected_category(extension),
        },
    )

    # Empty/truncated input.
    if size == 0:
        _add(result, "FILE_TYPE_EMPTY_FILE", "Empty attachment", "The attachment contains zero bytes and therefore has no identifiable content signature.", "LOW", 4.0, 0.99, {"size": 0}, "integrity")
    elif not data:
        _add(result, "FILE_TYPE_UNREADABLE_HEADER", "Unable to read file header", "No bytes were available for static signature analysis.", "MEDIUM", 12.0, 0.99, {"size": size}, "integrity")

    if detected:
        result.metadata["signature_description"] = detected.get("description")
        result.metadata["signature_category"] = detected.get("category")

        # Strong executable finding.
        if detected.get("executable"):
            _add(result, "FILE_TYPE_EXECUTABLE_SIGNATURE", "Executable file signature detected", f"The file content matches an executable format: {detected['type']}.", "HIGH", 26.0, 0.995, {"detected_type": detected["type"], "offset": detected.get("offset")}, "executable")

        if detected.get("archive"):
            _add(result, "FILE_TYPE_ARCHIVE_SIGNATURE", "Archive/container signature detected", f"The file content matches a container or archive format: {detected['type']}.", "INFO", 2.0, 0.99, {"detected_type": detected["type"]}, "container")

        if detected.get("type") == "Microsoft Compound File":
            details = _parse_ole(data)
            result.metadata["ole"] = details
            _add(result, "FILE_TYPE_OLE_CONTAINER", "Microsoft Compound File container detected", "The attachment uses the OLE Compound File format and requires deeper document/container inspection.", "MEDIUM", 10.0, 0.995, details, "container")

        result.metadata["detection_basis"] = "magic_bytes"
        result.metadata["detection_confidence"] = 0.995 if detected.get("type") not in {"HTML"} else 0.96

        if detected.get("type") == "ZIP":
            result.metadata["zip"] = _parse_zip_local_headers(data)
            identity = _zip_container_identity(data)
            result.metadata["zip_identity"] = identity
            if identity.get("subtype"):
                result.metadata["container_subtype"] = identity["subtype"]
                _add(
                    result,
                    "FILE_TYPE_ZIP_CONTAINER_IDENTITY",
                    "ZIP-based container subtype identified",
                    f"The ZIP container contains structural entry names consistent with {identity['subtype'] }.",
                    "INFO",
                    0.0,
                    float(identity.get("confidence") or 0.0),
                    {"subtype": identity["subtype"], "markers": identity.get("markers", []), "entry_names_sample": identity.get("entry_names_sample", [])[:16]},
                    "container",
                )

        if detected.get("type") == "PE/COFF":
            pe = _parse_pe_header(data)
            result.metadata["pe"] = pe
            if pe.get("valid_pe_signature_in_prefix") is False:
                _add(result, "FILE_TYPE_MZ_WITHOUT_VALID_PE", "MZ header without a valid PE signature in inspected prefix", "The file begins like a Windows executable but the expected PE header was not found within the inspected prefix.", "MEDIUM", 10.0, 0.93, pe, "integrity")
            elif pe.get("section_count") == 0:
                _add(result, "FILE_TYPE_PE_ZERO_SECTIONS", "PE image has zero sections", "A valid PE header was found, but it reports zero sections, which is structurally unusual.", "MEDIUM", 10.0, 0.94, pe, "integrity")

        if detected.get("type") == "ELF":
            result.metadata["elf"] = _parse_elf_header(data)

        if detected.get("type") == "HTML":
            lower_data = data[:MAX_EMBEDDED_SCAN].lower()
            if b"<script" in lower_data:
                _add(result, "FILE_TYPE_HTML_SCRIPT", "HTML script block detected", "The HTML attachment contains a script element and should be handled as active web content rather than a passive document.", "MEDIUM", 12.0, 0.96, {"marker": "<script"}, "active_content")
            if re.search(rb"(?:href|src|action)\s*=\s*[\"']?https?://", data[:MAX_EMBEDDED_SCAN], re.I):
                _add(result, "FILE_TYPE_HTML_EXTERNAL_RESOURCE", "HTML external resource reference detected", "The HTML attachment references an external HTTP(S) resource and should receive URL/content inspection.", "MEDIUM", 8.0, 0.90, {"marker": "external_http_reference"}, "active_content")

        if detected.get("type") == "PDF":
            if b"%%EOF" not in data and size < 65536:
                _add(result, "FILE_TYPE_PDF_EOF_MISSING", "Small PDF missing EOF marker in inspected bytes", "The PDF signature is present but the expected EOF marker was not found in the bounded inspection window.", "LOW", 5.0, 0.78, {"size": size}, "integrity")
            for marker, rid, title, severity, score in [
                (b"/JavaScript", "FILE_TYPE_PDF_JAVASCRIPT", "PDF JavaScript marker detected", "HIGH", 18.0),
                (b"/OpenAction", "FILE_TYPE_PDF_OPENACTION", "PDF automatic action detected", "HIGH", 16.0),
                (b"/AA", "FILE_TYPE_PDF_ADDITIONAL_ACTIONS", "PDF additional-action marker detected", "MEDIUM", 10.0),
                (b"/Launch", "FILE_TYPE_PDF_LAUNCH_ACTION", "PDF launch action marker detected", "HIGH", 20.0),
                (b"/EmbeddedFile", "FILE_TYPE_PDF_EMBEDDED_FILE", "PDF embedded-file marker detected", "MEDIUM", 12.0),
            ]:
                if marker in data:
                    _add(result, rid, title, f"The PDF content contains the marker {marker.decode('ascii', 'ignore')}.", severity, score, 0.93, {"marker": marker.decode("ascii", "ignore")}, "document")

        _structural_integrity_findings(result, detected, data, size)

    else:
        _add(result, "FILE_TYPE_UNKNOWN", "File signature could not be identified", "The file does not match the signatures currently supported by the analysis engine.", "INFO", 2.0, 1.0, {}, "unknown")
        if _looks_text(data):
            result.metadata["text_like"] = True
            _add(result, "FILE_TYPE_TEXT_LIKE_CONTENT", "Text-like content detected without a recognized binary signature", "The inspected bytes are predominantly printable text and do not match a known binary signature.", "INFO", 1.0, 0.90, {}, "content")
        if _looks_html(data):
            _add(result, "FILE_TYPE_HTML_CONTENT", "HTML content detected", "The attachment begins with HTML-like content and should not be treated as a generic binary document.", "MEDIUM", 8.0, 0.98, {}, "content")

    # Filename/content mismatch.
    if detected and extension:
        if not _extension_compatible(extension, detected):
            expected = _expected_category(extension)
            severity = "CRITICAL" if detected.get("executable") and expected in {"document", "archive"} else "HIGH"
            score = 40.0 if severity == "CRITICAL" else 24.0
            _add(result, "FILE_TYPE_EXTENSION_MISMATCH", "Filename extension does not match detected content", f"The filename extension {extension} is inconsistent with the detected content type {detected['type']}.", severity, score, 0.995, {"extension": extension, "detected_type": detected["type"], "expected_category": expected}, "masquerade")

        expected = _expected_category(extension)
        actual = str(detected.get("category") or "")
        if expected == "executable" and not detected.get("executable"):
            _add(result, "FILE_TYPE_EXPECTED_EXECUTABLE_BUT_NOT_DETECTED", "Executable extension without executable signature", "The filename claims an executable-capable type but the inspected bytes do not show a corresponding executable signature.", "MEDIUM", 12.0, 0.95, {"extension": extension, "detected_type": detected.get("type")}, "masquerade")
        elif expected == "document" and actual == "executable":
            _add(result, "FILE_TYPE_DOCUMENT_EXTENSION_EXECUTABLE_CONTENT", "Document-named attachment contains executable content", "A document-oriented filename extension is paired with an executable file signature.", "CRITICAL", 45.0, 0.998, {"extension": extension, "detected_type": detected.get("type")}, "masquerade")

    # Executable content with a non-executable suffix is itself important even
    # when the extension is a custom/unknown type.
    if detected and detected.get("executable") and normalize_extension(extension) not in {normalize_extension(e) for e in EXECUTABLE_EXTENSIONS}:
        _add(result, "FILE_TYPE_EXECUTABLE_CONTENT_NONEXEC_EXTENSION", "Executable content hidden behind non-executable extension", "Executable content was detected while the filename does not use a conventional executable extension.", "CRITICAL", 35.0, 0.995, {"extension": extension, "detected_type": detected.get("type")}, "masquerade")

    # Embedded/polyglot scan.
    embedded = _polyglot_indicators(data, result.detected_type)
    result.metadata["embedded_markers"] = embedded
    if embedded:
        _add(result, "FILE_TYPE_EMBEDDED_SIGNATURES", "Secondary file signatures detected", "Additional file-format markers were found away from the primary header, indicating possible embedded content, concatenation, or polyglot structure.", "HIGH", min(22.0, 8.0 + 4.0 * len(embedded)), 0.90, {"markers": embedded[:12]}, "polyglot")

    # Stronger polyglot conditions: executable marker inside a non-executable primary.
    embedded_names = {str(item.get("marker")) for item in embedded}
    if result.detected_type not in {"PE/COFF", "ELF", "Java class", "WASM"} and {"PE_MZ", "ELF"} & embedded_names:
        _add(result, "FILE_TYPE_EXECUTABLE_EMBEDDED", "Executable signature embedded in another file format", "A Windows PE or ELF marker was found away from the primary file signature.", "CRITICAL", 35.0, 0.97, {"primary_type": result.detected_type, "embedded": sorted({"PE_MZ", "ELF"} & embedded_names)}, "polyglot")

    # Entropy anomalies are contextual, never standalone malware verdicts.
    entropy = float(result.metadata.get("header_entropy", 0.0))

    # Unknown high-entropy content needs stronger escalation than a generic
    # anomaly because the static type engine cannot establish a benign identity.
    # This remains a triage signal, never a malware verdict.
    if not detected and entropy >= 7.8 and size >= 1024:
        _add(result, "FILE_TYPE_UNKNOWN_HIGH_ENTROPY",
             "Unknown high-entropy attachment requires enhanced inspection",
             "The attachment has no recognized file signature and its inspected prefix has very high entropy, so enhanced content inspection is recommended.",
             "MEDIUM", 15.0, 0.88,
             {"entropy": round(entropy, 3), "size": size, "bytes_inspected": len(data)}, "anomaly")
    result.metadata["high_entropy_header"] = entropy >= 7.4
    if entropy >= 7.8 and size >= 1024:
        _add(result, "FILE_TYPE_HIGH_ENTROPY_HEADER", "High-entropy file header", "The inspected prefix has very high byte entropy, which can be consistent with packed, encrypted, or compressed content.", "LOW", 5.0, 0.70, {"entropy": round(entropy, 3)}, "anomaly")

    # Truncation heuristics for common structured types.
    if detected and detected.get("type") in {"ZIP", "RAR4", "RAR5", "7-ZIP", "GZIP", "BZIP2", "XZ", "TAR ustar"}:
        if size < 32:
            _add(result, "FILE_TYPE_CONTAINER_TOO_SMALL", "Container is unusually small", "The file is smaller than expected for a normal container and may be incomplete or malformed.", "LOW", 5.0, 0.80, {"size": size, "detected_type": detected.get("type")}, "integrity")

    # SOC-grade identity/correlation semantics.
    _soc_type_postprocess(result, detected, extension, data)

    # Deep executable identity is descriptive, not a malware verdict.
    if detected and detected.get("type") == "PE/COFF":
        pe_meta = result.metadata.get("pe", {})
        result.metadata["executable_identity"] = {
            "format": "PE/COFF",
            "architecture": pe_meta.get("architecture", "unknown"),
            "pe_format": pe_meta.get("pe_format", "unknown"),
            "valid_pe_signature_in_prefix": pe_meta.get("valid_pe_signature_in_prefix"),
            "section_count": pe_meta.get("section_count"),
            "classification": "windows_executable_format",
        }
    elif detected and detected.get("type") == "ELF":
        elf_meta = result.metadata.get("elf", {})
        result.metadata["executable_identity"] = {
            "format": "ELF",
            "architecture": elf_meta.get("architecture", "unknown"),
            "elf_class": elf_meta.get("elf_class", "unknown"),
            "endianness": elf_meta.get("endianness", "unknown"),
            "machine": elf_meta.get("machine"),
            "classification": "unix_like_executable_format",
        }
    elif detected and detected.get("type") in {"Java class", "WASM", "Mach-O 32", "Mach-O 64", "Mach-O 32 LE", "Mach-O 64 LE", "FAT Mach-O"}:
        result.metadata["executable_identity"] = {
            "format": detected.get("type"),
            "classification": "executable_format",
        }
    else:
        result.metadata.setdefault("executable_identity", None)

    # Semantic package/extension conflict is tracked separately from physical ZIP identity.
    subtype = result.metadata.get("container_subtype")
    subtype_expected_extensions = {
        "JAR archive": {".jar"},
        "Android APK-like container": {".apk"},
        "EPUB-like container": {".epub"},
        "OOXML Word document": {".docx"},
        "OOXML Excel workbook": {".xlsx"},
        "OOXML PowerPoint presentation": {".pptx"},
        "MSIX-like ZIP package": {".msix"},
        "APPX-like ZIP package": {".appx"},
        "APPX bundle-like ZIP package": {".appxbundle"},
    }
    if subtype in subtype_expected_extensions and extension:
        subtype_consistent = extension in subtype_expected_extensions[subtype]
        result.metadata["container_subtype_extension_consistent"] = subtype_consistent
        if not subtype_consistent and not any(f.rule_id == "FILE_TYPE_EXTENSION_MISMATCH" for f in result.findings):
            _add(result, "FILE_TYPE_CONTAINER_SUBTYPE_EXTENSION_MISMATCH",
                 "Container subtype conflicts with filename extension",
                 "The bounded container structure indicates a package/document subtype inconsistent with the supplied filename extension.",
                 "HIGH", 18.0, 0.98, {"subtype": subtype, "extension": extension}, "masquerade")
    else:
        result.metadata["container_subtype_extension_consistent"] = None

    _v17_identity_hardening(result, detected, data, size, extension)

    # Final metadata used by downstream SOC/UI layers.
    # Recompute semantic identity AFTER all subtype detection so downstream
    # consumers never observe a stale/None semantic type for ZIP subtypes.
    final_semantic_type = result.metadata.get("semantic_file_type") or result.detected_type
    final_semantic_mime = result.metadata.get("semantic_mime_type") or result.mime_type
    if not final_semantic_type and result.metadata.get("content_is_text_like"):
        final_semantic_type = "Plain text"
    if not final_semantic_mime and result.metadata.get("inferred_mime_type"):
        final_semantic_mime = result.metadata.get("inferred_mime_type")
    result.metadata["semantic_file_type"] = final_semantic_type
    result.metadata["semantic_mime_type"] = final_semantic_mime
    if not result.mime_type and final_semantic_mime:
        result.mime_type = str(final_semantic_mime)

    # Reconcile extension consistency against the FINAL semantic identity.
    if extension and final_semantic_type:
        expected_extensions = _semantic_expected_extensions(str(final_semantic_type), result.detected_category)
        if expected_extensions is not None:
            result.metadata["semantic_extension_consistent"] = extension in {normalize_extension(e) for e in expected_extensions}
        elif result.detected_category == "executable":
            result.metadata["semantic_extension_consistent"] = extension in EXECUTABLE_EXTENSIONS
        elif result.detected_category == "archive":
            result.metadata["semantic_extension_consistent"] = extension in ARCHIVE_EXTENSIONS
        elif result.detected_category == "document":
            result.metadata["semantic_extension_consistent"] = extension in DOCUMENT_EXTENSIONS
        elif subtype in subtype_expected_extensions:
            result.metadata["semantic_extension_consistent"] = extension in subtype_expected_extensions[subtype]

    result.metadata["finding_count"] = len(result.findings)
    result.metadata["highest_severity"] = _highest_severity(result.findings)
    result.metadata["risk_score"] = round(result.risk_score, 2)
    result.metadata["executable_detected"] = bool(detected and detected.get("executable"))
    result.metadata["archive_detected"] = bool(detected and detected.get("archive"))
    result.metadata["recommended_action"] = {
        "CRITICAL": "QUARANTINE_AND_ANALYST_REVIEW",
        "HIGH": "HOLD_FOR_SECURITY_REVIEW",
        "MEDIUM": "ENHANCED_CONTENT_INSPECTION",
        "LOW": "MONITOR_WITH_CONTEXT",
        "INFO": "NO_ADDITIONAL_ACTION",
    }.get(result.metadata["highest_severity"], "NO_ADDITIONAL_ACTION")
    result.metadata["risk_factors"] = [f.title for f in sorted(result.findings, key=lambda item: (-item.score, item.rule_id))[:8]]
    result.metadata["confidence_summary"] = round(sum(f.confidence for f in result.findings) / len(result.findings), 3) if result.findings else 1.0

    return result


# Compatibility aliases used by different engine revisions.
analyze_file = analyze_file_type
analyze_attachment_file_type = analyze_file_type


def is_archive_type(detected_type: Optional[Union[str, Dict[str, object]]]) -> bool:
    if isinstance(detected_type, dict):
        return bool(detected_type.get("archive"))
    return str(detected_type or "") in {"ZIP", "GZIP", "BZIP2", "XZ", "7-ZIP", "RAR4", "RAR5", "WIM", "ISO9660", "AR", "ARJ", "TAR ustar"}


def is_executable_type(detected_type: Optional[Union[str, Dict[str, object]]]) -> bool:
    if isinstance(detected_type, dict):
        return bool(detected_type.get("executable"))
    return str(detected_type or "") in {"PE/COFF", "ELF", "Mach-O 32", "Mach-O 64", "Mach-O 32 LE", "Mach-O 64 LE", "FAT Mach-O", "Java class", "WASM"}


# Historical-style helper: true when a file begins with ZIP magic.
def is_zip_archive(path: Union[str, Path]) -> bool:
    try:
        return _read_bounded(path, 8).startswith(b"PK\x03\x04") or _read_bounded(path, 8).startswith((b"PK\x05\x06", b"PK\x07\x08"))
    except (OSError, ValueError):
        return False


__all__ = [
    "SignatureDefinition",
    "FileTypeFinding",
    "FileTypeAnalysisResult",
    "SIGNATURES",
    "normalize_extension",
    "get_extension",
    "read_header",
    "detect_file_signature",
    "detect_file_type",
    "analyze_file_type",
    "analyze_file",
    "analyze_attachment_file_type",
    "is_archive_type",
    "is_executable_type",
    "is_zip_archive",
]
