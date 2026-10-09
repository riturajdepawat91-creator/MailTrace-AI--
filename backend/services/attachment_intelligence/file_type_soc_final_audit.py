from __future__ import annotations

import ast
import hashlib
import os
import tempfile
import traceback
from pathlib import Path

from services.attachment_intelligence.file_type_analysis import (
    MAX_HEADER_READ,
    analyze_file_type,
    detect_file_signature,
    read_header,
)

TARGET = Path(__file__).resolve().parent / "file_type_analysis.py"

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed

    if condition:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}")
        if detail:
            print(f"       {detail}")


def write_temp(name, data):
    path = Path(tempfile.gettempdir()) / f"mailtrace_filetype_soc_{name}"
    path.write_bytes(data)
    return path


def result_findings(result):
    return list(getattr(result, "findings", []))


print("=" * 78)
print("MAILTRACE-AI — FILE TYPE INTELLIGENCE V17 FINAL SOC AUDIT")
print("=" * 78)
print("TARGET:", TARGET)
print()

# ------------------------------------------------------------------
# 1. Import / constant / provenance
# ------------------------------------------------------------------

try:
    check("MODULE_EXISTS", TARGET.exists())
    check("MAX_HEADER_READ_PRESENT", MAX_HEADER_READ == 65536, repr(MAX_HEADER_READ))

    import services.attachment_intelligence.file_type_analysis as ft

    check(
        "ACTIVE_MODULE_PATH",
        Path(ft.__file__).resolve() == TARGET.resolve(),
        str(ft.__file__),
    )

    result_version = getattr(
        ft.FileTypeAnalysisResult(
            original_filename="x",
            extension=".bin",
        ),
        "analysis_version",
        None,
    )

    check(
        "ANALYSIS_VERSION_17",
        result_version == "17.0.0",
        repr(result_version),
    )
except Exception as exc:
    check("IMPORT_AND_VERSION_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 2. AST / static safety
# ------------------------------------------------------------------

try:
    source = TARGET.read_text(encoding="utf-8")
    tree = ast.parse(source)

    forbidden_imports = {
        "subprocess",
        "socket",
        "requests",
        "urllib.request",
        "http.client",
    }

    bad_imports = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_imports:
                    bad_imports.append(alias.name)

        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in forbidden_imports:
                bad_imports.append(mod)

    check("NO_ACTIVE_NETWORK_IMPORTS", not bad_imports, repr(bad_imports))

    dangerous_calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func

            if isinstance(target, ast.Name):
                if target.id in {
                    "eval",
                    "exec",
                    "__import__",
                    "compile",
                }:
                    dangerous_calls.append(target.id)

            elif isinstance(target, ast.Attribute):
                if target.attr in {
                    "system",
                    "popen",
                    "run",
                    "Popen",
                }:
                    dangerous_calls.append(target.attr)

    check(
        "NO_ACTIVE_EXECUTION_CALLS",
        not dangerous_calls,
        repr(dangerous_calls),
    )

except Exception:
    check("STATIC_SAFETY_AUDIT", False, traceback.format_exc())

# ------------------------------------------------------------------
# 3. Direct bounded read
# ------------------------------------------------------------------

try:
    large = write_temp("large.unknown", os.urandom(2 * 1024 * 1024))

    data = read_header(large, 2 * 1024 * 1024)

    check(
        "DIRECT_READ_IS_BOUNDED",
        len(data) <= MAX_HEADER_READ,
        f"read={len(data)} max={MAX_HEADER_READ}",
    )

    result = analyze_file_type(
        file_path=large,
        filename="large.unknown",
    )

    metadata = getattr(result, "metadata", {})

    check(
        "RUNTIME_ANALYSIS_READ_IS_BOUNDED",
        metadata.get("header_bytes_read", 10**9) <= MAX_HEADER_READ,
        repr(metadata.get("header_bytes_read")),
    )

    check(
        "LARGE_UNKNOWN_HAS_FINDINGS",
        len(result_findings(result)) >= 1,
        str(len(result_findings(result))),
    )

except Exception:
    check("BOUNDED_READ_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 4. Magic-byte identity
# ------------------------------------------------------------------

samples = {
    "pdf": (b"%PDF-1.7\n1 0 obj\n", "PDF"),
    "png": (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "PNG"),
    "jpeg": (b"\xff\xd8\xff\xe0" + b"\x00" * 64, "JPEG"),
    "gif": (b"GIF89a" + b"\x00" * 64, "GIF"),
    "zip": (b"PK\x03\x04" + b"\x00" * 64, "ZIP"),
    "elf": (b"\x7fELF" + b"\x00" * 64, "ELF"),
    "pe": (b"MZ" + b"\x00" * 128, "PE/COFF"),
    "jar": (b"PK\x03\x04" + b"META-INF/MANIFEST.MF\x00" * 4, "ZIP"),
}

for label, (blob, expected) in samples.items():
    try:
        detected = detect_file_signature(blob)
        actual = detected.get("type") if detected else None

        check(
            f"MAGIC_{label.upper()}",
            actual == expected or (label == "jar" and actual == "ZIP"),
            f"expected={expected} actual={actual}",
        )
    except Exception:
        check(f"MAGIC_{label.upper()}", False, traceback.format_exc())

# ------------------------------------------------------------------
# 5. Filename/content masquerade
# ------------------------------------------------------------------

try:
    pe_stub = b"MZ" + b"\x00" * 128

    p = write_temp("invoice.pdf", pe_stub)

    r = analyze_file_type(
        file_path=p,
        filename="invoice.pdf",
    )

    ids = {f.rule_id for f in result_findings(r)}

    check(
        "DOCUMENT_EXTENSION_EXECUTABLE_SIGNAL",
        (
            "FILE_TYPE_DOCUMENT_EXTENSION_EXECUTABLE_CONTENT" in ids
            or "FILE_TYPE_EXTENSION_MISMATCH" in ids
        ),
        repr(sorted(ids)),
    )

except Exception:
    check("MASQUERADE_DETECTION", False, traceback.format_exc())

# ------------------------------------------------------------------
# 6. Executable hidden behind unknown suffix
# ------------------------------------------------------------------

try:
    p = write_temp("invoice.data", b"MZ" + b"\x00" * 128)

    r = analyze_file_type(
        file_path=p,
        filename="invoice.data",
    )

    ids = {f.rule_id for f in result_findings(r)}

    check(
        "EXECUTABLE_NONEXEC_EXTENSION_SIGNAL",
        "FILE_TYPE_EXECUTABLE_CONTENT_NONEXEC_EXTENSION" in ids,
        repr(sorted(ids)),
    )

except Exception:
    check("EXECUTABLE_HIDDEN_SUFFIX", False, traceback.format_exc())

# ------------------------------------------------------------------
# 7. PDF active content
# ------------------------------------------------------------------

try:
    payload = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"/JavaScript /OpenAction /AA /Launch /EmbeddedFile\n"
        b"%%EOF\n"
    )

    p = write_temp("active.pdf", payload)

    r = analyze_file_type(
        file_path=p,
        filename="active.pdf",
    )

    ids = {f.rule_id for f in result_findings(r)}

    expected = {
        "FILE_TYPE_PDF_JAVASCRIPT",
        "FILE_TYPE_PDF_OPENACTION",
        "FILE_TYPE_PDF_ADDITIONAL_ACTIONS",
        "FILE_TYPE_PDF_LAUNCH_ACTION",
        "FILE_TYPE_PDF_EMBEDDED_FILE",
    }

    check(
        "PDF_ACTIVE_CONTENT",
        expected.issubset(ids),
        f"missing={sorted(expected - ids)}",
    )

except Exception:
    check("PDF_ACTIVE_CONTENT", False, traceback.format_exc())

# ------------------------------------------------------------------
# 8. HTML script / external resource
# ------------------------------------------------------------------

try:
    payload = (
        b"<html><script>alert(1)</script>"
        b"<img src=\"https://evil.example/a\"></html>"
    )

    p = write_temp("page.html", payload)

    r = analyze_file_type(
        file_path=p,
        filename="page.html",
    )

    ids = {f.rule_id for f in result_findings(r)}

    check(
        "HTML_SCRIPT_SIGNAL",
        "FILE_TYPE_HTML_SCRIPT" in ids,
        repr(sorted(ids)),
    )

    check(
        "HTML_EXTERNAL_RESOURCE_SIGNAL",
        "FILE_TYPE_HTML_EXTERNAL_RESOURCE" in ids,
        repr(sorted(ids)),
    )

except Exception:
    check("HTML_ACTIVE_CONTENT", False, traceback.format_exc())

# ------------------------------------------------------------------
# 9. Embedded / polyglot
# ------------------------------------------------------------------

try:
    payload = b"%PDF-1.7\n" + b"A" * 4096 + b"MZ" + b"\x00" * 128

    p = write_temp("polyglot.pdf", payload)

    r = analyze_file_type(
        file_path=p,
        filename="polyglot.pdf",
    )

    ids = {f.rule_id for f in result_findings(r)}

    check(
        "POLYGLOT_SECONDARY_SIGNATURE",
        "FILE_TYPE_EMBEDDED_SIGNATURES" in ids,
        repr(sorted(ids)),
    )

    check(
        "POLYGLOT_EXECUTABLE_ESCALATION",
        "FILE_TYPE_EXECUTABLE_EMBEDDED" in ids,
        repr(sorted(ids)),
    )

except Exception:
    check("POLYGLOT_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 10. High entropy unknown content
# ------------------------------------------------------------------

try:
    payload = os.urandom(65536)
    p = write_temp("entropy.bin", payload)

    r = analyze_file_type(
        file_path=p,
        filename="entropy.bin",
    )

    metadata = getattr(r, "metadata", {})
    ids = {f.rule_id for f in result_findings(r)}

    check(
        "HIGH_ENTROPY_METADATA",
        float(metadata.get("header_entropy", 0.0)) >= 7.8,
        repr(metadata.get("header_entropy")),
    )

    check(
        "UNKNOWN_HIGH_ENTROPY_SIGNAL",
        "FILE_TYPE_UNKNOWN_HIGH_ENTROPY" in ids,
        repr(sorted(ids)),
    )

except Exception:
    check("HIGH_ENTROPY_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 11. Empty / malformed handling
# ------------------------------------------------------------------

try:
    p = write_temp("empty.bin", b"")

    r = analyze_file_type(
        file_path=p,
        filename="empty.bin",
    )

    ids = {f.rule_id for f in result_findings(r)}

    check(
        "EMPTY_FILE_SAFE_HANDLING",
        "FILE_TYPE_EMPTY_FILE" in ids,
        repr(sorted(ids)),
    )

except Exception:
    check("EMPTY_FILE_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 12. Determinism
# ------------------------------------------------------------------

try:
    payload = (
        b"%PDF-1.7\n"
        b"/JavaScript /OpenAction\n"
        b"MZ"
        + b"\x00" * 4096
    )

    p = write_temp("determinism.bin", payload)

    r1 = analyze_file_type(
        file_path=p,
        filename="determinism.bin",
    )

    r2 = analyze_file_type(
        file_path=p,
        filename="determinism.bin",
    )

    b1 = repr(r1.to_dict()).encode("utf-8")
    b2 = repr(r2.to_dict()).encode("utf-8")

    check(
        "DETERMINISTIC_OUTPUT",
        hashlib.sha256(b1).hexdigest() == hashlib.sha256(b2).hexdigest(),
    )

except Exception:
    check("DETERMINISM_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 13. Hostile Unicode / odd filename
# ------------------------------------------------------------------

try:
    p = write_temp("hostile.bin", b"not-a-known-format")

    hostile_name = (
        "invoice"
        + "\u202e"
        + "fdp"
        + ".unknown"
    )

    r = analyze_file_type(
        file_path=p,
        filename=hostile_name,
    )

    check(
        "HOSTILE_FILENAME_SAFE",
        isinstance(r.to_dict(), dict),
    )

except Exception:
    check("HOSTILE_INPUT_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# 14. Result contract
# ------------------------------------------------------------------

try:
    r = analyze_file_type(
        file_path=write_temp("contract.bin", b"hello world"),
        filename="contract.bin",
    )

    d = r.to_dict()

    required = {
        "original_filename",
        "extension",
        "detected_type",
        "detected_category",
        "mime_type",
        "file_size",
        "findings",
        "metadata",
        "analysis_version",
    }

    check(
        "RESULT_CONTRACT",
        required.issubset(d.keys()),
        f"missing={sorted(required - set(d.keys()))}",
    )

    check(
        "ANALYSIS_VERSION_VALUE",
        d.get("analysis_version") == "17.0.0",
        repr(d.get("analysis_version")),
    )

except Exception:
    check("RESULT_CONTRACT_GATE", False, traceback.format_exc())

# ------------------------------------------------------------------
# Final
# ------------------------------------------------------------------

print()
print("=" * 78)
print("SOC AUDIT RESULTS")
print("=" * 78)
print("PASS:", passed)
print("FAIL:", failed)
print("=" * 78)

if failed == 0:
    print("SOC AUDIT: PASS")
else:
    print("SOC AUDIT: FAIL")
    raise SystemExit(1)
