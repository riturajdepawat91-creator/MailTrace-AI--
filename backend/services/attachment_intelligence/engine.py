"""
Attachment Intelligence Engine - Main Orchestrator

Coordinates filename analysis, cryptographic hashing, file type
identification, archive inspection, and centralized risk scoring
into one complete attachment security analysis result.
"""

from __future__ import annotations

import uuid

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import (
    AttachmentAnalysisResult,
    Evidence,
    FileIdentity,
    Finding,
    RiskAssessment,
    utc_now_iso,
)

from .hashing import (
    calculate_standard_file_hashes,
    get_file_size,
)

from .filename_analysis import (
    analyze_filename,
)

from .file_type_analysis import (
    analyze_file_type,
)

from .archive_analysis import (
    analyze_zip_archive,
    is_zip_archive,
)

from .risk_engine import (
    build_risk_result,
    collect_findings,
)


ENGINE_NAME = "Attachment Intelligence Engine"
ENGINE_VERSION = "1.1.0"


def _convert_to_models_findings(
    findings: List[Any],
) -> List[Finding]:
    """
    Convert module-specific findings into the common Finding model.
    """

    converted = []

    for item in findings:

        if hasattr(item, "to_dict"):

            data = item.to_dict()

        elif isinstance(item, dict):

            data = item

        else:

            continue


        converted.append(
            Finding(
                finding_id=str(
                    data.get(
                        "rule_id",
                        data.get(
                            "finding_id",
                            "UNKNOWN_FINDING",
                        ),
                    )
                ),
                title=str(
                    data.get(
                        "title",
                        "Unknown finding",
                    )
                ),
                description=str(
                    data.get(
                        "description",
                        "",
                    )
                ),
                category=str(
                    data.get(
                        "category",
                        "attachment",
                    )
                ),
                severity=str(
                    data.get(
                        "severity",
                        "UNKNOWN",
                    )
                ),
                confidence=float(
                    data.get(
                        "confidence",
                        1.0,
                    )
                ),
                score=float(
                    data.get(
                        "score",
                        0.0,
                    )
                ),
                evidence=data.get(
                    "evidence",
                    {},
                ) or {},
                recommendation=data.get(
                    "recommendation",
                ),
            )
        )


    return converted


def _create_evidence_from_findings(
    findings: List[Finding],
    source: str,
) -> List[Evidence]:
    """
    Create structured evidence records from findings.
    """

    evidence_items = []

    for finding in findings:

        if not finding.evidence:

            continue


        for field_name, value in (
            finding.evidence.items()
        ):

            evidence_items.append(
                Evidence(
                    source=source,
                    field=str(field_name),
                    value=value,
                    description=(
                        f"Evidence for "
                        f"{finding.finding_id}"
                    ),
                    confidence=finding.confidence,
                )
            )


    return evidence_items


def analyze_attachment(
    file_path: Union[str, Path],
    filename: Optional[str] = None,
    include_hashes: bool = True,
) -> AttachmentAnalysisResult:
    """
    Perform complete multi-layer attachment security analysis.

    The analysis currently includes:

    - Cryptographic hashing
    - Filename intelligence
    - File signature identification
    - Extension/content mismatch detection
    - Centralized risk scoring

    The function is designed so additional modules such as
    archive analysis, malware intelligence, and sandbox analysis
    can be integrated without changing the public API.
    """

    path = Path(file_path)


    if not path.exists():

        raise FileNotFoundError(
            f"Attachment not found: {path}"
        )


    if not path.is_file():

        raise ValueError(
            f"Attachment path is not a file: {path}"
        )


    display_name = filename or path.name


    analysis_id = str(
        uuid.uuid4()
    )


    result = AttachmentAnalysisResult(
        analysis_id=analysis_id,
        engine=ENGINE_NAME,
        engine_version=ENGINE_VERSION,
        analyzed_at=utc_now_iso(),
        file=FileIdentity(
            filename=display_name,
            size_bytes=0,
        ),
    )


    all_risk_findings = []


    # ---------------------------------------------------------
    # File identity and hashing
    # ---------------------------------------------------------

    try:

        file_size = get_file_size(
            path
        )


        result.file.size_bytes = (
            file_size
        )


    except Exception as error:

        result.add_error(
            f"Failed to determine file size: {error}"
        )


    if include_hashes:

        try:

            hashes = (
                calculate_standard_file_hashes(
                    path
                )
            )


            result.file.hashes = (
                hashes
            )


            result.add_evidence(
                Evidence(
                    source="hashing",
                    field="md5",
                    value=hashes.md5,
                    description=(
                        "MD5 file fingerprint"
                    ),
                )
            )


            result.add_evidence(
                Evidence(
                    source="hashing",
                    field="sha1",
                    value=hashes.sha1,
                    description=(
                        "SHA-1 file fingerprint"
                    ),
                )
            )


            result.add_evidence(
                Evidence(
                    source="hashing",
                    field="sha256",
                    value=hashes.sha256,
                    description=(
                        "SHA-256 file fingerprint"
                    ),
                )
            )


        except Exception as error:

            result.add_error(
                f"Hash calculation failed: {error}"
            )


    # ---------------------------------------------------------
    # Filename analysis
    # ---------------------------------------------------------

    try:

        filename_result = (
            analyze_filename(
                display_name
            )
        )


        filename_findings = (
            _convert_to_models_findings(
                filename_result.findings
            )
        )


        for finding in filename_findings:

            finding.category = (
                "filename"
            )

            result.add_finding(
                finding
            )


        result.evidence.extend(
            _create_evidence_from_findings(
                filename_findings,
                "filename_analysis",
            )
        )


        all_risk_findings.extend(
            collect_findings(
                source="filename_analysis",
                findings=filename_result.findings,
            )
        )


    except Exception as error:

        result.add_error(
            f"Filename analysis failed: {error}"
        )


    # ---------------------------------------------------------
    # File type / magic byte analysis
    # ---------------------------------------------------------

    try:

        type_result = (
            analyze_file_type(
                file_path=path,
                filename=display_name,
            )
        )


        result.file.extension = (
            type_result.extension
        )


        result.file.detected_type = (
            type_result.detected_type
        )

        # Preserve the richer SOC-grade file-type identity produced by the
        # File Type Intelligence module instead of flattening it into findings.
        # This is stored in the common result metadata so existing FileIdentity
        # schemas remain backward-compatible.
        type_metadata = getattr(type_result, "metadata", {}) or {}
        result.metadata["file_type_intelligence"] = {
            "analysis_version": getattr(type_result, "analysis_version", None),
            "detected_type": type_result.detected_type,
            "detected_category": getattr(type_result, "detected_category", None),
            "mime_type": type_result.mime_type,
            "extension": type_result.extension,
            "container_subtype": type_metadata.get("container_subtype"),
            "semantic_file_type": type_metadata.get("semantic_file_type"),
            "semantic_mime_type": type_metadata.get("semantic_mime_type"),
            "semantic_extension_consistent": type_metadata.get(
                "semantic_extension_consistent"
            ),
            "extension_category": type_metadata.get("extension_category"),
            "executable_detected": type_metadata.get(
                "executable_detected"
            ),
            "archive_detected": type_metadata.get(
                "archive_detected"
            ),
            "malware_confirmed": type_metadata.get(
                "malware_confirmed",
                False,
            ),
            "detection_basis": type_metadata.get("detection_basis"),
            "identity_confidence": type_metadata.get(
                "identity_confidence"
            ),
            "recommended_action": type_metadata.get(
                "recommended_action"
            ),
            "embedded_markers": type_metadata.get(
                "embedded_markers",
                [],
            ),
        }

        # Mirror the most important identity values into the common file
        # record where the existing schema permits it.
        if type_result.mime_type:
            try:
                result.file.mime_type = type_result.mime_type
            except (AttributeError, TypeError):
                pass

        type_identity_evidence = result.metadata["file_type_intelligence"]
        result.add_evidence(
            Evidence(
                source="file_type_analysis",
                field="semantic_file_type",
                value=type_identity_evidence.get("semantic_file_type")
                or type_result.detected_type,
                description="SOC-grade semantic file identity",
                confidence=float(
                    type_identity_evidence.get("identity_confidence")
                    or 1.0
                ),
            )
        )

        result.add_evidence(
            Evidence(
                source="file_type_analysis",
                field="semantic_extension_consistent",
                value=type_identity_evidence.get(
                    "semantic_extension_consistent"
                ),
                description="Filename/content semantic consistency",
                confidence=float(
                    type_identity_evidence.get("identity_confidence")
                    or 1.0
                ),
            )
        )

        type_findings = (
            _convert_to_models_findings(
                type_result.findings
            )
        )


        for finding in type_findings:

            finding.category = (
                "file_type"
            )

            result.add_finding(
                finding
            )


        result.evidence.extend(
            _create_evidence_from_findings(
                type_findings,
                "file_type_analysis",
            )
        )


        if type_result.detected_type:

            result.add_evidence(
                Evidence(
                    source="file_type_analysis",
                    field="detected_type",
                    value=(
                        type_result.detected_type
                    ),
                    description=(
                        "File type identified "
                        "from internal signature"
                    ),
                )
            )


        all_risk_findings.extend(
            collect_findings(
                source="file_type_analysis",
                findings=type_result.findings,
            )
        )


    except Exception as error:

        result.add_error(
            f"File type analysis failed: {error}"
        )


    # ---------------------------------------------------------
    # Archive intelligence analysis
    # ---------------------------------------------------------

    try:

        if is_zip_archive(path):

            archive_result = (
                analyze_zip_archive(
                    file_path=path,
                    filename=display_name,
                )
            )


            archive_findings = (
                _convert_to_models_findings(
                    archive_result.findings
                )
            )


            for finding in archive_findings:

                finding.category = (
                    "archive"
                )

                result.add_finding(
                    finding
                )


            result.evidence.extend(
                _create_evidence_from_findings(
                    archive_findings,
                    "archive_analysis",
                )
            )


            # Preserve the complete Archive Intelligence result so all
            # SOC/V2 metadata propagates through the common engine output.
            result.metadata[
                "archive_analysis"
            ] = archive_result.to_dict()


            all_risk_findings.extend(
                collect_findings(
                    source="archive_analysis",
                    findings=archive_result.findings,
                )
            )


    except Exception as error:

        result.add_error(
            f"Archive analysis failed: {error}"
        )

    # ---------------------------------------------------------
    # Central risk calculation
    # ---------------------------------------------------------

    try:

        risk_result = (
            build_risk_result(
                all_risk_findings
            )
        )


        result.risk = RiskAssessment(
            score=risk_result.score,
            severity=risk_result.severity,
            confidence=risk_result.confidence,
            verdict=risk_result.verdict,
            risk_factors=(
                risk_result.risk_factors
            ),
        )


        result.metadata[
            "risk_statistics"
        ] = risk_result.statistics


        result.metadata[
            "source_scores"
        ] = risk_result.source_scores


    except Exception as error:

        result.add_error(
            f"Risk calculation failed: {error}"
        )


    return result


def analyze_attachment_to_dict(
    file_path: Union[str, Path],
    filename: Optional[str] = None,
    include_hashes: bool = True,
) -> Dict[str, Any]:
    """
    Analyze an attachment and return an API-ready dictionary.
    """

    result = analyze_attachment(
        file_path=file_path,
        filename=filename,
        include_hashes=include_hashes,
    )


    return result.to_dict()


__all__ = [
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "analyze_attachment",
    "analyze_attachment_to_dict",
]
