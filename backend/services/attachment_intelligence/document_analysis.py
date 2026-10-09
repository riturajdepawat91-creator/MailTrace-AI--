"""
Document Intelligence Module

Analyzes potentially dangerous indicators inside common documents,
including PDFs and Microsoft Office Open XML documents.
"""

from __future__ import annotations

import zipfile

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


PDF_EXTENSIONS = {
    ".pdf",
}

OFFICE_OPENXML_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
}

MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".xlsm",
    ".pptm",
}


@dataclass
class DocumentFinding:

    rule_id: str
    title: str
    description: str
    severity: str
    score: float
    evidence: Dict[str, Any] = field(
        default_factory=dict
    )
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": self.score,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class DocumentAnalysisResult:

    document_type: str = "UNKNOWN"

    findings: List[DocumentFinding] = field(
        default_factory=list
    )

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    def add_finding(
        self,
        finding: DocumentFinding,
    ) -> None:

        self.findings.append(
            finding
        )


def get_document_extension(
    filename: str | Path,
) -> str:

    return Path(
        filename
    ).suffix.lower()


def is_supported_document(
    filename: str | Path,
) -> bool:

    extension = get_document_extension(
        filename
    )

    return extension in (
        PDF_EXTENSIONS
        | OFFICE_OPENXML_EXTENSIONS
    )


def analyze_pdf_document(
    file_path: Path,
) -> DocumentAnalysisResult:

    result = DocumentAnalysisResult(
        document_type="PDF"
    )

    try:

        content = file_path.read_bytes()


        suspicious_indicators = {
            b"/JavaScript": (
                "PDF_JAVASCRIPT",
                "JavaScript detected inside PDF",
                "PDF contains a JavaScript indicator.",
                "HIGH",
                25.0,
            ),
            b"/JS": (
                "PDF_JAVASCRIPT_SHORT",
                "JavaScript indicator detected",
                "PDF contains a short JavaScript indicator.",
                "HIGH",
                20.0,
            ),
            b"/OpenAction": (
                "PDF_AUTO_ACTION",
                "Automatic PDF action detected",
                "PDF may execute an action automatically when opened.",
                "MEDIUM",
                15.0,
            ),
            b"/Launch": (
                "PDF_LAUNCH_ACTION",
                "Launch action detected",
                "PDF may attempt to launch an external resource.",
                "HIGH",
                25.0,
            ),
            b"/EmbeddedFile": (
                "PDF_EMBEDDED_FILE",
                "Embedded file detected",
                "PDF contains an embedded file indicator.",
                "MEDIUM",
                15.0,
            ),
        }


        detected_indicators = []


        for indicator, details in (
            suspicious_indicators.items()
        ):

            if indicator in content:

                (
                    rule_id,
                    title,
                    description,
                    severity,
                    score,
                ) = details


                detected_indicators.append(
                    indicator.decode(
                        errors="ignore"
                    )
                )


                result.add_finding(
                    DocumentFinding(
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        score=score,
                        evidence={
                            "indicator": (
                                indicator.decode(
                                    errors="ignore"
                                )
                            ),
                        },
                    )
                )


        result.metadata[
            "detected_indicators"
        ] = detected_indicators


        result.metadata[
            "file_size"
        ] = len(content)


    except Exception as error:

        result.add_finding(
            DocumentFinding(
                rule_id="PDF_ANALYSIS_ERROR",
                title="PDF analysis error",
                description=(
                    "The PDF could not be fully inspected."
                ),
                severity="INFO",
                score=0.0,
                evidence={
                    "error": str(error),
                },
            )
        )


    return result


def analyze_office_document(
    file_path: Path,
    extension: str,
) -> DocumentAnalysisResult:

    result = DocumentAnalysisResult(
        document_type=(
            f"OFFICE_OPENXML_{extension.upper()}"
        )
    )


    try:

        with zipfile.ZipFile(
            file_path,
            "r",
        ) as archive:


            archive_files = archive.namelist()


            result.metadata[
                "internal_file_count"
            ] = len(
                archive_files
            )


            result.metadata[
                "internal_files"
            ] = archive_files


            macro_files = [

                name

                for name in archive_files

                if (
                    "vbaproject.bin"
                    in name.lower()
                )

            ]


            if macro_files:

                result.add_finding(
                    DocumentFinding(
                        rule_id="OFFICE_MACRO_PRESENT",
                        title="Office macro detected",
                        description=(
                            "The Office document contains "
                            "a VBA macro project."
                        ),
                        severity="HIGH",
                        score=30.0,
                        evidence={
                            "macro_files": (
                                macro_files
                            ),
                        },
                    )
                )


            external_relationship_files = [

                name

                for name in archive_files

                if name.lower().endswith(
                    ".rels"
                )

            ]


            external_targets = []


            for relationship_file in (
                external_relationship_files
            ):

                try:

                    relationship_content = (
                        archive.read(
                            relationship_file
                        )
                    ).decode(
                        "utf-8",
                        errors="ignore",
                    )


                    if (
                        'TargetMode="External"'
                        in relationship_content
                    ):

                        external_targets.append(
                            relationship_file
                        )


                except Exception:

                    continue


            if external_targets:

                result.add_finding(
                    DocumentFinding(
                        rule_id="OFFICE_EXTERNAL_RELATIONSHIP",
                        title=(
                            "External document relationship "
                            "detected"
                        ),
                        description=(
                            "The Office document references "
                            "an external resource."
                        ),
                        severity="MEDIUM",
                        score=15.0,
                        evidence={
                            "relationship_files": (
                                external_targets
                            ),
                        },
                    )
                )


            if (
                extension
                in MACRO_ENABLED_EXTENSIONS
            ):

                result.add_finding(
                    DocumentFinding(
                        rule_id=(
                            "OFFICE_MACRO_ENABLED_EXTENSION"
                        ),
                        title=(
                            "Macro-enabled Office document"
                        ),
                        description=(
                            "The file extension indicates "
                            "that macros may be supported."
                        ),
                        severity="MEDIUM",
                        score=10.0,
                        evidence={
                            "extension": extension,
                        },
                    )
                )


    except zipfile.BadZipFile:

        result.add_finding(
            DocumentFinding(
                rule_id="OFFICE_INVALID_CONTAINER",
                title="Invalid Office document container",
                description=(
                    "The document could not be parsed "
                    "as a valid Office Open XML archive."
                ),
                severity="MEDIUM",
                score=15.0,
                evidence={},
            )
        )


    except Exception as error:

        result.add_finding(
            DocumentFinding(
                rule_id="OFFICE_ANALYSIS_ERROR",
                title="Office document analysis error",
                description=(
                    "An unexpected error occurred while "
                    "analyzing the document."
                ),
                severity="INFO",
                score=0.0,
                evidence={
                    "error": str(error),
                },
            )
        )


    return result


def analyze_document(
    file_path: str | Path,
    filename: str | None = None,
) -> DocumentAnalysisResult:

    path = Path(
        file_path
    )


    display_name = (
        filename
        or path.name
    )


    extension = get_document_extension(
        display_name
    )


    if extension in PDF_EXTENSIONS:

        return analyze_pdf_document(
            path
        )


    if extension in OFFICE_OPENXML_EXTENSIONS:

        return analyze_office_document(
            path,
            extension,
        )


    return DocumentAnalysisResult(
        document_type="UNSUPPORTED"
    )


__all__ = [
    "PDF_EXTENSIONS",
    "OFFICE_OPENXML_EXTENSIONS",
    "MACRO_ENABLED_EXTENSIONS",
    "DocumentFinding",
    "DocumentAnalysisResult",
    "get_document_extension",
    "is_supported_document",
    "analyze_pdf_document",
    "analyze_office_document",
    "analyze_document",
]
