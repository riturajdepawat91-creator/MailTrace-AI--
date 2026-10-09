from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

from .models import AnchorRequest, AnchorReceipt, AnchorVerification
from .rules import (
    ANCHOR_STATUS_ANCHORED,
    ANCHOR_STATUS_VERIFIED,
    PROVIDER_LOCAL,
    PROVIDER_RFC3161,
    TRUST_LEVEL_EXTERNAL,
    TRUST_LEVEL_LOCAL,
    TRUST_LEVEL_TSA,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnchorProvider(ABC):
    name: str
    trust_level: str

    @abstractmethod
    def create(self, request: AnchorRequest) -> AnchorReceipt:
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        request: AnchorRequest,
        receipt: AnchorReceipt,
    ) -> AnchorVerification:
        raise NotImplementedError


class LocalAnchorProvider(AnchorProvider):
    """
    Deterministic/local anchor provider.

    This is explicitly NOT an independent trust source. It exists for
    offline development, testing and deterministic platform behavior.

    The local proof cryptographically binds:
      - schema/version
      - anchor identity
      - evidence identity
      - commitment
      - commitment algorithm
      - nonce
      - anchor timestamp

    This prevents receipt-field substitution from silently preserving a
    valid proof.
    """

    name = PROVIDER_LOCAL
    trust_level = TRUST_LEVEL_LOCAL
    PROOF_SCHEMA = "mailtrace.local_anchor_proof.v2"

    @classmethod
    def _proof_material(
        cls,
        request: AnchorRequest,
        anchored_at_utc: str,
    ) -> bytes:
        material = (
            cls.PROOF_SCHEMA
            + "|"
            + request.anchor_id
            + "|"
            + request.evidence_id
            + "|"
            + request.commitment_algorithm
            + "|"
            + request.commitment_sha256
            + "|"
            + request.nonce
            + "|"
            + anchored_at_utc
        )
        return material.encode("utf-8")

    @classmethod
    def _build_proof(
        cls,
        request: AnchorRequest,
        anchored_at_utc: str,
    ) -> bytes:
        return hashlib.sha256(
            cls._proof_material(
                request,
                anchored_at_utc,
            )
        ).hexdigest().encode("ascii")

    def create(self, request: AnchorRequest) -> AnchorReceipt:
        anchored_at_utc = _utc_now()

        proof = self._build_proof(
            request,
            anchored_at_utc,
        )

        return AnchorReceipt(
            anchor_id=request.anchor_id,
            evidence_id=request.evidence_id,
            provider=self.name,
            status=ANCHOR_STATUS_ANCHORED,
            trust_level=self.trust_level,
            commitment_algorithm=request.commitment_algorithm,
            commitment_sha256=request.commitment_sha256,
            anchored_at_utc=anchored_at_utc,
            external_reference=f"local:{request.anchor_id}",
            proof=proof,
            verification_state="UNVERIFIED",
            nonce=request.nonce,
            metadata={
                "independent_trust_boundary": False,
                "test_provider": True,
                "proof_schema": self.PROOF_SCHEMA,
            },
        )

    def verify(
        self,
        request: AnchorRequest,
        receipt: AnchorReceipt,
    ) -> AnchorVerification:
        issues: list[str] = []

        anchor_id_match = (
            receipt.anchor_id == request.anchor_id
        )

        if not anchor_id_match:
            issues.append("Anchor ID mismatch.")

        evidence_id_match = (
            receipt.evidence_id == request.evidence_id
        )

        if not evidence_id_match:
            issues.append("Evidence ID mismatch.")

        provider_match = (
            receipt.provider == request.provider
        )

        if not provider_match:
            issues.append("Anchor provider mismatch.")

        algorithm_match = (
            receipt.commitment_algorithm
            == request.commitment_algorithm
        )

        if not algorithm_match:
            issues.append(
                "Anchor commitment algorithm mismatch."
            )

        commitment_match = (
            receipt.commitment_sha256
            == request.commitment_sha256
        )

        if not commitment_match:
            issues.append("Anchor commitment mismatch.")

        nonce_match = (
            receipt.nonce == request.nonce
        )

        if not nonce_match:
            issues.append("Anchor nonce mismatch.")

        timestamp_present = bool(
            receipt.anchored_at_utc
        )

        timestamp_valid = False

        if not timestamp_present:
            issues.append("Anchor timestamp is missing.")
        else:
            timestamp_text = receipt.anchored_at_utc.strip()

            try:
                parsed_timestamp = datetime.fromisoformat(
                    timestamp_text.replace(
                        "Z",
                        "+00:00",
                    )
                )

                if parsed_timestamp.tzinfo is None:
                    issues.append(
                        "Anchor timestamp must include timezone information."
                    )
                else:
                    parsed_utc = parsed_timestamp.astimezone(
                        timezone.utc
                    )

                    now_utc = datetime.now(timezone.utc)

                    if parsed_utc > now_utc:
                        issues.append(
                            "Anchor timestamp is in the future."
                        )
                    else:
                        timestamp_valid = True

            except (TypeError, ValueError):
                issues.append(
                    "Anchor timestamp is malformed."
                )

        proof_match = False

        if timestamp_present and timestamp_valid:
            expected_proof = self._build_proof(
                request,
                receipt.anchored_at_utc,
            )

            proof_match = (
                receipt.proof == expected_proof
            )

            if not proof_match:
                issues.append(
                    "Local anchor proof mismatch."
                )
        else:
            issues.append(
                "Local anchor proof cannot be validated "
                "without a valid timestamp."
            )

        provider_verified = (
            anchor_id_match
            and evidence_id_match
            and provider_match
            and algorithm_match
            and commitment_match
            and nonce_match
            and proof_match
        )

        valid = (
            provider_verified
            and timestamp_present
            and timestamp_valid
        )

        return AnchorVerification(
            anchor_id=request.anchor_id,
            evidence_id=request.evidence_id,
            valid=valid,
            commitment_match=commitment_match,
            provider_verified=provider_verified,
            timestamp_present=timestamp_present,
            trust_level=self.trust_level,
            issues=tuple(issues),
        )


@dataclass
class RFC3161Provider(AnchorProvider):
    """
    RFC 3161 adapter boundary.

    The cryptographic transport/token implementation is deliberately
    injected rather than silently emulated. A real deployment should
    provide request_transport and token_verifier implementations that
    perform RFC 3161 request/response processing and signature/certificate
    validation.

    The engine never treats an opaque token as trusted merely because it
    was returned by a URL.
    """

    tsa_url: str
    request_transport: Callable[[bytes], bytes] | None = None
    token_verifier: Callable[
        [bytes, str, str],
        tuple[bool, str | None, tuple[str, ...]],
    ] | None = None

    name = PROVIDER_RFC3161
    trust_level = TRUST_LEVEL_TSA

    def create(self, request: AnchorRequest) -> AnchorReceipt:
        if self.request_transport is None:
            return AnchorReceipt(
                anchor_id=request.anchor_id,
                evidence_id=request.evidence_id,
                provider=self.name,
                status="FAILED",
                trust_level=TRUST_LEVEL_EXTERNAL,
                commitment_algorithm=request.commitment_algorithm,
                commitment_sha256=request.commitment_sha256,
                anchored_at_utc=None,
                external_reference=self.tsa_url,
                proof=None,
                verification_state="UNVERIFIED",
                verification_issues=(
                    "RFC 3161 transport is not configured.",
                ),
                nonce=request.nonce,
                metadata={
                    "tsa_url": self.tsa_url,
                    "configuration_required": True,
                },
            )

        # The transport boundary expects a pre-built RFC 3161
        # TimeStampReq DER body. Building and validating ASN.1/CMS
        # is intentionally delegated to the injected implementation.
        request_bytes = request.commitment_sha256.encode("ascii")
        token = self.request_transport(request_bytes)

        return AnchorReceipt(
            anchor_id=request.anchor_id,
            evidence_id=request.evidence_id,
            provider=self.name,
            status=ANCHOR_STATUS_ANCHORED,
            trust_level=TRUST_LEVEL_EXTERNAL,
            commitment_algorithm=request.commitment_algorithm,
            commitment_sha256=request.commitment_sha256,
            anchored_at_utc=None,
            external_reference=self.tsa_url,
            proof=token,
            verification_state="UNVERIFIED",
            nonce=request.nonce,
            metadata={
                "tsa_url": self.tsa_url,
                "token_requires_validation": True,
            },
        )

    def verify(
        self,
        request: AnchorRequest,
        receipt: AnchorReceipt,
    ) -> AnchorVerification:
        issues: list[str] = []

        anchor_id_match = (
            receipt.anchor_id == request.anchor_id
        )

        if not anchor_id_match:
            issues.append("Anchor ID mismatch.")

        evidence_id_match = (
            receipt.evidence_id == request.evidence_id
        )

        if not evidence_id_match:
            issues.append("Evidence ID mismatch.")

        provider_match = (
            receipt.provider == self.name
            and receipt.provider == request.provider
        )

        if not provider_match:
            issues.append(
                "Receipt/provider identity does not match RFC 3161 provider."
            )

        algorithm_match = (
            receipt.commitment_algorithm
            == request.commitment_algorithm
        )

        if not algorithm_match:
            issues.append(
                "Anchor commitment algorithm mismatch."
            )

        commitment_match = (
            receipt.commitment_sha256
            == request.commitment_sha256
        )

        if not commitment_match:
            issues.append("Anchor commitment mismatch.")

        nonce_match = (
            receipt.nonce == request.nonce
        )

        if not nonce_match:
            issues.append("Anchor nonce mismatch.")

        provider_verified = False
        timestamp_present = False

        if self.token_verifier is None:
            issues.append(
                "RFC 3161 token verifier is not configured."
            )
        elif receipt.proof is None:
            issues.append(
                "RFC 3161 timestamp token is missing."
            )
        else:
            try:
                (
                    provider_verified,
                    anchored_at_utc,
                    verifier_issues,
                ) = self.token_verifier(
                    receipt.proof,
                    request.commitment_sha256,
                    request.nonce,
                )

                if anchored_at_utc:
                    timestamp_present = True

                    receipt_time = datetime.fromisoformat(
                        anchored_at_utc.replace(
                            "Z",
                            "+00:00",
                        )
                    )

                    now = datetime.now(timezone.utc)

                    skew = abs(
                        (now - receipt_time).total_seconds()
                    )

                    if skew > 300:
                        issues.append(
                            "RFC 3161 token timestamp is outside "
                            "the configured local clock-skew window."
                        )
                else:
                    issues.append(
                        "RFC 3161 token did not provide a timestamp."
                    )

                issues.extend(verifier_issues)

            except Exception as exc:
                issues.append(
                    f"RFC 3161 token verification failed: {type(exc).__name__}"
                )

        provider_verified = (
            anchor_id_match
            and evidence_id_match
            and provider_match
            and algorithm_match
            and commitment_match
            and nonce_match
            and provider_verified
        )

        valid = (
            anchor_id_match
            and evidence_id_match
            and provider_match
            and algorithm_match
            and commitment_match
            and nonce_match
            and provider_verified
            and timestamp_present
            and not issues
        )

        return AnchorVerification(
            anchor_id=request.anchor_id,
            evidence_id=request.evidence_id,
            valid=valid,
            commitment_match=commitment_match,
            provider_verified=provider_verified,
            timestamp_present=timestamp_present,
            trust_level=(
                TRUST_LEVEL_TSA
                if valid
                else TRUST_LEVEL_EXTERNAL
            ),
            issues=tuple(issues),
        )
