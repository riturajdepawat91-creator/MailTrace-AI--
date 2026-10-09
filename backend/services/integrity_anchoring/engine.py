from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .canonical import (
    canonical_commitment_payload,
    commitment_sha256,
)
from .models import (
    AnchorExport,
    AnchorReceipt,
    AnchorRequest,
    AnchorVerification,
)
from .providers import AnchorProvider
from .rules import (
    ANALYSIS_NAME,
    ANALYSIS_VERSION,
    MAX_EVIDENCE_ID_CHARS,
    MAX_METADATA_ITEMS,
    MAX_PROVIDER_NAME_CHARS,
    SUPPORTED_COMMITMENT_ALGORITHM,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_json(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class IntegrityAnchorError(Exception):
    pass


class IntegrityAnchorEngine:
    """
    Independent integrity-anchoring orchestration layer.

    The engine receives an already-established custody commitment.
    It does not calculate or replace Evidence Custody's own chain.
    """

    def __init__(
        self,
        *,
        providers: dict[str, AnchorProvider] | None = None,
    ) -> None:
        self._providers = dict(providers or {})
        self._requests: dict[str, AnchorRequest] = {}
        self._receipts: dict[str, AnchorReceipt] = {}

    # ---------------------------------------------------------
    # Provider management
    # ---------------------------------------------------------
    def register_provider(
        self,
        provider: AnchorProvider,
    ) -> None:
        if not isinstance(provider, AnchorProvider):
            raise TypeError(
                "provider must implement AnchorProvider."
            )

        if not provider.name:
            raise ValueError("Provider name is required.")

        if len(provider.name) > MAX_PROVIDER_NAME_CHARS:
            raise ValueError("Provider name is too long.")

        self._providers[provider.name] = provider

    def get_provider(
        self,
        provider_name: str,
    ) -> AnchorProvider:
        try:
            return self._providers[provider_name]
        except KeyError as exc:
            raise IntegrityAnchorError(
                f"Unknown anchor provider: {provider_name}"
            ) from exc

    # ---------------------------------------------------------
    # Anchor creation
    # ---------------------------------------------------------
    def create_anchor(
        self,
        *,
        evidence_id: str,
        evidence_sha256: str,
        terminal_event_hash: str,
        chain_anchor_digest: str,
        provider: str,
        manifest_sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AnchorReceipt:
        if not evidence_id:
            raise ValueError("Evidence ID is required.")

        if len(evidence_id) > MAX_EVIDENCE_ID_CHARS:
            raise ValueError("Evidence ID is too long.")

        metadata = dict(metadata or {})

        if len(metadata) > MAX_METADATA_ITEMS:
            raise ValueError("Too many anchor metadata items.")

        commitment_payload = canonical_commitment_payload(
            evidence_id=evidence_id,
            evidence_sha256=evidence_sha256,
            terminal_event_hash=terminal_event_hash,
            chain_anchor_digest=chain_anchor_digest,
            manifest_sha256=manifest_sha256,
        )

        commitment = commitment_sha256(
            commitment_payload
        )

        # Idempotency: the same evidence+commitment+provider returns
        # the already-created receipt instead of generating a duplicate.
        for existing_id, existing in self._receipts.items():
            if (
                existing.evidence_id == evidence_id
                and existing.provider == provider
                and existing.commitment_sha256 == commitment
            ):
                return existing

        anchor_id = (
            "anc_"
            + datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            + "_"
            + secrets.token_hex(8)
        )

        request = AnchorRequest(
            anchor_id=anchor_id,
            evidence_id=evidence_id,
            commitment_algorithm=SUPPORTED_COMMITMENT_ALGORITHM,
            commitment_sha256=commitment,
            commitment_payload=commitment_payload,
            requested_at_utc=_utc_now(),
            provider=provider,
            nonce=secrets.token_hex(16),
            metadata=metadata,
        )

        anchor_provider = self.get_provider(provider)

        receipt = anchor_provider.create(
            request
        )

        self._requests[anchor_id] = request
        self._receipts[anchor_id] = receipt

        return receipt

    # ---------------------------------------------------------
    # Verification
    # ---------------------------------------------------------
    def verify_anchor(
        self,
        anchor_id: str,
    ) -> AnchorVerification:
        if anchor_id not in self._requests:
            raise IntegrityAnchorError(
                f"Unknown anchor: {anchor_id}"
            )

        request = self._requests[anchor_id]
        receipt = self._receipts[anchor_id]
        provider = self.get_provider(
            request.provider
        )

        result = provider.verify(
            request,
            receipt,
        )

        if result.valid:
            self._receipts[anchor_id] = AnchorReceipt(
                **{
                    **asdict(receipt),
                    "status": "VERIFIED",
                    "trust_level": result.trust_level,
                    "verification_state": "VERIFIED",
                    "verification_issues": result.issues,
                }
            )
        else:
            self._receipts[anchor_id] = AnchorReceipt(
                **{
                    **asdict(receipt),
                    "verification_state": "FAILED",
                    "verification_issues": result.issues,
                }
            )

        return result

    # ---------------------------------------------------------
    # Lookup
    # ---------------------------------------------------------
    def get_anchor(
        self,
        anchor_id: str,
    ) -> AnchorReceipt:
        try:
            return self._receipts[anchor_id]
        except KeyError as exc:
            raise IntegrityAnchorError(
                f"Unknown anchor: {anchor_id}"
            ) from exc

    def list_anchors(
        self,
        *,
        evidence_id: str | None = None,
    ) -> list[AnchorReceipt]:
        values = list(
            self._receipts.values()
        )

        if evidence_id is None:
            return values

        return [
            item
            for item in values
            if item.evidence_id == evidence_id
        ]

    # ---------------------------------------------------------
    # Proof export
    # ---------------------------------------------------------
    def export_anchor_proof(
        self,
        anchor_id: str,
    ) -> AnchorExport:
        if anchor_id not in self._requests:
            raise IntegrityAnchorError(
                f"Unknown anchor: {anchor_id}"
            )

        request = self._requests[anchor_id]

        verification = self.verify_anchor(
            anchor_id
        )

        # verify_anchor() may replace the stored receipt with the
        # cryptographically-derived verification state. Always
        # re-read the canonical stored receipt after verification
        # so exported receipt state cannot become stale.
        receipt = self._receipts[anchor_id]

        request_dict = asdict(request)
        receipt_dict = asdict(receipt)
        verification_dict = asdict(verification)

        canonical = json.dumps(
            {
                "request": request_dict,
                "receipt": {
                    **receipt_dict,
                    "proof": (
                        receipt_dict["proof"].hex()
                        if isinstance(
                            receipt_dict["proof"],
                            bytes,
                        )
                        else receipt_dict["proof"]
                    ),
                },
                "verification": verification_dict,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

        return AnchorExport(
            analysis={
                "name": ANALYSIS_NAME,
                "version": ANALYSIS_VERSION,
                "static_only": True,
            },
            request=request_dict,
            receipt={
                **receipt_dict,
                "proof": (
                    receipt_dict["proof"].hex()
                    if isinstance(
                        receipt_dict["proof"],
                        bytes,
                    )
                    else receipt_dict["proof"]
                ),
            },
            verification=verification_dict,
            export_integrity={
                "sha256": hashlib.sha256(
                    canonical
                ).hexdigest(),
                "sha512": hashlib.sha512(
                    canonical
                ).hexdigest(),
            },
        )
