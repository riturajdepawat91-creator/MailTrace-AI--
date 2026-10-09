from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .models import (
    RedactionResult,
    RetentionEvaluation,
    RetentionPolicy,
)
from .rules import (
    DEFAULT_RETENTION_DAYS,
    DEFAULT_SENSITIVE_FIELDS,
    DataClassification,
    MAX_ACTOR_CHARS,
    MAX_CLASSIFICATION_CHARS,
    MAX_NESTING,
    MAX_POLICY_NAME_CHARS,
    MAX_PURPOSE_CHARS,
    MAX_RECORD_FIELDS,
    MAX_RETENTION_DAYS,
    MAX_STRING_CHARS,
    RedactionMode,
    RetentionAction,
)

_ACTOR_RE = re.compile(r"^[A-Za-z0-9._:@/+\\-]{1,256}$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")


class PrivacyGovernanceError(ValueError):
    pass


class PrivacyPolicyError(PrivacyGovernanceError):
    pass


class _RestrictedClassification(Exception):
    """Internal control-flow marker for restricted classification escalation."""



def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise PrivacyGovernanceError("timestamp must be a non-empty ISO-8601 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PrivacyGovernanceError("invalid UTC timestamp") from exc
    if dt.tzinfo is None:
        raise PrivacyGovernanceError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


def _bounded_text(value: str, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PrivacyGovernanceError(f"{name} must be a non-empty string")
    if len(value) > limit:
        raise PrivacyGovernanceError(f"{name} exceeds safety limit")
    return value


def _audit_fingerprint(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


class PrivacyGovernanceEngine:
    """Static policy engine for privacy, retention and controlled views.

    This module is intentionally separate from evidence custody. It governs access and
    derived-data handling without mutating immutable forensic evidence records.
    """

    def __init__(self, *, policies: list[RetentionPolicy] | None = None, sensitive_fields=None):
        self._policies: dict[str, RetentionPolicy] = {}
        self._sensitive_fields = set(sensitive_fields or DEFAULT_SENSITIVE_FIELDS)
        if len(self._sensitive_fields) > MAX_RECORD_FIELDS:
            raise PrivacyPolicyError("too many sensitive-field rules")
        for field_name in self._sensitive_fields:
            _FIELD_RE.fullmatch(str(field_name)) or self._raise("invalid sensitive field")
        for policy in policies or []:
            self.register_policy(policy)

    @staticmethod
    def _raise(message: str):
        raise PrivacyPolicyError(message)

    def register_policy(self, policy: RetentionPolicy) -> None:
        if not isinstance(policy, RetentionPolicy):
            raise TypeError("policy must be RetentionPolicy")
        _bounded_text(policy.policy_id, "policy_id", 128)
        _bounded_text(policy.name, "policy.name", MAX_POLICY_NAME_CHARS)
        if len(policy.classification) > MAX_CLASSIFICATION_CHARS:
            raise PrivacyPolicyError("classification too long")
        if policy.classification not in {x.value for x in DataClassification}:
            raise PrivacyPolicyError("unsupported data classification")
        if not isinstance(policy.retention_days, int) or isinstance(policy.retention_days, bool):
            raise PrivacyPolicyError("retention_days must be an integer")
        if policy.retention_days < 0 or policy.retention_days > MAX_RETENTION_DAYS:
            raise PrivacyPolicyError("retention_days outside safety bounds")
        if not policy.purge_derived_views and policy.purge_raw_evidence:
            raise PrivacyPolicyError("raw purge cannot be enabled without derived-view purge")
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> RetentionPolicy:
        try:
            return self._policies[policy_id]
        except KeyError as exc:
            raise PrivacyPolicyError("unknown policy") from exc

    def policies(self) -> list[RetentionPolicy]:
        return list(self._policies.values())

    def classify(self, value: Any) -> str:
        """Deterministically classify a record, including nested structures.

        Explicit top-level `_classification` wins. Otherwise the complete nested
        structure is inspected. Restricted indicators take precedence over
        sensitive indicators. Traversal is bounded by the same safety limits
        used by redaction.
        """
        allowed = {x.value for x in DataClassification}

        if not isinstance(value, (Mapping, list, tuple)):
            return DataClassification.INTERNAL.value

        if isinstance(value, Mapping):
            explicit = value.get("_classification")
            if explicit in allowed:
                return explicit

        restricted_keys = {
            "raw_email",
            "authorization",
            "token",
            "secret",
            "cookie",
        }

        found_sensitive = False

        def walk(obj: Any, depth: int) -> None:
            nonlocal found_sensitive

            if depth > MAX_NESTING:
                raise PrivacyGovernanceError(
                    "record nesting exceeds safety limit"
                )

            if isinstance(obj, Mapping):
                if len(obj) > MAX_RECORD_FIELDS:
                    raise PrivacyGovernanceError(
                        "record exceeds field limit"
                    )

                for key, child in obj.items():
                    key_text = str(key).lower()

                    if key_text in restricted_keys:
                        raise _RestrictedClassification()

                    if key_text in self._sensitive_fields:
                        found_sensitive = True

                    walk(child, depth + 1)
                return

            if isinstance(obj, (list, tuple)):
                if len(obj) > MAX_RECORD_FIELDS:
                    raise PrivacyGovernanceError(
                        "collection exceeds field limit"
                    )

                for child in obj:
                    walk(child, depth + 1)
                return

            if isinstance(obj, str) and len(obj) > MAX_STRING_CHARS:
                raise PrivacyGovernanceError(
                    "string value exceeds safety limit"
                )

        try:
            walk(value, 0)
        except _RestrictedClassification:
            return DataClassification.RESTRICTED.value

        if found_sensitive:
            return DataClassification.SENSITIVE.value

        return DataClassification.INTERNAL.value


    def evaluate_retention(
        self,
        *,
        evidence_id: str,
        classification: str,
        acquired_at_utc: str,
        policy_id: str,
        legal_hold: bool = False,
        forensic_hold: bool = False,
        now_utc: str | None = None,
    ) -> RetentionEvaluation:
        evidence_id = _bounded_text(evidence_id, "evidence_id", 128)
        acquired = _parse_utc(acquired_at_utc)
        now = _parse_utc(now_utc) if now_utc else _utc_now()
        policy = self.get_policy(policy_id)

        allowed = {x.value for x in DataClassification}
        if not isinstance(classification, str):
            raise PrivacyPolicyError("classification must be a string")
        if len(classification) > MAX_CLASSIFICATION_CHARS:
            raise PrivacyPolicyError("classification too long")
        if classification not in allowed:
            raise PrivacyPolicyError("unsupported data classification")

        if policy.classification != classification:
            raise PrivacyPolicyError("policy/classification mismatch")

        if legal_hold and not policy.legal_hold_allowed:
            raise PrivacyPolicyError(
                "legal hold is not permitted by the selected policy"
            )

        if forensic_hold and not policy.forensic_hold_allowed:
            raise PrivacyPolicyError(
                "forensic hold is not permitted by the selected policy"
            )

        expires = acquired + timedelta(days=policy.retention_days)

        if legal_hold:
            action = RetentionAction.LEGAL_HOLD.value
            reason = "legal hold overrides normal purge eligibility"
        elif forensic_hold:
            action = RetentionAction.FORENSIC_HOLD.value
            reason = "forensic hold protects investigative material"
        elif now >= expires:
            action = RetentionAction.ELIGIBLE_FOR_PURGE.value
            reason = "retention period elapsed"
        else:
            action = RetentionAction.RETAIN.value
            reason = "retention period active"
        return RetentionEvaluation(
            action=action,
            evidence_id=evidence_id,
            classification=classification,
            policy_id=policy.policy_id,
            expires_at_utc=expires.isoformat(),
            legal_hold=bool(legal_hold),
            forensic_hold=bool(forensic_hold),
            reason=reason,
        )

    def redact(self, record: Mapping[str, Any], *, classification: str | None = None, mode: RedactionMode = RedactionMode.MASK, pseudonym_key: bytes | None = None) -> RedactionResult:
        if not isinstance(record, Mapping):
            raise TypeError("record must be a mapping")
        if len(record) > MAX_RECORD_FIELDS:
            raise PrivacyGovernanceError("record exceeds field limit")
        if classification is None:
            classification = self.classify(record)
        if classification not in {x.value for x in DataClassification}:
            raise PrivacyGovernanceError("unsupported classification")
        if isinstance(mode, str):
            mode = RedactionMode(mode)
        if mode == RedactionMode.PSEUDONYMIZE and not pseudonym_key:
            raise PrivacyGovernanceError("pseudonym_key is required")
        data = copy.deepcopy(dict(record))
        redacted: list[str] = []
        removed: list[str] = []
        pseudonymized: list[str] = []

        def transform(obj: Any, depth: int, path: str) -> Any:
            if depth > MAX_NESTING:
                raise PrivacyGovernanceError("record nesting exceeds safety limit")
            if isinstance(obj, Mapping):
                out = {}
                for key, value in obj.items():
                    key_text = str(key)
                    field_path = f"{path}.{key_text}" if path else key_text
                    sensitive = key_text.lower() in self._sensitive_fields
                    if sensitive:
                        if mode == RedactionMode.REMOVE:
                            removed.append(field_path)
                            continue
                        if mode == RedactionMode.MASK:
                            out[key] = "[REDACTED]"
                            redacted.append(field_path)
                            continue
                        raw = str(value)
                        if len(raw) > MAX_STRING_CHARS:
                            raise PrivacyGovernanceError("field exceeds safe transformation length")
                        token = hmac.new(pseudonym_key, raw.encode(), hashlib.sha256).hexdigest()[:20]
                        out[key] = f"pst_{token}"
                        pseudonymized.append(field_path)
                        continue
                    out[key] = transform(value, depth + 1, field_path)
                return out
            if isinstance(obj, list):
                return [transform(v, depth + 1, path) for v in obj]
            if isinstance(obj, tuple):
                return [transform(v, depth + 1, path) for v in obj]
            if isinstance(obj, str) and len(obj) > MAX_STRING_CHARS:
                raise PrivacyGovernanceError("string value exceeds safety limit")
            return obj

        result = transform(data, 0, "")
        warnings: list[str] = []
        if classification == DataClassification.RESTRICTED.value and mode == RedactionMode.MASK:
            warnings.append("restricted data is only suitable for controlled masked views")
        return RedactionResult(
            data=result,
            classification=classification,
            mode=mode.value,
            redacted_fields=tuple(sorted(redacted)),
            removed_fields=tuple(sorted(removed)),
            pseudonymized_fields=tuple(sorted(pseudonymized)),
            warnings=tuple(warnings),
        )
