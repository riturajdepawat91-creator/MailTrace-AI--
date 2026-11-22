"""Bounded SPF/DKIM/DMARC verification for explicitly synthetic EML uploads.

This module never treats Authentication-Results or Received-SPF as trusted.
SPF message PASS requires trusted SMTP context; EML uploads do not provide it.
"""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from typing import Callable
import re

from services.domain_alignment import compare_domains, normalized_host


class BoundedTXTResolver:
    """Small injectable TXT resolver with strict per-analysis bounds."""

    def __init__(self, *, timeout: float = 1.0, lifetime: float = 2.5, max_queries: int = 8, resolver=None):
        if resolver is None:
            import dns.resolver
            resolver = dns.resolver.Resolver(configure=True)
        self._resolver = resolver
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        self._max_queries = max_queries
        self._queries = 0
        self._cache: dict[str, tuple[bytes, ...]] = {}

    def txt(self, name: str) -> tuple[bytes, ...]:
        normalized = name.rstrip(".").lower()
        if normalized in self._cache:
            return self._cache[normalized]
        if self._queries >= self._max_queries:
            raise RuntimeError("DNS_QUERY_LIMIT")
        if len(normalized) > 253 or not normalized or any(not label or len(label) > 63 for label in normalized.split(".")):
            raise ValueError("DNS_NAME_INVALID")
        self._queries += 1
        answers = self._resolver.resolve(normalized, "TXT", lifetime=self._resolver.lifetime)
        packed = []
        for record in answers:
            chunks = getattr(record, "strings", None)
            packed.append(b"".join(chunks) if chunks is not None else bytes(record))
        records = tuple(packed)
        self._cache[normalized] = records
        return records


def _status_error(exc: Exception) -> str:
    name = type(exc).__name__.casefold()
    if isinstance(exc, (TimeoutError, OSError, RuntimeError)) or "timeout" in name or "nameservers" in name:
        return "UNAVAILABLE"
    if name in {"nxdomain", "noanswer"}:
        return "NONE"
    return "INVALID"


def verify_email_authentication(
    raw_email: bytes,
    *,
    resolver=None,
    smtp_context: dict[str, str] | None = None,
    spf_checker: Callable | None = None,
) -> dict:
    """Perform independent verification; resolver/checker are injectable for tests."""
    from email.utils import parseaddr

    result = {
        "checks": {},
        "sender_domain_alignment": {"state": "UNAVAILABLE", "source": "INDEPENDENT_DNS_AND_SIGNATURE_CHECK"},
        "independent_verification": True,
        "reported_header_trusted": False,
    }
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        sender = parseaddr(str(msg.get("From", "")))[1]
        domain = sender.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in sender else ""
        if not domain or len(domain) > 253:
            raise ValueError("FROM_DOMAIN_INVALID")
    except Exception:
        for name in ("spf", "dkim", "dmarc"):
            result["checks"][name] = {"state": "INVALID", "source": "INDEPENDENT_VERIFICATION"}
        return result

    if resolver is None:
        try:
            resolver = BoundedTXTResolver()
        except Exception:
            resolver = None
    elif not callable(getattr(resolver, "txt", None)):
        try:
            resolver = BoundedTXTResolver(resolver=resolver)
        except Exception:
            resolver = None

    # SPF policy publication is checked independently. A policy record alone
    # cannot authenticate a message without a trusted SMTP client IP.
    spf_record = None
    if resolver is None:
        spf_policy = "UNAVAILABLE"
    else:
        try:
            spf_records = [r.decode("ascii", "replace") for r in resolver.txt(domain) if r.lower().startswith(b"v=spf1")]
            if len(spf_records) > 1:
                spf_policy = "INVALID"
            elif spf_records:
                spf_record = spf_records[0]
                spf_policy = "POLICY_FOUND"
            else:
                spf_policy = "NONE"
        except Exception as exc:
            spf_policy = _status_error(exc)
    spf_state = "UNAVAILABLE"
    spf_source = "TRUSTED_SMTP_CONTEXT_REQUIRED"
    if smtp_context and spf_record:
        try:
            if spf_checker is None:
                import spf
                spf_checker = spf.check2
            verdict, _ = spf_checker(
                i=smtp_context["client_ip"], s=smtp_context.get("mail_from", sender),
                h=smtp_context.get("helo", domain), timeout=2, querytime=5,
            )
            normalized = str(verdict).upper()
            spf_state = (
                "PASS" if normalized == "PASS" else
                "FAIL" if normalized in {"FAIL", "SOFTFAIL", "PERMERROR"} else
                "NONE" if normalized == "NONE" else
                "UNAVAILABLE" if normalized in {"TEMPERROR", "ERROR"} else
                "INVALID"
            )
            spf_source = "INDEPENDENT_SPF_CHECK"
        except Exception:
            spf_state = "UNAVAILABLE"
            spf_source = "INDEPENDENT_SPF_CHECK"
    result["checks"]["spf"] = {
        "state": spf_state, "policy_state": spf_policy,
        "source": spf_source,
    }

    dkim_signatures = msg.get_all("DKIM-Signature", [])
    dkim_domains: list[str] = []
    dkim_state = "NONE" if not dkim_signatures else "UNAVAILABLE"
    if dkim_signatures and resolver is not None:
        outcomes = []
        for index, signature in enumerate(dkim_signatures[:3]):
            tags = {k.lower(): v.strip() for k, v in re.findall(r"(?:^|;)\s*([a-zA-Z]+)\s*=\s*([^;\s]+)", str(signature))}
            d, selector = tags.get("d", "").lower().rstrip("."), tags.get("s", "").lower()
            if not d or not selector or not re.fullmatch(r"[a-z0-9_-]{1,63}", selector):
                outcomes.append("INVALID")
                continue
            dkim_domains.append(d)
            try:
                import dkim
                verifier = dkim.DKIM(raw_email, timeout=2)
                dns_failures: list[str] = []
                def dnsfunc(qname: bytes, timeout: float = 2.0):
                    q = qname.decode("ascii", "strict").rstrip(".")
                    try:
                        records = resolver.txt(q)
                    except Exception as exc:
                        dns_failures.append(_status_error(exc))
                        raise
                    if len(records) != 1:
                        return b""
                    return records[0]
                verified = verifier.verify(idx=index, dnsfunc=dnsfunc)
                outcomes.append(dns_failures[-1] if dns_failures else "PASS" if verified else "FAIL")
            except Exception as exc:
                error_state = _status_error(exc)
                outcomes.append("FAIL" if error_state == "NONE" else error_state)
        dkim_state = "PASS" if "PASS" in outcomes else "FAIL" if outcomes and all(v == "FAIL" for v in outcomes) else "INVALID" if outcomes and all(v == "INVALID" for v in outcomes) else "UNAVAILABLE"
    result["checks"]["dkim"] = {"state": dkim_state, "source": "DKIM_CRYPTOGRAPHIC_VERIFICATION", "aligned_domains": dkim_domains[:3]}

    dmarc_record = None
    dmarc_state = "UNAVAILABLE"
    alignment = "UNAVAILABLE"
    if resolver is not None:
        try:
            candidates = [r.decode("ascii", "replace") for r in resolver.txt(f"_dmarc.{domain}") if r.lower().startswith(b"v=dmarc1")]
            if len(candidates) > 1:
                dmarc_state = "INVALID"
            elif not candidates:
                dmarc_state = "NONE"
            else:
                dmarc_record = candidates[0]
                tags = {k.strip().lower(): v.strip().lower() for k, v in re.findall(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;\s]+)", dmarc_record)}
                if tags.get("v", "").upper() != "DMARC1" or tags.get("p", "") not in {"none", "quarantine", "reject"}:
                    dmarc_state = "INVALID"
                else:
                    dkim_mode = tags.get("adkim", "r")
                    spf_mode = tags.get("aspf", "r")
                    if dkim_mode not in {"r", "s"} or spf_mode not in {"r", "s"}:
                        raise ValueError("DMARC_ALIGNMENT_MODE_INVALID")
                    dkim_aligned = any(
                        (normalized_host(d) == normalized_host(domain) if dkim_mode == "s"
                         else compare_domains(d, domain) in {"EXACT_HOST", "ORGANIZATIONAL_ALIGNMENT"})
                        for d in dkim_domains
                    ) and dkim_state == "PASS"
                    spf_domain = (smtp_context or {}).get("mail_from", "").rsplit("@", 1)[-1].lower().rstrip(".")
                    spf_aligned = spf_state == "PASS" and bool(spf_domain) and (
                        normalized_host(spf_domain) == normalized_host(domain) if spf_mode == "s"
                        else compare_domains(spf_domain, domain) in {"EXACT_HOST", "ORGANIZATIONAL_ALIGNMENT"}
                    )
                    if dkim_aligned or spf_aligned:
                        dmarc_state, alignment = "PASS", "PASS"
                    elif (
                        spf_state in {"PASS", "FAIL"}
                        and dkim_state in {"PASS", "FAIL", "NONE"}
                    ) or (
                        dkim_state in {"PASS", "FAIL"}
                        and spf_state in {"PASS", "FAIL", "NONE"}
                    ):
                        dmarc_state, alignment = "FAIL", "FAIL"
                    else:
                        dmarc_state, alignment = "UNAVAILABLE", "UNAVAILABLE"
        except Exception as exc:
            dmarc_state = _status_error(exc)
    result["checks"]["dmarc"] = {"state": dmarc_state, "source": "DMARC_DNS_POLICY_AND_ALIGNMENT"}
    result["sender_domain_alignment"] = {
        "state": alignment,
        "source": "INDEPENDENT_DNS_AND_SIGNATURE_CHECK",
    }
    return result
