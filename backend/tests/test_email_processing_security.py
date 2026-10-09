from __future__ import annotations

import unittest
import asyncio
import hashlib
import hmac
import json
import os
import time
import tempfile
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from services.email_ai.intelligence_fusion import _header_signals
from services.email_forensics.authentication_analyzer import (
    validate_email_authentication,
)
from services.email_parser import parse_email


class EmailProcessingSecurityTests(unittest.TestCase):
    def test_untrusted_authentication_results_do_not_create_fusion_signal(self):
        email = {
            "headers": {
                "authentication_results": "spf=fail dkim=fail dmarc=fail",
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
            }
        }

        self.assertEqual(_header_signals(email), [])

    def test_spoofed_authentication_failure_does_not_change_parser_verdict(self):
        parsed = parse_email(
            b"From: user@example.invalid\r\n"
            b"Authentication-Results: attacker; spf=fail; dkim=fail; dmarc=fail\r\n"
            b"Subject: Routine note\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello team, here are the meeting notes.\r\n",
            "spoofed-auth.eml",
        )

        self.assertEqual(parsed["threat_analysis"]["score"], 0)
        self.assertEqual(parsed["authentication"]["spf"], "FAIL")
        self.assertFalse(
            parsed["authentication"]["authentication_results_trusted"]
        )

    def test_offline_validation_does_not_claim_spf_or_dkim_result(self):
        raw_email = (
            b"Authentication-Results: attacker; spf=pass; dkim=pass; dmarc=pass\r\n"
            b"\r\nhello\r\n"
        )
        validation = validate_email_authentication(
            raw_email,
            None,
            {"dkim_signature": []},
        )

        self.assertEqual(
            validation["spf"]["status"],
            "UNVERIFIED_NO_TRUSTED_SMTP_IP",
        )
        self.assertEqual(validation["dkim"]["status"], "NOT_PRESENT")
        self.assertFalse(validation["reported_headers_trusted"])

        trusted_relay_validation = validate_email_authentication(
            raw_email,
            None,
            {"dkim_signature": []},
            {
                "client_ip": "10.0.0.12",
                "mail_from": "sender@example.invalid",
                "helo": "mx.example.invalid",
            },
        )
        self.assertEqual(
            trusted_relay_validation["spf"]["status"],
            "NOT_VERIFIABLE_NON_PUBLIC_CLIENT_IP",
        )

        with patch("spf.check2", return_value=("pass", "sender authorized")) as spf_check:
            verified = validate_email_authentication(
                raw_email,
                None,
                {"dkim_signature": []},
                {
                    "client_ip": "8.8.8.8",
                    "mail_from": "sender@example.invalid",
                    "helo": "mx.example.invalid",
                },
            )
        self.assertEqual(verified["spf"]["status"], "PASS")
        spf_check.assert_called_once()

    def test_invalid_msg_container_is_rejected(self):
        with self.assertRaises(Exception):
            parse_email(b"This is not an Outlook compound file", "broken.msg")

    def test_msg_adapter_normalizes_headers_body_and_attachments(self):
        import extract_msg

        converted = EmailMessage()
        converted["From"] = "sender@example.invalid"
        converted["To"] = "soc@example.invalid"
        converted["Subject"] = "Outlook sample"
        converted.set_content("Review this attachment.")
        converted.add_attachment(
            b"sample attachment",
            maintype="application",
            subtype="octet-stream",
            filename="sample.bin",
        )

        outlook_message = Mock()
        outlook_message.asEmailMessage.return_value = converted
        with patch.object(extract_msg, "openMsg", return_value=outlook_message):
            parsed = parse_email(b"mock-msg-bytes", "sample.msg")

        self.assertEqual(parsed["source_format"], "outlook_msg")
        self.assertEqual(parsed["basic_information"]["subject"], "Outlook sample")
        self.assertIn("Review this attachment.", parsed["body"]["text"])
        self.assertEqual(parsed["attachments"][0]["filename"], "sample.bin")
        outlook_message.close.assert_called_once()

    def test_eml_path_still_parses(self):
        parsed = parse_email(
            b"From: analyst@example.invalid\r\n"
            b"To: soc@example.invalid\r\n"
            b"Subject: Test\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"A routine message.\r\n",
            "routine.eml",
        )

        self.assertEqual(parsed["source_format"], "eml")
        self.assertEqual(parsed["basic_information"]["subject"], "Test")
        self.assertEqual(parsed["body"]["text"], "A routine message.")

    def test_webhook_requires_fresh_hmac_and_sends_raw_email_to_pipeline(self):
        import main
        import database.database as database

        secret = "local-test-webhook-secret-32-chars-minimum"
        body = b"From: user@example.invalid\r\n\r\nTest message\r\n"
        filename = "incoming.eml"

        smtp_context = {
            "client_ip": "8.8.8.8",
            "mail_from": "user@example.invalid",
            "helo": "mx.example.invalid",
        }

        def signed_headers(event_id, message_body, timestamp=None):
            timestamp = timestamp or str(int(time.time()))
            metadata = json.dumps(
                {
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "filename": filename,
                    "smtp_context": smtp_context,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            fingerprint_material = metadata + b"\n" + message_body
            signature = hmac.new(
                secret.encode(), fingerprint_material, hashlib.sha256
            ).hexdigest()
            headers = {
                "X-MailTrace-Filename": filename,
                "X-MailTrace-Event-Id": event_id,
                "X-MailTrace-Timestamp": timestamp,
                "X-MailTrace-Signature": "sha256=" + signature,
            }
            headers.update({
                "X-MailTrace-SMTP-Client-IP": smtp_context["client_ip"],
                "X-MailTrace-SMTP-Mail-From": smtp_context["mail_from"],
                "X-MailTrace-SMTP-HELO": smtp_context["helo"],
            })
            return headers

        async def capture(upload, smtp_context=None):
            return {
                "success": True,
                "filename": upload.filename,
                "size": len(await upload.read()),
                "investigation_id": "INV-WEBHOOK-TEST",
            }

        with tempfile.TemporaryDirectory(prefix="mailtrace-webhook-ledger-") as root:
            with patch.object(database, "DATABASE_PATH", Path(root) / "test.db"):
                database.initialize_database()
                database.initialize_email_webhook_events()
                with patch.dict(os.environ, {"MAILTRACE_WEBHOOK_SECRET": secret}):
                    with patch.object(main, "_analyze_email", side_effect=capture) as pipeline:
                        client = TestClient(main.app)
                        rejected = client.post(
                            "/api/webhooks/email",
                            content=body,
                            headers={**signed_headers("event-a", body), "X-MailTrace-Signature": "0" * 64},
                        )
                        accepted = client.post(
                            "/api/webhooks/email",
                            content=body,
                            headers=signed_headers("event-a", body),
                        )
                        duplicate = client.post(
                            "/api/webhooks/email",
                            content=body,
                            headers=signed_headers("event-a", body),
                        )
                        collision_body = body + b"different"
                        collision = client.post(
                            "/api/webhooks/email",
                            content=collision_body,
                            headers=signed_headers("event-a", collision_body),
                        )
                        self.assertEqual(pipeline.call_count, 1)
                        self.assertEqual(pipeline.call_args.args[1], smtp_context)

                        with patch.object(
                            main,
                            "_analyze_email",
                            side_effect=[
                                HTTPException(status_code=500, detail="transient failure"),
                                {"success": True, "investigation_id": "INV-WEBHOOK-RETRY"},
                            ],
                        ):
                            first_attempt = client.post(
                                "/api/webhooks/email",
                                content=body,
                                headers=signed_headers("event-retry", body),
                            )
                            retry_attempt = client.post(
                                "/api/webhooks/email",
                                content=body,
                                headers=signed_headers("event-retry", body),
                            )

        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["size"], len(body))
        self.assertEqual(accepted.json()["webhook"]["status"], "completed")
        self.assertTrue(duplicate.json()["duplicate"])
        self.assertEqual(duplicate.json()["investigation_id"], "INV-WEBHOOK-TEST")
        self.assertEqual(collision.status_code, 409)
        self.assertEqual(first_attempt.status_code, 500)
        self.assertEqual(first_attempt.json()["detail"]["status"], "failed")
        self.assertEqual(retry_attempt.status_code, 200)
        self.assertEqual(retry_attempt.json()["webhook"]["attempts"], 2)

    def test_sse_stream_emits_initial_snapshot(self):
        import main
        import database.database as database

        async def verify_stream():
            with tempfile.TemporaryDirectory(prefix="mailtrace-sse-test-") as root:
                with patch.object(database, "DATABASE_PATH", Path(root) / "test.db"):
                    database.initialize_database()
                    database.initialize_email_webhook_events()
                    request = Mock()
                    request.is_disconnected = AsyncMock(side_effect=[False, True])
                    response = await main.stream_live_threat_intelligence(request)
                    event = await response.body_iterator.__anext__()
                    self.assertIn("data:", event)
                    self.assertIn('"success":true', event)

        asyncio.run(verify_stream())

    def test_webhook_ledger_recovers_stale_processing_delivery(self):
        import database.database as database

        with tempfile.TemporaryDirectory(prefix="mailtrace-stale-delivery-") as root:
            with patch.object(database, "DATABASE_PATH", Path(root) / "test.db"):
                database.initialize_database()
                database.initialize_email_webhook_events()
                first = database.begin_email_webhook_event("stale-event", "f" * 64)
                connection = database.get_connection()
                connection.execute(
                    "UPDATE email_webhook_events SET updated_at=datetime('now', '-20 minutes') WHERE event_id=?",
                    ("stale-event",),
                )
                connection.commit()
                connection.close()

                recovered = database.begin_email_webhook_event("stale-event", "f" * 64)

        self.assertEqual(first["attempts"], 1)
        self.assertEqual(recovered["attempts"], 2)
        self.assertTrue(recovered["retry"])


if __name__ == "__main__":
    unittest.main()
