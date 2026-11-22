from __future__ import annotations

import hashlib
import unittest
from email.message import EmailMessage

from services.email_forensics.header_anomaly_detector import detect_header_anomalies
from services.email_forensics.header_parser import parse_email_headers
from services.email_parser import parse_email
from services.email_parsing import EmailParseLimitError, parse_email_bytes


class Phase3Step11HeaderMimeTests(unittest.TestCase):
    def test_single_part_email_has_stable_fields_and_original_evidence_fingerprint(self):
        raw = (
            b"From: analyst@example.invalid\r\n"
            b"To: soc@example.invalid\r\n"
            b"Subject: Routine note\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hello team.\r\n"
        )
        result = parse_email(raw, "routine.eml")
        self.assertEqual(result["parsing"]["status"], "COMPLETE")
        self.assertEqual(result["basic_information"]["from"], "analyst@example.invalid")
        self.assertEqual(result["body"]["text"], "Hello team.")
        self.assertEqual(result["source_evidence"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result["source_evidence"]["original_bytes_changed"])

    def test_multipart_alternative_and_attachment_are_parsed_without_execution(self):
        message = EmailMessage()
        message["From"] = "sender@example.invalid"
        message["To"] = "soc@example.invalid"
        message["Subject"] = "Report"
        message.set_content("Plain version")
        message.add_alternative("<p>HTML version</p>", subtype="html")
        message.add_attachment(b"MZ\x00sample", maintype="application", subtype="octet-stream", filename="sample.bin")

        result = parse_email(message.as_bytes(), "multipart.eml")
        self.assertEqual(result["body"]["text"], "Plain version")
        self.assertGreaterEqual(result["parsing"]["mime_part_count"], 4)
        self.assertEqual(result["attachments"][0]["filename"], "sample.bin")
        self.assertEqual(result["attachments"][0]["detonation"]["content_executed"], False)
        self.assertEqual(result["parsing"]["status"], "COMPLETE")

    def test_duplicate_identity_and_received_headers_are_preserved_and_detected(self):
        raw = (
            b"From: first@example.invalid\r\n"
            b"From: second@example.invalid\r\n"
            b"Reply-To: reply1@example.invalid\r\n"
            b"Reply-To: reply2@example.invalid\r\n"
            b"Received: from mx1.example.invalid\r\n"
            b"Received: from mx2.example.invalid\r\n\r\nBody"
        )
        result = parse_email(raw, "duplicates.eml")
        self.assertEqual(result["basic_information"]["from"], "first@example.invalid")
        self.assertEqual(result["headers"]["from"], "first@example.invalid")
        self.assertEqual(result["headers"]["header_occurrences"]["from"], ["first@example.invalid", "second@example.invalid"])
        self.assertEqual(len(result["headers"]["received"]), 2)

        forensic = parse_email_headers(raw)
        self.assertEqual(forensic["header_occurrences"]["reply-to"], ["reply1@example.invalid", "reply2@example.invalid"])
        duplicate_findings = [
            item for item in detect_header_anomalies(forensic)["findings"]
            if item["category"] == "duplicate_header"
        ]
        self.assertEqual({item["evidence"]["header"] for item in duplicate_findings}, {"from", "reply-to"})

    def test_missing_headers_remain_missing(self):
        result = parse_email(b"Content-Type: text/plain\r\n\r\nNo identity headers.", "missing.eml")
        self.assertIsNone(result["basic_information"]["from"])
        self.assertIsNone(result["basic_information"]["message_id"])
        self.assertEqual(result["parsing"]["status"], "COMPLETE")

    def test_malformed_boundary_is_explicitly_partial(self):
        raw = (
            b'Content-Type: multipart/mixed; boundary="part"\r\n\r\n'
            b"--part\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPartial body\r\n"
        )
        result = parse_email(raw, "malformed-boundary.eml")
        self.assertEqual(result["parsing"]["status"], "PARTIAL")
        self.assertTrue(any("Boundary" in defect["type"] for defect in result["parsing"]["defects"]))

    def test_invalid_charset_is_reported_as_partial_decode(self):
        raw = (
            b"Content-Type: text/plain; charset=x-mailtrace-unknown\r\n\r\n"
            b"Undecodable text"
        )
        result = parse_email(raw, "invalid-charset.eml")
        self.assertEqual(result["parsing"]["status"], "PARTIAL")
        self.assertIn("BODY_DECODE_FAILED", {issue["code"] for issue in result["parsing"]["issues"]})

    def test_email_size_header_count_and_mime_depth_are_bounded(self):
        with self.assertRaises(EmailParseLimitError):
            parse_email_bytes(b"x" * (25 * 1024 * 1024 + 1))

        with self.assertRaises(EmailParseLimitError):
            parse_email(b"x" * (25 * 1024 * 1024 + 1), "oversized.msg")

        many_headers = b"".join(f"X-{index}: value\r\n".encode() for index in range(1001)) + b"\r\nbody"
        with self.assertRaises(EmailParseLimitError):
            parse_email_bytes(many_headers)

        nested = b"Content-Type: text/plain\r\n\r\nbody"
        for depth in range(22):
            boundary = f"layer{depth}".encode()
            nested = (
                b"Content-Type: multipart/mixed; boundary=\"" + boundary + b"\"\r\n\r\n--"
                + boundary + b"\r\n" + nested + b"\r\n--" + boundary + b"--\r\n"
            )
        with self.assertRaises(EmailParseLimitError):
            parse_email_bytes(nested)


if __name__ == "__main__":
    unittest.main()
