import unittest

from fastapi.testclient import TestClient

import main


class CorsPolicyTests(unittest.TestCase):
    def test_configured_local_frontend_origin_is_allowed(self):
        with TestClient(main.app) as client:
            response = client.options(
                "/api/campaigns",
                headers={
                    "Origin": "http://127.0.0.1:5503",
                    "Access-Control-Request-Method": "GET",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://127.0.0.1:5503",
        )
        self.assertNotIn("access-control-allow-credentials", response.headers)

    def test_arbitrary_web_origin_is_rejected(self):
        with TestClient(main.app) as client:
            response = client.options(
                "/api/campaigns",
                headers={
                    "Origin": "https://untrusted.example",
                    "Access-Control-Request-Method": "GET",
                },
            )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_provider_webhook_headers_are_allowed_for_local_frontend(self):
        requested_headers = (
            "content-type,x-mailtrace-filename,x-mailtrace-event-id,"
            "x-mailtrace-timestamp,x-mailtrace-signature,"
            "x-mailtrace-smtp-client-ip,x-mailtrace-smtp-mail-from,"
            "x-mailtrace-smtp-helo"
        )
        with TestClient(main.app) as client:
            response = client.options(
                "/api/webhooks/email",
                headers={
                    "Origin": "http://127.0.0.1:5503",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": requested_headers,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "http://127.0.0.1:5503",
        )
        allowed_headers = response.headers.get("access-control-allow-headers", "").lower()
        for header in requested_headers.split(","):
            self.assertIn(header, allowed_headers)


if __name__ == "__main__":
    unittest.main()
