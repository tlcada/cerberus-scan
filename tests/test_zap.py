"""Runtime orchestration contracts, exercised without contacting a target."""

import json
import unittest
from unittest.mock import patch

from mcp_server import zap


class ZapScanTests(unittest.TestCase):
    def test_scan_collects_all_alert_pages_and_preserves_evidence_limit(self) -> None:
        first_page = [{"alert": "SQL injection", "evidence": "x" * 250}] * 500
        last_page = [{"alert": "Missing header", "evidence": None}]
        pages = iter([first_page, last_page])

        def respond(path: str, **params: object) -> dict:
            if path == "/JSON/core/view/alerts/":
                return {"alerts": next(pages)}
            if path.endswith("/action/scan/"):
                return {"scan": "1"}
            return {}

        with (
            patch.object(zap, "_reachable", return_value=True),
            patch.object(zap, "_api", side_effect=respond) as api,
            patch.object(zap, "_wait", return_value=True),
        ):
            result = zap.full_active_scan("http://localhost:3000", ["/api/users"])

        self.assertEqual(result["alert_count"], 501)
        self.assertEqual(result["alerts"][0]["evidence"], "x" * 200)
        self.assertEqual(result["alerts"][-1]["evidence"], "")
        self.assertFalse(result["partial"])
        self.assertEqual(result["endpoints_seeded"], ["GET /api/users"])
        alert_calls = [
            call
            for call in api.call_args_list
            if call.args[0] == "/JSON/core/view/alerts/"
        ]
        self.assertEqual([call.kwargs["start"] for call in alert_calls], [0, 500])

    def test_partial_scan_still_returns_collected_alerts(self) -> None:
        for completion in [(False, True), (True, False), (False, False)]:
            with (
                self.subTest(completion=completion),
                patch.object(zap, "_reachable", return_value=True),
                patch.object(
                    zap,
                    "_api",
                    return_value={"scan": "1", "alerts": [{"alert": "XSS"}]},
                ),
                patch.object(zap, "_wait", side_effect=completion),
            ):
                result = zap.full_active_scan("http://localhost:3000")
            self.assertTrue(result["partial"])
            self.assertEqual(result["alert_count"], 1)
            self.assertEqual(result["spider_completed"], completion[0])
            self.assertEqual(result["active_scan_completed"], completion[1])

    def test_body_and_auth_vectors_are_seeded_as_real_requests(self) -> None:
        sent: list[dict] = []

        def respond(path: str, **params: object) -> dict:
            if path == "/JSON/replacer/view/rules/":
                return {"rules": []}
            if path == "/JSON/core/action/sendRequest/":
                sent.append(params)
            if path == "/JSON/core/view/alerts/":
                return {"alerts": []}
            if path.endswith("/action/scan/"):
                return {"scan": "1"}
            return {}

        with (
            patch.object(zap, "_reachable", return_value=True),
            patch.object(zap, "_api", side_effect=respond) as api,
            patch.object(zap, "_wait", return_value=True),
        ):
            result = zap.full_active_scan(
                "http://localhost:3000",
                [
                    "GET /api/users/:id",
                    {"method": "POST", "path": "/api/login",
                     "body": {"email": "a@b.c", "password": "x"}},
                ],
                auth_headers={"Authorization": "Bearer secret-token"},
            )

        # The POST vector is replayed with its JSON body via sendRequest; the
        # GET path template is concretised to /api/users/1.
        self.assertEqual(len(sent), 1)
        raw = sent[0]["request"]
        self.assertIn("POST http://host.docker.internal:3000/api/login", raw)
        self.assertIn('"password": "x"', raw)
        self.assertEqual(result["endpoints_seeded"], ["GET /api/users/1", "POST /api/login"])
        self.assertTrue(result["authenticated"])

        # The auth token is installed as a replacer rule but never returned or
        # left in the result for saving.
        self.assertNotIn("secret-token", json.dumps(result))
        add_rules = [
            call for call in api.call_args_list
            if call.args[0] == "/JSON/replacer/action/addRule/"
            and call.kwargs.get("matchString") == "Authorization"
        ]
        self.assertEqual(len(add_rules), 1)
        self.assertEqual(add_rules[0].kwargs["replacement"], "Bearer secret-token")

    def test_normalize_vectors_accepts_strings_and_dicts(self) -> None:
        specs = zap.normalize_vectors(
            ["/a", "post /b", {"path": "/c/{id}", "method": "PUT"}]
        )
        self.assertEqual([s["method"] for s in specs], ["GET", "POST", "PUT"])
        self.assertEqual(specs[2]["path"], "/c/1")
        for bad in [{"method": "POST"}, {"path": "/x", "method": "FOO"}]:
            with self.assertRaises(zap.ZapError):
                zap.normalize_vectors([bad])

    def test_target_access_failure_stops_before_spider(self) -> None:
        def respond(path: str, **params: object) -> dict:
            if path == "/JSON/core/action/accessUrl/":
                raise zap.ZapError("connection refused")
            return {}

        with (
            patch.object(zap, "_reachable", return_value=True),
            patch.object(zap, "_api", side_effect=respond) as api,
            self.assertRaisesRegex(zap.ZapError, "could not reach the target"),
        ):
            zap.full_active_scan("http://localhost:3000")
        self.assertFalse(
            any(
                call.args[0] == "/JSON/spider/action/scan/"
                for call in api.call_args_list
            )
        )


if __name__ == "__main__":
    unittest.main()
