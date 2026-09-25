"""Background validation lifecycle without scanning any live application."""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_server import validation, zap


class ValidationJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = patch.multiple(
            validation,
            STATE_DIR=Path(self.temporary.name),
            _job={},
            _worker=None,
            _cancel=threading.Event(),
        )
        self.state.start()
        self.addCleanup(self.state.stop)

    def test_start_returns_while_scan_runs_and_reuses_active_job(self) -> None:
        release = threading.Event()
        entered = threading.Event()

        def scan(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test scan was not released")
            return {"partial": False, "alerts": [{"alert": "XSS"}] * 101}

        with (
            patch.object(zap, "start_zap"),
            patch.object(zap, "full_active_scan", side_effect=scan) as run,
        ):
            try:
                job = validation.start("http://localhost:3000", [], [])
                self.assertTrue(entered.wait(2))
                self.assertEqual(job["status"], "running")
                repeated = validation.start("http://localhost:3000", [], [])
                self.assertEqual(repeated["job_id"], job["job_id"])
                with self.assertRaises(zap.ZapError):
                    validation.start("http://localhost:4000", [], [])
                self.assertEqual(run.call_count, 1)
            finally:
                release.set()
                validation._worker.join(3)
        result = validation.status(job["job_id"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["result"]["alerts"]), 20)
        self.assertTrue(result["truncated"])
        self.assertEqual(
            len(validation.status(job["job_id"], 100)["result"]["alerts"]), 1
        )
        saved = json.loads(
            (validation.STATE_DIR / (job["job_id"] + ".json")).read_text()
        )
        self.assertEqual(len(saved["result"]["alerts"]), 101)

    def test_cancel_retains_partial_alerts_and_stops_container(self) -> None:
        entered = threading.Event()

        def scan(*args, **kwargs):
            entered.set()
            kwargs["cancel"].wait(5)
            raise zap.ZapError("cancelled")

        with (
            patch.object(zap, "start_zap"),
            patch.object(zap, "full_active_scan", side_effect=scan),
            patch.object(zap, "_collect_alerts", return_value=[{"alert": "XSS"}]),
            patch.object(zap, "stop_zap") as stop,
        ):
            job = validation.start("http://localhost:3000", [], [])
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(validation.stop()["status"], "stopping")
            finally:
                validation._cancel.set()
                validation._worker.join(3)
        result = validation.status(job["job_id"])
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["result"]["alert_count"], 1)
        stop.assert_called_once()

    def test_saved_running_job_is_interrupted_after_restart(self) -> None:
        identifier = "a" * 32
        (validation.STATE_DIR / (identifier + ".json")).write_text(
            json.dumps({"job_id": identifier, "status": "running"})
        )
        self.assertEqual(validation.status(identifier)["status"], "interrupted")

    def test_snapshot_keeps_complete_alert_inventory_for_local_reporting(self) -> None:
        identifier = "c" * 32
        alerts = [{"alert": f"alert-{index}"} for index in range(150)]
        (validation.STATE_DIR / (identifier + ".json")).write_text(
            json.dumps(
                {
                    "job_id": identifier,
                    "status": "complete",
                    "result": {"alert_count": len(alerts), "alerts": alerts},
                }
            )
        )
        self.assertEqual(len(validation.status(identifier)["result"]["alerts"]), 20)
        self.assertEqual(len(validation.snapshot(identifier)["result"]["alerts"]), 150)

    def test_cleanup_preserves_completed_result(self) -> None:
        validation._job = {
            "job_id": "b" * 32,
            "status": "complete",
            "result": {"alerts": [{"alert": "XSS"}]},
        }
        with patch.object(zap, "stop_zap") as stop:
            validation.stop()
            validation._worker.join(3)
        result = validation.status()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["cleanup_status"], "complete")
        self.assertEqual(len(result["result"]["alerts"]), 1)
        stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
