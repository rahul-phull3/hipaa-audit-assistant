"""End-to-end check against a real uvicorn process: sockets, lifespan, API key, upload, polling and shutdown."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = "live-test-key"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def multipart(filename: str, data: bytes, boundary: str = "----hipaa-live") -> tuple[bytes, str]:
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + data + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


@unittest.skipUnless(find_spec("uvicorn"), "uvicorn is not installed")
class LiveServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never go through an outbound proxy
        env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("HIPAA_AUDIT_") and k != "ANTHROPIC_API_KEY"},
            "PYTHONPATH": str(ROOT / "src"),
            "HIPAA_AUDIT_API_KEY": KEY,
        }
        cls.server = subprocess.Popen(
            [sys.executable, "-m", "hipaa_audit", "serve", "--port", str(cls.port), "--backend", "heuristic",
             "--db", str(Path(cls.dir.name) / "live.db"), "--log-level", "warning"],
            cwd=cls.dir.name, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            if cls.server.poll() is not None:
                raise RuntimeError(f"the server exited early:\n{cls.server.stdout.read()}")
            try:
                if cls.call("GET", "/api/health")[0] == 200:
                    return
            except OSError:
                time.sleep(0.1)
        cls.server.kill()
        raise RuntimeError("the server did not become ready")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        try:
            cls.output, _ = cls.server.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.output, _ = cls.server.communicate()
            cls.dir.cleanup()
            raise AssertionError("the server did not stop within 15 seconds of SIGTERM")
        cls.dir.cleanup()
        # uvicorn finishes its graceful shutdown and then re-raises the signal, so SIGTERM shows as -15.
        if cls.server.returncode not in (0, -signal.SIGTERM):
            raise AssertionError(f"the server exited with {cls.server.returncode}:\n{cls.output}")
        if "Traceback" in cls.output:
            raise AssertionError(f"the server logged an exception:\n{cls.output}")

    @classmethod
    def call(cls, method, path, *, body=None, content_type=None, key=KEY):
        request = urllib.request.Request(cls.base + path, data=body, method=method)
        if key:
            request.add_header("X-API-Key", key)
        if content_type:
            request.add_header("Content-Type", content_type)
        try:
            with cls.opener.open(request, timeout=15) as response:
                return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()

    def test_upload_to_report_over_real_sockets(self):
        status, headers, body = self.call("GET", "/api/health", key=None)
        self.assertEqual((status, json.loads(body)["status"]), (200, "ok"))
        self.assertEqual(headers["x-content-type-options"], "nosniff")

        self.assertEqual(self.call("GET", "/api/status", key=None)[0], 401)
        self.assertEqual(self.call("GET", "/api/status", key="wrong")[0], 401)
        status, _, body = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["backend"]["name"], "heuristic:keywords")

        payload, content_type = multipart("sample_policy.md", (ROOT / "examples" / "sample_policy.md").read_bytes())
        status, headers, body = self.call("POST", "/api/audits", body=payload, content_type=content_type)
        self.assertEqual(status, 202, body)
        audit = json.loads(body)
        self.assertEqual(headers["location"], f"/api/audits/{audit['id']}")

        deadline, state = time.time() + 30, audit
        while state["status"] in ("queued", "running") and time.time() < deadline:
            time.sleep(0.1)
            state = json.loads(self.call("GET", f"/api/audits/{audit['id']}")[2])
        self.assertEqual((state["status"], state["done_controls"]), ("completed", 48))

        findings = json.loads(self.call("GET", f"/api/audits/{audit['id']}/findings")[2])["findings"]
        self.assertEqual(len(findings), 48)
        status, headers, body = self.call("GET", f"/api/audits/{audit['id']}/report?format=md")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["content-disposition"])
        self.assertIn("# HIPAA Security Rule policy review", body.decode())

        self.assertEqual(self.call("DELETE", f"/api/audits/{audit['id']}")[0], 204)
        self.assertEqual(self.call("GET", f"/api/audits/{audit['id']}")[0], 404)

    def test_bad_upload_is_refused_cleanly(self):
        payload, content_type = multipart("malware.exe", b"MZ\x90\x00")
        status, _, body = self.call("POST", "/api/audits", body=payload, content_type=content_type)
        self.assertEqual((status, json.loads(body)["error"]["code"]), (422, "invalid_request"))
        status, _, body = self.call("POST", "/api/audits", body=b"garbage", content_type="multipart/form-data; boundary=x")
        self.assertEqual((status, json.loads(body)["error"]["code"]), (422, "invalid_request"))


if __name__ == "__main__":
    unittest.main()
