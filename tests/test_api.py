import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from starlette.testclient import TestClient

from hipaa_audit import service as service_module
from hipaa_audit.api import create_app
from hipaa_audit.config import Settings
from tests.fixtures import make_pdf
from tests.test_service import IDS, SlowBackend, make_service, policy_text

KEY = "test-key-123"


def make_client(backend=None, *, backend_error=None, **settings):
    service = make_service(backend, backend_error=backend_error, **settings)
    return TestClient(create_app(service.settings, service)), service


def upload(client, name="policy.txt", data=None, controls=None, headers=None):
    fields = {"controls": controls} if controls else None
    return client.post(
        "/api/audits",
        files={"file": (name, data if data is not None else policy_text(), "text/plain")},
        data=fields,
        headers=headers,
    )


def wait_until_done(client, audit_id, headers=None, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/audits/{audit_id}", headers=headers).json()
        if body["status"] not in ("queued", "running"):
            return body
        time.sleep(0.03)
    raise AssertionError("the audit did not finish in time")


class AuditFlowTests(unittest.TestCase):
    def test_upload_poll_read_and_delete(self):
        client, _ = make_client()
        with client:
            created = upload(client)
            self.assertEqual(created.status_code, 202)
            body = created.json()
            self.assertEqual(created.headers["location"], f"/api/audits/{body['id']}")
            self.assertEqual((body["filename"], body["total_controls"]), ("policy.txt", 48))
            done = wait_until_done(client, body["id"])
            self.assertEqual((done["status"], done["done_controls"]), ("completed", 48))
            self.assertEqual(done["summary"]["assessed"], 48)

            findings = client.get(f"/api/audits/{body['id']}/findings").json()["findings"]
            self.assertEqual(len(findings), 48)
            first = findings[0]
            self.assertEqual(
                set(first) >= {"control", "status", "rationale", "evidence", "missing_elements", "confidence", "flags"},
                True,
            )
            with_evidence = next(f for f in findings if f["evidence"])
            chunk = client.get(f"/api/audits/{body['id']}/chunks/{with_evidence['evidence'][0]['chunk_id']}")
            self.assertEqual(chunk.status_code, 200)
            self.assertIn("text", chunk.json())

            listing = client.get("/api/audits").json()
            self.assertEqual((listing["total"], listing["audits"][0]["id"]), (1, body["id"]))
            self.assertEqual(sum(listing["audits"][0]["counts"].values()), 48)

            md = client.get(f"/api/audits/{body['id']}/report?format=md")
            self.assertEqual(md.status_code, 200)
            self.assertIn('attachment; filename="hipaa-review-policy.md"', md.headers["content-disposition"])
            self.assertIn("# HIPAA Security Rule policy review", md.text)
            as_json = client.get(f"/api/audits/{body['id']}/report?format=json")
            self.assertEqual(as_json.json()["summary"]["assessed"], 48)
            self.assertEqual(client.get(f"/api/audits/{body['id']}/report?format=pdf").status_code, 422)

            self.assertEqual(client.delete(f"/api/audits/{body['id']}").status_code, 204)
            self.assertEqual(client.get(f"/api/audits/{body['id']}").status_code, 404)
            self.assertEqual(client.get("/api/audits").json()["total"], 0)

    def test_selected_controls_by_comma_list(self):
        client, _ = make_client()
        with client:
            body = upload(client, controls=",".join(IDS[:2])).json()
            self.assertEqual(body["total_controls"], 2)
            self.assertEqual(wait_until_done(client, body["id"])["done_controls"], 2)

    def test_cancel_and_rerun(self):
        client, _ = make_client(SlowBackend(delay=0.05), concurrency=1)
        with client:
            body = upload(client).json()
            time.sleep(0.15)
            cancelled = client.post(f"/api/audits/{body['id']}/cancel")
            self.assertEqual(cancelled.status_code, 200)
            done = wait_until_done(client, body["id"])
            self.assertEqual(done["status"], "cancelled")
            self.assertTrue(0 < done["done_controls"] < 48)
            rerun = client.post(f"/api/audits/{body['id']}/rerun")
            self.assertEqual(rerun.status_code, 202)
            self.assertNotEqual(rerun.json()["id"], body["id"])
            client.post(f"/api/audits/{rerun.json()['id']}/cancel")
            wait_until_done(client, rerun.json()["id"])

    def test_deleting_a_running_audit_is_refused(self):
        client, _ = make_client(SlowBackend(delay=0.1), concurrency=1)
        with client:
            body = upload(client).json()
            time.sleep(0.05)
            refused = client.delete(f"/api/audits/{body['id']}")
            self.assertEqual((refused.status_code, refused.json()["error"]["code"]), (409, "conflict"))
            client.post(f"/api/audits/{body['id']}/cancel")
            wait_until_done(client, body["id"])
            self.assertEqual(client.delete(f"/api/audits/{body['id']}").status_code, 204)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.client, self.service = make_client(max_upload_mb=1)
        self.addCleanup(self.service.repo.close)

    def error(self, response, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["error"]["code"], code)
        self.assertTrue(response.json()["error"]["message"])

    def test_missing_file_wrong_type_empty_and_unknown_control(self):
        with self.client as client:
            self.error(client.post("/api/audits", data={"x": "y"}), 422, "invalid_request")
            self.error(upload(client, "x.exe", b"MZ"), 422, "invalid_request")
            self.error(upload(client, "x.txt", b""), 422, "invalid_request")
            self.error(upload(client, "x.txt", controls="not-a-control"), 422, "invalid_request")
            self.error(upload(client, "x.pdf", b"not a pdf"), 422, "invalid_request")

    def test_declared_size_over_the_limit_is_refused_before_reading(self):
        with self.client as client:
            self.error(upload(client, "big.txt", b"a " * (700 * 1024)), 413, "too_large")

    def test_streamed_body_over_the_limit_is_refused_without_a_content_length(self):
        opening = b'--zzz\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n'

        def body():
            yield opening
            for _ in range(8):
                yield b"x " * (128 * 1024)  # 2 MB in all, against a 1 MB limit

        with self.client as client:
            response = client.post(
                "/api/audits", content=body(), headers={"content-type": "multipart/form-data; boundary=zzz"}
            )
        self.assertNotIn(
            "content-length", response.request.headers
        )  # this must be the streaming path, not the declared-size check
        self.error(response, 413, "too_large")

    def test_a_damaged_document_is_a_client_error_not_a_server_error(self):
        intact = make_pdf([["Passwords must be at least fourteen characters long and may not be shared."] * 4])
        damaged = intact.replace(b"/Kids [", b"/Kidz [")  # makes pypdf raise a KeyError deep inside
        with self.client as client:
            self.assertEqual(upload(client, "ok.pdf", intact).status_code, 202)
            refused = upload(client, "damaged.pdf", damaged)
            self.error(refused, 422, "invalid_request")
            self.assertIn("could not be read", refused.json()["error"]["message"])
            self.assertNotIn("Kids", refused.text)  # nothing from the exception reaches the client

    def test_malformed_uploads_are_client_errors(self):
        form = {"content-type": "multipart/form-data; boundary=zzz"}
        with self.client as client:
            self.error(
                client.post("/api/audits", content=b"this is not multipart", headers=form), 422, "invalid_request"
            )
            self.error(
                client.post("/api/audits", content=b"x", headers={"content-type": "multipart/form-data"}),
                422,
                "invalid_request",
            )
            two_files = client.post(
                "/api/audits",
                files=[("file", ("a.txt", b"one", "text/plain")), ("file", ("b.txt", b"two", "text/plain"))],
            )
            self.error(two_files, 422, "invalid_request")
            self.error(client.post("/api/audits", json={"file": "x"}), 422, "invalid_request")
            self.error(upload(client, ""), 422, "invalid_request")  # no usable file name, so no recognised type
            self.assertEqual(self.service.repo.count_audits(), 0)

    def test_unknown_resources_and_methods(self):
        with self.client as client:
            self.error(client.get("/api/audits/nope"), 404, "not_found")
            self.error(client.get("/api/nothing-here"), 404, "not_found")
            self.error(client.put("/api/audits"), 405, "method_not_allowed")
            self.error(client.get("/api/audits/nope/findings"), 404, "not_found")
            self.error(client.get("/api/audits/nope/chunks/c0001"), 404, "not_found")
            self.error(client.get("/api/audits?limit=abc"), 422, "invalid_request")

    def test_service_busy_and_unavailable(self):
        busy_client, busy_service = make_client(SlowBackend(delay=0.2), concurrency=1)
        self.addCleanup(busy_service.repo.close)
        with busy_client as client, mock.patch.object(service_module, "MAX_PENDING_AUDITS", 1):
            self.assertEqual(upload(client).status_code, 202)
            busy = upload(client)
            self.error(busy, 429, "busy")
            self.assertEqual(busy.headers["retry-after"], "30")
        down, service = make_client(backend_error="ANTHROPIC_API_KEY is not set.")
        self.addCleanup(service.repo.close)
        with down:
            response = upload(down)
            self.error(response, 503, "unavailable")
            self.assertIn("ANTHROPIC_API_KEY", response.json()["error"]["message"])
            self.assertFalse(down.get("/api/status").json()["backend"]["ready"])


class SecurityTests(unittest.TestCase):
    def test_api_key_is_required_except_for_health(self):
        client, service = make_client(api_key=KEY)
        self.addCleanup(service.repo.close)
        with client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            for path in ("/api/status", "/api/controls", "/api/audits"):
                response = client.get(path)
                self.assertEqual((response.status_code, response.json()["error"]["code"]), (401, "unauthorized"), path)
            self.assertEqual(client.get("/api/status", headers={"X-API-Key": "wrong"}).status_code, 401)
            self.assertEqual(client.get("/api/status", headers={"X-API-Key": KEY[:-1]}).status_code, 401)
            self.assertEqual(client.get("/api/status", headers={"X-API-Key": KEY}).status_code, 200)
            self.assertEqual(upload(client).status_code, 401)  # no audit is created without the key
            self.assertEqual(service.repo.count_audits(), 0)
            created = upload(client, headers={"X-API-Key": KEY})
            self.assertEqual(created.status_code, 202)
            wait_until_done(client, created.json()["id"], headers={"X-API-Key": KEY})

    def test_headers_on_api_responses(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client:
            r = client.get("/api/health")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertEqual(r.headers["referrer-policy"], "no-referrer")
        self.assertNotIn("content-security-policy", r.headers)

    def test_cors_only_for_listed_origins(self):
        client, service = make_client(cors_origins=("http://localhost:5173",), api_key=KEY)
        self.addCleanup(service.repo.close)
        with client:
            ok = client.options(
                "/api/audits",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "x-api-key",
                },
            )
            self.assertEqual(ok.status_code, 200)  # preflight needs no key
            self.assertEqual(ok.headers["access-control-allow-origin"], "http://localhost:5173")
            other = client.get("/api/health", headers={"Origin": "http://evil.example"})
            self.assertNotIn("access-control-allow-origin", other.headers)

    def test_a_browser_request_from_another_site_cannot_change_anything(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client:
            for headers in (
                {"Origin": "http://evil.example"},
                {"Origin": "null"},  # a sandboxed or local page
                {"Origin": "http://testserver.evil.example"},
                {"Sec-Fetch-Site": "cross-site"},
                {"Sec-Fetch-Site": "same-site"},  # another subdomain or port on the same host
            ):
                with self.subTest(headers=headers):
                    refused = upload(client, headers=headers)
                    self.assertEqual((refused.status_code, refused.json()["error"]["code"]), (403, "forbidden_origin"))
                    self.assertEqual(refused.headers["x-content-type-options"], "nosniff")
            self.assertEqual(service.repo.count_audits(), 0, "nothing was created by a refused request")
            self.assertEqual(
                client.delete("/api/audits/none", headers={"Origin": "http://evil.example"}).status_code, 403
            )
            self.assertEqual(
                client.post("/api/audits/none/cancel", headers={"Origin": "http://evil.example"}).status_code, 403
            )

    def test_requests_that_are_not_cross_site_still_work(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client:
            for headers in (
                None,  # a script or curl: no browser headers at all
                {"Origin": "http://testserver"},  # the page this server serves, calling its own API
                {"Origin": "http://TESTSERVER", "Sec-Fetch-Site": "same-origin"},
                {"Sec-Fetch-Site": "none"},  # typed into the address bar
            ):
                with self.subTest(headers=headers):
                    self.assertEqual(upload(client, headers=headers).status_code, 202)
            # Reading is left to the browser's own rule: without CORS headers another site cannot read the answer.
            self.assertEqual(client.get("/api/status", headers={"Origin": "http://evil.example"}).status_code, 200)

    def test_a_listed_cors_origin_may_change_things(self):
        client, service = make_client(cors_origins=("http://localhost:5173/",))
        self.addCleanup(service.repo.close)
        with client:
            self.assertEqual(upload(client, headers={"Origin": "http://localhost:5173"}).status_code, 202)
            self.assertEqual(upload(client, headers={"Origin": "http://evil.example"}).status_code, 403)

    def test_only_the_configured_host_names_are_answered(self):
        client, service = make_client(allowed_hosts=("localhost", "127.0.0.1", "[::1]"))
        self.addCleanup(service.repo.close)
        with client:
            for host in ("localhost", "localhost:8000", "LOCALHOST:8000", "127.0.0.1:9", "[::1]:8000", "[::1]"):
                with self.subTest(host=host):
                    self.assertEqual(client.get("/api/health", headers={"Host": host}).status_code, 200)
            for host in (
                "evil.example",
                "evil.example:8000",
                "localhost.evil.example",
                "127.0.0.1.evil.example",
                "[::2]:8000",
                "",
            ):
                with self.subTest(host=host):
                    refused = client.get("/api/health", headers={"Host": host})
                    self.assertEqual((refused.status_code, refused.json()["error"]["code"]), (400, "invalid_host"))
                    self.assertEqual(refused.headers["x-content-type-options"], "nosniff")
            # the interface is protected too, not only the API
            self.assertEqual(client.get("/", headers={"Host": "evil.example"}).status_code, 400)

    def test_any_host_is_answered_when_none_are_configured(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client:
            self.assertEqual(client.get("/api/health", headers={"Host": "anything.example"}).status_code, 200)

    def test_unexpected_errors_do_not_leak_details_and_keep_the_headers(self):
        client, service = make_client(cors_origins=("http://localhost:5173",))
        self.addCleanup(service.repo.close)
        with client, mock.patch.object(service, "health", side_effect=RuntimeError("secret path /srv/app/x.py")):
            r = client.get("/api/status", headers={"Origin": "http://localhost:5173"})
        self.assertEqual((r.status_code, r.json()["error"]["code"]), (500, "internal_error"))
        self.assertNotIn("secret", r.text)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(r.headers["access-control-allow-origin"], "http://localhost:5173")


class StaticUiTests(unittest.TestCase):
    def test_ui_is_served_with_a_content_security_policy(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "index.html").write_text("<!doctype html><title>UI</title><div id=root></div>", encoding="utf-8")
            (Path(d) / "app.js").write_text("console.log(1)", encoding="utf-8")
            client, service = make_client(static_dir=d)
            self.addCleanup(service.repo.close)
            with client:
                page = client.get("/")
                self.assertEqual(page.status_code, 200)
                self.assertIn("<title>UI</title>", page.text)
                self.assertIn("script-src 'self'", page.headers["content-security-policy"])
                self.assertEqual(client.get("/app.js").status_code, 200)
                self.assertEqual(client.get("/api/health").json()["status"], "ok")
                missing = client.get("/does-not-exist.js")
                self.assertEqual(missing.status_code, 404)

    def test_without_a_built_ui_the_root_explains_itself(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client, mock.patch("hipaa_audit.api.app._static_dir", return_value=None):
            pass
        app = create_app(service.settings, service)
        with mock.patch("hipaa_audit.api.app._static_dir", return_value=None):
            app = create_app(service.settings, service)
        with TestClient(app) as c:
            self.assertEqual(c.get("/").json()["ui"], "not built")


class MetadataTests(unittest.TestCase):
    def test_controls_and_status(self):
        client, service = make_client()
        self.addCleanup(service.repo.close)
        with client:
            controls = client.get("/api/controls").json()
            self.assertEqual(len(controls["controls"]), 48)
            self.assertIn("rule_status", controls)
            self.assertIn("flag_labels", controls)
            status = client.get("/api/status").json()
            self.assertEqual(status["backend"]["name"], "heuristic:keywords")
            self.assertFalse(status["backend"]["is_ai_model"])
            self.assertEqual(status["limits"]["max_upload_mb"], Settings().max_upload_mb)


if __name__ == "__main__":
    unittest.main()
