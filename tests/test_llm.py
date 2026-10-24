import os
import sys
import tempfile
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from hipaa_audit.assess.llm import (
    AnthropicBackend,
    HeuristicBackend,
    LLMAuthError,
    LLMFormatError,
    LLMUnavailable,
)
from hipaa_audit.assess.schema import TOOL_NAME
from hipaa_audit.assess.verify import finalize
from hipaa_audit.catalog import load_catalog
from hipaa_audit.config import ConfigError, Settings, load_env_file
from hipaa_audit.models import Chunk


class FakeSDK(types.ModuleType):
    """Just enough of the anthropic package for the adapter: the error classes and a client constructor."""

    class APIError(Exception):
        pass

    class AuthenticationError(APIError):
        pass

    class PermissionDeniedError(APIError):
        pass

    class AsyncAnthropic:
        def __init__(self, **kwargs):
            self.kwargs = kwargs


def fake_sdk():
    module = FakeSDK("anthropic")
    module.APIError = FakeSDK.APIError
    module.AuthenticationError = FakeSDK.AuthenticationError
    module.PermissionDeniedError = FakeSDK.PermissionDeniedError
    module.AsyncAnthropic = FakeSDK.AsyncAnthropic
    return module


def tool_response(payload, *, stop_reason="tool_use", usage=(100, 20, 0, 0), name=TOOL_NAME):
    block = SimpleNamespace(type="tool_use", name=name, input=payload)
    u = SimpleNamespace(
        input_tokens=usage[0], output_tokens=usage[1], cache_read_input_tokens=usage[2], cache_creation_input_tokens=usage[3]
    )
    return SimpleNamespace(content=[block], stop_reason=stop_reason, usage=u)


class FakeClient:
    def __init__(self, *queue):
        self.queue = list(queue)
        self.calls = []
        self.messages = self

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


GOOD = {
    "status": "met",
    "rationale": "Backups are daily.",
    "evidence": [{"excerpt_id": "c0001", "quote": "Backups are taken daily."}],
    "missing_elements": [],
    "confidence": 0.9,
}
CHUNK = Chunk(id="c0001", ord=0, page=2, section="Backups", n_words=4, text="Backups are taken daily.")


class AnthropicBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        patcher = mock.patch.dict(sys.modules, {"anthropic": fake_sdk()})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.control = load_catalog().get("data-backup-plan")

    async def test_request_shape_and_parsing(self):
        client = FakeClient(tool_response(GOOD, usage=(1200, 150, 900, 300)))
        backend = AnthropicBackend(api_key=None, model="claude-test", client=client)
        raw, usage = await backend.assess(self.control, [CHUNK])
        call = client.calls[0]
        self.assertEqual(call["model"], "claude-test")
        self.assertEqual(call["tool_choice"], {"type": "tool", "name": TOOL_NAME})
        self.assertEqual([t["name"] for t in call["tools"]], [TOOL_NAME])
        self.assertEqual(call["temperature"], 0.0)
        self.assertEqual(call["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertIn('<excerpt id="c0001" page="2" section="Backups">', call["messages"][0]["content"])
        self.assertEqual((raw.status, raw.evidence[0].excerpt_id), ("met", "c0001"))
        self.assertEqual(
            (usage.input_tokens, usage.output_tokens, usage.cache_read_tokens, usage.cache_creation_tokens), (1200, 150, 900, 300)
        )
        self.assertEqual(backend.name, "anthropic:claude-test")

    async def test_end_to_end_with_verification(self):
        client = FakeClient(tool_response(GOOD))
        backend = AnthropicBackend(api_key=None, model="m", client=client)
        raw, _ = await backend.assess(self.control, [CHUNK])
        finding = finalize(self.control.id, raw, [CHUNK], model=backend.name)
        self.assertEqual((finding.status, finding.evidence[0].page), ("met", 2))

    async def test_malformed_first_answer_is_retried_once_with_more_room(self):
        empty = SimpleNamespace(content=[SimpleNamespace(type="text", text="Sorry")], stop_reason="end_turn", usage=None)
        client = FakeClient(empty, tool_response(GOOD, usage=(10, 5, 0, 0)))
        backend = AnthropicBackend(api_key=None, model="m", client=client, max_tokens=500)
        raw, usage = await backend.assess(self.control, [CHUNK])
        self.assertEqual(raw.status, "met")
        self.assertEqual([c["max_tokens"] for c in client.calls], [500, 1000])
        self.assertEqual(usage.input_tokens, 10)

    async def test_truncated_twice_raises_format_error(self):
        cut = tool_response(GOOD, stop_reason="max_tokens")
        backend = AnthropicBackend(api_key=None, model="m", client=FakeClient(cut, cut))
        with self.assertRaises(LLMFormatError):
            await backend.assess(self.control, [CHUNK])

    async def test_schema_violation_counts_as_malformed(self):
        bad = tool_response({"status": "perfect", "rationale": "x", "evidence": [], "missing_elements": [], "confidence": 1})
        backend = AnthropicBackend(api_key=None, model="m", client=FakeClient(bad, bad))
        with self.assertRaises(LLMFormatError):
            await backend.assess(self.control, [CHUNK])

    async def test_error_mapping(self):
        sdk = sys.modules["anthropic"]
        auth = AnthropicBackend(api_key=None, model="m", client=FakeClient(sdk.AuthenticationError("bad key")))
        with self.assertRaises(LLMAuthError):
            await auth.assess(self.control, [CHUNK])
        down = AnthropicBackend(api_key=None, model="m", client=FakeClient(sdk.APIError("overloaded")))
        with self.assertRaises(LLMUnavailable):
            await down.assess(self.control, [CHUNK])

    def test_missing_key_is_a_clear_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            AnthropicBackend(api_key=None, model="m")
        self.assertIn("ANTHROPIC_API_KEY", str(ctx.exception))

    def test_client_is_built_with_key_and_retries(self):
        backend = AnthropicBackend(api_key="k", model="m", max_retries=3, timeout=30.0)
        self.assertEqual(backend._client.kwargs, {"api_key": "k", "timeout": 30.0, "max_retries": 3})


class HeuristicBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.control = load_catalog().get("password-management")
        self.creation, self.safeguarding = (c.synth[0] for c in self.control.criteria)

    def chunk(self, *sentences):
        return Chunk(id="c0001", ord=0, n_words=20, text=" ".join(sentences))

    async def test_met_partial_gap(self):
        backend = HeuristicBackend()
        full = self.chunk(self.creation, self.safeguarding)
        raw, usage = await backend.assess(self.control, [full])
        self.assertEqual((raw.status, len(raw.evidence), raw.missing_elements), ("met", 2, []))
        self.assertEqual(usage.input_tokens, 0)

        raw, _ = await backend.assess(self.control, [self.chunk(self.creation)])
        self.assertEqual((raw.status, len(raw.missing_elements)), ("partial", 1))

        raw, _ = await backend.assess(self.control, [self.chunk("The cafeteria opens at eight.")])
        self.assertEqual((raw.status, raw.evidence), ("gap", []))
        self.assertIn("not an AI model", raw.rationale)

    async def test_quotes_survive_verification(self):
        chunk = self.chunk(self.creation, "Unrelated sentence about parking.", self.safeguarding)
        raw, _ = await HeuristicBackend().assess(self.control, [chunk])
        finding = finalize(self.control.id, raw, [chunk], model="heuristic")
        self.assertEqual((finding.status, len(finding.evidence), finding.flags), ("met", 2, []))

    async def test_hyphenated_keywords_match_both_spellings(self):
        control = load_catalog().get("login-monitoring")
        for text in ("Log-in attempts, including failed attempts, are monitored and accounts are locked after repeated failures.",
                     "Login attempts, including failed attempts, are monitored and accounts are locked after repeated failures."):
            raw, _ = await HeuristicBackend().assess(control, [self.chunk(text)])
            self.assertGreaterEqual(len(raw.evidence), 1, text)


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        s = Settings.from_env({})
        self.assertEqual((s.llm_backend, s.model, s.embedder, s.concurrency, s.top_k), ("anthropic", "claude-sonnet-5-5", "auto", 4, 6))
        self.assertIsNone(s.api_key)
        self.assertEqual(s.max_upload_bytes, 10 * 1024 * 1024)

    def test_values_and_cors_list(self):
        s = Settings.from_env(
            {"HIPAA_AUDIT_LLM_BACKEND": "HEURISTIC", "HIPAA_AUDIT_CORS_ORIGINS": "http://a.test, http://b.test,", "HIPAA_AUDIT_CONCURRENCY": "8"}
        )
        self.assertEqual((s.llm_backend, s.concurrency), ("heuristic", 8))
        self.assertEqual(s.cors_origins, ("http://a.test", "http://b.test"))

    def test_invalid_values(self):
        for env in ({"HIPAA_AUDIT_LLM_BACKEND": "gpt"}, {"HIPAA_AUDIT_EMBEDDER": "x"}, {"HIPAA_AUDIT_CONCURRENCY": "four"}, {"HIPAA_AUDIT_MAX_PAGES": "0"}):
            with self.assertRaises(ConfigError, msg=str(env)):
                Settings.from_env(env)

    def test_env_file_does_not_override_existing_variables(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, ".env")
            with open(path, "w", encoding="utf-8") as f:
                f.write("# comment\nHIPAA_TEST_A=from-file\nHIPAA_TEST_B='quoted'\nbroken line\n")
            with mock.patch.dict(os.environ, {"HIPAA_TEST_A": "already-set"}, clear=False):
                os.environ.pop("HIPAA_TEST_B", None)
                load_env_file(path)
                self.assertEqual(os.environ["HIPAA_TEST_A"], "already-set")
                self.assertEqual(os.environ["HIPAA_TEST_B"], "quoted")
                os.environ.pop("HIPAA_TEST_B", None)
        load_env_file("/nonexistent/.env")  # a missing file is fine


if __name__ == "__main__":
    unittest.main()
