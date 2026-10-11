"""Offline contract tests for replay's HTTP assertion and evidence-export behavior.

These test only the replay harness. They do not simulate an AWS authorizer or
prove that an application security control or detector executed.
"""
import importlib.util
import json
import pathlib
import sys

import pytest


@pytest.fixture()
def replay(monkeypatch):
    path = pathlib.Path(__file__).resolve().parents[1] / "demo" / "replay.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("replay_contract_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("observed,expected,success", [
    (401, 401, True),
    (403, 401, False),
    (401, None, False),
])
def test_hardened_http_assertion_and_redacted_evidence(
    replay, monkeypatch, tmp_path, observed, expected, success
):
    scenario = tmp_path / "case.json"
    item = {"user": "unknown-service-account", "phase": "jwt-edge", "prompt": "sensitive string"}
    if expected is not None:
        item["expected_status_hardened"] = expected
    scenario.write_text(json.dumps({"requests": [item]}))
    output = tmp_path / "result.json"
    monkeypatch.setattr(replay, "get_token", lambda *args: None)
    monkeypatch.setattr(replay, "post", lambda *args: (observed, {"request_id": "req-test"}))
    monkeypatch.setattr(replay.time, "sleep", lambda *args: None)
    monkeypatch.setattr(sys, "argv", ["replay.py", "--scenario", str(scenario),
        "--url", "https://example.test/chat", "--key", "do-not-log-me",
        "--client-id", "client", "--assert-expected", "--results-json", str(output)])
    assert replay.main() == (0 if success else 1)
    raw = output.read_text()
    saved = json.loads(raw)
    assert saved["requests"][0]["http_status"] == observed
    assert saved["requests"][0]["mode"] == "hardened"
    assert "do-not-log-me" not in raw
    assert "sensitive string" not in raw


def test_baseline_http_assertion(replay, monkeypatch, tmp_path):
    scenario = tmp_path / "baseline.json"
    scenario.write_text(json.dumps({"requests": [
        {"user": "demo", "prompt": "hello", "expected_status_baseline": 200}
    ]}))
    monkeypatch.setattr(replay, "post", lambda *args: (200, {"request_id": "baseline"}))
    monkeypatch.setattr(replay.time, "sleep", lambda *args: None)
    monkeypatch.setattr(sys, "argv", ["replay.py", "--scenario", str(scenario),
        "--url", "https://example.test/chat", "--key", "fake",
        "--no-auth", "--assert-expected"])
    assert replay.main() == 0



def test_default_cli_is_compact_and_verbose_shows_details(replay, monkeypatch, tmp_path, capsys):
    scenario = tmp_path / "normal.json"
    scenario.write_text(json.dumps({"requests": [
        {"user": "demo", "prompt": "hello"}
    ]}))
    monkeypatch.setattr(replay, "post", lambda *args: (200, {
        "request_id": "req-secret-detail",
        "documents_returned": [{"document_name": "Example_Public.md"}],
        "documents_blocked": [],
    }))
    monkeypatch.setattr(replay.time, "sleep", lambda *args: None)
    base_args = ["replay.py", "--scenario", str(scenario),
                 "--url", "https://example.test/chat", "--key", "fake",
                 "--no-auth", "--no-detection-check"]
    monkeypatch.setattr(sys, "argv", base_args)
    assert replay.main() == 0
    compact = capsys.readouterr().out
    assert "AWS AI SECURITY LAB | REPLAY" in compact
    assert "Documents returned: 1" in compact
    assert "req-secret-detail" not in compact
    assert "Example_Public.md" not in compact
    monkeypatch.setattr(sys, "argv", base_args + ["--verbose"])
    assert replay.main() == 0
    expanded = capsys.readouterr().out
    assert "req-secret-detail" in expanded
    assert "Example_Public.md" in expanded


def test_gateway_401_correlation_headers(replay, monkeypatch):
    import io
    import urllib.error
    from email.message import Message

    headers = Message()
    headers["x-amzn-RequestId"] = "gateway-request-401"
    headers["x-amz-apigw-id"] = "gateway-extended"
    def rejected(req, timeout):
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", headers,
            io.BytesIO(b'{"message":"Unauthorized"}'))
    monkeypatch.setattr(replay.urllib.request, "urlopen", rejected)
    status, response = replay.post("https://example.test/chat", "fake", {"user":"svc"})
    assert status == 401
    assert response["_api_gateway_request_id"] == "gateway-request-401"
    assert response["_api_gateway_extended_id"] == "gateway-extended"
    assert "request_id" not in response


def test_invalid_gateway_json_still_keeps_correlation(replay, monkeypatch):
    from email.message import Message
    import io
    headers = Message()
    headers["x-amzn-RequestId"] = "gateway-non-json"
    def accepted(req, timeout):
        return io.BytesIO(b"not json")
    # Context-manager response with headers and status
    class Response:
        status = 200
        def __init__(self):
            self.headers = headers
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def read(self):
            return b"not json"
    monkeypatch.setattr(replay.urllib.request, "urlopen", lambda *a, **kw: Response())
    status, response = replay.post("https://example.test/chat", "fake", {})
    assert status == 200
    assert response["_api_gateway_request_id"] == "gateway-non-json"


def test_tampered_jwt_changes_signature_not_claims(replay):
    token = "header.payload.signature"
    altered = replay.altered_signature(token)
    assert altered.split(".")[:2] == token.split(".")[:2]
    assert altered.split(".")[2] != token.split(".")[2]


@pytest.mark.parametrize("mode,expected", [
    ("missing", None),
    ("malformed", "malformed.jwt.not-a-signature"),
])
def test_noncredential_cases_do_not_authenticate(replay, monkeypatch, mode, expected):
    monkeypatch.setattr(replay, "get_token", lambda *args: pytest.fail("Cognito must not be called"))
    assert replay.auth_test_token(mode, "client", "c.jones", "password", {}) == expected


def test_genuine_expired_jwt_required(replay, tmp_path):
    import base64
    import os
    def token_with_exp(exp):
        payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
        return "a." + payload + ".signature"
    p = tmp_path / "old.jwt"
    p.write_text(token_with_exp(1))
    os.chmod(p, 0o600)
    assert replay.expired_jwt_from_file(str(p)) == p.read_text()
    p.write_text(token_with_exp(9999999999))
    with pytest.raises(ValueError, match="not expired"):
        replay.expired_jwt_from_file(str(p))
    p.write_text(token_with_exp(1))
    os.chmod(p, 0o644)
    with pytest.raises(ValueError, match="owner-only"):
        replay.expired_jwt_from_file(str(p))


def test_missing_valid_cognito_token_fails_setup_not_fake_401(replay, monkeypatch):
    monkeypatch.setattr(replay, "get_token", lambda *args: None)
    with pytest.raises(ValueError, match="Cognito login failed"):
        replay.auth_test_token("tampered", "client", "c.jones", "password", {})


def test_jwt_boundary_scenario_keeps_network_gate_out_of_positive_control():
    scenario_path = pathlib.Path(__file__).resolve().parents[1] / "demo" / "scenarios" / "08_jwt_boundary.json"
    scenario = json.loads(scenario_path.read_text())
    cases = {r["auth_case"]: r for r in scenario["requests"]}
    assert set(cases) == {"missing", "malformed", "tampered", "valid"}
    assert all(r["x_source_ip"] == "10.12.8.44" for r in cases.values())
    assert cases["valid"]["expected_status_hardened"] == 200
    assert cases["tampered"]["expected_status_hardened"] == 403
    assert cases["missing"]["expected_status_hardened"] == 401
    assert cases["malformed"]["expected_status_hardened"] == 401


@pytest.mark.parametrize("model_status,expected_exit", [
    ("succeeded", 0),
    ("failed", 1),
    (None, 1),
])
def test_model_execution_contract_cannot_be_satisfied_by_http_200(
    replay, monkeypatch, tmp_path, model_status, expected_exit
):
    scenario = tmp_path / "model.json"
    scenario.write_text(json.dumps({
        "expected_model_status": "succeeded",
        "requests": [{"user": "c.jones", "prompt": "hello"}],
    }))
    monkeypatch.setattr(replay, "post", lambda *args: (200, {
        "request_id": "model-test",
        "model_status": model_status,
        "guardrail_action": "none",
    }))
    monkeypatch.setattr(replay.time, "sleep", lambda *args: None)
    monkeypatch.setattr(sys, "argv", [
        "replay.py", "--scenario", str(scenario),
        "--url", "https://example.test/chat", "--key", "fake",
        "--no-auth", "--no-detection-check",
    ])
    assert replay.main() == expected_exit


def test_token_scenario_declares_normal_negative_controls_and_one_spike():
    scenario_path = pathlib.Path(__file__).resolve().parents[1] / "demo" / "scenarios" / "10_token_deviation_hardened.json"
    scenario = json.loads(scenario_path.read_text())
    requests = scenario["requests"]
    assert [r["expected_detections"] for r in requests] == [
        [], [], ["token-volume-deviation"]]
    assert [r["simulate_tokens"] for r in requests] == [200, 250, 120000]


@pytest.mark.parametrize("unexpected_normal_alert,exit_code", [(False, 0), (True, 1)])
def test_per_request_detector_contract_rejects_normal_alert(
    replay, monkeypatch, tmp_path, unexpected_normal_alert, exit_code
):
    scenario = tmp_path / "per-request.json"
    scenario.write_text(json.dumps({
        "requests": [
            {"user": "c.jones", "phase": "normal", "prompt": "hello",
             "expected_detections": []},
            {"user": "c.jones", "phase": "spike", "prompt": "hello",
             "expected_detections": ["token-volume-deviation"]},
        ],
        "expected_detections": ["token-volume-deviation"],
    }))
    calls = iter(["normal-id", "spike-id"])
    monkeypatch.setattr(replay, "post",
                        lambda *args: (200, {"request_id": next(calls)}))
    monkeypatch.setattr(replay, "tf_output",
                        lambda *args, **kwargs: "/aws/lambda/ai-rag-lab-detector")
    monkeypatch.setattr(replay, "check_detections",
                        lambda *args, **kwargs: ("PASS",
                            [{"request_id": "spike-id", "detection": "token-volume-deviation"}]
                            + ([{"request_id": "normal-id", "detection": "token-volume-deviation"}]
                               if unexpected_normal_alert else []),
                            "Expected findings observed"))
    monkeypatch.setattr(replay.time, "sleep", lambda _: None)
    monkeypatch.setattr(sys, "argv", [
        "replay.py", "--scenario", str(scenario), "--url", "https://example.test",
        "--key", "fake", "--no-auth"
    ])
    assert replay.main() == exit_code
