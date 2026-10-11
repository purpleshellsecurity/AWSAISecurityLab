"""Offline contract checks for independent JWT gateway attribution."""
import importlib.util
from pathlib import Path


def verifier():
    path = Path(__file__).resolve().parents[1] / "demo" / "verify_jwt_gateway.py"
    spec = importlib.util.spec_from_file_location("gateway_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def case(kind, status):
    return {"auth_case": kind, "http_status": status,
            "api_gateway_request_id": "gateway-" + kind,
            "request_id": "gateway-valid" if kind == "valid" else None}


def test_differential_gateway_auth_attribution_passes():
    module = verifier()
    rows = [case("missing", 401), case("malformed", 401),
            case("tampered", 403), case("valid", 200)]
    gateway = {
        r["api_gateway_request_id"]: [{
            "status": str(r["http_status"]),
            "gateway_error": "Rejected" if r["auth_case"] != "valid" else "-",
            "gateway_error_type": "ACCESS_DENIED" if r["auth_case"] == "tampered" else "-",
            "integration_status": "200" if r["auth_case"] == "valid" else "-",
        }] for r in rows
    }
    chat = {"gateway-valid": [{"request_id": "gateway-valid", "log_type": "chat"}]}
    decisions = module.classify(rows, gateway, chat)
    assert len(decisions) == 4
    assert all(d == "PASS" for _, d, _ in decisions)


def test_tampered_requires_signed_token_positive_control():
    module = verifier()
    rows = [case("tampered", 403), case("valid", 200)]
    gateway = {
        "gateway-tampered": [{"status": "403", "gateway_error": "Forbidden",
                              "gateway_error_type": "ACCESS_DENIED", "integration_status": "-"}],
        "gateway-valid": [{"status": "200", "gateway_error": "-",
                           "gateway_error_type": "-", "integration_status": "200"}],
    }
    outcomes = dict((c, result) for c, result, _ in module.classify(rows, gateway, {}))
    assert outcomes["tampered"] == "INCONCLUSIVE"


def test_outdated_log_schema_is_not_claimed_as_auth_proof():
    module = verifier()
    row = case("tampered", 403)
    decisions = module.classify([row], {"gateway-tampered": [{"status": "403"}]}, {})
    assert decisions[0][1] == "INCONCLUSIVE"


def test_lambda_invocation_on_bad_jwt_fails():
    module = verifier()
    row = case("tampered", 403)
    gateway = {"gateway-tampered": [{"status": "403", "gateway_error": "Forbidden",
                                    "gateway_error_type": "ACCESS_DENIED",
                                    "integration_status": "200"}]}
    decisions = module.classify([row], gateway, {"gateway-tampered": [{"log_type": "chat"}]})
    assert decisions[0][1] == "FAIL"


def test_historical_event_is_not_misreported_as_stage_config_failure():
    module = verifier()
    row = case("tampered", 403)
    decision = module.classify([row], {"gateway-tampered": [{"status": "403"}]}, {})
    assert decision[0][1] == "INCONCLUSIVE"
    assert "Historical gateway event" in decision[0][2]


def test_current_stage_schema_detected(monkeypatch):
    module = verifier()
    from types import SimpleNamespace
    monkeypatch.setattr(module, "terraform_output",
                        lambda key: "https://hb764gr1g0.execute-api.us-east-1.amazonaws.com/prod/chat")
    def run(argv, **kwargs):
        assert argv[:3] == ["aws", "apigateway", "get-stage"]
        return SimpleNamespace(returncode=0, stdout='{"gateway_error":"$context.error.message","gateway_error_type":"$context.error.responseType","integration_status":"$context.integration.status"}', stderr="")
    monkeypatch.setattr(module.subprocess, "run", run)
    assert module.stage_schema_active("us-east-1")


def test_current_stage_schema_missing_diagnostic_fields(monkeypatch):
    module = verifier()
    from types import SimpleNamespace
    monkeypatch.setattr(module, "terraform_output",
                        lambda key: "https://hb764gr1g0.execute-api.us-east-1.amazonaws.com/prod/chat")
    monkeypatch.setattr(module.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout='{"request_id":"$context.requestId"}', stderr=""))
    assert not module.stage_schema_active("us-east-1")
