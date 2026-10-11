"""Offline tests of request-scoped CloudWatch detection verification."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


def load():
    path = Path(__file__).resolve().parents[1] / "demo" / "detection_check.py"
    spec = importlib.util.spec_from_file_location("detection_check_for_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_normal_scenario_has_no_correlated_findings():
    m = load()
    result = m.check("/aws/lambda/detector", {"r1"}, [], query=lambda *_: [])
    assert result[0] == "PASS"
    assert not result[1]


def test_expected_detection_is_correlated_by_request_id():
    m = load()
    data = {"events": [
        {"message": json.dumps({"event": "detection", "detection": "indirect-injection", "request_id": "other"})},
        {"message": json.dumps({"event": "detection", "detection": "indirect-injection", "request_id": "r1"})},
    ]}
    def run(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr="")
    findings = m.get_findings("/aws/lambda/detector", {"r1"}, runner=run)
    assert len(findings) == 1
    assert findings[0]["request_id"] == "r1"


def test_error_is_inconclusive_not_no_detections():
    m = load()
    def bad(*_):
        raise m.DetectionQueryError("AccessDenied")
    decision, records, reason = m.check("/aws/lambda/detector", {"r1"}, [], query=bad)
    assert decision == "INCONCLUSIVE"
    assert records == []
    assert "AccessDenied" in reason


def test_missing_expected_detection_fails_without_long_wait():
    m = load()
    decision, _, reason = m.check(
        "/aws/lambda/detector", {"r1"}, ["indirect-injection"],
        timeout_seconds=0, query=lambda *_: [])
    assert decision == "FAIL"
    assert "indirect-injection" in reason


def test_unexpected_detection_is_failure():
    m = load()
    outcome = m.check("/aws/lambda/detector", {"r1"}, [],
                      query=lambda *_: [{"detection": "token-volume-deviation"}])
    assert outcome[0] == "FAIL"


def test_uncontracted_scenario_is_not_tested():
    m = load()
    decision, _, _ = m.check("/aws/lambda/detector", {"r1"}, None)
    assert decision == "NOT TESTED"
