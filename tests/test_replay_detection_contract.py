"""Regression tests for strict per-request detection verdicts."""
import importlib.util
import pathlib
import sys


def _load_replay():
    root = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "demo"))
    spec = importlib.util.spec_from_file_location("soc_replay", root / "demo" / "replay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unexpected_finding_on_benign_request_is_failure():
    replay = _load_replay()
    requests = [
        {"phase": "authorized-benign", "expected_detections": []},
        {"phase": "authorized-high-risk", "expected_detections": ["sensitive-retrieval-anomaly"]},
    ]
    results = [{"request_id": "benign"}, {"request_id": "positive"}]
    findings = [
        {"request_id": "benign", "detection": "sensitive-retrieval-anomaly"},
        {"request_id": "positive", "detection": "sensitive-retrieval-anomaly"},
    ]
    decision, errors = replay.verify_per_request_detections(requests, results, findings)
    assert decision == "FAIL"
    assert "authorized-benign" in errors[0]


def test_expected_positive_and_negative_findings_pass():
    replay = _load_replay()
    reqs = [{"expected_detections": []}, {"expected_detections": ["indirect-injection"]}]
    res = [{"request_id": "a"}, {"request_id": "b"}]
    decision, failures = replay.verify_per_request_detections(
        reqs, res, [{"request_id": "b", "detection": "indirect-injection"}])
    assert decision == "PASS"
    assert failures == []


def test_missing_request_id_is_inconclusive():
    replay = _load_replay()
    decision, failures = replay.verify_per_request_detections(
        [{"expected_detections": []}], [{"request_id": None}], [])
    assert decision == "INCONCLUSIVE"
    assert "no application request ID" in failures[0]
