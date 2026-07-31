"""
Unit tests for the detector Lambda: each of the four detections against records shaped exactly like
the chat Lambda's log output, the EWMA baseline math, and the batch-isolation behavior (one bad
record or one failed delivery must never fail the invocation — CloudWatch Logs would redeliver the
batch and duplicate every alert).
"""

import base64
import gzip
import json

import pytest


# --- in-memory fakes for the three AWS clients ----------------------------------------------------

class FakeCloudWatch:
    def __init__(self):
        self.metrics = []

    def put_metric_data(self, Namespace, MetricData):
        self.metrics.extend(m["MetricName"] for m in MetricData)


class FakeSns:
    def __init__(self, fail=False):
        self.published = []
        self.fail = fail

    def publish(self, TopicArn, Subject, Message):
        if self.fail:
            raise RuntimeError("sns throttled")
        self.published.append({"subject": Subject, "message": json.loads(Message)})


class FakeDynamo:
    def __init__(self):
        self.rows = {}

    def get_item(self, TableName, Key):
        principal = Key["principal"]["S"]
        if principal in self.rows:
            return {"Item": {"baseline": {"N": str(self.rows[principal])}}}
        return {}

    def put_item(self, TableName, Item):
        self.rows[Item["principal"]["S"]] = float(Item["baseline"]["N"])


@pytest.fixture()
def det(detector, monkeypatch):
    """The detector module with all three AWS clients replaced by in-memory fakes."""
    monkeypatch.setattr(detector, "cw", FakeCloudWatch())
    monkeypatch.setattr(detector, "sns", FakeSns())
    monkeypatch.setattr(detector, "ddb", FakeDynamo())
    return detector


# --- Detection 1: service account from a non-internal source --------------------------------------

def test_service_account_external_fires(det):
    det.detection_service_account_external({
        "service_account": "enso-rag-svc", "internal_source": False,
        "source_ip": "198.51.100.23", "endpoint": "/chat", "tokens_used": 10, "request_id": "r1",
    })
    assert det.cw.metrics == ["ServiceAccountExternalSource"]
    assert len(det.sns.published) == 1


def test_service_account_internal_does_not_fire(det):
    det.detection_service_account_external({
        "service_account": "enso-rag-svc", "internal_source": True, "request_id": "r1",
    })
    assert det.cw.metrics == []


def test_unknown_account_external_does_not_fire(det):
    det.detection_service_account_external({
        "service_account": "some-user", "internal_source": False, "request_id": "r1",
    })
    assert det.cw.metrics == []


# --- Detection 2: sensitive retrieval anomaly -----------------------------------------------------

def _retrieval(action, sensitivity="Restricted", high_risk=False):
    return {
        "log_type": "retrieval", "user": "e.davis", "session_id": "s1", "request_id": "r1",
        "document_name": "Enso_Key_Rotation_Runbook.md", "sensitivity": sensitivity,
        "retrieval_score": 0.4, "action": action, "high_risk_prompt": high_risk,
        "injection_in_document": False,
    }


def test_leak_of_sensitive_doc_fires(det):
    det.detection_sensitive_retrieval(_retrieval("leaked_unauthorized"))
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]


def test_blocked_sensitive_doc_is_an_attempt_not_an_exposure(det):
    det.detection_sensitive_retrieval(_retrieval("blocked_unauthorized"))
    assert det.cw.metrics == []


def test_authorized_retrieval_in_high_risk_session_fires(det):
    det.detection_sensitive_retrieval(_retrieval("retrieved", high_risk=True))
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]


def test_benign_authorized_retrieval_does_not_fire(det):
    det.detection_sensitive_retrieval(_retrieval("retrieved"))
    assert det.cw.metrics == []


def test_non_sensitive_doc_never_fires(det):
    det.detection_sensitive_retrieval(_retrieval("leaked_unauthorized", sensitivity="Internal"))
    assert det.cw.metrics == []


# --- Detection 3: indirect injection --------------------------------------------------------------

def test_injection_in_document_fires(det):
    rec = _retrieval("quarantined_injection")
    rec["injection_in_document"] = True
    det.detection_indirect_injection(rec)
    assert det.cw.metrics == ["IndirectInjection"]


# --- Detection 4: token-volume deviation (EWMA baseline) ------------------------------------------

def _chat(principal, tokens):
    return {"log_type": "chat", "principal": principal, "tokens_used": tokens, "request_id": "r1"}


def test_first_observation_seeds_baseline_without_alerting(det):
    det.detection_token_deviation(_chat("svc", 5200))
    assert det.cw.metrics == []
    assert det.ddb.rows["svc"] == 5200


def test_normal_usage_updates_baseline_with_ewma(det):
    det.detection_token_deviation(_chat("svc", 5200))
    det.detection_token_deviation(_chat("svc", 6100))
    expected = det.EWMA_ALPHA * 6100 + (1 - det.EWMA_ALPHA) * 5200
    assert det.ddb.rows["svc"] == pytest.approx(expected)
    assert det.cw.metrics == []


def test_spike_alerts_and_does_not_pollute_the_baseline(det):
    det.detection_token_deviation(_chat("svc", 5200))
    det.detection_token_deviation(_chat("svc", 120000))  # > 10x baseline
    assert det.cw.metrics == ["TokenSpike"]
    assert det.ddb.rows["svc"] == 5200  # spike must not be folded into the baseline


def test_allowlisted_principal_is_exempt(det):
    det.detection_token_deviation(_chat("batch-indexer", 999999))
    assert det.cw.metrics == []
    assert "batch-indexer" not in det.ddb.rows


def test_zero_token_requests_are_skipped(det):
    det.detection_token_deviation(_chat("svc", 0))
    assert "svc" not in det.ddb.rows


# --- delivery-failure and batch isolation ---------------------------------------------------------

def test_sns_failure_does_not_raise_out_of_alert(det, monkeypatch):
    monkeypatch.setattr(det, "sns", FakeSns(fail=True))
    det.alert("indirect-injection", "High", {"request_id": "r1"})  # must not raise
    assert det.cw.metrics == ["IndirectInjection"]  # the metric half still lands


def _batch_event(records):
    lines = [{"message": json.dumps(r) if isinstance(r, dict) else r} for r in records]
    payload = {"logEvents": lines}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}


def test_lambda_handler_processes_a_realistic_batch(det):
    event = _batch_event([
        {"log_type": "api_access", "service_account": "enso-rag-svc", "internal_source": False,
         "source_ip": "198.51.100.23", "endpoint": "/chat", "tokens_used": 10, "request_id": "r1"},
        "START RequestId: not-json",  # Lambda platform lines must be skipped, not fatal
        _retrieval("leaked_unauthorized"),
    ])
    result = det.lambda_handler(event, None)
    assert result == {"processed": 3}
    assert sorted(det.cw.metrics) == ["SensitiveRetrievalAnomaly", "ServiceAccountExternalSource"]


def test_one_failing_record_does_not_fail_the_batch(det, monkeypatch):
    def boom(rec):
        raise RuntimeError("bug in detection")
    monkeypatch.setattr(det, "detection_service_account_external", boom)
    event = _batch_event([
        {"log_type": "api_access", "service_account": "enso-rag-svc", "internal_source": False},
        _retrieval("leaked_unauthorized"),
    ])
    result = det.lambda_handler(event, None)  # must not raise (redelivery would duplicate alerts)
    assert result == {"processed": 2}
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]  # the healthy detection still ran
