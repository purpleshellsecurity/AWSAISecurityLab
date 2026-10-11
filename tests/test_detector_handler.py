"""
Unit tests for the detector Lambda: each of the three detections against records shaped exactly like
the chat Lambda's log output, the EWMA baseline math, and the batch-isolation behavior (one bad
record or one failed delivery must never fail the invocation — CloudWatch Logs would redeliver the
batch and duplicate every alert).
"""

import base64
import gzip
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError

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
        self.receipts = {}
        self.lock = threading.RLock()

    def _fail(self, code='ConditionalCheckFailedException'):
        raise ClientError({'Error': {'Code': code, 'Message': 'condition failed'}}, 'DynamoDB')

    def get_item(self, TableName, Key, **kwargs):
        principal = Key["principal"]["S"]
        if principal in self.receipts:
            return {'Item': dict(self.receipts[principal])}
        if principal in self.rows:
            return {"Item": {"baseline": {"N": str(self.rows[principal])}}}
        return {}

    def put_item(self, TableName, Item, **kwargs):
        key = Item["principal"]["S"]
        with self.lock:
            if kwargs.get("ConditionExpression") and (key in self.receipts or key in self.rows):
                self._fail()
            if key.startswith("evt#"):
                self.receipts[key] = dict(Item)
            else:
                self.rows[key] = float(Item["baseline"]["N"])


    def update_item(self, TableName, Key, UpdateExpression,
                    ConditionExpression=None, ExpressionAttributeValues=None,
                    ExpressionAttributeNames=None, **kwargs):
        key = Key["principal"]["S"]
        values = ExpressionAttributeValues or {}
        names = ExpressionAttributeNames or {}
        with self.lock:
            if not key.startswith("evt#"):
                self.rows[key] = float(values[":value"]["N"])
                return
            item = self.receipts[key]
            if "#state" not in names:
                item["spike_baseline"] = values[":baseline"]
                return
            state = names["#state"]
            owner = names["#owner"]
            if ":inflight" in values:
                allowed = item[state]["S"] == "pending" or (
                    item[state]["S"] == "inflight" and
                    int(item[names["#lease"]]["N"]) < int(values[":now"]["N"]))
                if not allowed:
                    self._fail()
                item[state] = values[":inflight"]
                item[names["#lease"]] = values[":until"]
                item[owner] = values[":mine"]
            else:
                if item.get(owner, {}).get("S") != values[":mine"]["S"]:
                    self._fail()
                item[state] = values.get(":done", values.get(":pending"))

    def transact_write_items(self, TransactItems):
        with self.lock:
            put = TransactItems[0]["Put"]
            event_key = put["Item"]["principal"]["S"]
            if event_key in self.receipts:
                self._fail("TransactionCanceledException")
            operation = TransactItems[1]
            if "Update" in operation:
                update = operation["Update"]
                principal = update["Key"]["principal"]["S"]
                values = update["ExpressionAttributeValues"]
                old = self.rows.get(principal)
                if ":prior" in values:
                    if old != float(values[":prior"]["N"]):
                        self._fail("TransactionCanceledException")
                elif old is not None:
                    self._fail("TransactionCanceledException")
                next_value = float(values[":value"]["N"])
            else:
                check = operation["ConditionCheck"]
                principal = check["Key"]["principal"]["S"]
                if self.rows.get(principal) != float(
                        check["ExpressionAttributeValues"][":prior"]["N"]):
                    self._fail("TransactionCanceledException")
                next_value = None
            self.receipts[event_key] = dict(put["Item"])
            if next_value is not None:
                self.rows[principal] = next_value


@pytest.fixture()
def det(detector, monkeypatch):
    """The detector module with all three AWS clients replaced by in-memory fakes."""
    monkeypatch.setattr(detector, "cw", FakeCloudWatch())
    monkeypatch.setattr(detector, "sns", FakeSns())
    monkeypatch.setattr(detector, "ddb", FakeDynamo())
    return detector


# --- Detection 1: sensitive retrieval anomaly -----------------------------------------------------

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


# --- Detection 2: indirect injection --------------------------------------------------------------

def test_injection_in_document_fires(det):
    rec = _retrieval("quarantined_injection")
    rec["injection_in_document"] = True
    det.detection_indirect_injection(rec)
    assert det.cw.metrics == ["IndirectInjection"]


# --- Detection 3: token-volume deviation (EWMA baseline) ------------------------------------------

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
    with pytest.raises(RuntimeError, match="Finding delivery incomplete"):
        det.alert("indirect-injection", "High", {"request_id": "r1"})
    assert det.cw.metrics == ["IndirectInjection"]  # the metric half still lands


def _batch_event(records):
    lines = [{"id": "cw-id-" + str(i), "message": json.dumps(r) if isinstance(r, dict) else r} for i, r in enumerate(records)]
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
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]


def test_one_failing_record_does_not_fail_the_batch(det, monkeypatch):
    def boom(rec):
        raise RuntimeError("bug in detection")
    monkeypatch.setattr(det, "detection_sensitive_retrieval", boom)
    event = _batch_event([
        _retrieval("leaked_unauthorized"),
        {"log_type": "chat", "user": "e.davis", "principal": "e.davis", "tokens_used": 100, "request_id": "r2"},
    ])
    with pytest.raises(RuntimeError, match="Detector batch incomplete"):
        det.lambda_handler(event, None)
    assert "IndirectInjection" not in det.cw.metrics
    assert "SensitiveRetrievalAnomaly" not in det.cw.metrics


# Guardrail security events are telemetry, not automatically detector findings.
def test_guardrail_security_event_is_not_an_alert(det):
    event = _batch_event([{
        "log_type": "security_event",
        "schema_version": "1.0",
        "event_action": "guardrail_intervention",
        "event_outcome": "blocked",
        "principal": "e.davis",
        "request_id": "req-guardrail",
        "matched_policies": ["topic:DocumentEnumeration"],
    }])
    det.lambda_handler(event, None)
    assert det.cw.metrics == []
    assert det.sns.published == []


# --- At-least-once delivery characterization: current implementation ---

def _set_first_event_id(event, event_id):
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    payload["logEvents"][0]["id"] = event_id
    event["awslogs"]["data"] = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    return event


def test_duplicate_cloudwatch_delivery_does_not_republish(det):
    event = _batch_event([_retrieval("retrieved", high_risk=True)])
    assert det.lambda_handler(event, None) == {"processed": 1}
    assert det.lambda_handler(event, None) == {"processed": 1}
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    assert len(det.sns.published) == 1


def test_duplicate_normal_chat_event_does_not_change_ewma_twice(det):
    seed = _set_first_event_id(_batch_event([_chat("svc", 100)]), "cw-seed")
    normal = _set_first_event_id(_batch_event([_chat("svc", 200)]), "cw-normal")
    det.lambda_handler(seed, None)
    det.lambda_handler(normal, None)
    first = det.ddb.rows["svc"]
    det.lambda_handler(normal, None)
    assert first == pytest.approx(130)
    assert det.ddb.rows["svc"] == pytest.approx(130)


def test_failed_sns_delivery_surfaces_batch_error_and_logs_sink(det, monkeypatch, capsys):
    monkeypatch.setattr(det, "sns", FakeSns(fail=True))
    event = _batch_event([_retrieval("retrieved", high_risk=True)])
    with pytest.raises(RuntimeError, match="Detector batch incomplete"):
        det.lambda_handler(event, None)
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()
               if line.strip().startswith("{")]
    assert any(r.get("event") == "delivery_error" and r.get("target") == "sns"
               for r in records)


def test_concurrent_same_event_one_metric_and_one_sns(det):
    event = _batch_event([_retrieval("retrieved", high_risk=True)])
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: det.lambda_handler(event, None), range(2)))
    assert [x["processed"] for x in results] == [1, 1]
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    assert len(det.sns.published) == 1


def test_sns_failed_first_delivery_is_retried_without_repeating_metric(det, monkeypatch):
    event = _batch_event([_retrieval("retrieved", high_risk=True)])
    monkeypatch.setattr(det, "sns", FakeSns(fail=True))
    with pytest.raises(RuntimeError, match="Detector batch incomplete"):
        det.lambda_handler(event, None)
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    monkeypatch.setattr(det, "sns", FakeSns())
    det.lambda_handler(event, None)
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    assert len(det.sns.published) == 1


def test_duplicate_token_spike_republishes_neither_metric_nor_sns(det):
    seed = _set_first_event_id(_batch_event([_chat("svc", 5200)]), "seed")
    spike = _set_first_event_id(_batch_event([_chat("svc", 120000)]), "spike")
    det.lambda_handler(seed, None)
    det.lambda_handler(spike, None)
    det.lambda_handler(spike, None)
    assert det.ddb.rows["svc"] == 5200
    assert det.cw.metrics == ["TokenSpike"]
    assert len(det.sns.published) == 1


def test_indirect_injection_replay_does_not_duplicate_notifications(det):
    rec = _retrieval("quarantined_injection")
    rec["injection_in_document"] = True
    event = _batch_event([rec])
    det.lambda_handler(event, None)
    det.lambda_handler(event, None)
    assert det.cw.metrics == ["IndirectInjection"]
    assert len(det.sns.published) == 1


def test_inflight_sink_is_not_treated_as_success(det, monkeypatch):
    event = _batch_event([_retrieval("retrieved", high_risk=True)])
    original = det.deliver_once

    def deferred(key, target, send):
        if target == "sns":
            return False   # another worker holds lease; event is not finished
        return original(key, target, send)

    monkeypatch.setattr(det, "deliver_once", deferred)
    with pytest.raises(RuntimeError, match="Detector batch incomplete"):
        det.lambda_handler(event, None)
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    assert det.sns.published == []
    monkeypatch.setattr(det, "deliver_once", original)
    det.lambda_handler(event, None)
    assert det.cw.metrics == ["SensitiveRetrievalAnomaly"]
    assert len(det.sns.published) == 1


def test_transaction_capacity_failure_is_not_mistaken_for_duplicate(det, monkeypatch):
    rec = _chat("svc", 100)
    event = _batch_event([rec])

    def capacity_failure(**kwargs):
        raise ClientError({
            "Error": {"Code": "TransactionCanceledException", "Message": "capacity"},
            "CancellationReasons": [{"Code": "ProvisionedThroughputExceeded"},
                                    {"Code": "None"}]
        }, "TransactWriteItems")

    monkeypatch.setattr(det.ddb, "transact_write_items", capacity_failure)
    with pytest.raises(RuntimeError, match="Detector batch incomplete"):
        det.lambda_handler(event, None)
    assert det.ddb.rows == {}
