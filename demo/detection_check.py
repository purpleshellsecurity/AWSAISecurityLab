"""Correlate replay requests with CloudWatch detector findings (AWS CLI only).

This checks detector *finding logs*, not SNS delivery or CloudWatch alarm state.
No finding is expected for a normal scenario when expected_detections is [].
"""
import json
import subprocess
import time


class DetectionQueryError(RuntimeError):
    pass


def get_findings(log_group, request_ids, *, minutes=10, runner=subprocess.run):
    """Return finding records correlated to replay request IDs.

    Raises on AWS failures rather than interpreting a failed query as no findings.
    """
    if not request_ids:
        return []
    cmd = [
        "aws", "logs", "filter-log-events", "--log-group-name", log_group,
        "--start-time", str(int((time.time() - minutes * 60) * 1000)),
        "--filter-pattern", '{ $.event = "detection" }',
        "--output", "json",
    ]
    found = []
    marker = None
    while True:
        args = cmd + (["--next-token", marker] if marker else [])
        try:
            process = runner(args, capture_output=True, text=True)
        except (OSError, ValueError) as exc:
            raise DetectionQueryError(f"AWS CLI unavailable: {type(exc).__name__}") from exc
        if process.returncode:
            raise DetectionQueryError(
                f"CloudWatch query failed (exit {process.returncode}): "
                f"{process.stderr.strip()[:250]}"
            )
        try:
            response = json.loads(process.stdout)
        except (ValueError, TypeError) as exc:
            raise DetectionQueryError("CloudWatch returned invalid JSON") from exc
        for event in response.get("events", []):
            try:
                finding = json.loads(event["message"])
            except (KeyError, ValueError, TypeError):
                continue
            if finding.get("event") == "detection" and finding.get("request_id") in request_ids:
                found.append(finding)
        new_marker = response.get("nextToken")
        if not new_marker or new_marker == marker:
            break
        marker = new_marker
    return found


def check(log_group, request_ids, expected, *, timeout_seconds=60, interval_seconds=5,
          query=get_findings, sleep=time.sleep, monotonic=time.monotonic):
    """Return (decision, findings, reason) with bounded polling.

    expected None: NOT TESTED; []: expect no findings; names: expect named findings.
    A negative result is a snapshot, not proof of complete downstream delivery.
    """
    if expected is None:
        return "NOT TESTED", [], "Scenario has no declared detection expectations"
    if not isinstance(expected, list) or any(not isinstance(x, str) for x in expected):
        return "INCONCLUSIVE", [], "Invalid expected_detections metadata"
    if not request_ids:
        return "INCONCLUSIVE", [], "No request IDs to correlate with detector logs"
    deadline = monotonic() + max(0, timeout_seconds if expected else 0)
    while True:
        try:
            findings = query(log_group, request_ids)
        except DetectionQueryError as exc:
            return "INCONCLUSIVE", [], str(exc)
        actual = {f.get("detection") for f in findings}
        if not expected:
            if findings:
                return "FAIL", findings, "Unexpected detection finding(s) for normal scenario"
            return "PASS", [], "No correlated findings observed in this CloudWatch query"
        missing = sorted(set(expected) - actual)
        if not missing:
            return "PASS", findings, "Expected detector findings observed"
        if monotonic() >= deadline:
            return "FAIL", findings, "Missing expected detections: " + ", ".join(missing)
        sleep(min(interval_seconds, max(0, deadline - monotonic())))
