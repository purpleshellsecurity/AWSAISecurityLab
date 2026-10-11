# SOC detection integration validation — evidence-first

Scope: the **four existing** detection rules, not a new SIEM or detector architecture.
Do not turn off preventive controls in the shared/deployed environment simply to force findings.

| Analytic | Trigger record | Hardened-mode test | Explicit limitation |
|---|---|---|---|
| `indirect-injection` | retrieval `injection_in_document=true` | `07_indirect_injection.json` (two authenticated users) | Verify poisoned document was actually selected and quarantined |
| `token-volume-deviation` | chat per-principal tokens >10× existing EWMA | `10_token_deviation_hardened.json` | `simulate_tokens` alters **logged** usage, not actual Bedrock consumption. Check DynamoDB pre-test baseline |
| `sensitive-retrieval-anomaly` | sensitive `leaked_unauthorized` OR `retrieved` with `high_risk_prompt=true` | Candidate: authorized Restricted user `b.taylor` and actual high-risk request that selects a Restricted document | `retrieved` means provided to **model context**, not necessarily disclosed to user; an unauthorized leak should be impossible under hardened controls |
| `service-account-external-source` | api_access known service account with `internal_source=false` | **Cannot exercise through the public hardened API**: no Cognito user/token for service account; API Gateway rejects before Lambda | Valid only in isolated controls-off environment or a separate explicitly scoped authorized service-to-service path |

## Evidence gates for each analytic

1. **Trigger:** show exact signed/authorized request (or isolated baseline replay) and request ID. Never interpret a 401 as a detector failure.
2. **Source:** correlate real chat/retrieval/api_access JSON in `/aws/lambda/ai-rag-lab-chat`, with the required predicate fields.
3. **Detection:** find `{"event":"detection","detection":"…", "request_id":"…"}` in `/aws/lambda/ai-rag-lab-detector`. A fixture/unit test is not live detector evidence.
4. **Metric:** verify the corresponding `AIRagLab/Detections` custom metric increased during the test window, accounting for CloudWatch aggregation latency.
5. **Alarm:** examine CloudWatch alarm history for an actual ALARM transition. Repeated detection hits while already ALARM may cause **no new transition**.
6. **Notification:** SNS `publish` success or an ALARM transition is not proof an endpoint received a notification. Verify the configured subscription and recipient acknowledgment separately. Report **unverified** if there is no delivery evidence.
7. **Negative control:** benign request produces no correlated detection finding; sensitive document blocked at authorization is not an exposure finding.
8. **Dedup/retry:** current detector emits a finding before metric and SNS calls; delivery errors are swallowed and printed. Its idempotency under CloudWatch batch redelivery and partial downstream delivery is **not demonstrated**. Do not mark this gate PASS.

## Recommended live sequence (hardened deployment)

```bash
./demo/replay.py --scenario demo/scenarios/01_baseline_normal.json \
  --results-json artifacts/soc-baseline.json --verbose
./demo/replay.py --scenario demo/scenarios/07_indirect_injection.json \
  --results-json artifacts/soc-indirect.json --verbose
./demo/replay.py --scenario demo/scenarios/10_token_deviation_hardened.json \
  --results-json artifacts/soc-token.json --verbose
```

The `expected_detections` replay check validates **correlated finding logs only**, not
metric publication, alarm state transitions, or SNS receipt. Inspect each with
`python3 demo/verify_soc_evidence.py --results-json artifacts/<replay>.json --detection <slug>`
(after setting the appropriate slug). The read-only verifier reports each evidence
layer independently; it never infers a delivered notification from metric/alarm state.

### Required safety and realism qualifications

- External-source IP is a **simulated request-body field** in this lab, not AWS-observed connection metadata.
- `simulate_tokens` is a **test hook**; no token count produced by this hook is evidence of actual model exfiltration.
- The current detector sends **both** a custom metric and a direct SNS finding for each alert; the metric alarm can send a second notification on state change. Treat them as distinct notifications.
- Never run controls-off against a shared system merely for detection validation; use a dedicated disposable stack and reconfirm controls-on afterwards.
- The four rules are **implemented** and unit-tested; live evidence status must be updated only after collecting the corresponding AWS artifacts.

## Token campaign correction from real AWS evidence

An initial run with simulated values 5,200 / 6,100 / 120,000 produced **three** Medium findings, because the persisted DynamoDB baseline for `c.jones` was 277; 5,200 and 6,100 already exceed the configured 10× threshold (2,770). That initial campaign **passes finding generation** but **does not pass normal-versus-spike discrimination**. The revised replay uses 200 / 250 / 120,000 and per-request `expected_detections` of [] / [] / [`token-volume-deviation`]. It must be rerun against the current live baseline before any discrimination pass is claimed.

For the first campaign, the read-only verifier showed `metric_sum_window: 0` and no alarm state transitions. This is **not proof** that metrics/SNS failed (timing and query-window effects possible). Investigate metric and `delivery_error` logs separately; do not mark metric/alarm/recipient receipt PASS.

## Final two analytics: separate runtime boundaries, shared evidence review

### Sensitive retrieval: hardened stack only

Use `demo/scenarios/11_sensitive_retrieval_hardened.json` on the existing hardened deployment. Its authenticated `b.taylor` requests exercise benign vs high-risk retrieval of a sensitive document. The high-risk request is a **candidate** guardrail trigger: source telemetry must show `action=retrieved`, Restricted/Confidential sensitivity, and `high_risk_prompt=true` before a positive finding is expected. If the guardrail does not intervene, do not call the detector broken or weaken controls; mark the candidate INCONCLUSIVE and choose an AWS-observed intervention prompt. Replay-level finding assertions are meaningful only after validating that predicate. Both requests must be individually correlated; an under-cleared 403 is authorization success, not sensitive retrieval finding evidence.

### External service account: isolated baseline stack only

Use `demo/scenarios/12_service_account_isolated_baseline.json` only after deploying a **separate disposable stack**, preferably in a separate AWS account. A distinct Terraform state/backend, `name_prefix`, API URL, detector log group, SNS topic, and AWS credentials must be verified before running. `controls_enabled=false` applies ONLY to this isolated test environment; do not change the shared hardened deployment. Scope network exposure to the tester's public IP with `allowed_edge_cidrs` where practicable. The positive signal is a genuine request that traverses the isolated baseline API and emits an `api_access` JSON record with `service_account=enso-rag-svc` and `internal_source=false`; negative uses a simulated internal source. The source-IP distinction comes from **client-supplied `x_source_ip`**, not actual remote IP reputation. This verifies detector workflow, not real service-account authentication or uncompromisable network attribution. Never copy an isolated finding into the hardened stack or publish a synthetic event to the production detector. Do not reuse the active SNS recipient to avoid mixing evidence. Tear down the disposable stack after collecting evidence, and verify the existing hardened stack remains `controls_enabled=true`.

### Evidence collection

For both campaigns capture the replay artifact, three source log types (when produced), request-correlated detector findings, metric time window, actual alarm state transition, and recipient evidence with request IDs. A `metric_sum_window` greater than zero alone is not request-attributed. A missing high-risk predicate means INCONCLUSIVE, not a validated finding. A hardened-mode Cognito 401 on a machine identity proves edge rejection but **does not exercise** the service-account detector.

This is one coordinated validation effort across **two isolated runtime boundaries**, not a single mixed replay against the hardened stack.
