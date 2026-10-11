# Attack Scenarios

Each `*.json` here is a self-contained attack you can replay against the deployed API. They populate
your logs with realistic activity and exercise the controls + detections.

## Run one

```bash
./demo/replay.py --list                                  # list available scenarios
./demo/replay.py --scenario demo/scenarios/02_prompt_injection.json
```

Run the baseline first (`01_baseline_normal.json`) — it establishes clean traffic and seeds the
per-principal token baselines that detection 4 compares against.

## What's here

| File | Teaches | Detection it triggers |
|---|---|---|
| `01_baseline_normal.json` | what normal looks like | none (by design) |
| `02_prompt_injection.json` | LLM01 prompt injection | guardrail intervention (needs Bedrock access) |
| `03_data_exfiltration.json` | LLM02 RAG abuse / broken access control | sensitive-retrieval-anomaly *(when controls OFF)* |
| `05_jailbreak.json` | LLM01 jailbreak / persona override | guardrail intervention (needs Bedrock access) |
| `06_system_prompt_extraction.json` | LLM07 system-prompt / config extraction | guardrail + blocked-at-retrieval (system-prompt doc is Restricted) |
| `07_indirect_injection.json` | LLM01 indirect injection / RAG poisoning (benign user, poisoned doc) | indirect-injection |
| `99_incident_full.json` | the whole incident end to end | all of the above |

## Write your own

Copy any file and edit the `requests` list. Schema:

```jsonc
{
  "name": "Short title",
  "description": "What this scenario demonstrates.",
  "requests": [
    {
      "phase": "label",          // free-text tag shown in replay output (group related requests)
      "user": "e.davis",          // identity; clearance comes from corpus/manifest.json
      "service_account": "enso-rag-svc", // legacy body field (not authenticated machine identity)
      "x_source_ip": "198.51.100.23",  // simulated source IP (checked against internal_cidrs by the Lambda)
      "session_id": "sess-1300",     // ties related requests together in the logs
      "prompt": "the user's message",
      "simulate_tokens": 120000      // optional; overrides logged token count (for token-spike demos)
    }
  ]
}
```

Only `prompt` is strictly required. Tips:

- **Who is allowed to see what** comes from `corpus/manifest.json` (`users` → `max_clearance`,
  documents → `classification`). To test authorization, pick a `user` whose clearance is below the
  document you target.
- **Which document gets retrieved** is decided by name-token overlap with the `prompt`. Mention the
  document's name words (e.g. "Benefits FAQ 2026") to steer retrieval at it.
- **To see leaks + the sensitive-retrieval detection**, deploy with `controls_enabled=false`;
  with controls on, the same requests are blocked at retrieval instead.

After replaying: `./demo/show_detections.sh` (what fired) and `./demo/trace.sh '<body>'` (trace one
request across every layer).

## Integrated detection verification (Dev v2)

`./demo/replay.py --scenario demo/scenarios/01_baseline_normal.json` now queries CloudWatch for findings correlated by the replay's request IDs. Normal baseline declares `expected_detections: []`: no findings are expected. An empty result is a point-in-time observation, **not** proof that log delivery or SNS alerting works.

`./demo/replay.py --scenario demo/scenarios/07_indirect_injection.json` declares `expected_detections: ["indirect-injection"]`. The replay waits up to 60 seconds for a correlated finding, then reports `PASS`, `FAIL`, or `INCONCLUSIVE`. CloudWatch access errors are not interpreted as zero detections. Override polling with `--detection-timeout 90` or skip the check with `--no-detection-check`.

Scenarios without `expected_detections` report `NOT TESTED` for detector verification. Findings prove the detection Lambda logged an alert, **not** that the corresponding CloudWatch metric/Alarm/SNS notification reached an analyst. Those are separate release gates.

`./demo/show_detections.sh` remains available for manual all-requests inspection, but is no longer a required post-replay step.


## Cognito boundary negative tests (hardened only)

```bash
mkdir -p artifacts
./demo/replay.py --scenario demo/scenarios/08_jwt_boundary.json --assert-expected --verbose \
  --results-json artifacts/jwt-boundary.json
```

Four cases: missing JWT, malformed JWT, tampered signature of genuine Cognito ID token, and a valid Cognito ID token positive control. Expected HTTP in the current deployed lab: 401/401/403/200. The tampered-signature case was observed rejected at API Gateway with 403; correlate the gateway request ID before attributing a 403 to the authorizer. Each case includes `x_source_ip: 10.12.8.44` to exercise Cognito independently of the separate **simulated** application source-IP checkpoint. This does **not** validate real network perimeter enforcement. Failed Cognito login is a setup error, **not** evidence of edge enforcement. The evidence file holds request metadata and gateway correlation identifiers, never JWTs or secrets.

For genuine expiry testing, privately capture a real Cognito ID token from the disposable lab user pool to a local owner-only file (permissions `0600`). Once the original, correctly signed token has actually expired (configured ID token validity: one hour), run:

```bash
./demo/replay.py --scenario demo/scenarios/09_jwt_expired.json --assert-expected \
  --expired-jwt-file /secure/local/path/expired.jwt --verbose \
  --results-json artifacts/jwt-expired.json
```

Do not commit, print, paste or upload tokens. Modifying the `exp` claim without Cognito signing creates an invalid signature and **does not test expiry**. Invalid file permissions, missing token, or unexpired token produce a setup error (exit code 2). The CLI checks untrusted expiry metadata only to avoid running the wrong experiment; API Gateway itself must verify the JWT. Expected 401 and request IDs are still HTTP-only evidence and do not by themselves prove absence of Lambda invocation.


### Independent edge authorization attribution

HTTP 403 and a Gateway request ID do **not** on their own establish which component rejected a request. The API Gateway access-log format now records the gateway error and Lambda integration status, without JWTs or request bodies. Deploy this logging change before collecting a new campaign:

```bash
terraform -chdir=terraform plan -var="controls_enabled=true"
terraform -chdir=terraform apply -var="controls_enabled=true"
./demo/replay.py --scenario demo/scenarios/08_jwt_boundary.json \
  --assert-expected --results-json artifacts/jwt-boundary-v3.json --verbose
python3 demo/verify_jwt_gateway.py --results-json artifacts/jwt-boundary-v3.json
```

The last command queries CloudWatch access logs and the chat Lambda logs using each actual Gateway request ID. It expects all three rejected credentials to terminate before integration, and a signed Cognito positive control to invoke the application. A missing access-log schema, missing telemetry, or an observed Lambda invocation on a rejected credential yields **INCONCLUSIVE** or **FAIL**, never a fabricated PASS. The tampered case is tested by changing the signature bytes of a genuine Cognito ID token while retaining the same username, body and simulated internal source IP as the valid control. This is strong differential integration evidence, not a direct export of Cognito's cryptographic verifier decision.

Keep the Terraform plan under review before apply; the logging update should only modify stage access-log formatting. The cloud evidence from the old logging format cannot retroactively acquire these fields.
