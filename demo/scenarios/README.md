# Attack Scenarios

Each `*.json` here is a self-contained attack you can replay against the deployed API. They populate
your logs with realistic activity and exercise the controls + detections.

## Run one

```bash
./demo/replay.py --list                                  # list available scenarios
./demo/replay.py --scenario demo/scenarios/02_prompt_injection.json
./demo/replay.py --scenario demo/scenarios/04_account_compromise.json --delay 1
```

Run the baseline first (`01_baseline_normal.json`) — it establishes clean traffic and seeds the
per-principal token baselines that detection 4 compares against.

## What's here

| File | Teaches | Detection it triggers |
|---|---|---|
| `01_baseline_normal.json` | what normal looks like | none (by design) |
| `02_prompt_injection.json` | LLM01 prompt injection | guardrail intervention (needs Bedrock access) |
| `03_data_exfiltration.json` | LLM02 RAG abuse / broken access control | sensitive-retrieval-anomaly *(when controls OFF)* |
| `04_account_compromise.json` | LLM06 + token abuse | service-account-external-source, token-volume-deviation |
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
      "service_account": "enso-rag-svc", // optional; becomes the principal for the api_access log + detection 1
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
- **To trip the external-source detection**, set `service_account` to a known one
  (`enso-rag-svc`, `enso-vector-svc`, `enso-assistant-api`) and an `x_source_ip` outside `internal_cidrs`.
- **To trip the token-spike detection**, send a couple of normal requests for a principal first
  (to seed the baseline), then one with a large `simulate_tokens`.
- **To see leaks + the sensitive-retrieval detection**, deploy with `controls_enabled=false`;
  with controls on, the same requests are blocked at retrieval instead.

After replaying: `./demo/show_detections.sh` (what fired) and `./demo/trace.sh '<body>'` (trace one
request across every layer).
