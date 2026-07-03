# Tuning & Lessons Learned

This guide captures what an end-to-end test run of the lab surfaced, the knobs you can turn, the
diagnostic techniques that found the issues, and pointers to the authoritative AWS docs. If you're
adapting the lab toward something real, read this.

---

## 1. Issues found during validation

Each of these was found by running [TESTING.md](../TESTING.md) on a live deployment — not by reading
the code. That's the point: deploy → attack → observe surfaces things review misses.

| # | Symptom | Root cause | Fix | How it was found |
|---|---|---|---|---|
| 1 | Redeploy after `destroy` failed: *"a secret with this name is already scheduled for deletion."* | Secrets Manager keeps deleted secrets in a 30-day recovery window by default; the name stays reserved | `recovery_window_in_days = 0` on the secret (hard-delete) | destroy → redeploy cycle |
| 2 | Benign user's question intermittently blocked by the guardrail | The `DocumentEnumeration` denied topic evaluates **output too**, and the model cited source **file names** in answers (reads as "listing documents") | System prompt instructs the model not to mention file names → nothing for the output filter to match | capturing the guardrail **trace** and running the same input 4× |
| 3 | `sensitive-retrieval-anomaly` fired ~11× in **hardened** mode (noise) | Detection fired on `high_risk_prompt` even when the doc was **blocked** — i.e. on attempts the controls already stopped | Fire only when a sensitive doc actually **reached** the user (`leaked_unauthorized`, or authorized `retrieved` in a flagged session) | comparing detection counts hardened vs. vulnerable |
| 4 | `trace.sh` returned `403` and matched 0 log records | Shell quoting: the inner `"` closed the outer string, mangling the default JSON body; the 15s wait was also too short for KMS-encrypted log delivery | Single-quoted default body + retry while logs land | the trace returned a 403 for an internal IP |
| 5 | Fresh deploy threw transient `403`s for ~2 min | WAF web ACL + managed rule group propagation after creation | None needed — wait ~2 min after deploy before load-testing | repeated requests, then they cleared |
| 6 | `apply` failed: *"CloudWatch Logs Log Group ... already exists"* | A CloudWatch log group orphaned by an earlier interrupted/failed apply (or an API-Gateway log group that lingered after a destroy); a fresh-clone apply with empty state then collides with it | Delete the orphan and re-apply: `aws logs delete-log-group --log-group-name <name> --region <region>`, then `terraform apply`. (Or `terraform import aws_cloudwatch_log_group.<name> <name>` to adopt it.) | running `apply` from a fresh clone on an account with leftovers |

The meta-lesson for #2: **don't guess at a guardrail false positive — read the trace.** The first
attempt blamed the prompt-attack filter (and lowering it didn't help); the trace showed it was the
denied topic, on the output, non-deterministically.

---

## 2. What you can tune (and how to think about it)

### Guardrail (`bedrock_guardrail.tf`)
- **Prompt-attack strength** — `var.guardrail_prompt_attack_strength` (NONE/LOW/MEDIUM/HIGH, default
  MEDIUM). HIGH is stricter but false-positives more. This filter is **input-only**.
- **Denied topics** — evaluated on **both input and output**. This is the trap from issue #2: a topic
  meant to catch a *request* ("list all documents") will also match an *answer* that looks like the
  topic. Mitigations: keep the model from emitting matchable text (the file-name fix), write the
  `definition` tightly (≤200 chars, describe the content not the instruction), and remember you can't
  scope a topic to input-only.
- **PII policy** — `ANONYMIZE` (mask) vs `BLOCK` (refuse). Add entity types per your data.
- **Contextual grounding** — *not yet used here.* For RAG this is the most relevant guardrail feature:
  tag retrieved chunks as the grounding source and the query separately, and the guardrail can flag
  ungrounded (hallucinated) or irrelevant answers. This is the production-grade upgrade for the
  injection scanner. See the docs in §4.

### Detections (`src/detector/handler.py`, `detections.tf`)
- **Principle learned (issue #3): alert on *exposure*, not on *blocked attempts*.** A control that
  blocked an attack already handled it; alerting on it again is noise. Detections should fire on what
  got through, or on signals the controls don't enforce (e.g. an external-source service account).
- **Token deviation** — `var.token_deviation_factor` (default 10×), the `HIGH_VOLUME_ALLOWLIST`, and
  the EWMA baseline in DynamoDB. Raise the factor or allowlist a principal to cut false alarms.
- **Alarms are momentary** — they evaluate a 1-minute window and flip back to OK. The detector **log**
  is the durable record; don't rely on "is it in ALARM right now."

### Network / edge (`waf.tf`, `api_gateway.tf`, `variables.tf`)
- **`internal_cidrs`** = the scenario's logical internal range (checked against the simulated
  `x_source_ip` by the Lambda). **`allowed_edge_cidrs`** = what can actually reach the API (WAF + API
  GW resource policy, real IP). Keep these separate — conflating them locks you out (we hit this).
- **WAF rate limit** — `var.rate_limit_per_5min`. The managed `AWSManagedRulesCommonRuleSet` can also
  block; if you see unexplained 403s, check WAF sampled requests (§3).
- **Warm-up** — give a fresh deploy ~2 minutes before hammering it (issue #5).

### Authorization (`corpus/manifest.json`)
- The clearance model is data, not code: edit `users[].max_clearance` and document `classification`.
  This is the lab stand-in for real identity claims; see `docs/architecture.md` for the production
  path (Cognito/JWT, Verified Permissions, metadata pre-filtering at the vector store).

### Operational
- **Secret recovery window** — `recovery_window_in_days = 0` (lab convenience). In production you want
  the default 7–30 days so a deletion is recoverable.

---

## 3. Diagnostic techniques (how the issues were actually found)

**Capture the guardrail trace** — the single most useful technique. Send the exact input through
`Converse` with `trace="enabled"` and inspect which policy fired, on input vs output:

```python
r = bedrock.converse(
    modelId=MODEL, messages=[{"role":"user","content":[{"text": msg}]}],
    system=[{"text": SYSTEM_PROMPT}],
    guardrailConfig={"guardrailIdentifier": GID, "guardrailVersion": "DRAFT", "trace": "enabled"})
print(r["stopReason"])                       # 'guardrail_intervened' if blocked
print(r["trace"]["guardrail"])               # inputAssessment / outputAssessments -> which policy + action
```

**Characterize non-determinism** — guardrail decisions on borderline content are probabilistic. Run
the same input 4–6× and count, rather than concluding from one shot (issue #2 fired 3 of 4).

**Correlate one request across layers** — `./demo/trace.sh`, or a CloudWatch Logs Insights query over
the API-Gateway + chat log groups filtered by `request_id` (see `docs/end-to-end-logging.md`).

**Compare detection counts across modes** — run an attack with `controls_enabled=true` then `false`
and diff the detector output; that's how the hardened-mode noise (issue #3) showed up.

**Inspect WAF blocks** — `aws wafv2 get-sampled-requests` (or the console "Sampled requests" tab) tells
you which rule blocked a request when you get an unexplained edge 403.

**Check Bedrock invocation logs** — `/aws/bedrock/<prefix>-invocations` records the model input/output
and guardrail assessment for every real call (enabled in `logging.tf`).

---

## 4. Reference documentation

**Amazon Bedrock Guardrails**
- Overview: https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html
- How it works (input vs output evaluation): https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-how.html
- Components / create: https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html
- Denied topics (the issue-#2 control): https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html
- Contextual grounding (the RAG upgrade): https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html
- API — CreateGuardrail: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateGuardrail.html

**Bedrock models**
- Cross-region inference profiles (why the model id is `us.anthropic...`): https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html
- Model invocation logging: https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html

**AWS WAF**
- Rate-based rule statement: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
- Managed rule groups list: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
- Testing / sampled requests: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html

**Secrets Manager**
- Delete / recovery window: https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_delete-restore-secret.html

**CloudWatch Logs**
- Logs Insights query syntax: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
- Subscription filters (logs → detector): https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html

**Frameworks** (the lab's mappings: `docs/owasp-mapping.md`, `docs/atlas-mapping.md`)
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org
