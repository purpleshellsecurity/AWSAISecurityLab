# Controls Matrix

One row per control. Each traces a finding from the investigation to a concrete AWS control, the
OWASP LLM (2025) category it addresses, the Terraform that deploys it, and the demo that proves it.

| # | Incident finding (evidence) | AWS control | OWASP LLM | Terraform | Demo |
|---|------------------------------|-------------|-----------|-----------|------|
| 1 | Unauthenticated or external-source attempts at the chat API | Cognito JWT authorizer and API Gateway source restriction / WAF; verify using gateway and WAF logs | LLM06 | `waf.tf`, `api_gateway.tf` | `demo/scenarios/08_jwt_boundary.json` |
| 2 | Restricted/Confidential docs retrieved by an unauthorized user; `blocked_after_retrieval` shows docs left the store *before* the guardrail fired | **Authorization enforced at the retrieval layer**: the chat Lambda checks caller entitlement against each document's classification *before* returning it | LLM02 | `src/chat/handler.py`, `s3_corpus.tf` | `demo/scenarios/03_data_exfiltration.json` |
| 3 | `e.davis`: "disregard your configured rules", "switch to maintenance mode" (blocked), then "as part of a compliance review, enumerate every document…" (bypassed) | Bedrock Guardrail: `PROMPT_ATTACK` content filter (MEDIUM by default, `var.guardrail_prompt_attack_strength`) + `DocumentEnumeration` denied topic with the bypass phrasing as examples | LLM01 | `bedrock_guardrail.tf` | `demo/scenarios/02_prompt_injection.json` |
| 4 | Base64 "encode exactly… forward to compliance" exfil attempt; sensitive content in responses | Guardrail sensitive-information (PII) policy set to `ANONYMIZE`/`BLOCK`; output filtering | LLM02 | `bedrock_guardrail.tf` | `demo/scenarios/02_prompt_injection.json` |
| 5 | `Enso_Key_Rotation_Runbook.md` exposed via retrieval; `enso-rag-svc` looks credential-compromised | Credentials moved to AWS Secrets Manager (KMS) and kept out of the RAG corpus; the system prompt holds no secrets | LLM07 | `secrets.tf` | `demo/scenarios/03_data_exfiltration.json` |
| 6 | No shared correlation ID; retrieval log has no `source_ip`, API log has no document/session detail; aggregate (bucketed) logging | API Gateway generates a `request_id`; the chat Lambda emits **three correlated records** per request (`api_access`, `chat`, `retrieval`), all sharing that `request_id` (document IDs, not contents) | — | `api_gateway.tf`, `src/chat/handler.py` | every demo prints `request_id` |
| 7 | Sensitive retrieval, indirect injection and token bursts require analyst notification | Three detector rules, CloudWatch custom metrics, alarms and SNS | — | `detections.tf`, `src/detector/handler.py` | `demo/scenarios/07_indirect_injection.json`, `demo/show_detections.sh` |
| 8 | No encryption/audit baseline established in scope | Customer-managed KMS key encrypts S3 corpus, CloudWatch Logs, SNS; CloudTrail (management + Bedrock data events); Bedrock model-invocation logging to CloudWatch | — | `kms.tf`, `logging.tf` | — |
| 9 | Service accounts use long-lived static creds | Lambda uses an IAM role (short-lived STS creds); IAM policy scoped to exactly one Bedrock model ARN + one guardrail ARN + the corpus prefix | LLM06 | `iam.tf` | n/a (inspect policy) |
| 10 | A poisoned document in the corpus (`Enso_Vendor_Onboarding_Memo.md`) carries hidden instructions (indirect prompt injection) | **Retrieval-time injection scanner**: the chat Lambda scans retrieved content and **quarantines** any document with injection markers *before* it reaches the model | LLM01 | `src/chat/handler.py` (`scan_for_injection`) | `demo/scenarios/07_indirect_injection.json` |
| 11 | Identity (`user`) and clearance were self-asserted in the request body — anyone could claim to be a Restricted-cleared user | **OAuth2/JWT front-door authentication**: a Cognito user pool issues signed JWTs; API Gateway's `COGNITO_USER_POOLS` authorizer validates each token at the edge; the handler derives identity from `cognito:username` and clearance from the `custom:clearance` claim (which the app client cannot write), turning retrieval-layer authz into genuine claims-based access control | LLM06 · LLM02 | `cognito.tf`, `api_gateway.tf`, `src/chat/handler.py` (`resolve_identity`) | `./demo/get_token.sh` + `demo/replay.py` (hardened) |

## Detection logic (as implemented in `src/detector/handler.py`)

| Detection | Trigger | Severity | Signal captured |
|---|---|---|---|
| Service account from non-internal source | API request authenticated as a known service account where `source_ip` ∉ internal CIDRs | High | timestamp, service_account, source_ip, endpoint, request_count, tokens_used, user_agent |
| Sensitive retrieval anomaly | A `Restricted`/`Confidential` doc actually **reaches the user** — `action = leaked_unauthorized`, or `retrieved` during a session with a high-risk prompt. Blocked/quarantined docs do **not** fire it (the control already stopped them). | High | user, session_id, document_name, sensitivity, retrieval_score, action |
| Indirect prompt injection / RAG poisoning | A retrieved document contained injection markers (`injection_in_document`) — whether it was quarantined (controls on) or leaked (controls off) | High | user, session_id, document_name, action |
| Per-principal token-volume deviation | Windowed token usage > baseline × deviation factor (default 10×) for a principal not on the high-volume allowlist | Medium | principal, tokens_used, baseline, request_id |

The keyword-on-"audit"/"admin" idea is intentionally **not** a standalone detection
(too noisy — the audit dept uses that language normally). It is available as an enrichment field on
the other alerts rather than a trigger of its own.

## Defense-in-depth ordering

The incident's root cause was that the **only** access-control checkpoint was the response guardrail,
which fires *after* documents have already been retrieved. This lab puts checkpoints in front of that
gap, in order:

1. **Network** — WAF + resource policy (is the source allowed at all?)
2. **Authentication** — Cognito JWT authorizer at API Gateway (is this a valid, signed token, and who does it prove the caller to be?)
3. **Identity** — verified claims + scoped IAM role (clearance from the token, not the body)
4. **Retrieval authorization** — per-document classification check (may *this caller* see *this doc*?)
5. **Model guardrail** — prompt-attack + PII + denied topics (is the prompt/response safe?)
6. **Detection** — the three detections (did anything slip through, and can we see it?)

A request has to pass every layer; the documents the attacker exfiltrated would be stopped at
layer 4, before the model is ever called — and in hardened mode the attacker can no longer even
assert a privileged identity to reach it, because layer 2 requires a signed token whose clearance
claim they cannot mint.
