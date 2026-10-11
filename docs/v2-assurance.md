# v2.0.0 engineering assurance register (DRAFT)

This register applies the [AI Engineering Standard](https://github.com/purpleshellsecurity/EngineeringStandard) to the AWS AI Security Lab. It does not certify the system. **Release disposition: BLOCKED** until applicable critical controls are independently verified.

## Scope and risk

- Hardened RAG assistant: **provisional AES R2** because answers depend on classified documents, identity claims and security controls.
- Controls-off mode: intentionally vulnerable **disposable lab demonstration only**. Never expose it as a production service or run it in a shared account without safeguards.
- Critical invariants: document classification is recognized; a verified caller is authorized before bytes enter model context; invalid identity/clearance never increases access; detected findings and delivered notifications have separate evidence.
- This lab uses a **simulated** `x_source_ip` body field to reproduce attack narratives. Real network allow/deny testing must use observed connection IP and WAF/API Gateway access logs. They are separate controls.

## Current evidence matrix

| Control / requirement | Implementation or test | Evidence status | Remaining verification |
|---|---|---|---|
| AES-06 scope/risk | This register; app architecture and governance docs | Documented, provisional | Approve risk owner and prohibited outcomes |
| AES-08 control ownership | Cognito edge, Lambda retrieval authorization, Bedrock Guardrails, detection Lambda | Implemented | Show observed allow/deny outcomes per boundary |
| AES-09 trust boundaries | `docs/architecture.md`, `terraform/api_gateway.tf` | Documented | Prove real-IP enforcement independently of simulation |
| AES-11 outcome states | Handler exposes 403/503 and detector delivery errors | Partially implemented | Distinguish blocked, cannot determine, delivery failed in machine-readable evidence |
| Retrieval classification fail closed | `src/chat/handler.py` + `tests/test_chat_handler.py` | Code/tests added; CI pending | Confirm unit tests and deployed negative test |
| Cognito authenticated claims | `terraform/api_gateway.tf`, `src/chat/handler.py`, `demo/scenarios/08_jwt_boundary.json`, `demo/verify_jwt_gateway.py` | Live JWT replay and independent gateway verifier: **4/4 PASS** (missing 401, malformed 401, tampered 403, valid 200; 2026-10-09). This establishes differential pre-integration rejection, not direct visibility into signature math. | Genuine expiry and invalid-clearance live tests remain open |
| Token-volume deviation | `src/detector/handler.py`, `artifacts/soc-token-v2.json` (local operator artifact) | **Live evidence observed**: authenticated normal 200/250, spike 120000, request-correlated one Medium finding, metric window activity, SNS email receipt confirmed by operator | Attach sanitized evidence; window metric not strictly request-attributed; verify alarm state direction separately |
| Indirect injection | `demo/scenarios/07_indirect_injection.json` | **Live evidence observed**: two quarantined retrieved documents, two matching High findings, metric activity and SNS messages confirmed by operator | Retain sanitized evidence and separate alarm transition evidence |
| Bedrock model and Guardrail | Converse invocation plus `02_prompt_injection.json` and raw CloudWatch traces | Model access restored; benign model/Guardrail path succeeded and 3/3 attack cases produced Guardrail interventions with matched policies. | Verify response disclosures; retain evidence and test negative cases |
| SIEM-ready Guardrail security event | `src/chat/handler.py`, `docs/architecture.md` | Deployed to Dev; correlated retrieval records observed with input/output Guardrail stage. No SIEM destination deployed or verified. | Independently validate security-event schema and downstream SIEM integration if in scope |
| Sensitive retrieval anomaly | `src/detector/handler.py`; `demo/scenarios/11_sensitive_retrieval_hardened.json` | **LIVE PASS** for benign negative and input-side high-risk positive on hardened AWS; correlated finding, CloudWatch metric, alarm transition and SNS email receipt confirmed (2026-10-09) | Retain operator evidence; metric sum spans a time window, not one request; output nondisclosure and other release gates remain separate |\n| AES-36 release gate | This register | Blocked | Attach CI, AWS integration and approved exception evidence |
| AES-38 versioned regression | Git commit and scenario JSON | Partial | Pin model, guardrail, scenario dataset and Terraform deployment versions in release record |
| AES-40 limitations | This document | Documented | Publish observed gaps with v2 release notes |

## Test execution contract

For each scenario, record: scenario ID, environment/mode, deployed commit, model/guardrail versions, authoritative inputs, expected result at **each** enforcement boundary, actual HTTP outcome, correlated log evidence, detector finding, alarm/notification delivery, test time and evaluator decision.

Allowed decisions: **pass** (observable expectation verified), **fail** (contradiction), **inconclusive** (missing/ambiguous evidence), **not run**. A blocked HTTP request alone does **not** prove its intended detector fired. Source-IP simulation alone does **not** prove real perimeter enforcement. A detection log alone does **not** prove SNS receipt.

## Required gates before squash/PROD v2.0.0

1. All CI checks green on Dev PR; unit and scenario contract tests verified.
2. Deployed hardened-mode smoke and negative tests with request IDs and retained evidence.
3. Isolated controls-off demonstration in a dedicated AWS lab account, then confirmed restoration of hardened configuration.
4. Independent verification of three detector conditions, alarm/notification delivery and duplicate/retry behavior or recorded explicit exceptions.
5. Terraform plan, cost/teardown checks, permissions and real-IP boundary checks reviewed.
6. Engineering Standard assurance matrix completed with owner, requirement evidence, gaps and release approval. No unsupported claims promoted to verified.
7. Squash merge into PROD after review; create annotated `v2.0.0` tag/release only after the merged PROD commit has passed the release gate.

## Current decision

**BLOCKED / NOT RELEASED.** Hardened infrastructure has been deployed and the user supplied live evidence for retrieval authorization, indirect-injection detection and SNS/alarm delivery, and authentication HTTP outcomes. These are scoped observations, not blanket release approval. JWT gateway attribution has been verified 4/4 against live CloudWatch evidence; genuine expired-token and malformed-clearance tests remain open. Sensitive retrieval's scoped positive/negative detection and alert-delivery path is live verified; genuine token expiration, invalid-clearance tests, guardrail response nondisclosure and remaining release gates are open. See `demo/scenarios/README.md` for reproducible JWT attribution commands. Do not claim an AWS deploy or verifier pass based on repository CI alone.

## Scope note: retired detector

`service-account-external-source` is not part of the v2 detection pipeline because the hardened Cognito flow does not authenticate machine identities or populate trusted service-account identity claims. V2 retains the authentication and network prevention controls and focuses its active detection rules on sensitive retrieval, indirect injection, and token-volume deviation. This is a scope decision, not a claim that the legacy detector was validated.

## Section 2 — Security assurance closeout (2026-10-09)

No AWS changes are authorized by this document. The three supported analytics are sensitive-retrieval-anomaly, indirect-injection and token-volume-deviation. Retirement of service-account-external-source removes an unsupported downstream rule, **not** JWT or edge enforcement. PRs #2, #3, and #4 have been merged into Dev `main` (`78c5db136e553535bc465de2a0610ff15e5afdd2`). A targeted Terraform plan was applied in account `798489756599`: two Lambda updates and one retired alarm deletion, with Cognito/API Gateway updates excluded. This does not approve the outstanding full-plan drift.

| Test boundary | Evidence disposition | Exact closure criterion |
|---|---|---|
| Authenticated JWT: missing/malformed/tampered/valid | **PASS 4/4** live gateway and integration attribution, as reported earlier | Retain sanitized request IDs, timestamps, Gateway/CloudWatch verifier output |
| Genuine token expiry | **NOT RUN** | Correctly signed Cognito token allowed while unexpired, rejected after expiry; check gateway no-integration evidence, never paste token |
| Malformed / invalid clearance | **NOT RUN** | Signed identity with unsupported/invalid claim is denied or restricted; no restricted data/model-context exposure; don't alter live demo users blindly |
| Retrieval authorization | **Observed in earlier hardened tests** | Explicit under-cleared negative and authorized positive using same classified document, correlated retrieval action and document disposition |
| Guardrail and response nondisclosure | **PARTIAL** — interventions and matched policies observed; final response nondisclosure not independently reviewed | Compare response document IDs and sanitized returned content/disclosure signals for attack and negative control |
| Indirect injection detector → SNS | **PASS** at source→finding→metric activity→direct SNS inbox receipt | Preserve two request IDs, metric window and actual alarm history separately |
| Token deviation detector → SNS | **PASS** at source→finding→metric activity→direct SNS inbox receipt | Preserve normal-negative and 120000-token positive IDs; note simulate_tokens overrides logged usage, not model billable usage |
| Sensitive retrieval detector → SNS | **PASS** for scoped hardened AWS positive/negative and direct SNS notification (2026-10-09) | Benign `86a981c4-af05-438a-82b9-2c1aafae9295`: Restricted retrieval, `guardrail_stage=output`, `high_risk_prompt=false`, zero findings. Positive `cd45c034-bb44-47a8-92c4-9592473dcf52`: Restricted retrieval, `guardrail_stage=input`, `high_risk_prompt=true`, one High finding and matching SNS message received. CloudWatch metric sum=3 over 60 minutes (not request-attributed); alarm `OK → ALARM` at 2026-10-09 23:15:27 ET. No processing errors observed. |
| Detector retry/duplicate/delivery errors | **PARTIAL** unit-level isolation tests only | Prove behavior or record exception for CloudWatch subscription re-delivery, baseline idempotence, and alert deduplication; no claim of exactly-once delivery |
| Real perimeter restriction | **NOT VERIFIED** (simulated body IP does not count) | Independently test real edge source against WAF/API Gateway request logs from authorized addresses; avoid changing active allowlist during campaign |
| Terraform, IAM, teardown/cost | **PARTIAL** — targeted deploy confirmed; broader review pending | Targeted apply completed: 0 added, 2 Lambda updates, 1 retired alarm destroyed; both Lambdas `Active` / `Successful`. Full plan's 5 Cognito attribute updates and API Gateway policy rewrite were deliberately excluded and remain unreviewed; IAM, teardown and cost gates remain open. |

**Acceptance policy:** Do not use controls-off on the running hardened stack. Do not merge this assurance matrix as proof of AWS actions that were not observed. Keep v2 RELEASE BLOCKED until required gates are evidenced or explicitly accepted by owner with limitations.
