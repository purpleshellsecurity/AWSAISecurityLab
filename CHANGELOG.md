# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow semantic versioning.

## [Unreleased]

### Added
- **GRC layer (`docs/compliance/`).** A governance layer above the existing controls: a
  risk register (mitigate/accept decisions with role-based owners), a remediation register
  tracking four closed and three open governance gaps, a NIST AI RMF and EU AI Act
  framework map (limited-risk tier; ISO 42001 left out of scope), a one-page AI use policy,
  and an oversight and incident-response runbook. Linked from the README.
- **EU AI Act Art. 50 disclosure.** The chat handler now returns `AI_NOTICE` on every
  answer, telling users they are interacting with an AI. This meets the transparency
  obligation that actually applies to a limited-risk system.
- **OAuth2 / JWT authentication (Amazon Cognito).** Identity and clearance can no longer be
  self-asserted in the request body — this closes the lab's one acknowledged weakness and turns the
  retrieval-layer check into genuine claims-based access control.
  - A Cognito user pool (`cognito.tf`) issues signed JWTs; API Gateway's `COGNITO_USER_POOLS`
    authorizer validates them at the edge (hardened mode).
  - The chat handler's new `resolve_identity` takes identity from the verified `cognito:username`
    claim and clearance from a `custom:clearance` claim the app client cannot write.
  - Seeded demo users mirror the corpus manifest; `demo/replay.py` logs them in automatically, and
    `demo/get_token.sh` fetches a token by hand for inspection.
  - The `controls_enabled` toggle gates whether the API method enforces the token, so the vulnerable
    baseline (self-asserted identity) still replays.
  - New tests cover claim precedence over the body, the anti-escalation guarantee, and unknown-claim
    fallback. Docs: controls-matrix row 11, owasp-mapping LLM06, TUTORIAL §3/§7/§9.
- Unit tests (`tests/`, 43 cases) for both Lambdas — clearance lattice, network checkpoint,
  retrieval scoring, the injection scanner (verified against the real corpus), all four detections,
  the EWMA baseline math, and batch/delivery failure isolation — wired into CI as a `pytest` job.
- WAF request logging (`aws-waf-logs-*` log group + logging configuration): the outermost hop now
  produces a full per-request log like every other layer, not just metrics and samples.
- CloudTrail **management events** (the trail previously declared only a Bedrock Data selector, so
  it recorded no control-plane activity at all), plus CMK encryption, versioning, and a 90-day
  lifecycle on the trail bucket.
- A dead-man-switch alarm on the detector Lambda's `Errors` metric — a dead detector previously
  looked identical to a quiet, healthy system.
- A hard daily quota (2,000 req/day) on the API usage plan: throttling bounds the rate, the quota
  bounds the total — the control that actually caps denial-of-wallet spend from a leaked key.
- Guardrail trace logging: when the guardrail intervenes, the chat Lambda now emits a
  `guardrail_trace` record showing *which* policy fired (the tuning signal `docs/tuning.md` relies on).
- Detection identity lists (`service_accounts`, `high_volume_allowlist`) promoted to Terraform
  variables; the metric namespace is now a single shared local consumed by IAM, the Lambda env, and
  the alarms.

- Repository hygiene: `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, this changelog,
  `.editorconfig`, `.gitattributes`, pre-commit hooks, GitHub CI (Terraform + Python + JSON checks),
  and issue/PR templates.
- `docs/owasp-mapping.md` — controls mapped to OWASP LLM Top 10 (2025) prevention strategies.
- `docs/atlas-mapping.md` and ATLAS-tagged attack scenarios (`demo/scenarios/05`–`07`).
- Indirect prompt-injection / RAG poisoning defense: a poisoned corpus document, a retrieval-time
  injection scanner (`scan_for_injection`), and an `indirect-injection` detection.
- Idiot-proofing: `scripts/preflight.sh` (a prerequisite/deploy-status check), friendly "not
  deployed yet" errors in the demo scripts, and a `TUTORIAL.md` walkthrough.
- End-to-end correlated logging (`api_access`/`chat`/`retrieval` records sharing one `request_id`)
  and the `demo/trace.sh` request tracer.

### Changed
- **KMS key policy now grants `cloudwatch.amazonaws.com`** — without it, every alarm → SNS delivery
  failed silently because CloudWatch alarms cannot publish to a CMK-encrypted topic through IAM
  alone. Also added confused-deputy `SourceAccount`/encryption-context conditions to the SNS and
  new CloudTrail statements.
- Guardrail versions republish automatically on config change (`replace_triggered_by`): tuning
  `guardrail_prompt_attack_strength` previously updated only the DRAFT while the Lambda stayed
  pinned to the old published version.
- Provider constraints pinned to majors (`aws ~> 6.0` — required, since `main.tf` uses the v6-only
  `data.aws_region.current.region`), Terraform CLI pinned in CI, and `.terraform.lock.hcl` is now
  committed (it was gitignored, defeating the supply-chain checksums `versions.tf` describes).
- Corpus uploads now `depends_on` the bucket SSE/public-access-block config, closing a first-apply
  race where objects could land under SSE-S3 instead of the CMK; superseded corpus versions expire
  after 30 days.
- Removed the unused `secretsmanager:GetSecretValue` grant and `SERVICE_SECRET_ID` env var from the
  chat role (the handler never reads the secret — an unused standing grant on the internet-facing
  role is the LLM06 pattern the lab teaches against), and the unused `INTERNAL_CIDRS` env var from
  the detector.
- Both Lambdas fail closed and visibly: explicit botocore timeouts/retries, a structured 503 (with
  log line) when the corpus manifest is unreachable, per-document `read_error` handling, and
  per-record/per-delivery error isolation in the detector so a throttled `sns.publish` can't fail
  the batch and duplicate every alert on redelivery.
- `terraform.tfvars.example` model example updated (it pointed at legacy Claude 3 Haiku as a bare
  model id — copying it verbatim broke the deployment three ways); detection numbering unified
  across code and docs (1 service-account, 2 sensitive-retrieval, 3 indirect-injection, 4 token
  deviation).
- README states the honest idle cost (~$10–15/month baseline) and documents the shared-account
  blast radius of the two per-account singletons on `destroy`.
- Model is the Claude Haiku 4.5 cross-region inference profile (Claude 3 Haiku is now Legacy).
- Genericized the scenario (removed the original organization name) so the lab stands alone.
- Decoupled edge reachability (`allowed_edge_cidrs`) from the scenario's logical internal range
  (`internal_cidrs`).

### Fixed
- `demo/trace.sh`: the default request body was mangled by shell quoting (inner `"` closed the outer
  string), so it sent a bad request and 403'd; the 15s log wait was also too short. Now uses a
  single-quoted default body and retries while KMS-encrypted logs land.
- `sensitive-retrieval-anomaly` detection no longer fires on `blocked_unauthorized` /
  `quarantined_injection` docs (attempts the controls already stopped) — only on docs that actually
  reached the model/user. Removes the hardened-mode alert noise.
- Guardrail false positive on benign answers fixed: the `DocumentEnumeration` denied topic (evaluated
  on input *and* output) was intermittently firing because the model cited source file names in its
  answers. The system prompt now instructs the model not to mention file names, so the output filter
  has nothing to match — verified 0/6 trips (was ~3/4). Also lowered the prompt-attack filter from
  `HIGH` to `MEDIUM` (new `var.guardrail_prompt_attack_strength`) as general FP hygiene.
- `aws_secretsmanager_secret` now sets `recovery_window_in_days = 0` so destroy hard-deletes it and
  the lab can be redeployed without a name collision.

### Removed
- The `Makefile` — the lab now uses native Terraform and script commands directly (more transparent,
  nothing hidden behind a wrapper). See the README for the exact commands.

## [0.1.0] — initial lab

### Added
- Deployable Terraform lab reproducing a RAG-assistant breach with layered controls (network,
  retrieval-layer authorization, Bedrock Guardrail, least-privilege IAM, KMS, WAF, CloudTrail),
  three detections, and attack-replay scripts.
