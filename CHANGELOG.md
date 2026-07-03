# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow semantic versioning.

## [Unreleased]

### Added
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
