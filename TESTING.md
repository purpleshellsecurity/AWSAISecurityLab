# Testing & Validation Runbook

Run this top to bottom to validate the whole solution and understand what each part does. Every test
states **what it proves**, so by the end you've seen every control engage and know why it's there.

Run all commands from the repo root. A results table to fill in is at the bottom.

## Before manual E2E testing

Static checks in Phase 0 are local source evidence only. Phases 1–6 are a **bounded manual E2E
path** that creates, exercises, and destroys AWS resources; run them only after the account owner
approves the deployment and test scope. Use a dedicated lab account or other explicitly authorized
disposable environment. Never use controls-off mode to test a shared system or real data.

For a same-account isolated deployment, use `scripts/lab.py` with a new lowercase, hyphenated
identifier. It derives an isolated prefix/environment, keeps state in the ignored
`.lab-state/<id>/terraform.tfstate` path, always disables account/Region singleton management, and
does not add an alarm-email subscription. `plan` and `up` require an explicit, non-wildcard IPv4
`--allowed-edge-cidr`; obtain an authorized test source CIDR from the responsible network operator
(or use the approved public workstation address as a `/32`). This is a deliberate live-access
decision: the runner never looks up or automatically permits the caller's IP. Do not set
`manage_account_region_singletons=true` in a shared account.

| Observe | Minimum evidence | Does not prove |
|---|---|---|
| Control path | replay result plus request-correlated `api_access`, `chat`, and `retrieval` logs | Detector execution or notification delivery |
| Detector finding | matching `detection` record for the same `request_id` | Metric, alarm, or SNS recipient delivery |
| Alerting path | custom-metric activity, alarm-history transition, and separately verified subscription/recipient evidence | A release decision or general production readiness |

Record the authorized environment, deployed commit, request IDs, time window, and evaluator
decision. Mark missing or ambiguous evidence **INCONCLUSIVE**, not passed. For detector-specific
predicate and delivery limits, use [`docs/soc-detection-validation.md`](docs/soc-detection-validation.md).

**Legend — how to read `replay.py` output:**

| In the output | Means |
|---|---|
| `200` | request reached the app and returned a response |
| `403 network-blocked` | rejected at the network/identity checkpoint (external source) |
| `GUARDRAIL` | the Bedrock guardrail intervened on the prompt/response |
| `BLOCKED@RETRIEVAL=[...]` | a document was refused (authorization or injection scan) |
| `returned=[...]` | a document was used to answer |

**Legend — the `action` field in the logs (the real signal):**
`retrieved` = allowed · `blocked_unauthorized` = authz refused it · `quarantined_injection` = scanner
caught a poisoned doc · `leaked_unauthorized` = controls off, a doc escaped.

> Tests marked **🤖 needs Bedrock** require the Anthropic use-case form submitted (the guardrail/model
> tests). Everything else works without it.

---

## Phase 0 — Static checks (no deploy, no cost)

| # | Run | Expect |
|---|---|---|
| S1 | `terraform -chdir=terraform fmt -check -recursive` | no output (formatting clean) |
| S2 | `terraform -chdir=terraform init -backend=false && terraform -chdir=terraform validate` | `Success! The configuration is valid.` |
| S3 | `python3 -m py_compile src/chat/handler.py src/detector/handler.py demo/replay.py` | no output (compiles) |
| S4 | `python3 -c "import json,glob;[json.load(open(f)) for f in glob.glob('demo/scenarios/*.json')+['corpus/manifest.json']];print('ok')"` | `ok` |

**Proves:** the IaC and code are syntactically sound before you spend a cent. (CI runs these on every push.)

---

## Phase 1 — Deploy & smoke

```bash
python3 scripts/lab.py plan sandbox-20261010 --allowed-edge-cidr 203.0.113.5/32  # preflight + reviewed saved local plan
python3 scripts/lab.py up sandbox-20261010 --allowed-edge-cidr 203.0.113.5/32    # apply that isolated local plan
```

For an isolated same-account lab, review the generated plan before applying it:

```bash
python3 scripts/lab.py plan sandbox-20261010 --allowed-edge-cidr 203.0.113.5/32
python3 scripts/lab.py up sandbox-20261010 --allowed-edge-cidr 203.0.113.5/32
python3 scripts/lab.py verify sandbox-20261010
# Only when the lab is no longer needed:
python3 scripts/lab.py down sandbox-20261010 --confirm sandbox-20261010
```

`down` preserves `.lab-state/<id>/terraform.tfstate` if Terraform destroy fails, so the same state
can be used for investigation or a later retry. The runner rejects reserved/default identifiers and
never uses `terraform/terraform.tfstate`.

| # | Run | Expect |
|---|---|---|
| P1 | (after apply) `terraform -chdir=terraform output api_invoke_url` | a `https://...execute-api...` URL |
| P2 | `./scripts/preflight.sh` | `Lab is DEPLOYED` + `Bedrock model reachable` |
| P3 | `./demo/replay.py --scenario demo/scenarios/01_baseline_normal.json` | every line `200 returned=[...]`, no blocks |

**Machine-readable HTTP evidence:** `replay.py --assert-expected` checks each scenario's mode-specific `expected_status_hardened` / `expected_status_baseline` field and exits nonzero for a missing or mismatched status. `--results-json artifacts/name.json` stores status, request ID, guardrail action, and blocked/returned document identifiers without storing prompt text or credentials. Store test evidence securely and do not commit it. HTTP assertions alone do not prove retrieval authorization, detector execution, or notification delivery; those require independent correlated logs and AWS observations.

**Proves:** the stack deploys cleanly and a legitimate user gets normal answers. This is your control
group — everything after this is "does the system stop the *bad* stuff while still allowing this?"

---

## Phase 2 — Control tests (hardened mode, `controls_enabled=true`)

### T1 — Retrieval-layer authorization · OWASP LLM02 · ATLAS T0057
- **Run:** `./demo/replay.py --scenario demo/scenarios/03_data_exfiltration.json`
- **Expect:** the Restricted/Confidential docs show `BLOCKED@RETRIEVAL`; `documents_returned` empty for them.
- **Verify deeper:** CloudWatch → `/aws/lambda/ai-rag-lab-chat` → `retrieval` records show
  `action: "blocked_unauthorized"` with the `retrieval_score` present.
- **Proves:** an under-cleared user is refused the document **before its content is read** — the fix
  for the incident's "blocked *after* retrieval."

### T2 — Prompt injection · 🤖 needs Bedrock · OWASP LLM01 · ATLAS T0051
- **Run:** `./demo/replay.py --scenario demo/scenarios/02_prompt_injection.json`
- **Expect:** `GUARDRAIL` on the injection attempts; `guardrail_action: "intervened"`.
- **Verify deeper:** the `chat` log record shows `guardrail_action: "intervened"`, `risk_label: "high"`.
- **Proves:** manipulative prompts are caught at the model layer; the assistant doesn't follow them.

### T3 — Authentication boundary (hardened mode) · OWASP LLM06 · ATLAS T0012
- **Separate real network-perimeter test:** restrict `allowed_edge_cidrs` to an approved test source, invoke from a different real source IP, and verify the WAF/API Gateway deny and edge access logs. The request-body `x_source_ip` field is **only a simulation** and cannot prove actual network-origin enforcement.

### T4 — Jailbreak · 🤖 needs Bedrock · OWASP LLM01 · ATLAS T0054
- **Run:** `./demo/replay.py --scenario demo/scenarios/05_jailbreak.json`
- **Expect:** `GUARDRAIL` on each persona/roleplay attempt.
- **Proves:** safety-override framing ("you are DAN", "maintenance mode") is filtered, not obeyed.

### T5 — System-prompt extraction · OWASP LLM07 · ATLAS T0056
- **Run:** `./demo/replay.py --scenario demo/scenarios/06_system_prompt_extraction.json`
- **Expect:** the system-prompt document shows `BLOCKED@RETRIEVAL`; recon prompts may also hit `GUARDRAIL`.
- **Proves:** the system prompt isn't a trivially extractable secret; it's classified and access-controlled.

### T6 — Indirect injection / RAG poisoning · OWASP LLM01 · ATLAS T0051.001, T0070
- **Run:** `./demo/replay.py --scenario demo/scenarios/07_indirect_injection.json`
- **Expect:** the poisoned vendor doc shows `BLOCKED@RETRIEVAL` even though the user is *authorized* for it.
- **Verify deeper:** `retrieval` record shows `action: "quarantined_injection"`, `injection_in_document: true`.
- **Proves:** authorization alone doesn't stop injection — a second control (scan retrieved content,
  quarantine hidden instructions) is needed. The benign user was allowed the file; the *content* was stripped.

---

## Phase 3 — Detection tests

After the Phase 2 runs, allow time for log delivery, then:

```bash
./demo/show_detections.sh
```

| # | Detection | Triggered by | Expect in output |
|---|---|---|---|
| X1 | `token-volume-deviation` (Medium) | Baseline-only replay with `--no-auth` (120k-token burst) | a `detection` record, `tokens_used` ≫ `baseline`; **not expected from hardened T3** |
| X2 | `indirect-injection` (High) | T6 | a `detection` record for the poisoned doc |

Also check **CloudWatch → Alarms**: the matching alarms move to **In alarm**. Note alarms are
*momentary* — they evaluate a 1-minute window and flip back to **OK** once the attack stops, so you
may not see all three in ALARM at the same instant. The detector **log** (`show_detections.sh`) is the
reliable record of what fired.

**Proves only when the matching detector logs are observed:** the detector recognized those log records. A finding log does **not** prove CloudWatch metric delivery, SNS notification, or receipt by a human. Run baseline-only token tests in a dedicated lab account; restore hardened mode afterward. Do not treat a hardened-mode 401 as a successful X1/X2 result.

> The sensitive-retrieval detection, `sensitive-retrieval-anomaly`, fires only when a sensitive doc **actually
> reaches the model/user** — either it **leaked** (`action: leaked_unauthorized`, seen in Phase 5) or
> it was **retrieved by an authorized user during a flagged (high-risk) session**. It deliberately
> does **not** fire on `blocked_unauthorized` or `quarantined_injection` docs — those are attempts the
> controls already stopped, so alerting on them would just be noise. So in hardened mode (Phase 2),
> where the restricted docs are blocked, you should see few or none of these.

---

## Phase 4 — End-to-end correlation

```bash
./demo/trace.sh
```

- **Expect:** one request reconstructed across layers — an `api_access`, a `chat`, and a `retrieval`
  record, all sharing one `request_id`.
- **Proves:** the missing-correlation gap is closed — you can trace *who*, *from where*, *what prompt*,
  and *which document* for a single request, end to end.

---

## Phase 5 — Negative testing (the "before": prove the controls are load-bearing)

Flip the controls off and re-run the attacks — they should now **succeed**:

```bash
terraform -chdir=terraform apply -var=controls_enabled=false    # review plan, type yes
./demo/replay.py --scenario demo/scenarios/03_data_exfiltration.json
```

| # | Run | Expect (controls OFF) |
|---|---|---|
| N1 | the data-exfiltration scenario above | Restricted docs now `returned=[...]` (they **leak**) |
| N2 | wait ~45s, then `./demo/show_detections.sh` | `sensitive-retrieval-anomaly` now fires (the leak is detected) |

**Restore the hardened build when done:**
```bash
terraform -chdir=terraform apply -var=controls_enabled=true
```

**Proves:** the difference between "secure" and "breached" is exactly these controls — same attack,
one variable, opposite outcome. This is the strongest evidence that the controls are doing real work.

---

## Phase 6 — Teardown

```bash
terraform -chdir=terraform destroy        # type yes
./scripts/preflight.sh                    # should now report "Lab is NOT deployed yet"
```

**Proves:** the lab is fully reversible and stops billing. (Verify in the console that the guardrail,
Lambdas, and API Gateway are gone — or trust the `Destroy complete!` count.)

---

## Results

| Test | What it proves | Pass? |
|---|---|---|
| S1–S4 | IaC + code are valid | ☐ |
| P1–P3 | deploys; normal user allowed | ☐ |
| T1 | retrieval-layer authorization blocks restricted docs | ☐ |
| T2 | guardrail blocks prompt injection | ☐ |
| T4 | guardrail blocks jailbreaks | ☐ |
| T5 | system-prompt extraction blocked | ☐ |
| T6 | poisoned document quarantined (injection scan) | ☐ |
| X1–X3 | distinct detector logs confirmed in appropriate modes; delivery independently checked | ☐ |
| Phase 4 | one request traced across all layers | ☐ |
| N1–N2 | controls off → attack succeeds + leak detected | ☐ |
| Phase 6 | full teardown, no cost | ☐ |

Completed boxes document only the observations listed for those tests. A manual E2E run does not
replace separate evidence for notification delivery, real network-origin enforcement, deployment
approval, or production/release readiness.
