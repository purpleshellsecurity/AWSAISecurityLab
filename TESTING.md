# Testing & Validation Runbook

Run this top to bottom to validate the whole solution and understand what each part does. Every test
states **what it proves**, so by the end you've seen every control engage and know why it's there.

Run all commands from the repo root. A results table to fill in is at the bottom.

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
./scripts/preflight.sh                     # all green; submit the Bedrock form if it flags it
terraform -chdir=terraform init            # first time only
terraform -chdir=terraform apply           # review the plan, type "yes"
```

| # | Run | Expect |
|---|---|---|
| P1 | (after apply) `terraform -chdir=terraform output api_invoke_url` | a `https://...execute-api...` URL |
| P2 | `./scripts/preflight.sh` | `Lab is DEPLOYED` + `Bedrock model reachable` |
| P3 | `./demo/replay.py --scenario demo/scenarios/01_baseline_normal.json` | every line `200 returned=[...]`, no blocks |

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

### T3 — Network / identity (service account from external IP) · OWASP LLM06 · ATLAS T0012
- **Run:** `./demo/replay.py --scenario demo/scenarios/04_account_compromise.json`
- **Expect:** the `198.51.100.23` request returns `403 network-blocked`.
- **Verify deeper:** `api_access` log record shows `internal_source: false`, `http_status: 403`,
  `reason: "non_internal_source"`.
- **Proves:** a stolen credential used from outside the trusted range never reaches the app.

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

After the Phase 2 runs, wait ~30–60s for the log subscription to reach the detector, then:

```bash
./demo/show_detections.sh
```

| # | Detection | Triggered by | Expect in output |
|---|---|---|---|
| X1 | `service-account-external-source` (High) | T3 | a `detection` record for `enso-rag-svc` @ `198.51.100.23` |
| X2 | `token-volume-deviation` (Medium) | T3 (the 120k-token burst) | a `detection` record, `tokens_used` ≫ `baseline` |
| X3 | `indirect-injection` (High) | T6 | a `detection` record for the poisoned doc |

Also check **CloudWatch → Alarms**: the matching alarms move to **In alarm**. Note alarms are
*momentary* — they evaluate a 1-minute window and flip back to **OK** once the attack stops, so you
may not see all four in ALARM at the same instant. The detector **log** (`show_detections.sh`) is the
reliable record of what fired.

**Proves:** detection is decoupled from enforcement — the system not only blocks attacks, it *notices*
them and raises an alert a human can act on.

> The fourth detection, `sensitive-retrieval-anomaly`, fires only when a sensitive doc **actually
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
| T3 | external-source request blocked at the network | ☐ |
| T4 | guardrail blocks jailbreaks | ☐ |
| T5 | system-prompt extraction blocked | ☐ |
| T6 | poisoned document quarantined (injection scan) | ☐ |
| X1–X3 | detections fire + alarms trip | ☐ |
| Phase 4 | one request traced across all layers | ☐ |
| N1–N2 | controls off → attack succeeds + leak detected | ☐ |
| Phase 6 | full teardown, no cost | ☐ |

When every box is checked, you've exercised every control, both with and without enforcement, and
seen the detections and correlated logs — i.e. you've validated the whole solution end to end.
