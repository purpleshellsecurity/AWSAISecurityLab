# AI / RAG Security Lab

[![CI](https://github.com/purpleshellsecurity/aws-ai-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/purpleshellsecurity/aws-ai-security-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-000000)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-c5203e)

> A deployable AWS lab that **reproduces a RAG-assistant breach and the controls that stop it** —
> built with Terraform, mapped to the OWASP LLM Top 10 and MITRE ATLAS, and validated end-to-end
> through source, unit, and explicitly authorized manual live testing.

![Architecture — request path and detection path](docs/architecture.svg)

---

## What this demonstrates

| Skill | Demonstrated by |
|---|---|
| **AI/LLM security** | prompt injection, RAG abuse, data exfiltration, system-prompt leakage ([OWASP LLM Top 10](docs/owasp-mapping.md)) |
| **Threat modeling** | every attack tagged to a [MITRE ATLAS](docs/atlas-mapping.md) technique |
| **Detection engineering** | 3 CloudWatch detections → alarms → SNS, over structured logs |
| **Secure AWS architecture** | retrieval-layer authz, least-privilege IAM, KMS, WAF, correlated logging (one `request_id` end to end) |
| **Infrastructure as code** | the whole stack in Terraform; one command up, one down |
| **Validation** | a [test runbook](TESTING.md) that deploys, attacks, and proves each control ([lessons](docs/tuning.md)) |

## Scope and evidence boundary

This is a **security learning lab**, not a production reference implementation or a release
certification. It demonstrates control placement and observable behavior for a small, intentionally
simplified RAG stack. In particular, keyword retrieval, regex injection scanning, request-body
`x_source_ip`, and `simulate_tokens` are lab affordances; they do not establish production retrieval
quality, trusted network attribution, or actual model-token consumption.

| Evidence available | What it establishes | What it does not establish |
|---|---|---|
| Source review and unit/scenario-contract tests | Intended local behavior and regression coverage | That AWS accepted a deployment or a control ran in a live request |
| Replay HTTP result and correlated CloudWatch logs | The observed request path and control/detector behavior for that request | Metric publication, alarm transition, or human notification receipt |
| Metric, alarm-history, and subscription/recipient evidence | The separately observed delivery stages | A broader production or release approval |

Any deployment or live test requires the account owner's prior approval and must use an authorized,
disposable lab environment. Do not use controls-off mode, real data, or a shared system to create
demonstration evidence. See the [testing runbook](TESTING.md) for the bounded manual E2E path and
[`docs/soc-detection-validation.md`](docs/soc-detection-validation.md) for detector evidence gates.

## How it works

**Client → WAF → API Gateway → chat Lambda → Bedrock**, every layer logged under one `request_id`.

In hardened mode:

- API Gateway's **Cognito JWT authorizer** validates a signed token at the edge.
- The Lambda derives identity and clearance from **verified claims**, not the request body.
- It **enforces access control before any document is read**, then applies a **Bedrock Guardrail** for content safety.
- A second **detector Lambda** turns the logs into alarms.

## What it defends against

Each attack maps to a control, a framework, and a replayable scenario (full detail in
[controls-matrix.md](docs/controls-matrix.md)):

| Attack | Control that stops it | OWASP · ATLAS | Scenario |
|---|---|---|---|
| Caller asserts a privileged identity in the request | **OAuth2/JWT auth** — Cognito authorizer; identity + clearance from verified claims, not the body | LLM06 · T0012 | hardened `replay.py` / `get_token.sh` |
| Under-cleared user pulls restricted docs | **authorization at the retrieval layer** | LLM02 · T0057 | `03_data_exfiltration` |
| Prompt injection / "list all documents" | Bedrock Guardrail (prompt-attack + denied topic) | LLM01 · T0051 | `02_prompt_injection` |
| Jailbreak / persona override | Bedrock Guardrail | LLM01 · T0054 | `05_jailbreak` |
| System-prompt extraction | retrieval authz + Guardrail | LLM07 · T0056 | `06_system_prompt_extraction` |
| Poisoned document (hidden instructions) | retrieval-time injection scanner + detection | LLM01 · T0051.001 | `07_indirect_injection` |

---

## Quickstart

**You'll need:**

- **AWS account** with the `aws` CLI configured
- **Terraform ≥ 1.5**
- **Bedrock access** — Anthropic models need a one-time use-case form; `./scripts/preflight.sh` tells you where to click
- Default region **`us-east-1`**

*Usage costs a few cents/day, and everything is torn down by one `destroy`. Note the always-on
baseline: the WAF web ACL, KMS key, and CloudTrail Bedrock data events bill roughly **$10–15/month
even at zero traffic** — destroy the lab when you're not using it.*

### 1. Deploy (only after approval)

```bash
python3 scripts/lab.py plan sandbox-20261010  # check AWS CLI/Terraform, then save a local plan
python3 scripts/lab.py up sandbox-20261010    # deploy after reviewing the saved plan
```

These commands create billable AWS resources. Approval and a reviewed Terraform plan are required
before running them; repository checks alone are not deployment evidence.

### Shared-account isolation

Every deployment should set a unique `name_prefix` and `environment_id`. The default configuration
does **not** manage API Gateway's account-level CloudWatch logging role or Bedrock's account-level
model-invocation logging configuration, so a prefixed lab cannot overwrite those shared settings.
Use the local lab runner for a separate, ignored local state directory per environment. It never
uses the legacy `terraform/terraform.tfstate`, always keeps
`manage_account_region_singletons=false`, and does not configure an alarm email subscription.

```bash
python3 scripts/lab.py plan sandbox-20261010  # inspect a saved local plan
python3 scripts/lab.py up sandbox-20261010    # create the isolated lab
python3 scripts/lab.py verify sandbox-20261010
python3 scripts/lab.py down sandbox-20261010 --confirm sandbox-20261010
```

The identifier deterministically maps to `ai-rag-<id>`,
`AIRagLab/Detections/<id>`, and `.lab-state/<id>/terraform.tfstate`. Use a new
lowercase, hyphenated identifier for each disposable lab; the runner rejects default, shared, and
legacy/collision-prone identifiers. `down` requires the identifier again in `--confirm` and removes
the local state only after Terraform destroy succeeds.

### 2. Run an attack and see it caught

```bash
./demo/show_detections.sh   # ~30–60s later: what the detector caught
```

In hardened mode `replay.py` authenticates automatically — it logs each scenario user into Cognito
and sends their JWT. To do it by hand and inspect a token:

```bash
TOKEN=$(./demo/get_token.sh b.taylor)     # a signed OIDC token; paste it into jwt.io to read the claims
curl -s "$(terraform -chdir=terraform output -raw api_invoke_url)" \
  -H "x-api-key: $(terraform -chdir=terraform output -raw api_key_value)" \
  -H "Authorization: $TOKEN" -H 'content-type: application/json' \
  -d '{"prompt":"show me the key rotation runbook","x_source_ip":"10.12.0.5"}'
```

`x_source_ip` simulates an internal source. The handler's **network checkpoint runs before
retrieval authorization**, so a request without an internal (simulated) source is rejected with
`Source not permitted for this principal` *before* the clearance check is reached.

Swap `b.taylor` (Restricted) for `c.jones` (Internal) and the **same** request returns the runbook
in `documents_blocked` instead of `documents_returned` — identity and clearance enforced entirely
from the verified token, not the body. List the seeded users with `terraform output cognito_demo_users`.

### 3. Flip the controls off, then on

The headline demo — the *same* attack succeeds, then is blocked:

```bash
terraform -chdir=terraform apply -var=controls_enabled=false   # OFF — attack succeeds
terraform -chdir=terraform apply -var=controls_enabled=true    # ON  — attack blocked (default)
```

### 4. Run other attacks (optional)

```bash
./demo/replay.py --list   # list all scenarios
./demo/replay.py          # the full incident, end to end
./demo/trace.sh           # fire one request, trace it across every layer
```

Write your own by copying a file in [`demo/scenarios/`](demo/scenarios/README.md).

### 5. Tear down

```bash
python3 scripts/lab.py down sandbox-20261010 --confirm sandbox-20261010  # stops the cost
```

> **Shared-account caveat:** API Gateway's CloudWatch-logging role and Bedrock's model-invocation
> logging config are per-account/per-region singletons. The local lab runner never manages them.
> Do not bypass the runner with `manage_account_region_singletons=true` in a shared account.

---

## Documentation

- **Understand** — [overview](docs/overview.md) · [architecture](docs/architecture.md) · [tutorial](TUTORIAL.md)
- **Operate** — [testing runbook](TESTING.md) · [detector evidence gates](docs/soc-detection-validation.md) · [tuning & lessons](docs/tuning.md) · [attack scenarios](demo/scenarios/README.md)
- **Frameworks** — [controls matrix](docs/controls-matrix.md) · [MITRE ATLAS map](docs/atlas-mapping.md) · [OWASP LLM map](docs/owasp-mapping.md) · [end-to-end logging](docs/end-to-end-logging.md)
- **Governance & compliance** · [risk & governance](docs/compliance/governance.md) · [framework map](docs/compliance/compliance-framework-mapping.md) · [AI policy](docs/compliance/ai-policy.md) · [incident response](docs/compliance/incident-response.md)
- **Project** — [contributing](CONTRIBUTING.md) · [security](SECURITY.md) · [changelog](CHANGELOG.md)

## Repo layout

```
.
├── terraform/      all infrastructure (one .tf file per concern)
├── src/
│   ├── chat/       the assistant Lambda — access control + injection scan + guardrail
│   └── detector/   the detection Lambda — 3 detections
├── corpus/         seed documents (incl. a poisoned one) + classification manifest
├── demo/           replay.py, trace.sh, and scenarios/ (ATLAS-tagged attacks)
├── scripts/        preflight.sh (prerequisite + deploy-status checks)
└── docs/           overview, architecture, controls/ATLAS/OWASP maps, logging, tuning
```

MIT licensed.
