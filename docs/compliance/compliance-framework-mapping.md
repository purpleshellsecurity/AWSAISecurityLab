# Enso Compliance Map

For each security control: what attack it stops, and which rules and frameworks it lines
up with. Control numbers match `docs/controls-matrix.md`.

> Where each column comes from:
> - **OWASP + ATLAS**: already mapped in the lab (`docs/owasp-mapping.md`, `docs/atlas-mapping.md`). Real.
> - **NIST + EU**: reasoned and checked against the published frameworks. Defensible.
> - **ISO 42001**: not assessed (needs the licensed standard). Out of scope. See the note below.
>
> **Evidence type:** everything points at code/config, which is *design evidence* (the
> control exists and is built right). It is not operating-effectiveness evidence (log
> samples proving it worked over time). That is the SOC 2 Type I vs. Type II split. For a
> lab that is expected; stated so it is not a surprise.
>
> Fake data. Not a certified system. Not legal advice.

---

## EU AI Act tier

**Limited-risk.** Enso retrieves documents for staff. A human reads the answer and acts.
It makes no automated decision about any person, so it hits no Annex III high-risk
category. Under Art. 6(3), a system doing a narrow procedural task that does not
materially influence outcomes for people is not high-risk.

What that means for the EU column:

- **Art. 9 to 15 are the high-risk obligations.** Not legally binding here. Mapped as good
  practice, not as "the law we must meet."
- **The binding obligations are Art. 50** (disclose AI), now met by `AI_NOTICE`, and
  **Art. 4** (staff literacy), covered by `TUTORIAL.md` and `docs/`.
- **Provider vs. deployer:** Enso uses Bedrock, so GPAI duties (Art. 53/55) sit with the
  model provider, not this lab.

---

## The frameworks, one line each

- **OWASP LLM Top 10:** the 10 most common ways AI apps get attacked.
- **MITRE ATLAS:** a catalog of AI attack techniques (the "T####" codes).
- **NIST AI RMF:** four functions. GOVERN sets the rules, MAP finds and rates the risk,
  MEASURE tests it, MANAGE fixes it with a control. Tags below are at subcategory level.
- **EU AI Act:** the EU's AI law; rules are "Articles."

---

## The map

NIST tag = primary subcategory; secondary functions in parentheses.

| # | What we do | Stops (OWASP · ATLAS) | NIST AI RMF | EU | Proof |
|---|------------|-----------------------|-------------|-----|-------|
| 1 | Block non-internal sources + rate-limit | LLM06 · T0012 | MANAGE 1.3 | Art. 15 | `waf.tf`, `api_gateway.tf` · sc.04 |
| 2 | Only show docs you're cleared to see (checked before the doc is read) | LLM02 · T0057 | MANAGE 1.3 (MAP 1.1) | Art. 10, 15 | `handler.py:361` · sc.03 |
| 2 | Label every doc by sensitivity + who can see it | LLM02 | MAP 1.1 | Art. 10 | `corpus/manifest.json` · sc.03 |
| 3 | Block bad prompts + PII + denied topics at the model | LLM01 · T0051 | MANAGE 1.3 (MEASURE 2.7) | Art. 15 | `bedrock_guardrail.tf` · sc.02 |
| 10 | Quarantine booby-trapped docs before the model reads them | LLM01 · T0051.001, T0070 | MANAGE 1.3 | Art. 15 | `handler.py:177` · sc.07 |
| 11 | Signed login token proves identity + clearance | LLM06 · T0012 | MANAGE 1.3 | Art. 15 | `cognito.tf`, `handler.py` · replay |
| 9 | Least-privilege role (one model, one guardrail, one prefix) | LLM06 | MANAGE 1.3 | Art. 15 | `iam.tf` · inspect policy |
| 5 | Secrets in a vault; system prompt carries no secrets | LLM07 · T0056 | MANAGE 1.3 | Art. 15 | `secrets.tf`, `handler.py:61` · sc.03/06 |
| 6 | One `request_id` logged across every layer | n/a | MEASURE 3.1 (MANAGE 4.1) | Art. 12 | `docs/end-to-end-logging.md` · `trace.sh` |
| 7 | Detections raise alarms and alert a human | LLM10 · LLM02 | MANAGE 4.1 (MEASURE 3.1) | Art. 14, 72 | `detections.tf`, `detector/handler.py` · sc.04 |
| 8 | Encrypt at rest + record every action | n/a | MANAGE 1.3 (MEASURE 3.1) | Art. 12 | `kms.tf`, `logging.tf` |
| n/a | Attack it on purpose to prove the controls work | all | MEASURE 2.7 (MEASURE 1.1) | Art. 9, 15 | `TESTING.md`, `demo/scenarios/` · the A/B |
| n/a | Risk/control inventory (finding to control to test) | n/a | MAP 4.2 (MANAGE 1.3) | Art. 9 | `docs/controls-matrix.md`; risk register in `governance.md` |
| done | Tell users they're talking to an AI | n/a | GOVERN 1.1 (MANAGE) | Art. 50 | `handler.py` `AI_NOTICE` · every 200 response |

Key: GOVERN sets rules, MAP finds and rates, MEASURE tests, MANAGE builds a control.
Cross-cutting controls (logging, encryption) do not map to one OWASP risk, so "n/a".

**Why the spread matters.** Controls cluster in MANAGE, which is the "build a control"
function. But the lab also does real MAP (classification, the control inventory) and real
MEASURE (the controls-on/off A/B is MEASURE 2.7; logging plus detections is MEASURE 3.1).
The function it does least is GOVERN. Those gaps are tracked in `governance.md`.

---

## ISO 42001: deliberately out of scope

ISO/IEC 42001 is a certifiable AI management-system standard. It is not mapped here, and
that is a deliberate call, not an omission. Two reasons:

- **A credible mapping needs the licensed text.** The standard is paywalled. Mapping
  controls against a blog-summarized version would produce claims we cannot stand behind.
  An unverified compliance column is a liability, not evidence.
- **Certification is an audit outcome, not a self-declaration.** ISO 42001 conformity is
  attested by an accredited auditor against a real management system with real operating
  records. A lab on fake data cannot honestly claim it.

What the lab can say is narrower and true: it implements the technical substance of several
things ISO 42001 expects (data governance, access control, testing, logging). Bringing the
standard into scope would mean obtaining the licensed text, mapping each Annex A control,
and running an audit. Until then, out of scope is the honest label.

---

## What's still open

Three governance gaps stay open by design. They need real engineering or a real operating
org, and faking them is worse than tracking them:

- **AI impact assessment (MAP 5.1):** needs a real view of who could be harmed. A security
  risk register is not the same artifact.
- **Answer-accuracy evaluation (MEASURE 2.3):** needs a ground-truth test set. We test that
  the system is safe, not that it is right.
- **Team-based RBAC (MANAGE 1.3):** needs a change to the permission model, not a doc.

Owners, targets, and status are in `docs/compliance/governance.md`. A maintained gap list
makes the whole thing more trustworthy, not less.
