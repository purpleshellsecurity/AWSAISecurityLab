# Governance, Risk & Compliance (GRC)

The controls matrix says what is built. This says who owns the risk, why the controls
are the right ones, and what is still open. Three questions: **Governance** (who is
accountable), **Risk** (what could go wrong and what we decided), **Compliance** (which
rules apply and how we prove it).

> **Lab example, not a live program.** Fake data, not audited. Owners are roles, not
> people. This shows the *shape* of an AI GRC program. It is not itself a governing
> instrument, and no certification is claimed.

Framework spine: NIST AI RMF (Govern / Map / Measure / Manage) plus the EU AI Act
(limited-risk tier). See [`compliance-framework-mapping.md`](compliance-framework-mapping.md).

---

## 1. Governance statement

- **Accountable owner (AI risk):** CISO / Risk Owner. Signs off risk acceptances.
- **Control owners:** the role that operates each control. They build and run controls.
  They do not accept risk on their own authority.
- **Review cadence:** both registers reviewed quarterly, and on any material change.
- **Exceptions and risk acceptance:** recorded with a rationale, an owner, and a review
  date. Approved by the CISO, never by the engineer who built the control.
- **Evidence:** every "we comply" points at a file, a log field, or the controls-on/off
  demo. That demo is the control-effectiveness test.

---

## 2. Risk register

Risk = likelihood x impact. Each risk gets a decision (mitigate / accept / transfer /
avoid). We do not mitigate everything.

| ID | Risk | Likelihood | Impact | Treatment | Owner (accountable) | Linked control |
|----|------|-----------|--------|-----------|---------------------|----------------|
| R-01 | Under-cleared user retrieves Restricted docs | Med | High | Mitigate | Application / Product Owner | Retrieval authz (`handler.py:361`) |
| R-02 | Caller asserts a privileged identity | Med | High | Mitigate | Security Engineering | Cognito JWT authorizer |
| R-03 | Poisoned corpus doc injects instructions | Low | High | Mitigate | Data / Corpus Owner | Injection scanner (`handler.py:177`) + detection |
| R-04 | Users don't know they're talking to an AI | High | Low | Mitigate | Product Owner (w/ Legal) | Art. 50 disclosure (`AI_NOTICE`) |
| R-05 | Novel jailbreak slips the guardrail | Low | Med | **Accept** | CISO / Risk Owner | Detections catch it post-hoc; reviewed quarterly |

Owners follow authority over the failing layer, not who writes the code:

- **R-01, Product Owner.** "Who may see what" is a data-policy call, not a tooling one.
- **R-02, Security Engineering.** A pure auth-mechanism failure.
- **R-03, Data / Corpus Owner.** The risk enters through content. The scanner is a safety
  net; the owner keeps the corpus clean at intake.
- **R-04, Product Owner with Legal.** A legal duty (Art. 50) shipped through a product
  surface.
- **R-05, CISO.** The only Accept row. Accepting residual risk is an authority, not a task.

> **Risk owner vs. control owner.** ISO 27005 keeps them separate: the risk owner accepts
> residual risk, the control owner operates the control. This register merges them for
> brevity. That is a deliberate simplification, not an oversight.

---

## 3. Remediation register

Four gaps closed, three open by design. A tracked-open gap beats a faked-closed one.

| Gap | NIST | EU | Treatment | Owner | Target | Status |
|-----|------|-----|-----------|-------|--------|--------|
| User-facing "this is an AI" notice | GOVERN 1.1 | Art. 50 | Close | Product Owner | done | Done (`AI_NOTICE`) |
| Written AI policy | GOVERN 1.2 | Art. 17 | Close | CISO | done | Done (`docs/compliance/ai-policy.md`) |
| Oversight playbook (who acts on an alert) | GOVERN 2.1 | Art. 14 | Close | Security Engineering | done | Done (`docs/compliance/incident-response.md`) |
| Incident-reporting process | GOVERN 4.3 | Art. 73 | Close | Security Engineering | done | Done (`docs/compliance/incident-response.md`) |
| AI impact assessment (harm to people, not security risk) | MAP 5.1 | n/a | Plan | Product Owner (w/ Legal) | next cycle | Open |
| Answer-accuracy evaluation (we test *safe*, not *right*) | MEASURE 2.3 | Art. 15 | Plan | ML / App Engineering | next cycle | Open |
| Team-based RBAC (clearance-only lets a platform admin read HR data) | MANAGE 1.3 | Art. 10 | Plan | Security Engineering | next cycle | Open |

> Governance is not "everything green." It is every open item having a treatment, an
> owner, and a date. That is the GOVERN function working, before a single gap is closed.

---

## 4. Traceability

> risk (register) → control (`controls-matrix.md`) → evidence (code / log / demo) →
> owner (this doc) → obligation (`compliance-framework-mapping.md`)

Pick any risk and walk it end to end. That is what shows the program is real.

---

*See also: [`compliance-framework-mapping.md`](compliance-framework-mapping.md) ·
[`controls-matrix.md`](../controls-matrix.md) · [`ai-policy.md`](ai-policy.md) ·
[`incident-response.md`](incident-response.md)*
