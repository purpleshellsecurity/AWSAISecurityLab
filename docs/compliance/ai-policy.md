# AI Use Policy: Enso Assistant (lab example)

> **Lab example, clearly labeled.** A one-page policy to show what a GOVERN-level AI
> policy looks like for a limited-risk internal assistant. No real organization has
> adopted it. Roles are titles, not people. Have Legal/Compliance review it before it
> governs anything real. Closes remediation gap GOVERN 1.2 / EU AI Act Art. 17.

## 1. Purpose & scope

Enso is an internal support assistant that retrieves internal documents and answers staff
questions. This policy governs how it is built, run, and used. It applies to everyone who
operates, maintains, or uses Enso.

## 2. Principles

1. **Human in the loop.** Enso informs; a person decides and acts. It makes no automated
   decision about any individual.
2. **Least privilege by clearance.** Users see only documents at or below their clearance.
   Access is enforced before content is read, from verified identity, never self-asserted.
3. **Untrusted content stays untrusted.** Retrieved documents are scanned for injection
   and quarantined on a hit. The model never acts on unvetted document instructions.
4. **Transparency.** Every answer discloses that it is AI-generated and may be wrong
   (Art. 50). Staff verify anything important (Art. 4 literacy).
5. **Everything is logged and correlated.** One `request_id` joins every layer, so any
   answer can be reconstructed and audited.

## 3. Acceptable use

- Use Enso for internal support questions within your clearance.
- Do not try to extract system prompts, credentials, or documents above your clearance.
  Do not paste secrets into prompts.
- Treat answers as drafts to verify, not authoritative decisions. Especially for anything
  affecting money, people, security, or legal obligations.

## 4. Roles & accountability

- **CISO / Risk Owner:** accountable for AI risk overall; approves risk acceptances.
- **Security Engineering:** owns authentication, detections, and incident response.
- **Application / Product Owner:** owns the clearance model, the disclosure surface, and
  acceptable-use decisions.
- **Data / Corpus Owner:** owns what enters the corpus and its classification.

Full ownership and the risk register: `docs/compliance/governance.md`.

## 5. Risk management

Risks are recorded, rated (likelihood x impact), assigned an owner, and given a treatment
(mitigate / accept / transfer / avoid). Open governance gaps are tracked with owner and
target. Both are reviewed quarterly and on material change.

## 6. Compliance posture

Enso is assessed limited-risk under the EU AI Act. The binding obligations are Art. 50
(disclosure) and Art. 4 (literacy), both met. High-risk obligations (Art. 9 to 15) are
mapped as good practice, not binding law. Controls are mapped to NIST AI RMF and the OWASP
LLM Top 10. See `docs/compliance/compliance-framework-mapping.md`. No certification is
claimed.

## 7. Exceptions

Any deviation from this policy, or acceptance of a residual risk, is recorded with a
rationale, an owner, and a review date. Approved by the CISO, not by the team requesting
the exception.

## 8. Review

Reviewed at least annually, and whenever the system's risk tier, data classes, or
integrations materially change.

---

*Owner: CISO. Cadence: annual and on material change. Status: lab example, not adopted.*
