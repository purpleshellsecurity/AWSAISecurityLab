# Oversight & Incident Response

Two operational artifacts: an alert-response playbook (who acts on each detection, with
what authority) and an incident-reporting process (what counts, who's told, on what clock).
Closes gaps GOVERN 2.1 (oversight) and GOVERN 4.3 (incident reporting).

The lab already emits the signals. What was missing was the human side: who does what when
an alarm fires.

---

## Part 1: alert-response playbook

The detector (`src/detector/handler.py`) raises four alerts. For each: the trigger, who
owns the response, the authority they act under, and the first actions.

| Detection | Sev | First responder | Authority | First actions |
|-----------|-----|-----------------|-----------|---------------|
| Service account from non-internal source | High | Security Engineering (on-call) | Incident Commander once declared | Confirm source IP. Assume credential compromise. Rotate the credential. Check other requests on the principal. Preserve logs by `request_id`. |
| Sensitive-retrieval anomaly (a Restricted/Confidential doc reached a user) | High | Security Engineering + Data/Corpus Owner | CISO for data-exposure calls | Identify user, doc, and `session_id`. Confirm whether the doc leaked or was blocked. If leaked, treat as data exposure and escalate to reporting. |
| Indirect prompt injection / RAG poisoning | High | Data/Corpus Owner + Security Engineering | Product Owner for corpus changes | Quarantine or remove the poisoned document. Find how it entered. Review intake controls. Check whether it was served or quarantined. |
| Per-principal token-volume deviation | Med | Security Engineering (on-call) | Escalate to High if paired with another alert | Check for abuse or runaway. Correlate with the other three. Rate-limit or suspend the principal if abuse is confirmed. |

**Authority principle.** The first responder contains. Declaring an incident and accepting
business impact (notify externally, take the service down) is the Incident Commander or
CISO's call. Same build-vs-decide split as the risk register. On-call can always contain
first; they cannot accept the residual impact.

---

## Part 2: incident-reporting process

### What counts as an incident

Any of: a Restricted/Confidential document confirmed to have reached an unauthorized user;
a confirmed credential compromise; a poisoned document that was served rather than
quarantined; or any event a responder escalates. A single blocked or quarantined attempt
is not an incident. That is the controls working. Log it, do not escalate it.

### Steps

1. **Detect and contain.** First responder acts per Part 1; preserve evidence by `request_id`.
2. **Declare.** Escalate to the Incident Commander, who decides whether this is a formal incident.
3. **Assess impact.** What data, whose, how much, over what window. Reconstruct from the correlated logs.
4. **Notify.** Internal stakeholders always. Legal/Compliance decide on any external or
   regulatory notification. A limited-risk system does not carry the Art. 73 serious-incident
   duty that applies to high-risk systems, but the process is here so it is ready if the
   tier or data ever changes.
5. **Remediate.** Fix root cause. If it exposes a control gap, add a row to the remediation
   register in `docs/compliance/governance.md`.
6. **Review.** A short post-incident review: what fired, what worked, what to tune, what to
   add to the register.

### Timeline (target, lab illustration)

- Contain: immediately on alert.
- Declare and triage: within the on-call response window.
- Impact assessment: promptly after declaration.
- Notification decision: made by Legal/Compliance once impact is understood.
- Post-incident review: within one review cycle.

---

## Roles referenced

| Role | In an incident |
|------|----------------|
| Security Engineering (on-call) | First responder; contains |
| Incident Commander / CISO | Declares incidents; accepts business impact; approves external notification |
| Data / Corpus Owner | Owns corpus integrity; leads on poisoning or exposure |
| Product Owner | Owns acceptable-use and disclosure decisions |
| Legal / Compliance | Owns the external or regulatory notification decision |

---

*Owner: Security Engineering (playbook), CISO (declaration authority). Reviewed after every
incident and each quarterly cycle.*
