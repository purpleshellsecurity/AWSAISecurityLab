# OWASP Top 10 for LLM Applications (2025) Mapping

This lab is, in effect, an implementation of the OWASP LLM Top 10 prevention guidance. This doc maps
the lab's controls to the official OWASP strategies so each control traces to a published standard.

Primary reference: [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).

---

## LLM01:2025 — Prompt Injection (the lab's core focus)

OWASP lists seven prevention & mitigation strategies for LLM01. The lab implements most of them:

| # | OWASP LLM01 prevention strategy | Implemented? | In the lab |
|---|---|---|---|
| 1 | **Constrain model behavior** — define the model's role, capabilities, and limits in the system prompt | ✅ | `SYSTEM_PROMPT` in `src/chat/handler.py` ("answer only from context; never reveal config/credentials; do not enumerate documents") |
| 2 | **Define and validate expected output formats** — request reasoning/citations, verify with deterministic code | ⚠️ partial | the assistant returns `documents_returned` IDs (citations), but output format is not strictly validated — a documented gap |
| 3 | **Implement input and output filtering** — semantic filters, scan for disallowed content | ✅ | Bedrock **Guardrail** (prompt-attack filter, denied topic, PII policy) in `bedrock_guardrail.tf`; plus the **injection scanner** (`scan_for_injection`) on retrieved content |
| 4 | **Enforce privilege control and least privilege** — own credentials, minimum access | ✅ | scoped IAM role in `iam.tf` (one model, one guardrail, one corpus prefix, one secret); short-lived STS creds |
| 5 | **Require human approval for high-risk actions** (human-in-the-loop) | ➖ n/a | the lab assistant has no agent/tool actions to gate; noted for completeness |
| 6 | **Segregate and identify external content** — denote untrusted content to limit its influence | ✅ | retrieved documents are **treated as untrusted and scanned** before reaching the model (`scan_for_injection`); poisoned content is quarantined (indirect-injection defense) |
| 7 | **Conduct adversarial testing and attack simulations** — treat the model as an untrusted user | ✅ | the ATLAS-tagged attack scenarios in `demo/scenarios/` + `demo/replay.py` |

**Indirect injection / RAG content:** OWASP explicitly calls out indirect prompt injection (malicious
instructions arriving via external/retrieved content) and recommends segregating and validating it.
The lab's injection scanner + the `07_indirect_injection.json` scenario implement exactly this.
The production upgrade (LLM-as-judge / a purpose-built classifier / Bedrock `ApplyGuardrail` on
retrieved content) is OWASP #3's "semantic filters" taken further — see `docs/atlas-mapping.md`.

---

## Broader OWASP LLM Top 10 coverage

The lab addresses four of the Top 10 directly:

| OWASP risk | Lab control(s) | Where |
|---|---|---|
| **LLM01 Prompt Injection** | Guardrail + injection scanner + adversarial scenarios | `bedrock_guardrail.tf`, `handler.py`, `demo/scenarios/` |
| **LLM02 Sensitive Information Disclosure** | retrieval-layer authorization (per-classification), PII guardrail policy | `handler.py` clearance check, `corpus/manifest.json`, `bedrock_guardrail.tf` |
| **LLM06 Excessive Agency / Broken Access Control** | least-privilege IAM, network/source-IP enforcement, per-request identity | `iam.tf`, `waf.tf`, `api_gateway.tf`, `handler.py` |
| **LLM07 System Prompt Leakage** | secrets in Secrets Manager (not in corpus/prompt), system-prompt doc gated by authorization | `secrets.tf`, `corpus/`, `handler.py` |

Not in scope for this lab (no training pipeline, no agent tools, no plugins): LLM03 Supply Chain,
LLM04 Data/Model Poisoning (training-time), LLM05 Improper Output Handling (partially — see #2 above),
LLM08 Vector/Embedding Weaknesses (no vector store), LLM09 Misinformation, LLM10 Unbounded
Consumption (partially — the token-deviation detection touches this).

---

## How this complements the other mappings

- `docs/controls-matrix.md` — control → incident finding → demo (the "what/why")
- `docs/atlas-mapping.md` — control → MITRE ATLAS technique (the attacker's view)
- **this file** — control → OWASP LLM Top 10 prevention (the standards view)

Together: every control in the lab traces to a real incident finding, a named adversary technique
(ATLAS), and a published prevention standard (OWASP).

## Sources
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP Top 10 for LLM Applications 2025 (PDF): https://owasp.org/www-project-top-10-for-large-language-model-applications/
