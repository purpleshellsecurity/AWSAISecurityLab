# Overview

A plain-language summary of the whole project in standard AWS terms. Start here, then dig into the
other docs for detail.

## 1. What it is
A RAG (retrieval-augmented generation) chatbot on AWS, plus the security controls around it.

## 2. Request flow
`Client → WAF → API Gateway → Lambda (chat)`
- **WAF** filters the incoming request (IP allow-list, rate limiting, managed rules).
- **API Gateway** handles auth (API key), writes access logs, and assigns a `request_id`.
- **Lambda (chat)** is the application — it does the RAG and runs the controls.

## 3. The controls — two layers, different jobs
- **Lambda → access control:** checks the caller's clearance against each document's classification
  (**retrieval-layer authorization**) *before* reading it, and scans retrieved content for prompt injection.
- **Bedrock Guardrail → content safety:** prompt-attack filter, PII policy, denied topics.

> [!NOTE]
> The Lambda decides **who can see which document**; Bedrock decides **whether the text is safe**. Two different jobs.

Supporting: **S3** holds the document corpus (classified, KMS-encrypted) · **IAM** scopes the Lambda
to least privilege · **KMS** encrypts data at rest.

## 4. Logging
**CloudWatch Logs** captures three structured records per request — `api_access`, `chat`,
`retrieval` — all sharing one `request_id` for end-to-end correlation.

## 5. Detection
A **subscription filter** streams the logs to a second **Lambda (detector)**, which runs the
detection logic:

`CloudWatch Logs → detector → custom metrics → CloudWatch Alarms → SNS`

## 6. Deployment
Everything is **Terraform** (infrastructure-as-code): `terraform apply` builds it,
`terraform destroy` removes it. Attack scenarios can be replayed against a live API to collect
manual evidence for a bounded request path. Source/unit checks show intended behavior; they do not
prove live AWS outcomes. Deployment and live testing require prior approval from the account owner;
see the root [testing runbook](../TESTING.md) for the evidence boundary and expected observations.

---

Next: [architecture.md](architecture.md) for the diagram and data flow, [controls-matrix.md](controls-matrix.md)
for the per-control detail, or the root [TUTORIAL.md](../TUTORIAL.md) / [TESTING.md](../TESTING.md).
