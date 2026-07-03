# Architecture & Data Flow

![Architecture](architecture.svg)

The diagram shows two paths: a **request path** (Client → WAF → API Gateway → chat Lambda → Bedrock / S3)
and an out-of-band **detection path** (chat Lambda → CloudWatch Logs → detector → Alarms → SNS).
Because detection is out-of-band, it can never block or slow a request.

For *why* each control exists — traced to the evidence in the incident logs — see the
[controls matrix](controls-matrix.md). The control missing in the incident was **authorize at
retrieval**: the chat Lambda checks caller clearance against each document's `classification`
*before* the content is read.

## Reconstructed from the incident

The original system (deduced from `chat_logs.json`, `retrieval_logs.csv`, `api_access_logs.csv`)
had four layers: a chat/LLM layer, a RAG retrieval layer, a vector store, and a service-account API
layer. The lab reproduces those layers on AWS, then inserts the missing controls.

## Data flow for one request

1. Client calls `POST {api_invoke_url}/chat` with an API key and a JSON body
   `{ "user": "...", "prompt": "...", "session_id": "...", "x_source_ip": "..." }`.
   (`x_source_ip` is a lab affordance so the demo can simulate the external attacker IP without
   needing infrastructure outside AWS. In production this is the real connection source.)
2. **WAF** checks the source against the internal IPSet and the rate-based rule.
3. **API Gateway** authenticates the API key, generates a `request_id`, writes an access log line,
   and (when `controls_enabled`) enforces a resource policy restricting source ranges.
4. **Chat Lambda**:
   - resolves the caller identity and looks up their entitlements,
   - for every candidate document, checks the caller's clearance against the document's
     `classification` **before** the content is read — the retrieval-layer authorization that was
     missing in the incident,
   - scans the retrieved content for injection markers and **quarantines** any poisoned document
     before it reaches the model,
   - calls **Bedrock Converse** with the **Guardrail** attached,
   - emits **three correlated records** — `api_access`, `chat`, and `retrieval` — all sharing one
     `request_id`, so a single request can be traced across every layer.
5. A **subscription filter** streams those logs to the **Detector Lambda**, which runs the four
   detections and publishes custom metrics; **CloudWatch Alarms** on those metrics notify **SNS**.

## Why no OpenSearch / Bedrock Knowledge Base

**Cost.** A managed vector store (OpenSearch Serverless, the default backing for Bedrock Knowledge
Bases) starts around $700/month — overkill for a personal-account lab. The lab uses a small S3 corpus
with naive in-Lambda keyword retrieval (no embeddings) instead.

This doesn't change what's demonstrated: the security boundary — authorize per document
`classification` *before* returning content — is identical regardless of the vector backend.

## Production upgrade path

| Lab choice | Production equivalent |
|---|---|
| In-Lambda retrieval over S3 corpus | Bedrock Knowledge Base + OpenSearch Serverless (or Aurora pgvector for lower cost) |
| `x_source_ip` body field for the demo | Real source IP from the connection / `X-Forwarded-For` at the edge |
| API key + usage plan | Amazon Cognito / OIDC with per-user JWT claims driving entitlements |
| Entitlements in a JSON manifest | Centralized entitlement service / Verified Permissions (Cedar) |
| Detector Lambda on log subscription | Security Lake + Athena/OpenSearch detections, or GuardDuty + Detective |
| Single account | Multi-account with SCPs, delegated security tooling, AWS Config conformance packs |
