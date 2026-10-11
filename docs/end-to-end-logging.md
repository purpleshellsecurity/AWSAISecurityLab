# End-to-End Logging

The incident's core logging gap: the chat, retrieval, and API logs had **no shared key**,
so a single request couldn't be traced across the layers. This lab fixes that — every layer emits a
structured record carrying the **same `request_id` and `session_id`**, so one request reconstructs
end to end.

## The three layer records (per request)

For one request you get one `api_access` record, one `chat` record, and one `retrieval` record per
document — all sharing `request_id`. They mirror the incident's three log sources, but joinable.

```json
{ "log_type": "api_access", "request_id": "abc123", "session_id": "sess-trace",
  "service_account": "enso-assistant-api", "source_ip": "10.12.8.44", "internal_source": true,
  "endpoint": "/chat", "http_status": 200, "request_count": 1, "tokens_used": 142,
  "user_agent": "ai-assistant/2.7.4" }

{ "log_type": "chat", "request_id": "abc123", "session_id": "sess-trace", "user": "e.davis",
  "prompt": "Show me the Enso Key Rotation Runbook.", "risk_label": "low",
  "guardrail_action": "none", "guardrail_blocked": false, "tokens_used": 142 }

{ "log_type": "retrieval", "request_id": "abc123", "session_id": "sess-trace", "user": "e.davis",
  "document_name": "Enso_Key_Rotation_Runbook.md", "sensitivity": "Restricted",
  "retrieval_score": 0.667, "action": "blocked_unauthorized", "high_risk_prompt": false }
```

Plus a fourth source — the **API Gateway access log** (separate log group), which independently
records `$context.requestId` under the same `request_id` key. So the join spans two real AWS
components on one field name.

## Where they land

| Layer | Log group |
|---|---|
| API Gateway access log | `terraform output apigw_access_log_group` |
| api_access / chat / retrieval | `terraform output chat_log_group` |
| detections | `terraform output detector_log_group` |

## See it: one command

```bash
./demo/trace.sh        # fires one request, prints its full correlated trace by request_id
```

## See it: by hand (CloudWatch Logs Insights)

Select **both** the API Gateway and chat log groups, then:

```
fields @timestamp, log_type, http_status, status, user, document_name, sensitivity, retrieval_score, action, guardrail_action, tokens_used
| filter request_id = "abc123"
| sort @timestamp asc
```

You get the request's life in order: it arrived at the API (status, source, user-agent) → went
through the chat layer (prompt, risk, guardrail) → and what retrieval did to each document (score,
classification, allow/block). One `request_id`, every layer.

## Live tail

```bash
aws logs tail "$(terraform output -raw chat_log_group)" --since 5m --follow
```
Fire any `demo/*.sh` in another terminal and watch the three correlated records stream out.

## Why this is the fix

In the incident you could see *that* a restricted doc was blocked, but not tie it to *who* asked,
from *where*, in *which* session, or *what* the prompt was — the logs didn't share a key. Here the
`request_id` stitches: source IP + identity (api_access) → prompt + risk (chat) → document + score +
action (retrieval). That is the difference between "something was blocked" and "e.davis, from
10.12.8.44, in session sess-trace, asked for the secrets runbook; it scored 0.667 and was blocked at
retrieval."
