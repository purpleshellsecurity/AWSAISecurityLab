# Detector delivery contract — AWS research and implementation decision

Status: **PR #9 review; not deployed**. This document describes service guarantees and constraints, not a claim of exactly-once end-to-end delivery.

## Authoritative service contracts

- CloudWatch Logs subscription records arrive as a gzip-compressed, base64-encoded envelope containing per-log-event identifiers; retry/throttling handling is upstream of the Lambda function. [AWS CloudWatch Logs subscription filters](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html).
- The detector Lambda is invoked asynchronously. A function error ordinarily receives two additional attempts; throttling/system errors use separate queue retry behavior. A failed invocation can be retried, and duplicate deliveries are possible. [Lambda asynchronous error handling](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html).
- Lambda async event age and maximum function-error retries are configurable. Without a failure destination, events can be discarded after retry exhaustion or age expiry. [Configuring async error handling](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-configuring.html).
- DynamoDB transaction authorization is **per underlying operation**: PutItem, UpdateItem, GetItem, and ConditionCheckItem where applicable; `dynamodb:TransactWriteItems` is not the documented IAM grant for these individual operations. [DynamoDB transactional IAM](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html).
- DynamoDB transactions atomically condition event receipts and baseline updates, but they do not transact with SNS or CloudWatch metric APIs.

## Actual application signal routing

- **Direct SNS publish:** human-readable detection record containing request ID and context.
- **Metric -> CloudWatch alarm -> SNS:** alarm state changes (ALARM and OK) for the same metric; these are a second, *semantically different* notification path. The same finding may therefore produce both a direct alert and an alarm email without duplicate CloudWatch delivery. Retain both only if that operator experience is intended; do not label these distinct messages as duplicate deliveries.

## Proposed behavior (PR #9)

1. Use the CloudWatch subscription log event's `id`, plus a detection slug, for a stable finding receipt key. Different detection types on the same retrieval event remain independently addressable.
2. Conditionally create a finding receipt, track metric and direct SNS delivery independently using per-sink leases, and avoid resending acknowledged sinks on replay.
3. For normal token usage, atomically transact a receipt and one EWMA write to the existing baseline table, with conditional baseline version checking. Do not fold spikes into the baseline. Persist the spike decision with the receipt so a replay does not recompute against a new baseline.
4. Fail the overall Lambda batch when a sink fails or remains leased or processing encounters an error; Lambda may retry the batch. Previously acknowledged sinks and baseline changes are not repeated.
5. Store ephemeral receipts for seven days with DynamoDB TTL; baseline items do not expire.

## Explicit guarantees and non-guarantees

- **Expected:** the same source CloudWatch event processed repeatedly during the receipt retention window should update the EWMA once and not republish already acknowledged direct SNS/metric sends.
- **Not guaranteed:** exactly-once external delivery. A crash after an external publish but before receipt acknowledgement can cause a second publish later.
- **Not guaranteed:** durable recovery of failed notifications beyond the Lambda async retry limit. There is currently no configured on-failure queue/destination, background sweeper, or operator redrive process.
- **Not guaranteed:** that CloudWatch alarm state transitions create one email per finding. Alarms are stateful and publish on transitions, not one-for-one with metric events.
- **Caveat:** DynamoDB TTL expiry is asynchronous. Within a seven-day dedup window, a receipt exists; after expiry, a late replay may repeat work.
- **Caveat:** live Lambda asynchronous invoke configuration and the absence/presence of an on-failure destination must be independently checked in the deployed account before declaring release readiness.

## Read-only verification before merge/deploy

```bash
aws lambda get-function-event-invoke-config \
  --function-name ai-rag-lab-detector \
  --region us-east-1
aws lambda get-function-configuration \
  --function-name ai-rag-lab-detector \
  --region us-east-1 \
  --query '{Timeout:Timeout,State:State,LastUpdateStatus:LastUpdateStatus}'
```

If `get-function-event-invoke-config` returns `ResourceNotFoundException`, report **no function-specific async configuration**; use AWS defaults rather than treating the command failure as evidence that retries are disabled.

**Release blocker:** choose a concrete exhausted-retry recovery contract (such as an on-failure SQS destination plus a runbook and alarm) and validate retry/redrive semantics. Do not claim guaranteed notification recovery or merge merely because unit tests pass.

## Validation requirements

CI: replay of same source log record, simultaneous replay, independent detection types from one source, EWMA once, token-spike once, partial SNS failure and retry, leased in-flight send, unexpected transaction cancellation, missing source event ID. AWS: targeted plan review then controlled live duplicate delivery against a disposable request, with correlated detector logs, metric count, SNS receipt and baseline state. Avoid invoking real alerts during CI.
