# =============================================================================
# api_gateway.tf — the HTTP front door (authn, throttling, access logging, edge IP policy)
# =============================================================================
# API Gateway REST API in front of the chat Lambda.
# - API key + usage plan = authentication and per-key throttling.
# - Access logs carry $context.requestId, the correlation ID that was missing in the incident.
# - When controls_enabled, a resource policy restricts the *real* source IP to internal CIDRs
#   (the production-grade version of the "service account from external IP" control). The demo
#   simulates the attacker IP via a body field, which the Lambda enforces; see README.
#
# Where this fits: this is the layer that decides *who may reach the app at all*. It authenticates
# the caller (API key), rate-limits them (usage plan), can restrict them by source IP (resource
# policy), and — critically for incident response — records a per-request access log with a
# correlation ID that ties the API hop to the Lambda and Bedrock hops. WAF (waf.tf) sits in front of
# this stage; the Lambda (lambda_chat.tf) sits behind it.
# -----------------------------------------------------------------------------

# The REST API container. REGIONAL endpoint keeps traffic in-region (no CloudFront edge) which
# matches the "internal service" threat model and makes source-IP restriction meaningful.
resource "aws_api_gateway_rest_api" "this" {
  name        = "${local.prefix}-api"
  description = "RAG assistant API (security lab)"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  # Resource policy: only when controls are enabled, and only restricting source IP for real traffic.
  # A resource policy is evaluated by API Gateway itself, BEFORE the request reaches integration —
  # so an IP outside the allowed ranges is rejected at the edge, never touching the Lambda or Bedrock.
  policy = var.controls_enabled ? data.aws_iam_policy_document.api_resource_policy[0].json : null
}

# Builds the API Gateway resource policy JSON. Structured as allow-all + conditional deny so that
# in the remediated build the only requests permitted are those from the internal edge CIDRs.
data "aws_iam_policy_document" "api_resource_policy" {
  count = var.controls_enabled ? 1 : 0

  # Baseline allow: without an explicit Allow, the presence of any resource policy would deny all.
  statement {
    sid       = "AllowInvoke"
    effect    = "Allow"
    actions   = ["execute-api:Invoke"]
    resources = ["execute-api:/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }

  # Only deny by source IP when the edge is actually restricted (not the open default).
  # An explicit Deny always wins over the Allow above — this is the network gate that enforces
  # "internal callers only" at the API layer (mirrored at the WAF layer in waf.tf).
  dynamic "statement" {
    for_each = local.edge_restricted ? [1] : []
    content {
      sid       = "DenyNonInternalSource"
      effect    = "Deny"
      actions   = ["execute-api:Invoke"]
      resources = ["execute-api:/*"]
      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
      # NotIpAddress + aws:SourceIp: deny any request whose real source IP is NOT in the allowed
      # ranges. This is the production-grade version of the "service account calling from an
      # external IP" control that the incident lacked.
      condition {
        test     = "NotIpAddress"
        variable = "aws:SourceIp"
        values   = var.allowed_edge_cidrs
      }
    }
  }
}

# The /chat URL path. Kept minimal (single resource) to reduce attack surface.
resource "aws_api_gateway_resource" "chat" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "chat"
}

# POST /chat method definition. This is where the API-key requirement is declared.
resource "aws_api_gateway_method" "chat_post" {
  rest_api_id      = aws_api_gateway_rest_api.this.id
  resource_id      = aws_api_gateway_resource.chat.id
  http_method      = "POST"
  # authorization = NONE: no IAM/Cognito/custom authorizer in this lab — auth is by API key only.
  # In production an API key is an identifier/throttling handle, not a strong authenticator; it
  # would typically be paired with a JWT/IAM authorizer. The lab keeps it simple on purpose.
  authorization    = "NONE"
  # Require a valid API key on every call. Combined with the usage plan below this gives per-caller
  # identity and rate limiting, and populates $context.identity.apiKeyId in the access log.
  api_key_required = true
}

# Wires POST /chat to the Lambda using AWS_PROXY (Lambda proxy) integration, which forwards the full
# request (headers, source IP, body) to the handler so the app can make its own authz decisions.
resource "aws_api_gateway_integration" "chat" {
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = aws_api_gateway_resource.chat.id
  http_method             = aws_api_gateway_method.chat_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.chat.invoke_arn
}

# A deployment is an immutable snapshot of the API config. The triggers hash forces a fresh
# deployment whenever the routing OR the security posture changes — notably when controls_enabled or
# the allowed edge CIDRs change, so flipping controls actually takes effect at the edge.
resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id

  triggers = {
    redeploy = sha1(jsonencode([
      aws_api_gateway_resource.chat.id,
      aws_api_gateway_method.chat_post.id,
      aws_api_gateway_integration.chat.id,
      var.controls_enabled, # the toggle that changes the resource policy
      join(",", var.allowed_edge_cidrs),
    ]))
  }

  lifecycle {
    # Stand up the new deployment before tearing down the old one — no window where /chat 404s.
    create_before_destroy = true
  }
}

# The "prod" stage — the live, invokable endpoint. This is where access logging is configured, so
# the stage is the layer that produces the per-request audit trail.
resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = "prod"

  # Access logging can't work until the account-level CloudWatch role exists (api_gateway_account.tf).
  depends_on = [aws_api_gateway_account.this]

  # Access logs: one structured JSON line per request. This is the "api layer" of the trace and the
  # direct fix for the incident's missing correlation ID — $context.requestId links this log to the
  # Lambda and Bedrock logs so an investigator can reconstruct a full request end-to-end.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    # JSON (not CLF) so the detector and log queries can parse fields directly. Each field answers a
    # forensic question: who (apiKeyId), from where (sourceIp/userAgent), what (method/path),
    # outcome (status), and cost/latency signal (responseLatency).
    format = jsonencode({
      request_id = "$context.requestId" # correlation ID that was missing in the incident
      ip         = "$context.identity.sourceIp"
      apiKeyId   = "$context.identity.apiKeyId"
      httpMethod = "$context.httpMethod"
      path       = "$context.path"
      status     = "$context.status"
      latency    = "$context.responseLatency"
      userAgent  = "$context.identity.userAgent"
    })
  }
}

# ---------- API key + usage plan (authn + throttling) ----------
# The API key: the credential a caller presents in the x-api-key header. It identifies the caller
# for throttling and log attribution. (Output as sensitive in outputs.tf so it isn't shown in plans.)
resource "aws_api_gateway_api_key" "this" {
  name    = "${local.prefix}-key"
  enabled = true
}

# The usage plan binds the key to the prod stage and enforces throttling. Rate limiting here is a
# first-line control against LLM04 (unbounded consumption) and bulk-scraping abuse — it caps how
# fast any single key can drive expensive Bedrock calls, independent of the WAF rate rule.
resource "aws_api_gateway_usage_plan" "this" {
  name = "${local.prefix}-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.this.id
    stage  = aws_api_gateway_stage.prod.stage_name
  }

  # Per-key steady-state and burst caps (requests/second). Low values are intentional for a lab:
  # rate_limit = sustained RPS ceiling, burst_limit = short spike allowance (token-bucket). Tune to
  # legitimate traffic so abuse spikes get 429'd before they run up cost or exfiltrate at scale.
  throttle_settings {
    rate_limit  = 20
    burst_limit = 40
  }
}

# Associates the API key with the usage plan — without this join the key exists but is subject to no
# plan (no throttling, not usable on the stage).
resource "aws_api_gateway_usage_plan_key" "this" {
  key_id        = aws_api_gateway_api_key.this.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.this.id
}
