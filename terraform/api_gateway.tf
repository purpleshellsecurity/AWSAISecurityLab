# API Gateway REST API in front of the chat Lambda.
# - API key + usage plan = authentication and per-key throttling.
# - Access logs carry $context.requestId, the correlation ID that was missing in the incident.
# - When controls_enabled, a resource policy restricts the *real* source IP to internal CIDRs
#   (the production-grade version of the "service account from external IP" control). The demo
#   simulates the attacker IP via a body field, which the Lambda enforces; see README.

resource "aws_api_gateway_rest_api" "this" {
  name        = "${local.prefix}-api"
  description = "RAG assistant API (security lab)"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  # Resource policy: only when controls are enabled, and only restricting source IP for real traffic.
  policy = var.controls_enabled ? data.aws_iam_policy_document.api_resource_policy[0].json : null
}

data "aws_iam_policy_document" "api_resource_policy" {
  count = var.controls_enabled ? 1 : 0

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
      condition {
        test     = "NotIpAddress"
        variable = "aws:SourceIp"
        values   = var.allowed_edge_cidrs
      }
    }
  }
}

resource "aws_api_gateway_resource" "chat" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "chat"
}

resource "aws_api_gateway_method" "chat_post" {
  rest_api_id      = aws_api_gateway_rest_api.this.id
  resource_id      = aws_api_gateway_resource.chat.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "chat" {
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = aws_api_gateway_resource.chat.id
  http_method             = aws_api_gateway_method.chat_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.chat.invoke_arn
}

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
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.this.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = "prod"

  depends_on = [aws_api_gateway_account.this]

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    format = jsonencode({
      request_id = "$context.requestId"
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
resource "aws_api_gateway_api_key" "this" {
  name    = "${local.prefix}-key"
  enabled = true
}

resource "aws_api_gateway_usage_plan" "this" {
  name = "${local.prefix}-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.this.id
    stage  = aws_api_gateway_stage.prod.stage_name
  }

  throttle_settings {
    rate_limit  = 20
    burst_limit = 40
  }
}

resource "aws_api_gateway_usage_plan_key" "this" {
  key_id        = aws_api_gateway_api_key.this.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.this.id
}
