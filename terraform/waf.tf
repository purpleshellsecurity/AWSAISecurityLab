# WAF in front of API Gateway.
# - Internal-CIDR IPSet: when controls_enabled, block any source NOT in the internal ranges
#   (the network-layer version of the "service account from external IP" control).
# - Rate-based rule: blunts the bulk/token-spike abuse pattern.
# - AWS managed common rule set: baseline web protections.

resource "aws_wafv2_ip_set" "internal" {
  name               = "${local.prefix}-internal"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  # WAF IPSets reject 0.0.0.0/0. When the edge is open the block rule is removed and this set is
  # unused, so we park a valid placeholder (RFC 5737 TEST-NET). When restricted, it holds the real
  # allowed ranges.
  addresses = local.edge_restricted ? var.allowed_edge_cidrs : ["192.0.2.0/24"]
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${local.prefix}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Block sources outside the allowed edge ranges (only when the edge is actually restricted).
  dynamic "rule" {
    for_each = local.edge_restricted ? [1] : []
    content {
      name     = "block-non-internal"
      priority = 0
      action {
        block {}
      }
      statement {
        not_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.internal.arn
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "block-non-internal"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-common"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}
