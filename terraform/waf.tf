# =============================================================================
# waf.tf — AWS WAFv2 web ACL in front of the API Gateway stage
# =============================================================================
# WAF in front of API Gateway.
# - Edge-CIDR IPSet: when the edge is actually restricted (allowed_edge_cidrs narrowed from the open
#   default — see local.edge_restricted in main.tf), block any source NOT in the allowed ranges.
#   This keys on the REAL connection IP, independent of the app-layer controls_enabled toggle: the
#   network perimeter stays up even when the lab is flipped to its vulnerable baseline.
# - Rate-based rule: blunts the bulk/token-spike abuse pattern.
# - AWS managed common rule set: baseline web protections.
# - Full request logging: the outermost hop logs per-request like every other layer.
#
# WAF is the outermost enforcement layer — it inspects requests before they ever reach API Gateway.
# It complements, not duplicates, the API Gateway resource policy: the resource policy is IAM-style
# IP allow/deny, while WAF adds rate-based blocking and signature-based managed rules (SQLi/XSS/etc.)
# that IAM policies can't express. Rules are ordered by `priority` (lower = evaluated first); the
# first rule to `block` short-circuits the request.
# -----------------------------------------------------------------------------

# An IP set holding the edge-allowed ranges (var.allowed_edge_cidrs). Referenced by the
# block-non-internal rule below. WAF evaluates IP sets very cheaply, so this is an efficient
# network gate.
resource "aws_wafv2_ip_set" "internal" {
  name               = "${local.prefix}-internal"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  # WAF IPSets reject 0.0.0.0/0. When the edge is open the block rule is removed and this set is
  # unused, so we park a valid placeholder (RFC 5737 TEST-NET). When restricted, it holds the real
  # allowed ranges.
  addresses = local.edge_restricted ? var.allowed_edge_cidrs : ["192.0.2.0/24"]
}

# The web ACL: the ordered set of rules WAF applies to every request hitting the associated stage.
resource "aws_wafv2_web_acl" "this" {
  name  = "${local.prefix}-web-acl"
  scope = "REGIONAL"

  # Default = allow: requests that match no blocking rule pass through. This is a positive-security
  # posture with targeted blocks layered on top (rate + managed signatures + optional IP gate).
  default_action {
    allow {}
  }

  # Rule (priority 0, evaluated first): block anything whose source IP is NOT in the internal set.
  # Only present when the edge is restricted. This is the network-layer twin of the API Gateway
  # resource policy — defense in depth so a single misconfig doesn't open external access.
  dynamic "rule" {
    for_each = local.edge_restricted ? [1] : []
    content {
      name     = "block-non-internal"
      priority = 0
      action {
        block {}
      }
      statement {
        # not_statement wraps the IP set: match = "source is NOT in internal ranges" -> block.
        not_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.internal.arn
            }
          }
        }
      }
      visibility_config {
        # Emit CloudWatch metrics + keep sampled requests so blocks are observable/auditable.
        cloudwatch_metrics_enabled = true
        metric_name                = "block-non-internal"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule (priority 1): rate-based blocking. Counts requests per source IP over a rolling 5-minute
  # window and blocks any IP exceeding the limit. This is the primary anti-abuse control for bulk
  # scraping / token-spike attacks (LLM04 unbounded consumption) at the network edge.
  rule {
    name     = "rate-limit"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        # limit = max requests per IP per 5 min before blocking (var-driven so you can tune it).
        limit = var.rate_limit_per_5min
        # Aggregate by source IP: each IP gets its own counter.
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Rule (priority 2): AWS's managed Common Rule Set — curated signatures for common web attacks
  # (bad inputs, path traversal, some XSS/injection patterns). Cheap baseline hygiene you get for free.
  rule {
    name     = "aws-common"
    priority = 2
    # override_action none{} = honor the group's own block/allow actions (vs. count-only mode used
    # when tuning). Set to count first in real deployments to check for false positives before blocking.
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

  # ACL-wide visibility: aggregate metrics for the whole web ACL.
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-web-acl"
    sampled_requests_enabled   = true
  }
}

# Attaches the web ACL to the prod API Gateway stage. Without this association the ACL exists but
# inspects nothing — this is the line that actually puts WAF in the request path.
resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# ---------- WAF request logging ----------
# Metrics + sampled requests (above) tell you THAT a rule fired; only full WAF logs tell you WHICH
# request, WHICH rule, and WHAT terminating action — and blocked attacks are precisely the events
# this lab wants auditable. Without this, the outermost hop is the only layer in the stack with no
# per-request log, breaking the end-to-end correlation story at its first link.
# The log group name MUST start with "aws-waf-logs-" — WAF rejects any other destination name.
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.prefix}"
  retention_in_days = 30                   # same bounded retention as the other log groups
  kms_key_id        = aws_kms_key.main.arn # same CMK encryption as the other log groups
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}
