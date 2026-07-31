# =============================================================================
# main.tf - Environment lookups + shared locals (the values every other file
# builds ARNs and policies from)
# =============================================================================
# This file resolves "who and where am I running as?" and precomputes the
# Bedrock ARNs and the network-restriction flag that the IAM policies and
# guardrail wiring depend on.
#
# Why this matters for security:
#   - Building ARNs from the *actual* account/region/partition (instead of
#     hard-coding them) means the least-privilege IAM policies always scope to
#     THIS account's resources - they can't accidentally grant access to a
#     look-alike resource in another account or partition.
#   - The Bedrock ARN math below is the crux of least-privilege model access:
#     cross-region inference requires InvokeModel on both the inference-profile
#     ARN and the underlying foundation model in each region it may route to.
#     Get this wrong and you either break the app or over-grant.

# data sources: read the current identity/region/partition at plan time. These
# are lookups, not resources - they create nothing, they just tell us the
# account ID, region name, and partition (aws / aws-us-gov / aws-cn) so ARNs
# are correct wherever this is deployed.
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# locals: derived, reused values. Centralizing them here keeps the security
# boundaries (which model, which regions, whether the edge is locked down)
# defined in exactly one place instead of copy-pasted across policies.
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  prefix     = var.name_prefix

  # Bedrock invoke targets the Lambda role is scoped to (least privilege). For a cross-region
  # inference profile, IAM needs InvokeModel on the profile ARN AND on the underlying foundation
  # model in each region the profile can route to.
  #
  # The inference-profile ARN: the "us." routing endpoint the app actually calls.
  bedrock_inference_profile_arn = "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_model_id}"
  # One foundation-model ARN per region the profile can route to. Note these are
  # account-less (::) global foundation-model ARNs. Granting only these specific
  # regions - rather than a "*" wildcard - is the least-privilege win: the Lambda
  # can invoke exactly this one model in exactly these regions and nothing else.
  bedrock_foundation_model_arns = [
    for r in var.bedrock_inference_regions :
    "arn:${local.partition}:bedrock:${r}::foundation-model/${var.bedrock_foundation_model_id}"
  ]
  # The complete allow-list of Bedrock resources the chat role may invoke.
  bedrock_invoke_resources = concat([local.bedrock_inference_profile_arn], local.bedrock_foundation_model_arns)

  # Whether the network edge is actually restricted. When the allowed range is the open default,
  # we emit no Deny (a Deny with NotIpAddress 0.0.0.0/0 denies everyone in IAM).
  #
  # Security subtlety worth internalizing: an IP allow-list expressed as a Deny
  # on "NotIpAddress" is a no-op-or-lockout trap when the list is 0.0.0.0/0 -
  # "deny everyone whose IP is not in {the entire internet}" denies nobody, and
  # inverting it wrong denies everybody. So we compute a boolean and only emit
  # the restriction when a real, narrower range was supplied.
  edge_restricted = !contains(var.allowed_edge_cidrs, "0.0.0.0/0")
}
