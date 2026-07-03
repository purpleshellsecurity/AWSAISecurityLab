data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  prefix     = var.name_prefix

  # Bedrock invoke targets the Lambda role is scoped to (least privilege). For a cross-region
  # inference profile, IAM needs InvokeModel on the profile ARN AND on the underlying foundation
  # model in each region the profile can route to.
  bedrock_inference_profile_arn = "arn:${local.partition}:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_model_id}"
  bedrock_foundation_model_arns = [
    for r in var.bedrock_inference_regions :
    "arn:${local.partition}:bedrock:${r}::foundation-model/${var.bedrock_foundation_model_id}"
  ]
  bedrock_invoke_resources = concat([local.bedrock_inference_profile_arn], local.bedrock_foundation_model_arns)

  # Whether the network edge is actually restricted. When the allowed range is the open default,
  # we emit no Deny (a Deny with NotIpAddress 0.0.0.0/0 denies everyone in IAM).
  edge_restricted = !contains(var.allowed_edge_cidrs, "0.0.0.0/0")
}
