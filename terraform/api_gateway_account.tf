# =============================================================================
# api_gateway_account.tf — enables API Gateway access logging (account-level plumbing)
# =============================================================================
# API Gateway needs an account-level role to push access logs to CloudWatch. This is a one-time
# per-account/per-region setting that the access_log_settings on the stage depends on.
#
# Security relevance: without this role, the stage's access_log_settings silently fail and there is
# NO per-request audit trail — exactly the gap that made the original incident hard to investigate.
# This file is what makes the correlation logging in api_gateway.tf actually deliver.
# -----------------------------------------------------------------------------

# Trust policy: allows the API Gateway service (and only that service) to assume the logging role.
# Restricting the principal to apigateway.amazonaws.com prevents any other actor from using it.
data "aws_iam_policy_document" "apigw_cw_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

# The IAM role API Gateway assumes to write access logs into CloudWatch Logs.
resource "aws_iam_role" "apigw_cloudwatch" {
  name               = "${local.prefix}-apigw-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.apigw_cw_assume.json
}

# Attaches AWS's managed policy scoped to exactly the log actions API Gateway needs (create groups/
# streams, put events). Using the AWS-managed least-privilege policy avoids over-granting logs:* .
resource "aws_iam_role_policy_attachment" "apigw_cloudwatch" {
  role       = aws_iam_role.apigw_cloudwatch.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

# The account-level setting that registers the role. Note this is GLOBAL to the account/region —
# it affects every API in the account, which is why it lives in its own file and the prod stage
# depends_on it. depends_on the attachment ensures the role can actually log before it's registered.
resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch.arn
  depends_on          = [aws_iam_role_policy_attachment.apigw_cloudwatch]
}
