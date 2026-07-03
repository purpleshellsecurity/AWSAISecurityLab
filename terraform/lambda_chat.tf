# The chat assistant Lambda: identity check -> retrieval-layer authorization -> Bedrock + Guardrail
# -> structured correlation log. This is where the core RAG-abuse fix lives (authorize per document
# classification BEFORE returning content).

data "archive_file" "chat" {
  type        = "zip"
  source_dir  = "${path.module}/../src/chat"
  output_path = "${path.module}/.build/chat.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

resource "aws_lambda_function" "chat" {
  function_name = "${local.prefix}-chat"
  role          = aws_iam_role.chat.arn
  runtime       = "python3.12"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.chat.output_path
  source_code_hash = data.archive_file.chat.output_base64sha256

  environment {
    variables = {
      CORPUS_BUCKET     = aws_s3_bucket.corpus.id
      MODEL_ID          = var.bedrock_model_id
      GUARDRAIL_ID      = local.guardrail_id
      GUARDRAIL_VERSION = local.guardrail_version
      SERVICE_SECRET_ID = aws_secretsmanager_secret.svc_creds.id
      INTERNAL_CIDRS    = join(",", var.internal_cidrs)
      CONTROLS_ENABLED  = tostring(var.controls_enabled)
    }
  }

  depends_on = [aws_cloudwatch_log_group.chat]
}

resource "aws_lambda_permission" "apigw_invoke_chat" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chat.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.this.execution_arn}/*/*"
}
