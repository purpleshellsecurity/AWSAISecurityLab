output "api_invoke_url" {
  description = "Base URL for the chat API. POST to {url}/chat."
  value       = "${aws_api_gateway_stage.prod.invoke_url}/chat"
}

output "api_key_value" {
  description = "API key for the usage plan (send as x-api-key header)."
  value       = aws_api_gateway_api_key.this.value
  sensitive   = true
}

output "internal_cidr" {
  description = "CIDR(s) treated as internal. Sources outside these are blocked / flagged."
  value       = var.internal_cidrs
}

output "controls_enabled" {
  description = "Whether remediation controls are active (false = vulnerable baseline)."
  value       = var.controls_enabled
}

output "sns_topic_arn" {
  description = "SNS topic that detection alarms publish to."
  value       = aws_sns_topic.alarms.arn
}

output "corpus_bucket" {
  description = "S3 bucket holding the RAG corpus."
  value       = aws_s3_bucket.corpus.id
}

output "chat_log_group" {
  description = "CloudWatch log group for the chat assistant (correlation logs)."
  value       = aws_cloudwatch_log_group.chat.name
}

output "detector_log_group" {
  description = "CloudWatch log group for the detector."
  value       = aws_cloudwatch_log_group.detector.name
}

output "apigw_access_log_group" {
  description = "CloudWatch log group for API Gateway access logs (the api layer of the trace)."
  value       = aws_cloudwatch_log_group.apigw_access.name
}

output "guardrail_id" {
  description = "Bedrock guardrail id (empty when controls disabled)."
  value       = local.guardrail_id
}

output "bedrock_model_id" {
  description = "The model/inference-profile id the assistant invokes."
  value       = var.bedrock_model_id
}
