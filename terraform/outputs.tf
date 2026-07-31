# =============================================================================
# outputs.tf — values surfaced after apply (for using and inspecting the lab)
# =============================================================================
# These outputs give students the handles they need to drive the lab (the endpoint + key) and to
# inspect each security layer (log groups, guardrail id, controls toggle). Note which values are
# marked sensitive — that decision is itself a security lesson.
# -----------------------------------------------------------------------------

# The endpoint under test. Students POST attacks here.
output "api_invoke_url" {
  description = "Base URL for the chat API. POST to {url}/chat."
  value       = "${aws_api_gateway_stage.prod.invoke_url}/chat"
}

# The API key, needed in the x-api-key header. Marked sensitive = true so Terraform redacts it from
# plan/apply output and CI logs — a credential should never be printed to a console or log.
output "api_key_value" {
  description = "API key for the usage plan (send as x-api-key header)."
  value       = aws_api_gateway_api_key.this.value
  sensitive   = true
}

# The ranges treated as internal — lets students see exactly which sources the IP controls trust.
output "internal_cidr" {
  description = "CIDR(s) treated as internal. Sources outside these are blocked / flagged."
  value       = var.internal_cidrs
}

# The master preventive-controls toggle. Students read this to confirm whether they're hitting the
# vulnerable baseline (false) or the remediated build (true) before running an attack.
output "controls_enabled" {
  description = "Whether remediation controls are active (false = vulnerable baseline)."
  value       = var.controls_enabled
}

# Where detection alarms land — subscribe here (or check email) to observe the detect-and-respond path.
output "sns_topic_arn" {
  description = "SNS topic that detection alarms publish to."
  value       = aws_sns_topic.alarms.arn
}

# The RAG knowledge-base bucket — the data the authorization control protects.
output "corpus_bucket" {
  description = "S3 bucket holding the RAG corpus."
  value       = aws_s3_bucket.corpus.id
}

# Log groups exported so students can query each hop of the request trace directly.
# Chat log = the correlation logs (request_id + authz decisions).
output "chat_log_group" {
  description = "CloudWatch log group for the chat assistant (correlation logs)."
  value       = aws_cloudwatch_log_group.chat.name
}

# Detector log = the detection pipeline's own output (why an alarm did/didn't fire).
output "detector_log_group" {
  description = "CloudWatch log group for the detector."
  value       = aws_cloudwatch_log_group.detector.name
}

# API access log = the API-layer half of the end-to-end trace.
output "apigw_access_log_group" {
  description = "CloudWatch log group for API Gateway access logs (the api layer of the trace)."
  value       = aws_cloudwatch_log_group.apigw_access.name
}

# Guardrail id — empty string in the baseline, populated when controls are on; a quick way to confirm
# the model-layer control is actually attached.
output "guardrail_id" {
  description = "Bedrock guardrail id (empty when controls disabled)."
  value       = local.guardrail_id
}

# The model/inference-profile the assistant calls — useful context for understanding cost/latency
# and guardrail behavior. Not sensitive; it's just an identifier.
output "bedrock_model_id" {
  description = "The model/inference-profile id the assistant invokes."
  value       = var.bedrock_model_id
}
