variable "region" {
  description = "AWS region. Bedrock model access must be enabled here."
  type        = string
  default     = "us-east-1"
}

variable "owner" {
  description = "Tag applied to all resources."
  type        = string
  default     = "security-lab"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "ai-rag-lab"
}

variable "bedrock_model_id" {
  description = <<-EOT
    The model identifier the Lambda passes to the Converse API. Default is the Claude Haiku 4.5
    cross-region inference profile (current + cheap). Haiku 4.5 is INFERENCE_PROFILE-only, so this is
    the "us." profile id, not the bare model id. For Anthropic models a first-time account must submit
    the use-case details form once (Bedrock console > Model catalog).
  EOT
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "bedrock_foundation_model_id" {
  description = <<-EOT
    The underlying foundation-model id that the inference profile routes to. Used only to build the
    IAM resource ARNs the Lambda is allowed to invoke. Keep in sync with bedrock_model_id.
  EOT
  type        = string
  default     = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "bedrock_inference_regions" {
  description = <<-EOT
    Regions the cross-region inference profile can route requests to. The Lambda's IAM policy grants
    InvokeModel on the foundation model in each of these (required for cross-region inference). These
    are the regions a "us." Anthropic profile uses.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "internal_cidrs" {
  description = <<-EOT
    The scenario's logical "internal" range, mirroring the incident's 10.12.0.0/16. The chat Lambda
    and the detector check the *simulated* source IP (the x_source_ip request field) against this, so
    a request claiming to come from 198.51.100.23 is treated as external. This drives the app-level
    demo and detections; it is NOT what makes the API reachable (see allowed_edge_cidrs).
  EOT
  type        = list(string)
  default     = ["10.12.0.0/16"]
}

variable "allowed_edge_cidrs" {
  description = <<-EOT
    The CIDRs allowed to actually reach the API at the network edge (WAF + API Gateway resource
    policy act on your REAL connection IP). Default 0.0.0.0/0 so you can run the lab from your laptop
    and drive the attack simulation via x_source_ip. To demo the edge control for real, set this to
    your own IP (e.g. ["203.0.113.5/32"]) and watch any other source get a 403 at the WAF.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "guardrail_prompt_attack_strength" {
  description = <<-EOT
    Strength of the Bedrock guardrail's prompt-attack (injection) filter. HIGH false-positives on some
    benign prompts; MEDIUM (default) still catches overt injection with far fewer false positives.
  EOT
  type        = string
  default     = "MEDIUM"
  validation {
    condition     = contains(["NONE", "LOW", "MEDIUM", "HIGH"], var.guardrail_prompt_attack_strength)
    error_message = "Must be one of NONE, LOW, MEDIUM, HIGH."
  }
}

variable "controls_enabled" {
  description = <<-EOT
    Master switch for the remediation controls. true (default) = hardened system that blocks the
    attack. false = reproduces the original vulnerable system (no guardrail, no retrieval-layer
    authz, no source-IP restriction) so you can demonstrate the attack succeeding.
  EOT
  type        = bool
  default     = true
}

variable "rate_limit_per_5min" {
  description = "WAF rate-based rule limit per 5-minute window per source IP."
  type        = number
  default     = 300
}

variable "token_deviation_factor" {
  description = "Detection 3: alert when a principal's windowed token usage exceeds baseline by this factor."
  type        = number
  default     = 10
}

variable "alarm_email" {
  description = "Optional email to subscribe to the SNS alarm topic. Leave empty to skip (you can still read alarms in the console / via the demo script)."
  type        = string
  default     = ""
}
