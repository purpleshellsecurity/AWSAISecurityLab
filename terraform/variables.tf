# =============================================================================
# variables.tf - Tunable inputs for the lab (the "knobs" that shape its
# security posture)
# =============================================================================
# Every input that changes how the lab is deployed lives here. Several of these
# are not cosmetic - they directly control the security behavior you are meant
# to study:
#   - controls_enabled flips the whole system between "vulnerable" and
#     "hardened" so you can watch the same attack succeed then fail.
#   - allowed_edge_cidrs is the real network perimeter (WAF / API Gateway).
#   - internal_cidrs, guardrail strength, rate limits and token-deviation
#     factor tune the detection and prevention layers.
# Defaults are chosen so the lab runs from a laptop out of the box; the
# comments call out which defaults are "convenience" vs. "secure".

# region: the single AWS region everything is built in. Bedrock foundation-model
# access must be explicitly enabled in this region or the chat Lambda cannot
# invoke the model. Pinning one region keeps the audit/blast-radius footprint
# small and predictable.
variable "region" {
  description = "AWS region. Bedrock model access must be enabled here."
  type        = string
  default     = "us-east-1"
}

# owner: value for the Owner tag stamped on every resource (see providers.tf).
# Ownership tagging is a governance control - it establishes accountability and
# speeds up incident response and cleanup.
variable "owner" {
  description = "Tag applied to all resources."
  type        = string
  default     = "security-lab"
}

# name_prefix: prepended to every resource name (and the KMS alias, secret path,
# CloudWatch namespace, etc.). Consistent, predictable naming makes resources
# easy to find, audit, and scope IAM policies to - and avoids collisions if the
# lab is deployed more than once.
variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "ai-rag-lab"
}

# bedrock_model_id: which model the chat Lambda invokes. This value also feeds
# the least-privilege IAM ARN math in main.tf, so it is a security-relevant
# input, not just a functional one - the Lambda is permitted to call this model
# and no other.
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

# bedrock_foundation_model_id: the concrete model behind the inference profile.
# Used purely to construct the foundation-model ARNs in the Lambda's IAM policy.
# Must stay in sync with bedrock_model_id, otherwise IAM grants access to a
# model the app doesn't call (over-grant) or omits the one it does (breakage).
variable "bedrock_foundation_model_id" {
  description = <<-EOT
    The underlying foundation-model id that the inference profile routes to. Used only to build the
    IAM resource ARNs the Lambda is allowed to invoke. Keep in sync with bedrock_model_id.
  EOT
  type        = string
  default     = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

# bedrock_inference_regions: the exact regions the cross-region inference
# profile may route to. The Lambda gets InvokeModel on the foundation model in
# each - listing only these regions (not "*") is what keeps model access
# least-privilege. Add a region here only if the profile genuinely uses it.
variable "bedrock_inference_regions" {
  description = <<-EOT
    Regions the cross-region inference profile can route requests to. The Lambda's IAM policy grants
    InvokeModel on the foundation model in each of these (required for cross-region inference). These
    are the regions a "us." Anthropic profile uses.
  EOT
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

# internal_cidrs: the SIMULATED "internal" network for the attack scenario. This
# is an application-layer trust boundary - the Lambda and detector compare the
# request's self-reported x_source_ip field against this range to decide if a
# caller is "internal". It teaches a key lesson: trusting a client-supplied
# source-IP field is spoofable, which is exactly how the demo attack claims to
# be internal. It does NOT control real network reachability (that's the next
# variable).
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

# allowed_edge_cidrs: the REAL network perimeter. Enforced at the edge by WAF
# and the API Gateway resource policy against your actual TCP connection IP,
# which (unlike x_source_ip above) cannot be spoofed by a request field. Default
# 0.0.0.0/0 is open for laptop convenience; narrowing it to your own /32 is the
# genuine defense-in-depth control that returns 403 to everyone else at the WAF.
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

# guardrail_prompt_attack_strength: tunes the Bedrock Guardrail's prompt-injection
# filter (OWASP LLM01). This is a prevention control - stronger settings catch
# more injection attempts but raise false positives. It has a validation block
# below so an invalid value fails fast at plan time rather than misconfiguring
# the guardrail silently.
variable "guardrail_prompt_attack_strength" {
  description = <<-EOT
    Strength of the Bedrock guardrail's prompt-attack (injection) filter. HIGH false-positives on some
    benign prompts; MEDIUM (default) still catches overt injection with far fewer false positives.
  EOT
  type        = string
  default     = "MEDIUM"
  # Input validation is a security control in its own right: reject bad values at
  # plan time instead of letting a typo weaken the guardrail at runtime.
  validation {
    condition     = contains(["NONE", "LOW", "MEDIUM", "HIGH"], var.guardrail_prompt_attack_strength)
    error_message = "Must be one of NONE, LOW, MEDIUM, HIGH."
  }
}

# controls_enabled: the master vulnerable/hardened switch and the pedagogical
# heart of the lab. false rebuilds the original insecure system (no guardrail,
# no retrieval-layer authorization, no source-IP restriction) so you can watch
# the attack succeed; true turns every control back on so you can watch it fail.
variable "controls_enabled" {
  description = <<-EOT
    Master switch for the remediation controls. true (default) = hardened system that blocks the
    attack. false = reproduces the original vulnerable system (no guardrail, no retrieval-layer
    authz, no source-IP restriction) so you can demonstrate the attack succeeding.
  EOT
  type        = bool
  default     = true
}

# rate_limit_per_5min: threshold for the WAF rate-based rule. A prevention
# control against brute-force / scraping / denial-of-wallet abuse - once a
# single source IP exceeds this many requests per 5-minute window, WAF blocks
# it. Lower = more aggressive throttling.
variable "rate_limit_per_5min" {
  description = "WAF rate-based rule limit per 5-minute window per source IP."
  type        = number
  default     = 300
}

# token_deviation_factor: sensitivity of the anomaly detector. A detective
# control for LLM abuse / data-exfiltration and cost spikes (OWASP LLM10,
# denial-of-wallet) - if a principal suddenly burns this many times its
# historical token baseline, an alarm fires. Lower = more sensitive.
variable "token_deviation_factor" {
  description = "Detection 4: alert when a principal's windowed token usage exceeds baseline by this factor."
  type        = number
  default     = 10
}

# service_accounts: the identities Detection 1 treats as service accounts. Seeing
# any of these authenticate from a non-internal source is the incident's initial-
# access signature. A variable (not a hard-coded env string) because detection
# identity lists are tuning knobs, same as token_deviation_factor.
variable "service_accounts" {
  description = "Detection 1: identities treated as service accounts; any use from a non-internal source alerts."
  type        = list(string)
  default     = ["enso-rag-svc", "enso-vector-svc", "enso-assistant-api"]
}

# high_volume_allowlist: principals exempt from Detection 4 (token-volume
# deviation). Legitimate bulk jobs (e.g. a batch indexer) would otherwise trip
# the spike detection constantly - allow-listing them is standard detection
# tuning to keep the alert high-signal.
variable "high_volume_allowlist" {
  description = "Detection 4: principals exempt from the token-volume deviation detection (known bulk jobs)."
  type        = list(string)
  default     = ["batch-indexer"]
}

# alarm_email: where security alarms are delivered. Optional so the lab runs
# without email, but wiring a real inbox to the SNS topic is what turns a
# detection into an actual notified response. Empty = read alarms in-console
# only.
variable "alarm_email" {
  description = "Optional email to subscribe to the SNS alarm topic. Leave empty to skip (you can still read alarms in the console / via the demo script)."
  type        = string
  default     = ""
}

# demo_user_password: the permanent password stamped on every seeded Cognito
# user (cognito.tf) so the demo can fetch JWTs non-interactively. This is a
# DEMO credential for disposable lab accounts, not a real secret — but it is a
# credential: it lives in Terraform state, so protect the state backend, and
# override it (TF_VAR_demo_user_password=...) rather than shipping the default.
# Must satisfy the pool's password policy (>=12 chars, upper/lower/number/symbol).
variable "demo_user_password" {
  description = "Permanent password for the seeded Cognito demo users (override in production; must meet the pool password policy)."
  type        = string
  default     = "LabDemo#Passw0rd!"
  sensitive   = true
}
