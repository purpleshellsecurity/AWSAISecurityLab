# =============================================================================
# versions.tf - Terraform + provider version constraints (the "supply chain"
# pinning for the whole lab)
# =============================================================================
# This file provisions no infrastructure. It declares which version of the
# Terraform CLI and which provider plugins are allowed to build this lab.
#
# Why this matters for security:
#   - Provider plugins are executable code downloaded from a registry. Pinning a
#     minimum (and, in stricter setups, an exact) version and relying on the
#     accompanying .terraform.lock.hcl checksum file is how you prevent a
#     malicious or accidentally-broken provider release from silently entering
#     your build. This is Infrastructure-as-Code supply-chain hygiene.
#   - Newer AWS provider versions ship the resource schemas this lab depends on
#     (Bedrock guardrails, modern S3 encryption/public-access-block resources).
#     Requiring a floor version guarantees those security controls are even
#     expressible.
terraform {
  # Require a reasonably modern Terraform CLI. Older versions lack features and
  # bug/security fixes this configuration assumes.
  required_version = ">= 1.5"

  required_providers {
    # hashicorp/aws: the provider that creates every AWS control in this lab
    # (KMS, IAM, S3, Bedrock, WAF, etc.). 5.40+ ensures the Bedrock guardrail
    # and current S3 security resource types are available.
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    # hashicorp/archive: zips the Lambda source into a deployable artifact.
    # Used at build time; not itself a runtime security control.
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
    # hashicorp/random: generates the service-account token stored in Secrets
    # Manager. Using a generated secret (vs. a hard-coded one) keeps a real
    # credential value out of the source tree and state-as-cleartext exposure.
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}
