# =============================================================================
# versions.tf - Terraform + provider version constraints (the "supply chain"
# pinning for the whole lab)
# =============================================================================
# This file provisions no infrastructure. It declares which version of the
# Terraform CLI and which provider plugins are allowed to build this lab.
#
# Why this matters for security:
#   - Provider plugins are executable code downloaded from a registry. Pinning a
#     major version (~>) and committing the accompanying .terraform.lock.hcl
#     checksum file is how you prevent a malicious or accidentally-broken
#     provider release from silently entering your build. This is
#     Infrastructure-as-Code supply-chain hygiene. Commit the lock file that
#     `terraform init` generates - the checksums in it are the actual
#     supply-chain control; a constraint alone only narrows the version range.
#   - Newer AWS provider versions ship the resource schemas this lab depends on
#     (Bedrock guardrails, modern S3 encryption/public-access-block resources).
#     Pinning to one major version guarantees those security controls are
#     expressible AND that a future major release can't silently change resource
#     behavior underneath the lab.
terraform {
  # Require a reasonably modern Terraform CLI. Older versions lack features and
  # bug/security fixes this configuration assumes.
  required_version = ">= 1.5"

  required_providers {
    # hashicorp/aws: the provider that creates every AWS control in this lab
    # (KMS, IAM, S3, Bedrock, WAF, etc.). v6 is required: main.tf reads
    # data.aws_region.current.region, an attribute introduced in 6.0 (5.x only
    # has the deprecated .name), so a 5.x provider fails validate. ~> 6.0 allows
    # 6.x minor/patch updates but blocks a future 7.0 from entering unreviewed.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # hashicorp/archive: zips the Lambda source into a deployable artifact.
    # Used at build time; not itself a runtime security control.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    # hashicorp/random: generates the service-account token stored in Secrets
    # Manager. Using a generated secret (vs. a hard-coded one) keeps a real
    # credential value out of the source tree and state-as-cleartext exposure.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}
