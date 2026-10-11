# =============================================================================
# providers.tf - Configures the AWS provider (region + universal tagging)
# =============================================================================
# This file tells the AWS provider WHERE to build (region) and stamps every
# resource with identifying tags.
#
# Why this matters for security:
#   - Region selection is a data-residency and blast-radius decision. Bedrock
#     model access must be explicitly enabled in the chosen region, so the whole
#     lab is pinned to one region for a predictable, auditable footprint.
#   - default_tags applies consistent metadata to EVERY resource automatically.
#     Tagging is a foundational security/governance control: it powers cost
#     attribution, ownership/incident routing, and tag-based access policies and
#     resource discovery during an investigation. "Untagged mystery resources"
#     are a classic source of shadow risk.
provider "aws" {
  # Single region for the entire lab. Bedrock foundation-model access must be
  # granted in this region for the chat Lambda to work.
  region = var.region

  # default_tags: merged onto all taggable resources this provider creates, so
  # you never have to remember to tag each one individually.
  default_tags {
    tags = {
      # Project/Source identify these resources as belonging to this lab and
      # make cleanup / auditing unambiguous.
      Project     = "ai-rag-security-lab"
      Source      = "rag-incident-reproduction"
      Environment = var.environment_id
      # Owner establishes accountability - who to contact if a resource behaves
      # unexpectedly or needs to be torn down.
      Owner = var.owner
    }
  }
}
