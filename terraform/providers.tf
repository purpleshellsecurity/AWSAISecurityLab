provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "ai-rag-security-lab"
      Source  = "rag-incident-reproduction"
      Owner   = var.owner
    }
  }
}
