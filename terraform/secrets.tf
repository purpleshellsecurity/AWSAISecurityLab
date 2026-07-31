# =============================================================================
# secrets.tf - The credential vault (OWASP LLM07: Insecure Plugin/Secrets
# handling)
# =============================================================================
# This file provisions AWS Secrets Manager storage for the service-account
# credential, encrypted with the lab's CMK.
#
# The lesson it teaches:
#   In the modeled incident, Enso_Key_Rotation_Runbook.md sat INSIDE the RAG
#   corpus and a service-account credential looked compromised. Anything in the
#   corpus can be surfaced by the model to a user, and anything in the system
#   prompt can be extracted by prompt injection. So credentials must NEVER live
#   in the corpus or the prompt - they belong in a vault with its own access
#   control, encryption, and rotation. This file is that vault, and its
#   existence is the "right way" contrast to the incident's mistake.

# random_password.svc_token: generates the secret value in Terraform rather than
# hard-coding a credential in source. special=false keeps it to an
# alphanumeric, easy-to-handle token for the lab. NOTE: a Terraform-generated
# password is stored in Terraform STATE in cleartext, so in production the state
# backend itself must be encrypted and access-controlled.
resource "random_password" "svc_token" {
  length  = 40
  special = false
}

# aws_secretsmanager_secret.svc_creds: the secret container - metadata, name,
# and (critically) the encryption key. This is where the enso-rag-svc credential
# SHOULD live. Only the chat Lambda role is granted GetSecretValue on this exact
# ARN (see iam.tf), so access is least-privilege and fully auditable in
# CloudTrail.
resource "aws_secretsmanager_secret" "svc_creds" {
  name        = "${local.prefix}/service-account/enso-rag-svc"
  description = "Where the enso-rag-svc service credential SHOULD live (not in the corpus)."
  # Encrypt the secret at rest with the lab CMK (not the default AWS-managed
  # key), so the KMS key policy provides an independent second gate on who can
  # actually decrypt the credential.
  kms_key_id  = aws_kms_key.main.arn

  # Lab convenience: hard-delete on destroy (no 30-day recovery window) so the name frees up
  # immediately and the lab can be torn down and redeployed cleanly.
  # SECURITY NOTE: in production you normally KEEP a recovery window (7-30 days)
  # so an accidental or malicious delete of a live credential can be undone.
  recovery_window_in_days = 0
}

# aws_secretsmanager_secret_version.svc_creds: the actual secret payload (the
# JSON blob holding the account name, generated token, and a rotation-days
# hint). Storing rotation intent alongside the secret models the expectation
# that this credential is rotated on a schedule - the very control the incident
# runbook was about.
resource "aws_secretsmanager_secret_version" "svc_creds" {
  secret_id = aws_secretsmanager_secret.svc_creds.id
  secret_string = jsonencode({
    service_account = "enso-rag-svc"
    token           = random_password.svc_token.result
    rotation_days   = 30
  })
}
