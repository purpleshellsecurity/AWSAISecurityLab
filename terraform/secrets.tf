# Secrets Management (OWASP LLM07).
# In the incident, Enso_Key_Rotation_Runbook.md sat in the RAG corpus and a service-account
# credential looked compromised. The lesson: credentials live in a vault, never in the corpus and
# never in the system prompt. This is the vault.

resource "random_password" "svc_token" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "svc_creds" {
  name        = "${local.prefix}/service-account/enso-rag-svc"
  description = "Where the enso-rag-svc service credential SHOULD live (not in the corpus)."
  kms_key_id  = aws_kms_key.main.arn

  # Lab convenience: hard-delete on destroy (no 30-day recovery window) so the name frees up
  # immediately and the lab can be torn down and redeployed cleanly.
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "svc_creds" {
  secret_id = aws_secretsmanager_secret.svc_creds.id
  secret_string = jsonencode({
    service_account = "enso-rag-svc"
    token           = random_password.svc_token.result
    rotation_days   = 30
  })
}
