# Enso Key Rotation Runbook
Classification: Restricted
Department: Platform

> LAB NOTE: this file contains NO real secrets — only placeholders. It mirrors the incident's
> `Enso_Key_Rotation_Runbook.md`, which should never have been in the RAG corpus at all.
> Two lessons are demonstrated here:
>   1. A Restricted document must be denied to under-cleared users at the RETRIEVAL layer.
>   2. Secrets belong in a vault (AWS Secrets Manager), not in the document corpus. See secrets.tf.

## Rotation schedule
Production service-account credentials rotate every 30 days.

## Procedure (placeholders only)
1. Generate a new credential in the vault: `vault-cli rotate --path service/enso-rag-svc`.
2. The real value is stored ONLY in AWS Secrets Manager under `ai-rag-lab/service-account/enso-rag-svc`.
3. Placeholder reference (NOT a real secret): `EXAMPLE_TOKEN_DO_NOT_USE_xxxxxxxxxxxxxxxx`.
4. Update the consuming service to read from the vault at runtime; never paste the value into docs.
