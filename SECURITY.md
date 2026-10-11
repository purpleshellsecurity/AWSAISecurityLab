# Security Policy

## ⚠️ This is a security *lab*, not production software

This repository intentionally contains material that is dangerous if misused. Read this before
deploying.

- **It ships a deliberately poisoned document** (`corpus/Enso_Vendor_Onboarding_Memo.md`)
  containing embedded prompt-injection content, used to demonstrate indirect injection defenses.
- **It has a vulnerable mode.** `controls_enabled=false` intentionally disables
  the security controls so the attack succeeds. Never run that mode with real data.
- **It contains "lab affordances."** The API accepts `x_source_ip` and `simulate_tokens` in the
  request body so attacks can be reproduced without external infrastructure. These weaken trust
  boundaries and exist only for the lab — they must not exist in a real system.
- **The retrieval and injection-scanning are intentionally simplified** (keyword scoring, regex
  scanning) to teach concepts. They are not production-grade detection.

**Do not deploy this to an account containing sensitive data, and do not treat it as a hardened
reference implementation.** Use a personal/sandbox AWS account, and run `terraform -chdir=terraform destroy` when finished.

## Handling secrets

- Never commit Terraform state (`*.tfstate`), plans (`*.tfplan`), or `*.tfvars` — they contain the
  API key and generated tokens. These are gitignored; the pre-commit hooks and CI also guard against
  accidental secret commits.
- Real credentials belong in AWS Secrets Manager (see `secrets.tf`), never in the corpus or the
  system prompt.

## Reporting a vulnerability

This is a personal learning project. If you find a security issue in the lab itself (e.g. a control
that doesn't actually enforce what it claims), open a GitHub issue using the "Bug report" template,
or contact the repository owner directly. Please do not include real secrets or customer data in any
report.

## Cost safety

Deployed resources bill continuously until destroyed. Always run
`terraform -chdir=terraform destroy` when you are done.
