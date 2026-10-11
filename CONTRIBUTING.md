# Contributing

Thanks for working on the lab. This guide keeps things consistent and safe.

## Setup

```bash
git clone <repo>
cd aws-ai-security-lab
./scripts/preflight.sh   # checks AWS creds, Terraform, region, Bedrock access
```

Optionally install the local guards (recommended — they block committing secrets):

```bash
pip install pre-commit
pre-commit install
```

## The golden rule: never commit secrets or state

Terraform state/plans hold the API key and generated tokens. These are gitignored, and pre-commit +
CI guard against them, but stay alert. If you ever see `*.tfstate`, `*.tfplan`, or `*.tfvars` in a
diff, stop.

## Branching & commits

- Work on a branch, open a PR into `main` (don't push directly to `main`).
- Use **Conventional Commits** for messages:
  - `feat:` a new control, scenario, or detection
  - `fix:` a bug fix
  - `docs:` documentation only
  - `chore:` tooling/repo plumbing
  - `refactor:` behavior-preserving code change
- Keep commits atomic (one logical change) with a clear subject line.

## Before you push

CI runs these; run them locally first:

```bash
terraform -chdir=terraform fmt -check -recursive && terraform -chdir=terraform validate
python -m py_compile src/chat/handler.py src/detector/handler.py demo/replay.py
python -c "import json,glob;[json.load(open(f)) for f in glob.glob('demo/scenarios/*.json')]"
python -m pytest tests/ -q   # unit tests for both Lambdas (pip install pytest boto3)
```

## CI runner isolation

CI runs on the dedicated production-scoped self-hosted runner. Pushes and pull requests from
branches in this repository run validation; pull requests from forks are intentionally skipped so
untrusted fork code cannot execute on the self-hosted runner.

## How to extend the lab

See **[TUTORIAL.md](TUTORIAL.md) §8 (Extending it)** for the details. In short:

- **New attack scenario** — add a JSON file to `demo/scenarios/`, tag it with its MITRE ATLAS ID.
  No code change unless it needs a new control. Schema: `demo/scenarios/README.md`.
- **New control** — enforcement in `src/chat/handler.py` (gate it on `CONTROLS_ENABLED`), infra in a
  `.tf` file. Then map it in `docs/controls-matrix.md`, `docs/atlas-mapping.md`, `docs/owasp-mapping.md`.
- **New detection** — add a function in `src/detector/handler.py`, register its metric in `alert()`,
  add an alarm entry to `local.detections` in `terraform/detections.tf`.

## Documentation expectations

Every control should trace three ways: the incident finding (`controls-matrix.md`), the attacker
technique (`atlas-mapping.md`), and the prevention standard (`owasp-mapping.md`). If you add a
control, update all three and add a row to `CHANGELOG.md`.
