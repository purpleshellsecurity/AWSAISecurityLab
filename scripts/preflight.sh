#!/usr/bin/env bash
# Preflight doctor: checks everything the lab needs and tells you exactly how to fix what's missing.
# Run it any time with:  ./scripts/preflight.sh
# Note: no `set -e` here on purpose — we want to run EVERY check and report all problems, not bail on
# the first failure. `-u` (unset vars are errors) and `-o pipefail` are still on.
set -uo pipefail

# Resolve the lab root and terraform/ directory relative to this script.
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$LAB_DIR/terraform"
# Tiny colored status helpers: green ✓ (ok), red ✗ (blocker), yellow ! (warning).
ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; }
bad()  { printf "  \033[31m✗\033[0m %s\n" "$1"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; }
problems=0  # count of hard blockers; drives the exit summary

echo "AI/RAG Security Lab — preflight check"
echo "-------------------------------------"

# 1. Tools
# Confirm the three CLIs the lab drives are installed; a missing one is a hard blocker.
if command -v aws >/dev/null 2>&1; then ok "AWS CLI installed ($(aws --version 2>&1 | awk '{print $1}'))";
else bad "AWS CLI not found — install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"; problems=$((problems+1)); fi

if command -v terraform >/dev/null 2>&1; then ok "Terraform installed ($(terraform version | head -1 | awk '{print $2}'))";
else bad "Terraform not found — install: https://developer.hashicorp.com/terraform/install"; problems=$((problems+1)); fi

if command -v python3 >/dev/null 2>&1; then ok "python3 installed";
else bad "python3 not found (needed by demo/replay.py)"; problems=$((problems+1)); fi

# 2. AWS credentials
# sts get-caller-identity is the cheapest "are my credentials valid?" probe.
if aws sts get-caller-identity >/dev/null 2>&1; then
  acct="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
  ok "AWS credentials work (account $acct)"
else
  bad "AWS credentials not working — run: aws configure   (or set AWS_PROFILE)"
  problems=$((problems+1))
fi

# 3. Region
# A default region must be resolvable (from CLI config or AWS_REGION); only a warning, not a blocker.
region="$(aws configure get region 2>/dev/null || echo "${AWS_REGION:-}")"
if [ -n "$region" ]; then ok "Region set: $region"; else warn "No default region — set one: aws configure set region us-east-1"; fi

# 4. Is the lab deployed?
# If `terraform output api_invoke_url` returns a value, infrastructure is already applied.
deployed=false
api_url="$(terraform -chdir="$TF_DIR" output -raw api_invoke_url 2>/dev/null || true)"
if [ -n "$api_url" ]; then
  deployed=true
  ok "Lab is DEPLOYED — endpoint: $api_url"
else
  warn "Lab is NOT deployed yet — run: terraform -chdir=terraform apply"
fi

# 5. Bedrock model access (the usual blocker)
# Bedrock model access is the most common thing that isn't ready. Prefer the deployment's configured
# model id; fall back to a sensible default if the lab isn't applied yet.
model="$(terraform -chdir="$TF_DIR" output -raw bedrock_model_id 2>/dev/null || true)"
[ -z "$model" ] && model="us.anthropic.claude-haiku-4-5-20251001-v1:0"
if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then
  # Do a real one-token converse call and classify the result to give a precise fix.
  out="$(aws bedrock-runtime converse --region "${region:-us-east-1}" --model-id "$model" \
        --messages '[{"role":"user","content":[{"text":"ping"}]}]' 2>&1)"
  if echo "$out" | grep -q '"text"'; then
    ok "Bedrock model reachable ($model)"                       # got a completion back — good
  elif echo "$out" | grep -qi "use case details"; then
    # This specific error means the one-time Anthropic use-case form hasn't been submitted.
    bad "Bedrock: submit the Anthropic use-case form once — Bedrock console > Model catalog > $model > Open in Playground"
    problems=$((problems+1))
  elif echo "$out" | grep -qi "legacy"; then
    # The chosen model is retired/legacy — the user must pick a current one.
    bad "Bedrock: '$model' is Legacy. Pick a current model and set var.bedrock_model_id (see README > Models)."
    problems=$((problems+1))
  else
    # Some other error (e.g. access not yet granted) — warn with the first error line for context.
    warn "Bedrock model not reachable yet: $(echo "$out" | grep -i error | head -1)"
  fi
fi

echo "-------------------------------------"
# --- Final summary: tell the user the single most useful next command ---------------------------
if [ "$problems" -eq 0 ]; then
  if $deployed; then
    echo "READY. Try:  ./demo/replay.py --scenario demo/scenarios/01_baseline_normal.json"
  else
    echo "READY to deploy. Run:  terraform -chdir=terraform init && terraform -chdir=terraform apply"
  fi
else
  echo "$problems blocker(s) above — fix those, then re-run: ./scripts/preflight.sh"
fi
exit 0  # always exit 0: this is a doctor/report, not a gate — the summary conveys pass/fail
