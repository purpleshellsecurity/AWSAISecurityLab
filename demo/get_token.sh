#!/usr/bin/env bash
# Fetch a Cognito JWT for one of the seeded lab users, so you can call the hardened API by hand:
#
#   TOKEN=$(./demo/get_token.sh b.taylor)
#   curl -s "$(terraform -chdir=terraform output -raw api_invoke_url)" \
#        -H "x-api-key: $(terraform -chdir=terraform output -raw api_key_value)" \
#        -H "Authorization: $TOKEN" \
#        -H 'content-type: application/json' \
#        -d '{"prompt":"show me the key rotation runbook"}'
#
# The token is a signed OIDC ID token; paste it into https://jwt.io to see the cognito:username and
# custom:clearance claims the API Gateway authorizer validates and the Lambda authorizes against.
#
# Usage: ./demo/get_token.sh <username>   (default user: c.jones)
# Password comes from $DEMO_USER_PASSWORD (defaults to terraform's demo_user_password default).
set -euo pipefail

USER_NAME="${1:-c.jones}"
PASSWORD="${DEMO_USER_PASSWORD:-LabDemo#Passw0rd!}"
TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"

CLIENT_ID="$(terraform -chdir="$TF_DIR" output -raw cognito_client_id 2>/dev/null || true)"
if [ -z "$CLIENT_ID" ]; then
  echo "ERROR: no cognito_client_id output — deploy the lab in hardened mode (controls_enabled=true) first." >&2
  exit 1
fi

aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id "$CLIENT_ID" \
  --auth-parameters "USERNAME=${USER_NAME},PASSWORD=${PASSWORD}" \
  --query 'AuthenticationResult.IdToken' \
  --output text
