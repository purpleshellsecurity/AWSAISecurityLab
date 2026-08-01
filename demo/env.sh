#!/usr/bin/env bash
# Convenience: `source ./demo/env.sh` to load API_URL and API_KEY into your shell.
# Meant to be sourced (not executed) so the exported vars persist in your current shell session.

# Resolve the terraform/ directory relative to this script. ${BASH_SOURCE[0]:-$0} works whether the
# file is sourced (BASH_SOURCE is set) or run directly (fall back to $0).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../terraform" && pwd)"
# Pull the live endpoint + API key straight from Terraform state so they always match the deployment.
export API_URL="$(terraform -chdir="$DIR" output -raw api_invoke_url)"
export API_KEY="$(terraform -chdir="$DIR" output -raw api_key_value)"
# Confirm the URL but never echo the key (it's a secret; keep it out of scrollback/logs).
echo "Loaded API_URL=${API_URL}  (API_KEY hidden)"
