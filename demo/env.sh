#!/usr/bin/env bash
# Convenience: `source ./demo/env.sh` to load API_URL and API_KEY into your shell.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../terraform" && pwd)"
export API_URL="$(terraform -chdir="$DIR" output -raw api_invoke_url)"
export API_KEY="$(terraform -chdir="$DIR" output -raw api_key_value)"
echo "Loaded API_URL=${API_URL}  (API_KEY hidden)"
