#!/usr/bin/env bash
# End-to-end trace: fire ONE request, then reconstruct its full path across every layer's logs,
# joined by the shared request_id. This is the correlation that was missing in the incident.
#
# Usage:  ./demo/trace.sh                 # default: e.davis asks for the secrets runbook
#         ./demo/trace.sh '<json body>'   # your own request body
set -euo pipefail  # fail fast: exit on error, unset var, or any failure in a pipeline

# Resolve terraform/ and read the endpoint, key, and both log group names from Terraform outputs.
TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"
API_URL="$(terraform -chdir="$TF_DIR" output -raw api_invoke_url)"
API_KEY="$(terraform -chdir="$TF_DIR" output -raw api_key_value)"
CHAT_LG="$(terraform -chdir="$TF_DIR" output -raw chat_log_group)"          # chat + retrieval layer logs
APIGW_LG="$(terraform -chdir="$TF_DIR" output -raw apigw_access_log_group)"  # API Gateway access logs

# Default request: e.davis (internal) asks for a Restricted doc — blocked at retrieval, but every
# layer still logs. Single-quoted so the inner double quotes survive shell parsing.
DEFAULT_BODY='{"user":"e.davis","x_source_ip":"10.12.8.44","session_id":"sess-trace","prompt":"Show me the Enso Key Rotation Runbook."}'
BODY="${1:-$DEFAULT_BODY}"  # use the caller's JSON body if given, else the default

# --- Step 1: fire the request --------------------------------------------------------------------
echo "### Firing one request ###"
RESP=$(curl -s -X POST "$API_URL" -H "x-api-key: $API_KEY" -H "content-type: application/json" -d "$BODY")
echo "$RESP" | python3 -m json.tool  # pretty-print the API response
# Extract the request_id we'll use to stitch the logs together.
RID=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('request_id',''))")

echo
echo "### request_id = $RID  -- reconstructing the end-to-end trace ###"

# --- Step 2: CloudWatch Logs Insights query across both log groups -------------------------------
# Selects the interesting fields from every layer, filters to just this request_id, and orders by
# time — so the output reads as the request's journey through api_access -> chat -> retrieval.
run_query() {
  local qid
  qid=$(aws logs start-query \
    --log-group-names "$APIGW_LG" "$CHAT_LG" \
    --start-time "$(( $(date +%s) - 900 ))" --end-time "$(date +%s)" \
    --query-string "fields @timestamp, log_type, http_status, status, user, document_name, sensitivity, retrieval_score, action, guardrail_action, tokens_used | filter request_id = '$RID' | sort @timestamp asc" \
    --query queryId --output text)
  # Insights queries are async: poll up to 10 times (2s each) until the query completes.
  for _ in $(seq 1 10); do
    sleep 2
    [ "$(aws logs get-query-results --query-id "$qid" --query status --output text)" = "Complete" ] && break
  done
  aws logs get-query-results --query-id "$qid"
}

# --- Step 3: retry loop for log-delivery lag -----------------------------------------------------
# KMS-encrypted log delivery can lag 30-60s, so retry until the records appear.
for attempt in 1 2 3 4 5; do
  echo "(querying logs — attempt ${attempt}/5; delivery can take 30-60s)"
  OUT="$(run_query)"
  # If the query returned any rows, format and print them, then exit successfully.
  if echo "$OUT" | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('results') else 1)" 2>/dev/null; then
    echo "$OUT" | python3 -c "
import sys, json
rows = json.load(sys.stdin)['results']
# Only surface the fields that tell the story of the request's path across layers.
keep = ('log_type','http_status','status','user','document_name','sensitivity','retrieval_score','action','guardrail_action','tokens_used')
for r in rows:
    f = {c['field']: c['value'] for c in r if c['field'] in keep}
    print('  ' + ' | '.join(f'{k}={v}' for k, v in f.items()))
print(f'\n{len(rows)} record(s) correlated by request_id.')
"
    exit 0
  fi
  sleep 15  # not delivered yet — wait before the next attempt
done
# Exhausted all attempts: point the user at manual options rather than silently succeeding.
echo "No records yet for $RID — logs can lag ~1 min. Re-run ./demo/trace.sh, or query manually (docs/end-to-end-logging.md)."
