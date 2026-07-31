#!/usr/bin/env bash
# Shows what the detector found: recent detection log lines + any alarms currently in ALARM state.
# This is the fast "did my controls catch it?" check after running ./demo/replay.py.
set -euo pipefail  # -e: stop on first error  -u: error on unset vars  -o pipefail: catch piped failures

# Locate terraform/ relative to this script, then read the detector Lambda's log group name from it.
TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"
DETECTOR_LG="$(terraform -chdir="$TF_DIR" output -raw detector_log_group)"

# --- Recent detection findings -------------------------------------------------------------------
# Tail the detector's log group and keep only the structured finding lines (event=="detection").
# If nothing matches, remind the user the log subscription can lag ~30-60s.
echo "### Recent detections (last 10 min) ###"
aws logs tail "$DETECTOR_LG" --since 10m --format short 2>/dev/null | grep -i '"event": "detection"' \
  || echo "(no detections yet - give the log subscription 30-60s and retry)"

echo
# --- Alarms currently firing ---------------------------------------------------------------------
# List CloudWatch alarms that are in ALARM state and belong to this lab (name prefix ai-rag-lab).
echo "### Alarms currently in ALARM ###"
aws cloudwatch describe-alarms --state-value ALARM \
  --query "MetricAlarms[?starts_with(AlarmName, 'ai-rag-lab')].AlarmName" --output table \
  || echo "(none)"
