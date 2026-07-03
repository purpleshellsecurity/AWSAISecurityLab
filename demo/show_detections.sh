#!/usr/bin/env bash
# Shows what the detector found: recent detection log lines + any alarms currently in ALARM state.
set -euo pipefail
TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"
DETECTOR_LG="$(terraform -chdir="$TF_DIR" output -raw detector_log_group)"

echo "### Recent detections (last 10 min) ###"
aws logs tail "$DETECTOR_LG" --since 10m --format short 2>/dev/null | grep -i '"event": "detection"' \
  || echo "(no detections yet - give the log subscription 30-60s and retry)"

echo
echo "### Alarms currently in ALARM ###"
aws cloudwatch describe-alarms --state-value ALARM \
  --query "MetricAlarms[?starts_with(AlarmName, 'ai-rag-lab')].AlarmName" --output table \
  || echo "(none)"
