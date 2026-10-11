#!/usr/bin/env bash
# Manual finding/alarms inspection. The replay CLI now performs request-scoped
# detection checks automatically for scenarios with expected_detections.
set -euo pipefail
TF_DIR="$(cd "$(dirname "$0")/../terraform" && pwd)"
DETECTOR_LG="$(terraform -chdir="$TF_DIR" output -raw detector_log_group)"

echo "Detector findings — last 10 minutes (all requests)"
if ! LOGS="$(aws logs tail "$DETECTOR_LG" --since 10m --format short)"; then
  echo "ERROR: Could not read CloudWatch detector logs. Check AWS identity/permissions." >&2
  exit 1
fi
if printf '%s\n' "$LOGS" | grep -F '"event": "detection"'; then
  :
else
  echo "No detector findings observed. This is expected for normal baseline traffic."
  echo "Note: an empty result does not prove detector or notification delivery health."
fi

echo
echo "Alarms currently in ALARM"
# Ask AWS for matching alarms without losing nonzero exit codes.
if ! ALARMS="$(aws cloudwatch describe-alarms --state-value ALARM \
  --query "MetricAlarms[?starts_with(AlarmName, 'ai-rag-lab')].AlarmName" --output text)"; then
  echo "ERROR: Could not query CloudWatch alarm state." >&2
  exit 1
fi
if [[ -n "$ALARMS" && "$ALARMS" != "None" ]]; then
  printf '%s\n' "$ALARMS"
else
  echo "None currently in ALARM (alarms may have returned to OK)."
fi
