#!/usr/bin/env bash
# =============================================================================
# CloudTrail Security Audit Script
# =============================================================================
# Audits AWS CloudTrail configuration for common security issues:
#   - At least one trail is enabled and logging
#   - Multi-region trail coverage
#   - Log file validation enabled
#   - S3 bucket access logging for trail bucket
#   - CloudWatch Logs integration
#   - S3 bucket does NOT have public access
#   - KMS encryption of log files
#   - Global service events (IAM, STS, etc.) captured
#
# Prerequisites:
#   - AWS CLI configured with sufficient permissions
#   - jq installed
#
# Usage:
#   ./cloudtrail_audit.sh [--region <region>]
#
# Required IAM permissions:
#   cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus,
#   cloudtrail:GetEventSelectors,
#   s3:GetBucketPublicAccessBlock, s3:GetBucketLogging,
#   s3:GetBucketAcl
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REGION=""

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' YELLOW='' GREEN='' CYAN='' BOLD='' RESET=''
fi

log_info()   { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()     { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()   { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_fail()   { echo -e "${RED}[FAIL]${RESET}  $*"; }
log_header() { echo -e "\n${BOLD}========== $* ==========${RESET}"; }

FINDINGS=0
record_finding() { FINDINGS=$((FINDINGS + 1)); log_fail "$*"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --region) REGION="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | head -30
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

AWS_ARGS=()
[[ -n "$REGION" ]] && AWS_ARGS+=(--region "$REGION")

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
for cmd in aws jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is required but not installed." >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 1. Fetch all trails (include shadow trails)
# ---------------------------------------------------------------------------
log_header "CloudTrail Trails"

TRAILS_JSON=$(aws cloudtrail describe-trails \
    "${AWS_ARGS[@]}" \
    --include-shadow-trails \
    --output json 2>/dev/null)

TRAIL_COUNT=$(echo "$TRAILS_JSON" | jq '.trailList | length')

if [[ "$TRAIL_COUNT" -eq 0 ]]; then
    record_finding "No CloudTrail trails found in this account/region."
    log_header "Summary"
    log_warn "Total CloudTrail findings: $FINDINGS"
    exit 0
fi

log_info "Found $TRAIL_COUNT trail(s)."

# ---------------------------------------------------------------------------
# 2. Check for at least one active multi-region trail
# ---------------------------------------------------------------------------
ACTIVE_MULTIREGION=0

while IFS= read -r TRAIL_ARN; do
    TRAIL=$(echo "$TRAILS_JSON" | jq -r --arg arn "$TRAIL_ARN" '.trailList[] | select(.TrailARN == $arn)')
    TRAIL_NAME=$(echo "$TRAIL" | jq -r '.Name')
    HOME_REGION=$(echo "$TRAIL" | jq -r '.HomeRegion')
    IS_MULTIREGION=$(echo "$TRAIL" | jq -r '.IsMultiRegionTrail')

    log_header "Trail: $TRAIL_NAME ($HOME_REGION)"

    # Trail status (logging on/off)
    TRAIL_STATUS=$(aws cloudtrail get-trail-status \
        --name "$TRAIL_ARN" \
        --region "$HOME_REGION" \
        --output json 2>/dev/null || echo '{}')

    IS_LOGGING=$(echo "$TRAIL_STATUS" | jq -r '.IsLogging // false')

    if [[ "$IS_LOGGING" == "true" ]]; then
        log_ok "Trail '$TRAIL_NAME' is actively logging."
    else
        record_finding "Trail '$TRAIL_NAME' is NOT logging."
    fi

    # Multi-region
    if [[ "$IS_MULTIREGION" == "true" ]]; then
        log_ok "Trail '$TRAIL_NAME' is multi-region."
        [[ "$IS_LOGGING" == "true" ]] && ACTIVE_MULTIREGION=$((ACTIVE_MULTIREGION + 1))
    else
        record_finding "Trail '$TRAIL_NAME' is NOT multi-region. Consider enabling multi-region trails."
    fi

    # Log file validation
    LOG_VALIDATION=$(echo "$TRAIL" | jq -r '.LogFileValidationEnabled // false')
    if [[ "$LOG_VALIDATION" == "true" ]]; then
        log_ok "Trail '$TRAIL_NAME': log file validation is enabled."
    else
        record_finding "Trail '$TRAIL_NAME': log file validation is NOT enabled."
    fi

    # KMS encryption
    KMS_KEY=$(echo "$TRAIL" | jq -r '.KMSKeyId // ""')
    if [[ -n "$KMS_KEY" ]]; then
        log_ok "Trail '$TRAIL_NAME': logs are KMS-encrypted (key: $KMS_KEY)."
    else
        record_finding "Trail '$TRAIL_NAME': logs are NOT KMS-encrypted."
    fi

    # CloudWatch Logs integration
    CWL_ARN=$(echo "$TRAIL" | jq -r '.CloudWatchLogsLogGroupArn // ""')
    if [[ -n "$CWL_ARN" ]]; then
        log_ok "Trail '$TRAIL_NAME': CloudWatch Logs integration enabled ($CWL_ARN)."
    else
        record_finding "Trail '$TRAIL_NAME': CloudWatch Logs integration is NOT configured."
    fi

    # Global service events (IAM/STS)
    GLOBAL_EVENTS=$(echo "$TRAIL" | jq -r '.IncludeGlobalServiceEvents // false')
    if [[ "$GLOBAL_EVENTS" == "true" ]]; then
        log_ok "Trail '$TRAIL_NAME': global service events (IAM/STS) are captured."
    else
        record_finding "Trail '$TRAIL_NAME': global service events are NOT captured."
    fi

    # Event selectors — management events
    EVENT_SELECTORS=$(aws cloudtrail get-event-selectors \
        --trail-name "$TRAIL_ARN" \
        --region "$HOME_REGION" \
        --output json 2>/dev/null || echo '{}')

    MGMT_READ=$(echo "$EVENT_SELECTORS" | jq -r '
        .EventSelectors[]? | select(.IncludeManagementEvents == true) | .ReadWriteType' \
        2>/dev/null | head -1)

    if [[ -n "$MGMT_READ" ]]; then
        log_ok "Trail '$TRAIL_NAME': management events captured (ReadWriteType: $MGMT_READ)."
    else
        record_finding "Trail '$TRAIL_NAME': management events are NOT captured."
    fi

    # ------------------------------------------------------------------
    # S3 bucket checks for the trail's log destination
    # ------------------------------------------------------------------
    S3_BUCKET=$(echo "$TRAIL" | jq -r '.S3BucketName // ""')
    if [[ -z "$S3_BUCKET" ]]; then
        record_finding "Trail '$TRAIL_NAME': no S3 bucket configured."
        continue
    fi

    log_info "Trail '$TRAIL_NAME' logs to S3 bucket: $S3_BUCKET"

    # Bucket region (needed for API calls)
    BUCKET_REGION=$(aws s3api get-bucket-location \
        --bucket "$S3_BUCKET" --output json 2>/dev/null \
        | jq -r '.LocationConstraint // "us-east-1"')
    [[ "$BUCKET_REGION" == "null" ]] && BUCKET_REGION="us-east-1"
    BUCKET_ARGS=(--region "$BUCKET_REGION")

    # Public access block
    BUCKET_PAB=$(aws s3api get-public-access-block \
        --bucket "$S3_BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    if [[ "$BUCKET_PAB" == "{}" ]]; then
        record_finding "Trail bucket '$S3_BUCKET': Public Access Block is NOT configured."
    else
        for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
            val=$(echo "$BUCKET_PAB" | jq -r ".PublicAccessBlockConfiguration.${setting} // false")
            [[ "$val" == "true" ]] \
                && log_ok "Trail bucket '$S3_BUCKET' PAB: $setting = true" \
                || record_finding "Trail bucket '$S3_BUCKET' PAB: $setting is NOT enabled."
        done
    fi

    # Bucket ACL — no public grants
    BUCKET_ACL=$(aws s3api get-bucket-acl \
        --bucket "$S3_BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    PUBLIC_GRANTS=$(echo "$BUCKET_ACL" | jq -r '
        .Grants[]? |
        select(
            .Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" or
            .Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ) | .Permission' 2>/dev/null || true)

    if [[ -z "$PUBLIC_GRANTS" ]]; then
        log_ok "Trail bucket '$S3_BUCKET': ACL does not expose data publicly."
    else
        record_finding "Trail bucket '$S3_BUCKET': ACL grants public access ($PUBLIC_GRANTS)."
    fi

    # S3 bucket access logging for the trail bucket
    BUCKET_LOGGING=$(aws s3api get-bucket-logging \
        --bucket "$S3_BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    LOG_TARGET=$(echo "$BUCKET_LOGGING" | jq -r '.LoggingEnabled.TargetBucket // ""')
    if [[ -n "$LOG_TARGET" ]]; then
        log_ok "Trail bucket '$S3_BUCKET': S3 access logging → $LOG_TARGET"
    else
        record_finding "Trail bucket '$S3_BUCKET': S3 access logging is NOT enabled."
    fi

done < <(echo "$TRAILS_JSON" | jq -r '.trailList[].TrailARN')

# ---------------------------------------------------------------------------
# 3. Ensure at least one active multi-region trail exists
# ---------------------------------------------------------------------------
log_header "Multi-Region Trail Coverage"
if [[ "$ACTIVE_MULTIREGION" -ge 1 ]]; then
    log_ok "At least one active multi-region trail is present."
else
    record_finding "No active multi-region trail found. API activity in all regions may not be captured."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_header "Summary"
if [[ "$FINDINGS" -eq 0 ]]; then
    log_ok "No CloudTrail findings detected."
else
    log_warn "Total CloudTrail findings: $FINDINGS"
fi

exit 0
