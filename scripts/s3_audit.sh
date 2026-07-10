#!/usr/bin/env bash
# =============================================================================
# S3 Security Audit Script
# =============================================================================
# Audits all S3 buckets in the account for common security issues:
#   - Public access block settings (account-level and per-bucket)
#   - Bucket ACLs granting public or authenticated-users access
#   - Server-side encryption (SSE) configuration
#   - Bucket versioning status
#   - Access logging
#   - Bucket policy allowing public access
#   - SSL-only bucket policy enforcement
#
# Prerequisites:
#   - AWS CLI configured with sufficient permissions
#   - jq installed
#
# Usage:
#   ./s3_audit.sh [--region <region>] [--bucket <bucket-name>]
#
# Required IAM permissions:
#   s3:ListAllMyBuckets, s3:GetBucketLocation,
#   s3:GetBucketPublicAccessBlock, s3:GetBucketAcl,
#   s3:GetBucketEncryption, s3:GetBucketVersioning,
#   s3:GetBucketLogging, s3:GetBucketPolicy,
#   s3:GetAccountPublicAccessBlock
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SINGLE_BUCKET=""
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
        --region) REGION="$2";        shift 2 ;;
        --bucket) SINGLE_BUCKET="$2"; shift 2 ;;
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
# Account-level public access block
# ---------------------------------------------------------------------------
log_header "Account-Level S3 Public Access Block"

ACCOUNT_PAB=$(aws s3control get-public-access-block \
    --account-id "$(aws sts get-caller-identity --output json | jq -r '.Account')" \
    "${AWS_ARGS[@]}" --output json 2>/dev/null || echo '{}')

if [[ "$ACCOUNT_PAB" == "{}" ]]; then
    record_finding "Account-level S3 Public Access Block is NOT configured."
else
    for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
        val=$(echo "$ACCOUNT_PAB" | jq -r ".PublicAccessBlockConfiguration.${setting} // false")
        if [[ "$val" == "true" ]]; then
            log_ok "Account PAB: $setting = true"
        else
            record_finding "Account PAB: $setting is NOT enabled."
        fi
    done
fi

# ---------------------------------------------------------------------------
# Per-bucket audit
# ---------------------------------------------------------------------------
if [[ -n "$SINGLE_BUCKET" ]]; then
    BUCKETS=("$SINGLE_BUCKET")
else
    mapfile -t BUCKETS < <(aws s3api list-buckets "${AWS_ARGS[@]}" --output json \
        | jq -r '.Buckets[].Name')
fi

log_info "Auditing ${#BUCKETS[@]} bucket(s)…"

for BUCKET in "${BUCKETS[@]}"; do
    log_header "Bucket: $BUCKET"

    # Determine bucket region for region-specific API calls
    BUCKET_REGION=$(aws s3api get-bucket-location \
        --bucket "$BUCKET" --output json 2>/dev/null \
        | jq -r '.LocationConstraint // "us-east-1"')
    [[ "$BUCKET_REGION" == "null" ]] && BUCKET_REGION="us-east-1"
    BUCKET_ARGS=(--region "$BUCKET_REGION")

    # ------------------------------------------------------------------
    # 1. Bucket-level Public Access Block
    # ------------------------------------------------------------------
    BUCKET_PAB=$(aws s3api get-public-access-block \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    if [[ "$BUCKET_PAB" == "{}" ]]; then
        record_finding "[$BUCKET] Bucket-level Public Access Block is NOT configured."
    else
        for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
            val=$(echo "$BUCKET_PAB" | jq -r ".PublicAccessBlockConfiguration.${setting} // false")
            if [[ "$val" == "true" ]]; then
                log_ok "[$BUCKET] PAB: $setting = true"
            else
                record_finding "[$BUCKET] PAB: $setting is NOT enabled."
            fi
        done
    fi

    # ------------------------------------------------------------------
    # 2. Bucket ACL
    # ------------------------------------------------------------------
    BUCKET_ACL=$(aws s3api get-bucket-acl \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    PUBLIC_GRANTS=$(echo "$BUCKET_ACL" | jq -r '
        .Grants[]? |
        select(
            .Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" or
            .Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ) |
        "  Grantee: \(.Grantee.URI) | Permission: \(.Permission)"
    ' 2>/dev/null || true)

    if [[ -z "$PUBLIC_GRANTS" ]]; then
        log_ok "[$BUCKET] ACL does not grant public or authenticated-users access."
    else
        while IFS= read -r grant; do
            record_finding "[$BUCKET] ACL grants broad access:$grant"
        done <<< "$PUBLIC_GRANTS"
    fi

    # ------------------------------------------------------------------
    # 3. Server-Side Encryption
    # ------------------------------------------------------------------
    SSE=$(aws s3api get-bucket-encryption \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    if [[ "$SSE" == "{}" ]]; then
        record_finding "[$BUCKET] Server-Side Encryption (SSE) is NOT enabled."
    else
        SSE_ALGO=$(echo "$SSE" | jq -r \
            '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm // "none"')
        log_ok "[$BUCKET] SSE enabled with algorithm: $SSE_ALGO"
    fi

    # ------------------------------------------------------------------
    # 4. Versioning
    # ------------------------------------------------------------------
    VERSIONING=$(aws s3api get-bucket-versioning \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    VERSION_STATUS=$(echo "$VERSIONING" | jq -r '.Status // "Disabled"')
    if [[ "$VERSION_STATUS" == "Enabled" ]]; then
        log_ok "[$BUCKET] Versioning is Enabled."
    else
        log_warn "[$BUCKET] Versioning is $VERSION_STATUS (recommended: Enabled)."
    fi

    # ------------------------------------------------------------------
    # 5. Access Logging
    # ------------------------------------------------------------------
    LOGGING=$(aws s3api get-bucket-logging \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null || echo '{}')

    LOG_TARGET=$(echo "$LOGGING" | jq -r '.LoggingEnabled.TargetBucket // ""')
    if [[ -n "$LOG_TARGET" ]]; then
        log_ok "[$BUCKET] Access logging → $LOG_TARGET"
    else
        record_finding "[$BUCKET] Access logging is NOT enabled."
    fi

    # ------------------------------------------------------------------
    # 6. Bucket policy: public principal and SSL enforcement
    # ------------------------------------------------------------------
    BUCKET_POLICY=$(aws s3api get-bucket-policy \
        --bucket "$BUCKET" "${BUCKET_ARGS[@]}" --output json 2>/dev/null \
        | jq -r '.Policy' || echo '{}')

    if [[ "$BUCKET_POLICY" != "{}" && -n "$BUCKET_POLICY" ]]; then
        # Detect statements allowing Principal: "*" with Effect: Allow
        PUBLIC_STMT=$(echo "$BUCKET_POLICY" | jq -r '
            .Statement[]? |
            select(.Effect == "Allow") |
            select(.Principal == "*" or (.Principal.AWS? | arrays | contains(["*"])) or .Principal.AWS? == "*")
            | .Sid // "(no Sid)"
        ' 2>/dev/null || true)

        if [[ -n "$PUBLIC_STMT" ]]; then
            while IFS= read -r sid; do
                record_finding "[$BUCKET] Bucket policy has a public Allow statement (Sid: $sid)."
            done <<< "$PUBLIC_STMT"
        else
            log_ok "[$BUCKET] Bucket policy does not have a public Allow statement."
        fi

        # Detect if SSL-only (aws:SecureTransport) is enforced via Deny
        SSL_DENY=$(echo "$BUCKET_POLICY" | jq -r '
            .Statement[]? |
            select(.Effect == "Deny") |
            select(.Condition.Bool."aws:SecureTransport" == "false")
            | .Sid // "found"
        ' 2>/dev/null || true)

        if [[ -n "$SSL_DENY" ]]; then
            log_ok "[$BUCKET] Bucket policy enforces SSL-only access."
        else
            record_finding "[$BUCKET] Bucket policy does NOT enforce SSL-only (aws:SecureTransport) access."
        fi
    else
        record_finding "[$BUCKET] No bucket policy found — SSL enforcement is missing."
    fi

done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_header "Summary"
log_info "Buckets audited: ${#BUCKETS[@]}"
if [[ "$FINDINGS" -eq 0 ]]; then
    log_ok "No S3 findings detected."
else
    log_warn "Total S3 findings: $FINDINGS"
fi

exit 0
