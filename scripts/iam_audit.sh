#!/usr/bin/env bash
# =============================================================================
# IAM Security Audit Script
# =============================================================================
# Audits AWS IAM configuration for common security issues:
#   - Root account usage and MFA
#   - IAM password policy strength
#   - Users without MFA enabled
#   - Users with unused/old access keys
#   - Users with console access but no recent login
#   - Inline and directly attached administrator policies
#   - Access keys older than 90 days
#
# Prerequisites:
#   - AWS CLI configured with sufficient permissions
#   - jq installed
#
# Usage:
#   ./iam_audit.sh [--region <region>] [--output <text|json>]
#
# Required IAM permissions:
#   iam:GetAccountSummary, iam:GetAccountPasswordPolicy,
#   iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys,
#   iam:GetAccessKeyLastUsed, iam:ListAttachedUserPolicies,
#   iam:ListUserPolicies, iam:GetCredentialReport,
#   iam:GenerateCredentialReport
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OUTPUT_FORMAT="text"
REGION=""
KEY_AGE_THRESHOLD_DAYS=90
LOGIN_INACTIVE_THRESHOLD_DAYS=90

# ---------------------------------------------------------------------------
# Colours (disabled when not a terminal)
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_fail()    { echo -e "${RED}[FAIL]${RESET}  $*"; }
log_header()  { echo -e "\n${BOLD}========== $* ==========${RESET}"; }

FINDINGS=0
record_finding() { FINDINGS=$((FINDINGS + 1)); log_fail "$*"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --region)   REGION="$2";        shift 2 ;;
        --output)   OUTPUT_FORMAT="$2"; shift 2 ;;
        -h|--help)
            sed -n '/^# Usage/,/^# =/p' "$0" | grep -v '^#' || true
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
# 1. Root account summary
# ---------------------------------------------------------------------------
log_header "Root Account"

ACCOUNT_SUMMARY=$(aws iam get-account-summary "${AWS_ARGS[@]}" --output json 2>/dev/null)

ROOT_MFA=$(echo "$ACCOUNT_SUMMARY" | jq -r '.SummaryMap.AccountMFAEnabled')
ROOT_KEYS=$(echo "$ACCOUNT_SUMMARY" | jq -r '.SummaryMap.AccountAccessKeysPresent')

if [[ "$ROOT_MFA" == "1" ]]; then
    log_ok "Root account has MFA enabled."
else
    record_finding "Root account does NOT have MFA enabled."
fi

if [[ "$ROOT_KEYS" == "0" ]]; then
    log_ok "Root account has no active access keys."
else
    record_finding "Root account has active access keys. Remove them immediately."
fi

# ---------------------------------------------------------------------------
# 2. Password policy
# ---------------------------------------------------------------------------
log_header "Password Policy"

POLICY_JSON=$(aws iam get-account-password-policy "${AWS_ARGS[@]}" --output json 2>/dev/null || echo '{}')

if [[ "$POLICY_JSON" == "{}" ]]; then
    record_finding "No IAM account password policy is set."
else
    PP=$(echo "$POLICY_JSON" | jq -r '.PasswordPolicy')

    MIN_LEN=$(echo "$PP" | jq -r '.MinimumPasswordLength // 0')
    REQUIRE_UPPER=$(echo "$PP" | jq -r '.RequireUppercaseCharacters // false')
    REQUIRE_LOWER=$(echo "$PP" | jq -r '.RequireLowercaseCharacters // false')
    REQUIRE_NUMBERS=$(echo "$PP" | jq -r '.RequireNumbers // false')
    REQUIRE_SYMBOLS=$(echo "$PP" | jq -r '.RequireSymbols // false')
    MAX_AGE=$(echo "$PP" | jq -r '.MaxPasswordAge // 0')
    REUSE=$(echo "$PP" | jq -r '.PasswordReusePrevention // 0')
    ALLOW_CHANGE=$(echo "$PP" | jq -r '.AllowUsersToChangePassword // false')

    [[ "$MIN_LEN" -ge 14 ]] && log_ok "Minimum password length: $MIN_LEN (>= 14)" \
        || record_finding "Minimum password length is $MIN_LEN (recommended >= 14)."
    [[ "$REQUIRE_UPPER" == "true" ]] && log_ok "Uppercase required." \
        || record_finding "Password policy does not require uppercase characters."
    [[ "$REQUIRE_LOWER" == "true" ]] && log_ok "Lowercase required." \
        || record_finding "Password policy does not require lowercase characters."
    [[ "$REQUIRE_NUMBERS" == "true" ]] && log_ok "Numbers required." \
        || record_finding "Password policy does not require numbers."
    [[ "$REQUIRE_SYMBOLS" == "true" ]] && log_ok "Symbols required." \
        || record_finding "Password policy does not require symbols."
    if [[ "$MAX_AGE" -gt 0 && "$MAX_AGE" -le 90 ]]; then
        log_ok "Passwords expire after $MAX_AGE days (<= 90)."
    else
        record_finding "Password expiry is not set or exceeds 90 days (current: $MAX_AGE)."
    fi
    [[ "$REUSE" -ge 24 ]] && log_ok "Password reuse prevention: last $REUSE passwords." \
        || record_finding "Password reuse prevention is $REUSE (recommended >= 24)."
fi

# ---------------------------------------------------------------------------
# 3. Per-user checks via credential report
# ---------------------------------------------------------------------------
log_header "User Credential Report"

log_info "Generating credential report (may take a few seconds)…"
aws iam generate-credential-report "${AWS_ARGS[@]}" --output text &>/dev/null || true

# Wait until the report is ready
for i in {1..10}; do
    STATE=$(aws iam generate-credential-report "${AWS_ARGS[@]}" --output json 2>/dev/null \
        | jq -r '.State // "STARTED"')
    [[ "$STATE" == "COMPLETE" ]] && break
    sleep 3
done

CREDENTIAL_REPORT=$(aws iam get-credential-report "${AWS_ARGS[@]}" --output json 2>/dev/null \
    | jq -r '.Content' | base64 --decode)

# Parse CSV (skip header)
USERS_WITHOUT_MFA=()
USERS_OLD_KEYS=()
USERS_INACTIVE=()
USERS_NO_PASSWORD_MFA=()

NOW_EPOCH=$(date +%s)

while IFS=',' read -r \
    user arn user_creation_time \
    password_enabled password_last_used password_last_changed password_next_rotation \
    mfa_active \
    access_key_1_active access_key_1_last_rotated access_key_1_last_used_date \
    access_key_1_last_used_region access_key_1_last_used_service \
    access_key_2_active access_key_2_last_rotated access_key_2_last_used_date \
    access_key_2_last_used_region access_key_2_last_used_service \
    cert_1_active cert_1_last_rotated cert_2_active cert_2_last_rotated
do
    # Skip CSV header
    [[ "$user" == "user" ]] && continue
    # Skip root
    [[ "$user" == "<root_account>" ]] && continue

    # ---- MFA check ----
    if [[ "$mfa_active" == "false" && "$password_enabled" == "true" ]]; then
        USERS_WITHOUT_MFA+=("$user")
    fi

    # ---- Access key age check ----
    for key_date in "$access_key_1_last_rotated" "$access_key_2_last_rotated"; do
        if [[ "$key_date" != "N/A" && "$key_date" != "" ]]; then
            key_epoch=$(date -d "${key_date%%T*}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${key_date%%T*}" +%s 2>/dev/null || echo 0)
            age_days=$(( (NOW_EPOCH - key_epoch) / 86400 ))
            if [[ "$age_days" -gt "$KEY_AGE_THRESHOLD_DAYS" ]]; then
                USERS_OLD_KEYS+=("$user (key age: ${age_days}d)")
            fi
        fi
    done

    # ---- Inactive console user ----
    if [[ "$password_enabled" == "true" ]]; then
        if [[ "$password_last_used" == "no_information" || "$password_last_used" == "N/A" ]]; then
            USERS_INACTIVE+=("$user (never logged in)")
        else
            last_epoch=$(date -d "${password_last_used%%T*}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${password_last_used%%T*}" +%s 2>/dev/null || echo "$NOW_EPOCH")
            inactive_days=$(( (NOW_EPOCH - last_epoch) / 86400 ))
            if [[ "$inactive_days" -gt "$LOGIN_INACTIVE_THRESHOLD_DAYS" ]]; then
                USERS_INACTIVE+=("$user (last login: ${inactive_days}d ago)")
            fi
        fi
    fi

done < <(echo "$CREDENTIAL_REPORT")

# Report MFA findings
if [[ ${#USERS_WITHOUT_MFA[@]} -eq 0 ]]; then
    log_ok "All console users have MFA enabled."
else
    for u in "${USERS_WITHOUT_MFA[@]}"; do
        record_finding "User '$u' has console access but NO MFA enabled."
    done
fi

# Report old key findings
if [[ ${#USERS_OLD_KEYS[@]} -eq 0 ]]; then
    log_ok "All access keys are within the ${KEY_AGE_THRESHOLD_DAYS}-day rotation policy."
else
    for u in "${USERS_OLD_KEYS[@]}"; do
        record_finding "Access key older than ${KEY_AGE_THRESHOLD_DAYS} days: $u"
    done
fi

# Report inactive user findings
if [[ ${#USERS_INACTIVE[@]} -eq 0 ]]; then
    log_ok "No console users inactive for more than ${LOGIN_INACTIVE_THRESHOLD_DAYS} days."
else
    for u in "${USERS_INACTIVE[@]}"; do
        record_finding "Inactive console user: $u"
    done
fi

# ---------------------------------------------------------------------------
# 4. Users with administrator policy attached
# ---------------------------------------------------------------------------
log_header "Administrator Policy Check"

USERS=$(aws iam list-users "${AWS_ARGS[@]}" --output json | jq -r '.Users[].UserName')

ADMIN_USERS=()
while IFS= read -r username; do
    # Check attached managed policies
    ATTACHED=$(aws iam list-attached-user-policies "${AWS_ARGS[@]}" \
        --user-name "$username" --output json \
        | jq -r '.AttachedPolicies[].PolicyArn')
    if echo "$ATTACHED" | grep -q "AdministratorAccess"; then
        ADMIN_USERS+=("$username (attached: AdministratorAccess)")
    fi

    # Check inline policies for wildcards
    INLINE_NAMES=$(aws iam list-user-policies "${AWS_ARGS[@]}" \
        --user-name "$username" --output json \
        | jq -r '.PolicyNames[]' 2>/dev/null || true)
    while IFS= read -r policy_name; do
        [[ -z "$policy_name" ]] && continue
        POLICY_DOC=$(aws iam get-user-policy "${AWS_ARGS[@]}" \
            --user-name "$username" --policy-name "$policy_name" \
            --output json | jq -r '.PolicyDocument')
        # Detect Action:* with Resource:*
        if echo "$POLICY_DOC" | jq -e \
            '.Statement[] | select(.Effect=="Allow") | select(.Action=="*") | select(.Resource=="*")' \
            &>/dev/null 2>&1; then
            ADMIN_USERS+=("$username (inline policy '$policy_name' grants Action:* Resource:*)")
        fi
    done <<< "$INLINE_NAMES"
done <<< "$USERS"

if [[ ${#ADMIN_USERS[@]} -eq 0 ]]; then
    log_ok "No users have direct administrator access."
else
    for u in "${ADMIN_USERS[@]}"; do
        record_finding "User has administrator-level access: $u"
    done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_header "Summary"
if [[ "$FINDINGS" -eq 0 ]]; then
    log_ok "No IAM findings detected."
else
    log_warn "Total IAM findings: $FINDINGS"
fi

exit 0
