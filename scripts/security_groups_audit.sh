#!/usr/bin/env bash
# =============================================================================
# Security Groups Audit Script
# =============================================================================
# Audits all EC2 Security Groups across all (or a specified) region for
# common security issues:
#   - Inbound rules allowing unrestricted access (0.0.0.0/0 or ::/0) on
#     sensitive ports (SSH:22, RDP:3389, etc.)
#   - Rules permitting ALL traffic from any source
#   - Unused security groups (not attached to any ENI)
#   - Default VPC security groups with non-default rules
#   - Overly permissive outbound rules (all traffic to 0.0.0.0/0)
#
# Prerequisites:
#   - AWS CLI configured with sufficient permissions
#   - jq installed
#
# Usage:
#   ./security_groups_audit.sh [--region <region>] [--all-regions]
#
# Required IAM permissions:
#   ec2:DescribeSecurityGroups, ec2:DescribeNetworkInterfaces,
#   ec2:DescribeVpcs, ec2:DescribeRegions
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REGION=""
ALL_REGIONS=false

# Ports that should NEVER be open to 0.0.0.0/0
SENSITIVE_PORTS=(20 21 22 23 25 110 135 137 138 139 143 445 1433 1521 3306 3389 5432 5900 6379 27017)

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
        --region)      REGION="$2"; shift 2 ;;
        --all-regions) ALL_REGIONS=true; shift ;;
        -h|--help)
            grep '^#' "$0" | head -30
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

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
# Determine regions to audit
# ---------------------------------------------------------------------------
if [[ "$ALL_REGIONS" == "true" ]]; then
    mapfile -t REGIONS < <(aws ec2 describe-regions --output json | jq -r '.Regions[].RegionName')
elif [[ -n "$REGION" ]]; then
    REGIONS=("$REGION")
else
    CURRENT_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
    REGIONS=("$CURRENT_REGION")
fi

# ---------------------------------------------------------------------------
# Helper: is_sensitive_port <from_port> <to_port>
# Returns 0 (true) if the port range covers any sensitive port
# ---------------------------------------------------------------------------
is_sensitive_port() {
    local from_port="$1"
    local to_port="$2"
    for port in "${SENSITIVE_PORTS[@]}"; do
        if [[ "$from_port" -le "$port" && "$to_port" -ge "$port" ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Audit each region
# ---------------------------------------------------------------------------
for AUDIT_REGION in "${REGIONS[@]}"; do
    log_header "Region: $AUDIT_REGION"

    REGION_ARGS=(--region "$AUDIT_REGION")

    # Fetch all security groups
    SG_JSON=$(aws ec2 describe-security-groups "${REGION_ARGS[@]}" --output json 2>/dev/null)
    SG_COUNT=$(echo "$SG_JSON" | jq '.SecurityGroups | length')
    log_info "Found $SG_COUNT security group(s) in $AUDIT_REGION."

    # Fetch all ENIs to determine which SGs are in use
    ENI_SG_IDS=$(aws ec2 describe-network-interfaces "${REGION_ARGS[@]}" --output json 2>/dev/null \
        | jq -r '.NetworkInterfaces[].Groups[].GroupId' | sort -u)

    # Iterate over each security group
    while IFS= read -r SG_ID; do
        SG=$(echo "$SG_JSON" | jq -r --arg id "$SG_ID" '.SecurityGroups[] | select(.GroupId == $id)')
        SG_NAME=$(echo "$SG" | jq -r '.GroupName')
        VPC_ID=$(echo "$SG" | jq -r '.VpcId // "EC2-Classic"')
        DESC=$(echo "$SG" | jq -r '.Description // ""')

        # ---- Unused security group ----
        if ! echo "$ENI_SG_IDS" | grep -q "^${SG_ID}$"; then
            log_warn "[$AUDIT_REGION] SG $SG_ID ($SG_NAME) is NOT attached to any network interface."
        fi

        # ---- Default SG with non-default rules ----
        if [[ "$SG_NAME" == "default" ]]; then
            INBOUND_RULES=$(echo "$SG" | jq '.IpPermissions | length')
            OUTBOUND_RULES=$(echo "$SG" | jq '.IpPermissionsEgress | length')
            if [[ "$INBOUND_RULES" -gt 0 || "$OUTBOUND_RULES" -gt 1 ]]; then
                record_finding "[$AUDIT_REGION] Default SG $SG_ID in VPC $VPC_ID has non-default rules (inbound: $INBOUND_RULES, outbound: $OUTBOUND_RULES). Default SGs should have no rules."
            fi
        fi

        # ---- Inbound rules ----
        while IFS= read -r RULE; do
            IP_PROTOCOL=$(echo "$RULE" | jq -r '.IpProtocol')
            FROM_PORT=$(echo "$RULE"   | jq -r '.FromPort // -1')
            TO_PORT=$(echo "$RULE"     | jq -r '.ToPort // 65535')

            # All traffic from any source
            if [[ "$IP_PROTOCOL" == "-1" ]]; then
                for CIDR in $(echo "$RULE" | jq -r '.IpRanges[].CidrIp // empty'); do
                    if [[ "$CIDR" == "0.0.0.0/0" ]]; then
                        record_finding "[$AUDIT_REGION] SG $SG_ID ($SG_NAME): inbound ALL TRAFFIC from 0.0.0.0/0."
                    fi
                done
                for CIDR6 in $(echo "$RULE" | jq -r '.Ipv6Ranges[].CidrIpv6 // empty'); do
                    if [[ "$CIDR6" == "::/0" ]]; then
                        record_finding "[$AUDIT_REGION] SG $SG_ID ($SG_NAME): inbound ALL TRAFFIC from ::/0."
                    fi
                done
                continue
            fi

            # Sensitive ports from 0.0.0.0/0 or ::/0
            FROM_INT=$(echo "$FROM_PORT" | grep -oE '^-?[0-9]+' || echo -1)
            TO_INT=$(echo "$TO_PORT"   | grep -oE '^-?[0-9]+' || echo 65535)

            for CIDR in $(echo "$RULE" | jq -r '.IpRanges[].CidrIp // empty'); do
                if [[ "$CIDR" == "0.0.0.0/0" ]]; then
                    if is_sensitive_port "$FROM_INT" "$TO_INT"; then
                        record_finding "[$AUDIT_REGION] SG $SG_ID ($SG_NAME): inbound port(s) $FROM_PORT-$TO_PORT open to 0.0.0.0/0."
                    fi
                fi
            done
            for CIDR6 in $(echo "$RULE" | jq -r '.Ipv6Ranges[].CidrIpv6 // empty'); do
                if [[ "$CIDR6" == "::/0" ]]; then
                    if is_sensitive_port "$FROM_INT" "$TO_INT"; then
                        record_finding "[$AUDIT_REGION] SG $SG_ID ($SG_NAME): inbound port(s) $FROM_PORT-$TO_PORT open to ::/0."
                    fi
                fi
            done

        done < <(echo "$SG" | jq -c '.IpPermissions[]?')

        # ---- Outbound: all traffic to 0.0.0.0/0 (informational) ----
        while IFS= read -r RULE; do
            IP_PROTOCOL=$(echo "$RULE" | jq -r '.IpProtocol')
            if [[ "$IP_PROTOCOL" == "-1" ]]; then
                for CIDR in $(echo "$RULE" | jq -r '.IpRanges[].CidrIp // empty'); do
                    if [[ "$CIDR" == "0.0.0.0/0" ]]; then
                        log_warn "[$AUDIT_REGION] SG $SG_ID ($SG_NAME): outbound ALL traffic to 0.0.0.0/0 (consider restricting)."
                    fi
                done
            fi
        done < <(echo "$SG" | jq -c '.IpPermissionsEgress[]?')

    done < <(echo "$SG_JSON" | jq -r '.SecurityGroups[].GroupId')

done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_header "Summary"
if [[ "$FINDINGS" -eq 0 ]]; then
    log_ok "No Security Group findings detected."
else
    log_warn "Total Security Group findings: $FINDINGS"
fi

exit 0
