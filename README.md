# aws-audit-scripts

A collection of Bash scripts for performing AWS security audits. Each script
targets a specific AWS service area and checks for common misconfigurations
or security gaps aligned with the [AWS CIS Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
and AWS security best practices.

---

## Contents

| Script | Description |
|--------|-------------|
| [`scripts/iam_audit.sh`](#iam_auditsh) | IAM users, credentials, password policy, MFA, and admin access |
| [`scripts/s3_audit.sh`](#s3_auditsh) | S3 bucket public access, encryption, logging, and policies |
| [`scripts/security_groups_audit.sh`](#security_groups_auditsh) | EC2 Security Group open ports, default groups, and unused groups |
| [`scripts/cloudtrail_audit.sh`](#cloudtrail_auditsh) | CloudTrail logging, encryption, multi-region coverage, and S3 bucket security |

---

## Prerequisites

- **AWS CLI v2** — [installation guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
- **jq** — JSON processor (`brew install jq` / `apt install jq` / `yum install jq`)
- AWS credentials configured (`aws configure` or via environment variables / IAM role)

---

## Quick Start

```bash
# Make all scripts executable
chmod +x scripts/*.sh

# Run a specific audit
./scripts/iam_audit.sh
./scripts/s3_audit.sh
./scripts/security_groups_audit.sh
./scripts/cloudtrail_audit.sh
```

Each script exits with code `0` and outputs coloured `[OK]` / `[WARN]` / `[FAIL]`
lines to stdout. Redirect to a file for a persistent report:

```bash
./scripts/iam_audit.sh 2>&1 | tee reports/iam-$(date +%Y%m%d).txt
```

---

## Scripts

### `iam_audit.sh`

Checks IAM for the following issues:

| Check | Severity |
|-------|----------|
| Root account MFA not enabled | Critical |
| Root account has active access keys | Critical |
| Password policy not configured or too weak | High |
| Console user without MFA | High |
| Access key older than 90 days | Medium |
| Console user inactive for >90 days | Medium |
| User with AdministratorAccess policy directly attached | High |
| Inline policy granting `Action:* Resource:*` | High |

**Usage:**

```bash
./scripts/iam_audit.sh [--region <region>]
```

**Required IAM permissions:**
`iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:ListUsers`,
`iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`,
`iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`,
`iam:GetCredentialReport`, `iam:GenerateCredentialReport`

---

### `s3_audit.sh`

Checks every S3 bucket (or a single specified bucket) for:

| Check | Severity |
|-------|----------|
| Account-level Public Access Block not fully enabled | Critical |
| Bucket-level Public Access Block not fully enabled | High |
| Bucket ACL grants public or AuthenticatedUsers access | Critical |
| Server-Side Encryption (SSE) not enabled | High |
| Versioning disabled | Medium |
| Access logging not enabled | Medium |
| Bucket policy allows public principal (`*`) | Critical |
| Bucket policy does not enforce SSL-only access | Medium |

**Usage:**

```bash
# Audit all buckets
./scripts/s3_audit.sh [--region <region>]

# Audit a single bucket
./scripts/s3_audit.sh --bucket my-bucket-name
```

**Required IAM permissions:**
`s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`,
`s3:GetBucketAcl`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`,
`s3:GetBucketLogging`, `s3:GetBucketPolicy`, `s3:GetAccountPublicAccessBlock`,
`sts:GetCallerIdentity`, `s3control:GetPublicAccessBlock`

---

### `security_groups_audit.sh`

Checks EC2 Security Groups in one or all regions for:

| Check | Severity |
|-------|----------|
| Inbound ALL traffic from `0.0.0.0/0` or `::/0` | Critical |
| Sensitive port open to `0.0.0.0/0` (SSH, RDP, DB ports, etc.) | High |
| Default VPC Security Group has non-default rules | High |
| Security Group not attached to any network interface | Low |
| Outbound ALL traffic to `0.0.0.0/0` (informational) | Info |

Sensitive ports audited: `20, 21, 22, 23, 25, 110, 135, 137-139, 143, 445,
1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017`

**Usage:**

```bash
# Audit current region
./scripts/security_groups_audit.sh

# Audit a specific region
./scripts/security_groups_audit.sh --region eu-west-1

# Audit all regions
./scripts/security_groups_audit.sh --all-regions
```

**Required IAM permissions:**
`ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`,
`ec2:DescribeVpcs`, `ec2:DescribeRegions`

---

### `cloudtrail_audit.sh`

Checks CloudTrail configuration for:

| Check | Severity |
|-------|----------|
| No trails configured | Critical |
| Trail is not actively logging | Critical |
| Trail is not multi-region | High |
| Log file validation not enabled | High |
| Logs not KMS-encrypted | Medium |
| CloudWatch Logs integration not configured | Medium |
| Global service events (IAM/STS) not captured | High |
| Management events not captured | High |
| Trail S3 bucket Public Access Block not fully enabled | Critical |
| Trail S3 bucket ACL grants public access | Critical |
| Trail S3 bucket access logging not enabled | Medium |
| No active multi-region trail present | High |

**Usage:**

```bash
./scripts/cloudtrail_audit.sh [--region <region>]
```

**Required IAM permissions:**
`cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`,
`cloudtrail:GetEventSelectors`, `s3:GetBucketPublicAccessBlock`,
`s3:GetBucketLogging`, `s3:GetBucketAcl`, `s3:GetBucketLocation`

---

## Output Format

All scripts use the same output convention:

```
[OK]    Description of a passing check
[WARN]  Advisory finding that does not constitute a failure
[FAIL]  Security finding that should be remediated
[INFO]  Informational message
```

The exit code is always `0`; the total number of `[FAIL]` findings is printed
in the summary at the end of each script.

---

## IAM Policy for Auditing

The following IAM policy grants the minimum permissions required to run all
four scripts:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMAudit",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Audit",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2Audit",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeVpcs",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailAudit",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Contributing

1. Fork the repository and create a feature branch.
2. Add a new script under `scripts/` following the existing style (colour
   helpers, `record_finding`, summary block).
3. Document the new script in this README.
4. Open a pull request.
