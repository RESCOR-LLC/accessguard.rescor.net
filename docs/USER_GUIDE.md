# AccessGuard User Guide

## Overview

AccessGuard audits AWS IAM entities across one or more accounts and identifies
opportunities to consolidate roles. It operates in two modes:

- **Local mode** (default) — runs from the CLI against the current AWS account,
  writes HTML and JSON reports to local files. No cloud infrastructure required.
- **Pipeline mode** — runs as a Lambda function with DynamoDB storage, S3 output,
  and SSM parameter configuration. Requires CDK deployment.

Most users should start with local mode.

---

## Installation

```bash
git clone https://github.com/arobthearab/accessguard.rescor.net.git
cd accessguard.rescor.net
pip install -r requirements.txt
```

### Prerequisites

| Requirement | Purpose | Required? |
|-------------|---------|-----------|
| Python 3.9+ | Runtime | Yes |
| boto3 | AWS API access | Yes |
| anthropic | AI analysis | Only with `--ai` |
| aws-cdk-lib | Infrastructure deployment | Only for CDK |
| pytest, moto | Testing | Only for development |

---

## Authentication

AccessGuard needs AWS credentials with IAM read permissions. It reads but never
writes IAM entities.

### Required IAM Permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole", "iam:GetGroup", "iam:GetRolePolicy",
    "iam:GetUserPolicy", "iam:GetGroupPolicy",
    "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies", "iam:ListGroupPolicies",
    "iam:ListGroups", "iam:ListRolePolicies", "iam:ListRoles",
    "iam:ListUserPolicies", "iam:ListUsers",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

For SSO permission set auditing, add:

```json
{
  "Effect": "Allow",
  "Action": [
    "sso-admin:ListInstances",
    "sso-admin:ListPermissionSets",
    "sso-admin:DescribePermissionSet",
    "sso-admin:ListManagedPoliciesInPermissionSet",
    "sso-admin:GetInlinePolicyForPermissionSet"
  ],
  "Resource": "*"
}
```

### Credential Sources

AccessGuard uses the standard boto3 credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. AWS config file with profiles (`~/.aws/config`)
4. IAM role (when running on EC2 or Lambda)

For multi-account scanning, configure a profile that assumes a role in each
target account:

```ini
# ~/.aws/config
[profile target-account]
role_arn = arn:aws:iam::111111111111:role/AccessGuardReadRole
source_profile = default
region = us-east-1
```

---

## Local Mode (Recommended)

### Basic Usage

```bash
# Deterministic analysis only — no API key needed
python3 tests/test_live.py

# With AI-powered consolidation recommendations
export ANTHROPIC_API_KEY=sk-ant-...
python3 tests/test_live.py --ai
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--ai` | off | Enable AI-powered consolidation analysis |
| `--model=MODEL` | `sonnet` | AI model: `opus`, `sonnet`, `haiku`, or full model ID |
| `--threshold=N` | `0.70` | Jaccard similarity threshold (0.0-1.0) |

### Output Files

Each run produces two files in the current directory:

- **`accessguard-report-YYYY-MM-DD.html`** — Self-contained HTML report with:
  - Summary cards (entity count, accounts, duplicates, clusters, subsets, recommendations)
  - Entity breakdown by type and account
  - Exact duplicate table (managed policies, group membership, inline policies)
  - Subset relationship table
  - AI consolidation recommendations with risk ratings and rationale

- **`accessguard-report-YYYY-MM-DD.json`** — Machine-readable JSON containing
  the full catalog, similarity data, and analysis results.

---

## Understanding the Analysis

### Stage 1: Exact Similarity Detection

AccessGuard detects exact duplicates across three dimensions:

1. **Managed Policies** — entities with identical attached managed policy lists
2. **Group Membership** — IAM groups with identical member lists
3. **Inline Policies** — entities with identical inline policy content, regardless
   of policy name. Policies are canonicalized (JSON sorted by key) before
   comparison, so structurally identical policies match even if key order differs.

### Stage 2: Jaccard Clustering

For entities with overlapping (but not identical) managed policies, AccessGuard
computes the Jaccard similarity coefficient:

```
J(A,B) = |A ∩ B| / |A ∪ B|
```

Entities with similarity at or above the threshold (default 70%) are grouped
into clusters using single-linkage clustering. Entities with no managed policies
are excluded.

The threshold controls sensitivity:
- **0.90** — only near-identical roles cluster (conservative)
- **0.70** — roles sharing most policies cluster (default, recommended)
- **0.50** — roles sharing half their policies cluster (aggressive)
- **0.30** — roles with any significant overlap cluster (very aggressive)

### Stage 3: Subset Detection

AccessGuard identifies strict subset relationships: role A's managed policies
are entirely contained within role B's. These are strong consolidation candidates
because merging A into B adds no new permissions — A's users just gain the
additional permissions B already has.

### Stage 4: AI Analysis (Optional)

When `--ai` is enabled, each cluster is sent to the selected Claude model with
full context:

- Managed and inline policies for each entity
- Trust policy (who/what can assume the role)
- Tags (including CloudFormation stack ownership)
- Last-used date and creation date

The model returns structured recommendations:

| Field | Description |
|-------|-------------|
| `action` | `CONSOLIDATE`, `REVIEW`, or `KEEP_SEPARATE` |
| `targetRole` | The role to keep (usually the one with the most permissions) |
| `mergeRoles` | Roles that can be merged into the target |
| `additionalPermissions` | Permissions the merged role would gain |
| `risk` | `LOW` (read-only additions), `MEDIUM` (write to non-sensitive), `HIGH` (write to IAM/KMS/STS) |
| `riskRationale` | Why the risk rating was assigned |
| `rationale` | Explanation of the recommendation |

The AI will NOT recommend consolidating:
- Roles managed by different CloudFormation stacks or CDK constructs
- Roles with trust policies bound to different service principals
- AWS-reserved roles (`AWSReservedSSO_*`, `aws-service-role/*`)
- CDK bootstrap roles (`cdk-hnb659fds-*`)

---

## AI Model Selection

AccessGuard supports any Anthropic Claude model. Use the `--model` flag:

| Shortcut | Model ID | Best For |
|----------|----------|----------|
| `sonnet` | claude-sonnet-4-6 | Default — best balance of speed, cost, and quality |
| `opus` | claude-opus-4-6 | Complex environments with hundreds of roles |
| `haiku` | claude-haiku-4-5-20251001 | Cost-sensitive batch runs |

You can also pass a full model ID: `--model=claude-sonnet-4-6`

The model provider architecture is extensible. To add support for another LLM
vendor (OpenAI, AWS Bedrock, Google, etc.), subclass `ModelProvider` in
`src/modelProvider.py` and implement the `analyze()` method.

---

## Pipeline Mode (Lambda + DynamoDB)

For scheduled, automated auditing across multiple accounts, deploy the full
infrastructure stack:

### CDK Deployment

```bash
# Bootstrap CDK (one-time per account/region)
cdk bootstrap aws://ACCOUNT_ID/REGION

# Deploy production infrastructure
cdk deploy AccessGuard

# Deploy test fixtures (for validation — destroy after testing)
cdk deploy AGTestFixtures
cdk destroy AGTestFixtures
```

The AccessGuard stack creates:
- 3 DynamoDB tables (Configuration, Results, Similarity)
- S3 bucket (encrypted, object lock, lifecycle to Glacier)
- SSM parameters (resource ARNs and paths)
- Lambda function with execution role

### Multi-Account Configuration

Create a CSV file with one row per target account:

```csv
AccountId,Nickname,AssumableRole,Partition,DefaultRegion,SSORegion
111111111111,production,arn:aws:iam::111111111111:role/AccessGuardReadRole,aws,us-east-1,us-east-1
222222222222,staging,arn:aws:iam::222222222222:role/AccessGuardReadRole,aws,us-east-1,us-east-1
```

| Column | Description |
|--------|-------------|
| AccountId | 12-digit AWS account number |
| Nickname | Human-readable label |
| AssumableRole | IAM role ARN to assume (must trust the AccessGuard Lambda role) |
| Partition | `aws` or `aws-us-gov` |
| DefaultRegion | Region for IAM/STS API calls |
| SSORegion | Region for SSO operations (leave empty if not applicable) |

Load the configuration:

```bash
python3 src/accessGuard.py -c accountConfiguration.csv -r us-east-1 -o dynamodb
```

Run the analysis:

```bash
python3 src/accessGuard.py -o s3 -o dynamodb -o . -r us-east-1
```

### Pipeline Output Options

| Flag | Destination |
|------|-------------|
| `-o s3` | CSV files to the AccessGuard S3 bucket |
| `-o dynamodb` | JSON records to DynamoDB tables |
| `-o .` | CSV + HTML + JSON to current directory |
| `-o /path/to/dir` | CSV + HTML + JSON to specified directory |

Multiple `-o` flags can be combined.

---

## Testing

### Run All Tests (no AWS credentials needed)

```bash
# Level 1 (unit) + Level 2 (moto mock)
python3 -m pytest tests/ --ignore=tests/test_live.py -v
```

### Run Live Test (requires AWS credentials)

```bash
# Deterministic only
python3 tests/test_live.py

# With AI
export ANTHROPIC_API_KEY=sk-ant-...
python3 tests/test_live.py --ai
```

### Deploy Test Fixtures

For Level 3 validation, deploy known IAM roles to a test account:

```bash
cdk deploy AGTestFixtures
python3 tests/test_live.py --ai
cdk destroy AGTestFixtures
```

The test fixtures create 10 roles with deliberate overlaps:
- 2 exact duplicates
- 2 near-matches (75% Jaccard)
- 1 strict subset
- 1 unique (no overlap)
- 2 identical inline policies (different names)
- 1 mixed managed + inline
- 1 empty role (no policies)

---

## Interpreting Risk Ratings

| Rating | Meaning | Action |
|--------|---------|--------|
| **LOW** | Only read-only permissions added by consolidation | Safe to consolidate after verifying trust policies match |
| **MEDIUM** | Write permissions added to non-sensitive services | Review with the application owner before consolidating |
| **HIGH** | Write permissions added to IAM, KMS, STS, Organizations, or other sensitive services | Do not consolidate without thorough review and approval |

### Important Caveats

- **Roles owned by CloudFormation/CDK stacks** should not be manually consolidated.
  Changing a role that a stack manages will cause drift and may break the next
  deployment. The correct approach is to update the stack template/CDK code.

- **Roles with different trust principals** serve different purposes even if their
  permissions are identical. A role trusted by `ec2.amazonaws.com` and a role
  trusted by `lambda.amazonaws.com` should remain separate.

- **Unused roles** (lastUsed > 90 days) are often better candidates for deletion
  than consolidation. If no one is using it, removing it is simpler and safer
  than merging it into something else.

---

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for the full history of changes.
