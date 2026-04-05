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

## Platform Setup

AccessGuard needs read-only identity permissions on each target platform.
It reads but never writes IAM entities. Each platform requires:

1. A CLI tool for authentication
2. Read-only permissions for AccessGuard to scan

---

### AWS Setup

**Prerequisites:**

| Component | Required? | Install |
|-----------|-----------|---------|
| AWS CLI | Recommended | `brew install awscli` or [AWS docs](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| AWS credentials | Yes | `aws configure` or `~/.aws/credentials` |

**Step 1 — Configure credentials:**

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, region (e.g., us-east-1)
```

Or set environment variables:
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

**Step 2 — Ensure IAM read permissions.** Your credentials need:

```
iam:Get*        iam:List*        sts:GetCallerIdentity
sso-admin:ListInstances          sso-admin:ListPermissionSets
sso-admin:DescribePermissionSet  sso-admin:ListManagedPoliciesInPermissionSet
sso-admin:GetInlinePolicyForPermissionSet
```

The easiest path: use the CDK scanner role (creates an assumable read-only role):

```bash
# Deploy to the management account
source .venv/bin/activate
cdk deploy AGScannerRole

# Or trust a specific account
cdk deploy AGScannerRole --context trusted_principal=arn:aws:iam::ACCOUNT_ID:root
```

**Step 3 — Scan:**

```bash
./accessguard --provider aws                              # current account
./accessguard --provider aws --org                        # all Organization accounts
./accessguard --provider aws --role AccessGuardScannerRole --org  # using the CDK role
./accessguard --provider aws --accounts 111111111111,222222222222  # specific accounts
```

**Multi-account scanning** requires either:
- Running as the management account root (can use `organizations:ListAccounts`)
- Or an IAM role that can `sts:AssumeRole` into target accounts

For cross-account role assumption, configure `~/.aws/config`:

```ini
[profile target-account]
role_arn = arn:aws:iam::111111111111:role/AccessGuardScannerRole
source_profile = default
region = us-east-1
```

---

### Azure Setup

**Prerequisites:**

| Component | Required? | Install |
|-----------|-----------|---------|
| Azure CLI | Yes | `brew install azure-cli` or [Microsoft docs](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| Azure subscription | Yes | Any Entra ID tenant with Azure subscription |

**Step 1 — Authenticate with Azure CLI:**

```bash
az login
```

This opens a browser for Entra ID authentication. AccessGuard uses
`DefaultAzureCredential` which picks up the `az login` session
automatically.

**Step 2 — Verify access:**

```bash
az account list --output table
```

You should see your subscription(s) listed. AccessGuard needs:

| Permission | Scope | Purpose |
|------------|-------|---------|
| `Reader` (Azure RBAC) | Subscription or Management Group | List role definitions and assignments |
| `Directory.Read.All` (Graph API) | Entra ID tenant | List users, groups, service principals |

For a quick test with your own account, `az login` typically gives you
sufficient permissions. For production scanning, create an App Registration:

```bash
# Create an app registration
az ad app create --display-name "AccessGuard Scanner"

# Note the appId from the output, then create a service principal
az ad sp create --id <appId>

# Grant Reader on the subscription
az role assignment create \
  --assignee <appId> \
  --role "Reader" \
  --scope "/subscriptions/<subscription-id>"

# Grant Graph API permissions (requires admin consent)
az ad app permission add --id <appId> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

az ad app permission admin-consent --id <appId>
```

For unattended/automated scanning, use service principal credentials:

```bash
export AZURE_TENANT_ID=your-tenant-id
export AZURE_CLIENT_ID=your-app-client-id
export AZURE_CLIENT_SECRET=your-client-secret
```

**Step 3 — Scan:**

```bash
./accessguard --provider azure                    # current subscription
./accessguard --provider azure --org              # all subscriptions in tenant
./accessguard --provider azure --accounts <subscription-id>  # specific subscription
```

---

### GCP Setup

**Prerequisites:**

| Component | Required? | Install |
|-----------|-----------|---------|
| Google Cloud CLI | Yes | `brew install --cask google-cloud-sdk` or [Google docs](https://cloud.google.com/sdk/docs/install) |
| GCP project | Yes | Any project where you have IAM permissions |

**Step 1 — Authenticate with gcloud:**

```bash
gcloud auth application-default login
```

This opens a browser for Google authentication and writes credentials to
`~/.config/gcloud/application_default_credentials.json`. AccessGuard reads
these automatically.

**Note:** `gcloud auth login` (without `application-default`) authenticates
the CLI itself but does NOT create Application Default Credentials. You
need `application-default login` specifically.

**Step 2 — Enable required APIs in your project:**

```bash
# Cloud Asset API — required for bulk IAM policy scanning
gcloud services enable cloudasset.googleapis.com --project=<project-id>

# IAM API — required for service account details
gcloud services enable iam.googleapis.com --project=<project-id>
```

You can also enable these in the Cloud Console:
- https://console.cloud.google.com/apis/api/cloudasset.googleapis.com
- https://console.cloud.google.com/apis/api/iam.googleapis.com

**Step 3 — Ensure permissions.** Your credentials need:

| Role | Purpose |
|------|---------|
| `roles/cloudasset.viewer` | Bulk-scan all IAM bindings via Cloud Asset API |
| `roles/iam.securityReviewer` | Service account details, role definitions |

For a quick test with your own account, Owner or Editor permissions on the
project are sufficient. For production scanning, create a dedicated service
account:

```bash
# Create service account
gcloud iam service-accounts create accessguard-scanner \
  --display-name="AccessGuard Scanner" \
  --project=<project-id>

# Grant permissions
SA_EMAIL=accessguard-scanner@<project-id>.iam.gserviceaccount.com

gcloud projects add-iam-policy-binding <project-id> \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudasset.viewer"

gcloud projects add-iam-policy-binding <project-id> \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.securityReviewer"

# For on-premise use: download a key
gcloud iam service-accounts keys create ~/accessguard-gcp-key.json \
  --iam-account=$SA_EMAIL

export GOOGLE_APPLICATION_CREDENTIALS=~/accessguard-gcp-key.json
```

**Step 4 — Scan:**

```bash
./accessguard --provider gcp --accounts <project-id>   # specific project
./accessguard --provider gcp --org                      # all projects (needs org-level access)
```

**Troubleshooting:**

| Error | Fix |
|-------|-----|
| "Cloud Asset API has not been used in project" | Enable the API: `gcloud services enable cloudasset.googleapis.com --project=<id>` |
| "GCP credentials expired" | Re-authenticate: `gcloud auth application-default login` |
| "Permission denied" on Cloud Asset | Grant `roles/cloudasset.viewer` to your identity |
| 0 entities found | Check that the project has IAM bindings (new projects may only have the owner binding) |

---

### AI Analysis Setup (All Platforms)

AI-powered consolidation recommendations require an Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./accessguard --provider aws --ai --model sonnet
```

Without the key, `--ai` is silently disabled and deterministic analysis
(exact duplicates, Jaccard clustering, subset detection) runs instead.

| Model | Flag | Best For |
|-------|------|----------|
| Claude Sonnet | `--model sonnet` (default) | Standard analysis — best cost/speed/quality |
| Claude Opus | `--model opus` | Complex environments with 500+ entities |
| Claude Haiku | `--model haiku` | Cost-sensitive batch runs |

---

## Usage

### Basic Usage

```bash
./accessguard --provider aws                              # current account, deterministic
./accessguard --provider aws --ai                         # with AI recommendations
./accessguard --provider aws --org --ai                   # all Organization accounts
./accessguard --provider azure --org                      # all Azure subscriptions
./accessguard --provider gcp --accounts my-project        # specific GCP project
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--provider` | `aws` | Cloud provider: `aws`, `azure`, `gcp` |
| `--org` | off | Scan all accounts/subscriptions/projects |
| `--accounts` | — | Comma-separated account IDs to scan |
| `--role` | provider default | Role name to assume in target accounts |
| `--ai` | off | Enable AI-powered consolidation analysis |
| `--model` | `sonnet` | AI model: `opus`, `sonnet`, `haiku`, or full model ID |
| `--threshold` | `0.70` | Jaccard similarity threshold (0.0-1.0) |

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
./accessguard --provider aws

# With AI
export ANTHROPIC_API_KEY=sk-ant-...
./accessguard --provider aws --ai
```

### Deploy Test Fixtures

For Level 3 validation, deploy known IAM roles to a test account:

```bash
cdk deploy AGTestFixtures
./accessguard --provider aws --ai
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
