# AccessGuard

**AI-powered AWS IAM role engineering and RBAC optimization.**

AccessGuard audits IAM users, groups, roles, and SSO permission sets across
multiple AWS accounts, identifies duplicates and consolidation opportunities,
and uses AI analysis to recommend an optimal set of roles — reducing role
explosion while maintaining security boundaries.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan the current AWS account (deterministic analysis, no AI)
python3 src/cli.py

# Scan with AI-powered consolidation recommendations
export ANTHROPIC_API_KEY=sk-ant-...
python3 src/cli.py --ai

# Scan all accounts in an AWS Organization
python3 src/cli.py --org --ai

# Scan specific accounts
python3 src/cli.py --accounts 111111111111,222222222222 --ai

# Customize the model and threshold
python3 src/cli.py --ai --model=opus --threshold=0.60
```

Reports are written to the current directory (override with `--output`):
- `accessguard-report-YYYY-MM-DD.html` — self-contained HTML report
- `accessguard-report-YYYY-MM-DD.json` — machine-readable JSON

## What It Does

1. **Catalogs** every IAM user, group, role, and SSO permission set — including
   managed policies, inline policies, trust policies, tags, and last-used dates
2. **Detects exact duplicates** across three dimensions: managed policies, group
   membership, and inline policy content (canonicalized, ignoring policy names)
3. **Clusters near-matches** using Jaccard similarity on managed policy sets at a
   configurable threshold (default 70%)
4. **Identifies subset relationships** — roles whose permissions are strictly
   contained within another role
5. **AI analysis** (optional) — sends each cluster to Claude with full context
   (trust policies, tags, usage dates) and receives structured consolidation
   recommendations with risk ratings

## Project Structure

```
src/                    Application source
  cli.py                Primary CLI entry point
  accessGuard.py        Lambda/pipeline entry point (DynamoDB/S3/SSM)
  accessGuardClasses.py IAM entity classes and similarity detection
  commonClasses.py      AWS utilities (stripped to used classes only)
  roleAnalyzer.py       Jaccard clustering + AI consolidation analysis
  reportGenerator.py    HTML/JSON report generation
  modelProvider.py      Abstract LLM provider (Anthropic implementation)

tests/                  Test suite
  test_live.py          Live test harness (runs against real AWS)
  test_role_analyzer.py Level 1: Jaccard, clustering, subset detection
  test_similarity.py    Level 1: policy canonicalization, 3D similarity
  test_model_provider.py Level 1: alias resolution, JSON parsing
  test_report_generator.py Level 1: HTML/JSON output validation
  test_integration_iam.py  Level 2: full pipeline with moto mock AWS

cdk/                    Infrastructure as code (AWS CDK)
  app.py                CDK application entry point
  stacks/
    accessguard_stack.py     Production: DynamoDB, S3, SSM, Lambda
    test_fixtures_stack.py   Test: sample IAM roles with known overlaps

archive/                Legacy files (historical reference)
  AgDatastore.yaml      Original CloudFormation (replaced by CDK)
  AgInstaller.yaml      Original CloudFormation (replaced by CDK)
```

## Documentation

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for complete usage documentation
including all command-line options, output formats, AI model selection, CDK
deployment, and multi-account configuration.

## Requirements

- Python 3.9+
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- For AI analysis: `ANTHROPIC_API_KEY` environment variable
- For infrastructure deployment: AWS CDK (`npm install -g aws-cdk`)

## License

Copyright RESCOR LLC. All rights reserved.
