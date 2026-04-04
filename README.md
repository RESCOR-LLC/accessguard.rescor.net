# AccessGuard

**AI-powered AWS IAM role engineering and RBAC optimization.**

AccessGuard audits IAM users, groups, roles, and SSO permission sets across
multiple AWS accounts, identifies duplicates and consolidation opportunities,
and uses AI analysis to recommend an optimal set of roles — reducing role
explosion while maintaining security boundaries.

## Quick Start

```bash
# Clone and set up (one-time)
git clone https://github.com/RESCOR-LLC/accessguard.rescor.net.git
cd accessguard.rescor.net
./scripts/setup.sh                    # all providers
./scripts/setup.sh aws                # AWS only
./scripts/setup.sh aws azure          # AWS + Azure

# Scan (no venv activation needed — ./accessguard handles it)
./accessguard --provider aws
./accessguard --provider aws --org --ai
./accessguard --provider azure --org
./accessguard --provider gcp --accounts my-project-id

# With AI analysis
export ANTHROPIC_API_KEY=sk-ant-...
./accessguard --provider aws --ai --model=sonnet
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

Copyright (C) 2020-2026 RESCOR LLC.

AccessGuard is licensed under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0). You may use, modify, and redistribute this software under the terms
of the AGPL. If you offer a modified version as a network service, you must make
the source code available to users of that service.

See [LICENSE](LICENSE) for the full text.
