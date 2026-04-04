#!/usr/bin/env python3
# Copyright (C) 2020-2026 RESCOR LLC. All rights reserved.
#
# This file is part of AccessGuard.
#
# AccessGuard is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# AccessGuard is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with AccessGuard. If not, see <https://www.gnu.org/licenses/>.
"""
AccessGuard CDK application.

Stacks:
  AccessGuardStack     — production infrastructure (DynamoDB, S3, SSM, Lambda)
  AGScannerRole        — read-only scanner role for target AWS accounts
  TestFixturesStack    — test IAM roles with deliberate overlaps (deploy/destroy for testing)

Usage:
  cdk deploy AccessGuard          # deploy production infrastructure
  cdk deploy AGScannerRole        # deploy scanner role (per target account)
  cdk deploy AGTestFixtures       # deploy test roles for Level 3 testing
  cdk destroy AGTestFixtures      # clean up test roles
  cdk synth                       # synthesize all stacks (for validation)

Scanner role deployment:
  # Trust a specific account:
  cdk deploy AGScannerRole --context trusted_principal=arn:aws:iam::MGMT_ACCT:root

  # Trust all accounts in an Organization:
  cdk deploy AGScannerRole --context trusted_org_id=o-xxxxxxxxxx

  # Custom role name:
  cdk deploy AGScannerRole --context trusted_principal=... role_name=MyCustomName
"""

import aws_cdk as cdk

from stacks.accessguard_stack import AccessGuardStack
from stacks.scanner_roles_stack import ScannerRolesStack
from stacks.test_fixtures_stack import TestFixturesStack

app = cdk.App()

# Production infrastructure
AccessGuardStack(app, "AccessGuard",
    description="AccessGuard — IAM role engineering infrastructure",
)

# Scanner role — deploy in each target account
ScannerRolesStack(app, "AGScannerRole",
    description="AccessGuard — read-only scanner role for IAM auditing",
)

# Test fixtures (deploy only when testing, destroy after)
TestFixturesStack(app, "AGTestFixtures",
    description="AccessGuard — test IAM roles for Level 3 validation",
)

app.synth()
