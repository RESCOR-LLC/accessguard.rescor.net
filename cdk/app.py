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
  TestFixturesStack    — test IAM roles with deliberate overlaps (deploy/destroy for testing)

Usage:
  cdk deploy AccessGuard          # deploy production infrastructure
  cdk deploy AGTestFixtures       # deploy test roles for Level 3 testing
  cdk destroy AGTestFixtures      # clean up test roles
  cdk synth                       # synthesize all stacks (for validation)
"""

import aws_cdk as cdk

from stacks.accessguard_stack import AccessGuardStack
from stacks.test_fixtures_stack import TestFixturesStack

app = cdk.App()

# Production infrastructure
AccessGuardStack(app, "AccessGuard",
    description="AccessGuard — IAM role engineering infrastructure",
)

# Test fixtures (deploy only when testing, destroy after)
TestFixturesStack(app, "AGTestFixtures",
    description="AccessGuard — test IAM roles for Level 3 validation",
)

app.synth()
