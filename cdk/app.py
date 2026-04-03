#!/usr/bin/env python3
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
