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
AccessGuard scanner roles — minimum read-only IAM permissions for each
cloud provider.

Deploy this stack in each AWS account you want to scan. The role trusts
the account where AccessGuard runs (on-premise or Lambda) and provides
only the IAM/SSO read permissions needed for auditing.

For Azure and GCP, this file documents the equivalent role setup since
those platforms don't use CloudFormation/CDK for IAM provisioning.
"""

from aws_cdk import (
    CfnOutput,
    Stack,
    Tags,
    aws_iam as iam,
)
from constructs import Construct


class ScannerRolesStack(Stack):
    """
    Creates an AccessGuard scanner role in this AWS account.

    The role is assumable from a specified trusted principal (account root,
    specific role ARN, or Organization) and has read-only IAM + SSO
    permissions — nothing else.

    Deploy in each target account:
        cdk deploy AGScannerRole --context trusted_principal=arn:aws:iam::MANAGEMENT_ACCT:root
    """

    def __init__(self, scope: Construct, id: str,
                 trusted_principal: str = None,
                 trusted_org_id: str = None,
                 role_name: str = "AccessGuardScannerRole",
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Resolve trusted principal from context or parameter
        trusted_principal = trusted_principal or \
            self.node.try_get_context("trusted_principal")
        trusted_org_id = trusted_org_id or \
            self.node.try_get_context("trusted_org_id")

        # Build trust policy
        if trusted_org_id:
            # Trust any account in the Organization
            principal = iam.AccountRootPrincipal()
            conditions = {"StringEquals": {
                "aws:PrincipalOrgID": trusted_org_id
            }}
        elif trusted_principal:
            # Trust a specific ARN (account root, role, or user)
            principal = iam.ArnPrincipal(trusted_principal)
            conditions = None
        else:
            # Default: trust the current account (for local testing)
            principal = iam.AccountRootPrincipal()
            conditions = None

        # =====================================================================
        # Scanner Role — read-only IAM + SSO
        # =====================================================================

        self.scanner_role = iam.Role(
            self, "ScannerRole",
            role_name=role_name,
            assumed_by=principal,
            description="AccessGuard read-only scanner role for IAM auditing",
            max_session_duration=None,  # default 1 hour
        )

        # Add org condition if specified (can't do this via assumed_by directly)
        if conditions:
            self.scanner_role.assume_role_policy.add_statements(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[principal],
                    actions=["sts:AssumeRole"],
                    conditions=conditions,
                )
            )

        # IAM read-only
        self.scanner_role.add_to_policy(iam.PolicyStatement(
            sid="IAMReadOnly",
            actions=[
                "iam:GetRole",
                "iam:GetGroup",
                "iam:GetRolePolicy",
                "iam:GetUserPolicy",
                "iam:GetGroupPolicy",
                "iam:ListAttachedGroupPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListGroupPolicies",
                "iam:ListGroups",
                "iam:ListRolePolicies",
                "iam:ListRoles",
                "iam:ListUserPolicies",
                "iam:ListUsers",
            ],
            resources=["*"],
        ))

        # SSO read-only
        self.scanner_role.add_to_policy(iam.PolicyStatement(
            sid="SSOReadOnly",
            actions=[
                "sso-admin:ListInstances",
                "sso-admin:ListPermissionSets",
                "sso-admin:DescribePermissionSet",
                "sso-admin:ListManagedPoliciesInPermissionSet",
                "sso-admin:GetInlinePolicyForPermissionSet",
            ],
            resources=["*"],
        ))

        # STS — only GetCallerIdentity (no AssumeRole needed for scanning)
        self.scanner_role.add_to_policy(iam.PolicyStatement(
            sid="STSIdentity",
            actions=["sts:GetCallerIdentity"],
            resources=["*"],
        ))

        # Organizations — for account discovery (only needed in management account)
        self.scanner_role.add_to_policy(iam.PolicyStatement(
            sid="OrganizationsReadOnly",
            actions=["organizations:ListAccounts"],
            resources=["*"],
        ))

        Tags.of(self).add("Application", "AccessGuard")
        Tags.of(self).add("Purpose", "IAM-Audit-ReadOnly")

        # Outputs
        CfnOutput(self, "ScannerRoleArn",
                  value=self.scanner_role.role_arn,
                  description="ARN of the AccessGuard scanner role")

        CfnOutput(self, "ScannerRoleName",
                  value=self.scanner_role.role_name,
                  description="Name of the AccessGuard scanner role")


# =========================================================================
# Azure and GCP equivalent roles (documentation only — not CDK-provisionable)
# =========================================================================

AZURE_SCANNER_SETUP = """
## Azure Scanner Role Setup

AccessGuard needs two types of permissions in Azure:

### 1. Entra ID (Microsoft Graph) — App Registration

Create an App Registration in Entra ID with these API permissions:
  - Microsoft Graph > Application > Directory.Read.All
  - Microsoft Graph > Application > User.Read.All (if sign-in data needed)

Grant admin consent, then create a client secret or certificate.

Set environment variables:
  AZURE_TENANT_ID=your-tenant-id
  AZURE_CLIENT_ID=your-app-client-id
  AZURE_CLIENT_SECRET=your-client-secret

### 2. Azure RBAC — Role Assignment

Assign the built-in "Reader" role to the App Registration's service
principal at the management group or subscription scope:

  az role assignment create \\
    --assignee <app-client-id> \\
    --role "Reader" \\
    --scope "/subscriptions/<subscription-id>"

For multi-subscription scanning, assign at the management group level:

  az role assignment create \\
    --assignee <app-client-id> \\
    --role "Reader" \\
    --scope "/providers/Microsoft.Management/managementGroups/<mg-id>"

### Minimum Permissions Summary

| System | Permission | Purpose |
|--------|-----------|---------|
| Graph API | Directory.Read.All | Users, groups, service principals |
| Azure RBAC | Reader | Role definitions, role assignments |
"""

GCP_SCANNER_SETUP = """
## GCP Scanner Role Setup

AccessGuard needs these predefined roles on the target project or org:

### Service Account Setup

Create a service account for AccessGuard:

  gcloud iam service-accounts create accessguard-scanner \\
    --display-name="AccessGuard Scanner" \\
    --project=<project-id>

### Role Assignments

Assign at the project level (or org level for multi-project scanning):

  # Cloud Asset read — bulk IAM policy scanning
  gcloud projects add-iam-policy-binding <project-id> \\
    --member="serviceAccount:accessguard-scanner@<project-id>.iam.gserviceaccount.com" \\
    --role="roles/cloudasset.viewer"

  # IAM read — service account details and keys
  gcloud projects add-iam-policy-binding <project-id> \\
    --member="serviceAccount:accessguard-scanner@<project-id>.iam.gserviceaccount.com" \\
    --role="roles/iam.securityReviewer"

### Authentication

For on-premise scanning, create and download a key:

  gcloud iam service-accounts keys create ~/accessguard-key.json \\
    --iam-account=accessguard-scanner@<project-id>.iam.gserviceaccount.com

  export GOOGLE_APPLICATION_CREDENTIALS=~/accessguard-key.json

### Minimum Permissions Summary

| Role | Purpose |
|------|---------|
| roles/cloudasset.viewer | searchAllIamPolicies (bulk IAM scan) |
| roles/iam.securityReviewer | Service account details, role definitions |
"""
