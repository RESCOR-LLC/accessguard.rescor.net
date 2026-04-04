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
AWS cloud provider for AccessGuard.

Scans IAM users, groups, roles, and SSO permission sets across one or
more AWS accounts. Supports Organizations auto-discovery and cross-account
role assumption.
"""

import logging

import boto3
import botocore

import commonClasses as cc
import accessGuardClasses as agc
from providers.base import CloudProvider, EntityRecord

_LOGGER = logging.getLogger(__name__)


class AwsProvider(CloudProvider):

    def __init__(self, region: str = "us-east-1",
                 role_name: str = "OrganizationAccountAccessRole"):
        self.region = region
        self.role_name = role_name
        self._sts = boto3.client("sts", region_name=region)
        self._current_account = self._sts.get_caller_identity()["Account"]

    @property
    def name(self) -> str:
        return "aws"

    def discover_accounts(self) -> list:
        """List all active accounts in the AWS Organization."""
        client = boto3.client("organizations", region_name=self.region)
        accounts = []
        paginator = client.get_paginator("list_accounts")

        for page in paginator.paginate():
            for acct in page["Accounts"]:
                if acct["Status"] == "ACTIVE":
                    accounts.append({
                        "id": acct["Id"],
                        "name": acct.get("Name", acct["Id"]),
                    })

        return accounts

    def get_identity_client(self, account_id: str, role: str = None):
        """
        Get an IAM client for a target account. For the current account,
        returns a direct client. For others, assumes the named role.
        Returns None on failure (with a logged warning).
        """
        if account_id == self._current_account:
            return boto3.client("iam", region_name=self.region)

        role_name = role or self.role_name
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        try:
            creds = self._sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="accessguard-scan",
            )["Credentials"]

            return boto3.client(
                "iam",
                region_name=self.region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            cc.emit("700010", "w",
                f"Cannot assume {role_arn}: {code} - skipping account {account_id}")
            return None

        except Exception as e:
            cc.emit("700020", "w",
                f"Error accessing account {account_id}: {e} - skipping")
            return None

    def scan_entities(self, client, account_id: str,
                      report_date: str) -> list:
        """Scan an AWS account's IAM entities, returning EntityRecord objects."""
        results = []

        # Users
        try:
            users = agc.IamUsers(client=client).download()
            for entity in users:
                results.append(EntityRecord(
                    name=entity.userName,
                    account=account_id,
                    entity_type="User",
                    platform="aws",
                    identifier=f"arn:aws:iam::{account_id}:user/{entity.userName}",
                    managed_policies=entity.managed,
                    inline_policies=entity.policies,
                    report_date=report_date,
                ))
            cc.emit("700030", "i", f"  {len(users)} users")
        except Exception as e:
            cc.emit("700031", "w", f"  Users failed: {e}")

        # Groups
        try:
            groups = agc.IamGroups(client=client).download()
            for entity in groups:
                results.append(EntityRecord(
                    name=entity.groupName,
                    account=account_id,
                    entity_type="Group",
                    platform="aws",
                    identifier=f"arn:aws:iam::{account_id}:group/{entity.groupName}",
                    managed_policies=entity.managed,
                    inline_policies=entity.policies,
                    members=entity.members,
                    report_date=report_date,
                ))
            cc.emit("700032", "i", f"  {len(groups)} groups")
        except Exception as e:
            cc.emit("700033", "w", f"  Groups failed: {e}")

        # Roles (with trust policy, tags, lastUsed from GetRole)
        try:
            roles = agc.IamRoles(client=client).download()
            for entity in roles:
                trust_policy = {}
                tags = {}
                last_used = None
                create_date = None

                try:
                    detail = client.get_role(RoleName=entity.roleName)["Role"]
                    trust_policy = detail.get("AssumeRolePolicyDocument", {})
                    tags_list = detail.get("Tags", [])
                    tags = {t["Key"]: t["Value"] for t in tags_list}
                    lu = detail.get("RoleLastUsed", {}).get("LastUsedDate")
                    last_used = lu.isoformat() if lu else None
                    cd = detail.get("CreateDate")
                    create_date = cd.isoformat() if cd else None
                except Exception:
                    pass  # GetRole enrichment is best-effort

                results.append(EntityRecord(
                    name=entity.roleName,
                    account=account_id,
                    entity_type="Role",
                    platform="aws",
                    identifier=f"arn:aws:iam::{account_id}:role/{entity.roleName}",
                    managed_policies=entity.managed,
                    inline_policies=entity.policies,
                    trust_info=trust_policy,
                    tags=tags,
                    last_used=last_used,
                    create_date=create_date,
                    report_date=report_date,
                ))
            cc.emit("700034", "i", f"  {len(roles)} roles")
        except Exception as e:
            cc.emit("700035", "w", f"  Roles failed: {e}")

        return results

    def system_prompt_context(self) -> str:
        return """CRITICAL CONTEXT for AWS entities:
- trustPolicy: reveals WHO or WHAT can assume this role (service principals, \
SSO SAML providers, account roots, specific IAM entities). Roles with different \
trust principals serve different purposes even if their permissions are identical.
- tags: may include aws:cloudformation:stack-name (created by CFN/CDK), \
Application, Environment, or other ownership tags. Consolidating roles owned \
by different stacks/applications will cause drift or breakage on next deploy.
- lastUsed: when the role was last assumed. Roles unused for 90+ days are \
strong candidates for deletion rather than consolidation.
- createDate: when the role was created.

Do NOT recommend consolidating:
- Roles managed by different CloudFormation stacks or CDK constructs
- Roles with trust policies bound to different service principals
- AWS-reserved roles (AWSReservedSSO_*, aws-service-role/*)
- CDK bootstrap roles (cdk-hnb659fds-*)"""

    def build_identifier(self, account: str, entity_type: str,
                         name: str) -> str:
        return f"arn:aws:iam::{account}:{entity_type.lower()}/{name}"
