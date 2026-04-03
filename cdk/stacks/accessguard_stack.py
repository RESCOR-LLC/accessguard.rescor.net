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
AccessGuard infrastructure stack.

Consolidates the former AgDatastore.yaml and AgInstaller.yaml into a
single CDK stack. CDK resolves the dependency ordering that previously
required two separate CloudFormation stacks.

Resources:
  - 3 DynamoDB tables (Configuration, Results, Similarity)
  - S3 bucket (encrypted, object lock, lifecycle to Glacier)
  - SSM parameters (resource ARNs and paths)
  - Lambda function with IAM execution role
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_ssm as ssm,
)
from constructs import Construct


class AccessGuardStack(Stack):

    def __init__(self, scope: Construct, id: str,
                 code_folder: str = "Code",
                 data_folder: str = "Data",
                 glacier_days: int = 31,
                 expiration_days: int = 365,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # =====================================================================
        # DynamoDB Tables
        # =====================================================================

        self.configuration_table = dynamodb.Table(
            self, "ConfigurationTable",
            partition_key=dynamodb.Attribute(
                name="accountId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.results_table = dynamodb.Table(
            self, "ResultsTable",
            partition_key=dynamodb.Attribute(
                name="id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="reportDate", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="TTL",
        )

        self.similarity_table = dynamodb.Table(
            self, "SimilarityTable",
            partition_key=dynamodb.Attribute(
                name="id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="reportDate", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="TTL",
        )

        # =====================================================================
        # S3 Bucket
        # =====================================================================

        self.bucket = s3.Bucket(
            self, "Bucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            object_lock_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="MoveToGlacier",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(glacier_days),
                        )
                    ],
                    expiration=Duration.days(expiration_days),
                ),
            ],
        )

        # =====================================================================
        # SSM Parameters
        # =====================================================================

        ssm.StringParameter(
            self, "BucketParam",
            parameter_name="/AccessGuard/Bucket",
            string_value=self.bucket.bucket_name,
            description="S3 bucket for AccessGuard data",
        )

        ssm.StringParameter(
            self, "CodeFolderParam",
            parameter_name="/AccessGuard/CodeFolder",
            string_value=code_folder,
            description="S3 folder for Lambda code archives",
        )

        ssm.StringParameter(
            self, "DataFolderParam",
            parameter_name="/AccessGuard/DataFolder",
            string_value=data_folder,
            description="S3 folder for AccessGuard results",
        )

        ssm.StringParameter(
            self, "ArchiveKeyParam",
            parameter_name="/AccessGuard/ArchiveKey",
            string_value="Not Initialized",
            description="Lambda code archive key",
        )

        ssm.StringParameter(
            self, "ConfigTableParam",
            parameter_name="/AccessGuard/ConfigurationTableArn",
            string_value=self.configuration_table.table_arn,
            description="Configuration table ARN",
        )

        ssm.StringParameter(
            self, "ResultsTableParam",
            parameter_name="/AccessGuard/ResultsTableArn",
            string_value=self.results_table.table_arn,
            description="Results table ARN",
        )

        ssm.StringParameter(
            self, "SimilarityTableParam",
            parameter_name="/AccessGuard/SimilarityTableArn",
            string_value=self.similarity_table.table_arn,
            description="Similarity table ARN",
        )

        # =====================================================================
        # Lambda Execution Role
        # =====================================================================

        self.lambda_role = iam.Role(
            self, "LambdaRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lambda.amazonaws.com"),
                iam.ServicePrincipal("ec2.amazonaws.com"),
                iam.ServicePrincipal("ssm.amazonaws.com"),
            ),
            description="Permissions for AccessGuard Lambda execution",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )

        # SSO read
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "sso-admin:ListInstances",
                "sso-admin:ListPermissionSets",
                "sso-admin:DescribePermissionSet",
                "sso-admin:ListManagedPoliciesInPermissionSet",
                "sso-admin:GetInlinePolicyForPermissionSet",
            ],
            resources=["*"],
        ))

        # STS
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            actions=["sts:AssumeRole", "sts:GetCallerIdentity"],
            resources=["*"],
        ))

        # IAM read
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "iam:GetRole", "iam:GetGroup", "iam:GetRolePolicy",
                "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies", "iam:ListGroupPolicies",
                "iam:ListGroups", "iam:ListRolePolicies", "iam:ListRoles",
                "iam:ListUserPolicies", "iam:ListUsers", "iam:GetUserPolicy",
                "iam:GetGroupPolicy",
            ],
            resources=["*"],
        ))

        # DynamoDB — scoped to our tables
        self.configuration_table.grant_read_write_data(self.lambda_role)
        self.results_table.grant_read_write_data(self.lambda_role)
        self.similarity_table.grant_read_write_data(self.lambda_role)

        # S3 — scoped to our bucket
        self.bucket.grant_read_write(self.lambda_role)

        # SSM
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            actions=["ssm:PutParameter", "ssm:GetParameters"],
            resources=[
                f"arn:{self.partition}:ssm:{self.region}:{self.account}:parameter/AccessGuard/*"
            ],
        ))

        # =====================================================================
        # Lambda Function
        # =====================================================================

        self.function = lambda_.Function(
            self, "Function",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="accessGuard.lambdaHandler",
            code=lambda_.Code.from_bucket(
                self.bucket, f"{code_folder}/accessGuard.zip"
            ),
            role=self.lambda_role,
            memory_size=2048,
            timeout=Duration.minutes(15),
            description="Catalog IAM entities and similarities for role engineering",
        )

        Tags.of(self).add("Application", "AccessGuard")
