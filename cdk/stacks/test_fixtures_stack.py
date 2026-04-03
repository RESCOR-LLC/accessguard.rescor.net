"""
Test fixtures stack for AccessGuard Level 3 testing.

Creates sample IAM roles with deliberate overlaps, subsets, and inline
policy equivalents for validating the analysis pipeline against real AWS.

This stack is designed to be deployed and destroyed as part of testing.
It creates NO production resources.
"""

import json

from aws_cdk import (
    RemovalPolicy,
    Stack,
    Tags,
    aws_iam as iam,
)
from constructs import Construct


# Shared assume-role document for all test roles
ASSUME_ROLE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

# Inline policy documents for testing
INLINE_S3_READ = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": "*",
    }],
}

INLINE_S3_READ_RENAMED = {
    # Identical content to INLINE_S3_READ -tests canonicalization
    "Version": "2012-10-17",
    "Statement": [{
        "Resource": "*",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Effect": "Allow",
    }],
}


class TestFixturesStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # =================================================================
        # Managed policies (test-scoped, harmless)
        # =================================================================

        policy_s3_read = iam.ManagedPolicy(
            self, "AGTestS3Read",
            managed_policy_name="AGTest-S3ReadOnly",
            statements=[iam.PolicyStatement(
                actions=["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                resources=["*"],
            )],
        )

        policy_cw_logs = iam.ManagedPolicy(
            self, "AGTestCloudWatch",
            managed_policy_name="AGTest-CloudWatchLogs",
            statements=[iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["*"],
            )],
        )

        policy_ec2_describe = iam.ManagedPolicy(
            self, "AGTestEC2Describe",
            managed_policy_name="AGTest-EC2Describe",
            statements=[iam.PolicyStatement(
                actions=["ec2:Describe*"],
                resources=["*"],
            )],
        )

        policy_rds_read = iam.ManagedPolicy(
            self, "AGTestRDSRead",
            managed_policy_name="AGTest-RDSReadOnly",
            statements=[iam.PolicyStatement(
                actions=["rds:Describe*", "rds:List*"],
                resources=["*"],
            )],
        )

        policy_lambda_full = iam.ManagedPolicy(
            self, "AGTestLambdaFull",
            managed_policy_name="AGTest-LambdaFullAccess",
            statements=[iam.PolicyStatement(
                actions=["lambda:*"],
                resources=["*"],
            )],
        )

        policy_sqs_full = iam.ManagedPolicy(
            self, "AGTestSQSFull",
            managed_policy_name="AGTest-SQSFullAccess",
            statements=[iam.PolicyStatement(
                actions=["sqs:*"],
                resources=["*"],
            )],
        )

        policy_iam_read = iam.ManagedPolicy(
            self, "AGTestIAMRead",
            managed_policy_name="AGTest-IAMReadOnly",
            statements=[iam.PolicyStatement(
                actions=["iam:Get*", "iam:List*"],
                resources=["*"],
            )],
        )

        # =================================================================
        # Test Roles
        # =================================================================

        # --- Exact duplicates: identical managed policies ---
        iam.Role(
            self, "AGTestAppRole1",
            role_name="AGTest-AppRole1",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_cw_logs, policy_ec2_describe],
            description="Test role 1 -exact duplicate of AppRole2",
        )

        iam.Role(
            self, "AGTestAppRole2",
            role_name="AGTest-AppRole2",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_cw_logs, policy_ec2_describe],
            description="Test role 2 -exact duplicate of AppRole1",
        )

        # --- Near-match: high overlap (3/4 shared = 75% Jaccard) ---
        iam.Role(
            self, "AGTestDataRole1",
            role_name="AGTest-DataRole1",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_rds_read, policy_cw_logs],
            description="Test role -near-match with DataRole2 (75% overlap)",
        )

        iam.Role(
            self, "AGTestDataRole2",
            role_name="AGTest-DataRole2",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_rds_read, policy_cw_logs, policy_ec2_describe],
            description="Test role -near-match with DataRole1 (75% overlap), superset",
        )

        # --- Strict subset ---
        iam.Role(
            self, "AGTestReadOnlyRole",
            role_name="AGTest-ReadOnlyRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_ec2_describe],
            description="Test role -strict subset of AppRole1/AppRole2",
        )

        # --- Unique (no overlap with others) ---
        iam.Role(
            self, "AGTestLambdaExec",
            role_name="AGTest-LambdaExec",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[policy_lambda_full, policy_sqs_full],
            description="Test role -unique, should not cluster",
        )

        # --- Identical inline policies, different policy names ---
        inline_role_1 = iam.Role(
            self, "AGTestInlineRole1",
            role_name="AGTest-InlineRole1",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Test role -identical inline policy as InlineRole2 (different name)",
        )
        inline_role_1.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=["*"],
        ))

        inline_role_2 = iam.Role(
            self, "AGTestInlineRole2",
            role_name="AGTest-InlineRole2",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Test role -identical inline policy as InlineRole1 (different name)",
        )
        inline_role_2.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=["*"],
        ))

        # --- Role with both managed and inline ---
        mixed_role = iam.Role(
            self, "AGTestMixedRole",
            role_name="AGTest-MixedRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[policy_s3_read, policy_iam_read],
            description="Test role -has both managed and inline policies",
        )
        mixed_role.add_to_policy(iam.PolicyStatement(
            actions=["sts:AssumeRole"],
            resources=["*"],
        ))

        # --- Empty role (no policies) ---
        iam.Role(
            self, "AGTestEmptyRole",
            role_name="AGTest-EmptyRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Test role -no policies at all, should be excluded from analysis",
        )

        # =================================================================
        # Test runner role -what AccessGuard assumes to read IAM
        # =================================================================

        self.test_runner_role = iam.Role(
            self, "AGTestRunnerRole",
            role_name="AGTest-RunnerRole",
            assumed_by=iam.CompositePrincipal(
                iam.AccountRootPrincipal(),
                iam.ServicePrincipal("lambda.amazonaws.com"),
            ),
            description="AccessGuard test execution role -IAM read + SSO read",
            inline_policies={
                "IAMRead": iam.PolicyDocument(statements=[
                    iam.PolicyStatement(
                        actions=[
                            "iam:Get*", "iam:List*",
                            "sts:GetCallerIdentity", "sts:AssumeRole",
                        ],
                        resources=["*"],
                    ),
                ]),
                "SSORead": iam.PolicyDocument(statements=[
                    iam.PolicyStatement(
                        actions=[
                            "sso-admin:ListInstances",
                            "sso-admin:ListPermissionSets",
                            "sso-admin:DescribePermissionSet",
                            "sso-admin:ListManagedPoliciesInPermissionSet",
                            "sso-admin:GetInlinePolicyForPermissionSet",
                        ],
                        resources=["*"],
                    ),
                ]),
            },
        )

        Tags.of(self).add("Application", "AccessGuard")
        Tags.of(self).add("Environment", "Test")
        Tags.of(self).add("AutoCleanup", "True")
