"""
Shared test fixtures for AccessGuard tests.
"""

import sys
import os
import pytest

# Add src/ to path so imports work
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)


class MockIamOutputRow:
    """
    Lightweight mock of IamOutputRow for unit tests that don't need
    the full class with its AWS dependencies.
    """

    def __init__(self, name, account="111111111111", entityType="Role",
                 managed=None, members=None, policy=None, arn=None):
        self.name = name
        self.account = account
        self.entityType = entityType
        self.managed = managed or []
        self.members = members or []
        self.policy = policy or {}
        self.arn = arn or f"arn:aws:iam::{account}:{entityType.lower()}/{name}"
        self.reportDate = "2026-04-03T00:00:00"
        self.id = f"mock-{name}"
        self.description = None

    def asDict(self, ttl=None):
        d = {
            "reportDate": self.reportDate,
            "id": self.id,
            "account": self.account,
            "type": self.entityType,
            "name": self.name,
            "arn": self.arn,
            "description": self.description,
            "members": self.members,
            "managed": self.managed,
            "policy": self.policy,
        }
        if ttl:
            import time
            d["TTL"] = int(time.time() + ttl)
        return d


@pytest.fixture
def sample_roles():
    """
    A set of mock roles with known overlaps for testing clustering
    and similarity detection.
    """
    return [
        # Exact duplicates — identical managed policies
        MockIamOutputRow("AppRole1", managed=["S3ReadOnly", "EC2Describe", "CloudWatchLogs"]),
        MockIamOutputRow("AppRole2", managed=["S3ReadOnly", "EC2Describe", "CloudWatchLogs"]),

        # High overlap (2/3 = 67%) — below default threshold
        MockIamOutputRow("DataRole1", managed=["S3ReadOnly", "RDSReadOnly", "CloudWatchLogs"]),
        MockIamOutputRow("DataRole2", managed=["S3ReadOnly", "RDSReadOnly", "GlueFullAccess"]),

        # Very high overlap (4/5 = 80%) — above default threshold
        MockIamOutputRow("AdminRole1", managed=["IAMFullAccess", "S3FullAccess", "EC2FullAccess", "VPCFullAccess", "CloudWatchLogs"]),
        MockIamOutputRow("AdminRole2", managed=["IAMFullAccess", "S3FullAccess", "EC2FullAccess", "VPCFullAccess", "RDSFullAccess"]),

        # Strict subset
        MockIamOutputRow("ReadOnlyRole", managed=["S3ReadOnly", "EC2Describe"]),  # subset of AppRole1

        # No overlap — unique
        MockIamOutputRow("LambdaRole", managed=["LambdaFullAccess", "SQSFullAccess"]),

        # Identical inline policies, different policy names
        MockIamOutputRow("InlineRole1", managed=[], policy={
            "MyCustomPolicy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        }),
        MockIamOutputRow("InlineRole2", managed=[], policy={
            "DifferentName": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        }),

        # No policies at all
        MockIamOutputRow("EmptyRole", managed=[], policy={}),
    ]
