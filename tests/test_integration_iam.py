"""
Level 2 — Integration tests using moto to mock AWS IAM.
No real credentials needed. Moto intercepts all boto3 calls in-process.

Tests the full pipeline: create IAM entities → extract → detect similarities
→ analyze → generate report.
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import boto3
from moto import mock_aws

from accessGuardClasses import SimilarEntities, IamOutputRow
from roleAnalyzer import RoleAnalyzer
from reportGenerator import generate_html, generate_json


@pytest.fixture
def aws_env():
    """Set mock AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield


def create_role_with_policies(iam_client, role_name, managed_policies=None,
                               inline_policies=None):
    """Helper to create an IAM role with attached policies in mocked AWS."""
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }),
        Path="/",
    )

    # Attach managed policies (create them first if needed)
    for policy_name in (managed_policies or []):
        policy_arn = f"arn:aws:iam::123456789012:policy/{policy_name}"
        try:
            iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }),
            )
        except iam_client.exceptions.EntityAlreadyExistsException:
            pass
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # Add inline policies
    for policy_name, policy_doc in (inline_policies or {}).items():
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
        )


class TestMotoIamIntegration:

    @mock_aws
    def test_create_and_list_roles(self, aws_env):
        """Basic sanity: create roles in moto and verify they exist."""
        client = boto3.client("iam", region_name="us-east-1")

        create_role_with_policies(client, "TestRole1", managed_policies=["ReadOnly"])
        create_role_with_policies(client, "TestRole2", managed_policies=["ReadOnly"])

        roles = client.list_roles()["Roles"]
        names = [r["RoleName"] for r in roles]
        assert "TestRole1" in names
        assert "TestRole2" in names

    @mock_aws
    def test_duplicate_detection_via_output_rows(self, aws_env):
        """Create two roles with identical managed policies, verify SimilarEntities detects them."""
        client = boto3.client("iam", region_name="us-east-1")

        create_role_with_policies(client, "DupRole1", managed_policies=["PolicyA", "PolicyB"])
        create_role_with_policies(client, "DupRole2", managed_policies=["PolicyA", "PolicyB"])

        # Simulate what processIam does — build IamOutputRow objects
        similar = SimilarEntities()
        rows = []

        for role_name in ["DupRole1", "DupRole2"]:
            attached = client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            managed = [p["PolicyName"] for p in attached]

            row = IamOutputRow(
                name=role_name,
                account="123456789012",
                entityType="Role",
                managed=managed,
                policy={},
            )
            rows.append(row)
            similar.add(row)

        results = similar.extract()
        managed_results = [r for r in results if r["similarity"] == "Managed Policies"]

        assert len(managed_results) == 1
        assert len(managed_results[0]["entities"]) == 2

    @mock_aws
    def test_inline_policy_detection(self, aws_env):
        """Two roles with identical inline policies but different names should be detected."""
        client = boto3.client("iam", region_name="us-east-1")

        policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}

        create_role_with_policies(client, "InlineA", inline_policies={"CustomPolicyA": policy_doc})
        create_role_with_policies(client, "InlineB", inline_policies={"CustomPolicyB": policy_doc})

        similar = SimilarEntities()
        rows = []

        for role_name in ["InlineA", "InlineB"]:
            inline_names = client.list_role_policies(RoleName=role_name)["PolicyNames"]
            policy = {}
            for pname in inline_names:
                pdoc = client.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
                policy[pname] = pdoc

            row = IamOutputRow(
                name=role_name,
                account="123456789012",
                entityType="Role",
                managed=[],
                policy=policy,
            )
            rows.append(row)
            similar.add(row)

        results = similar.extract()
        inline_results = [r for r in results if r["similarity"] == "Inline Policies"]

        assert len(inline_results) == 1

    @mock_aws
    def test_full_pipeline_no_ai(self, aws_env):
        """
        Full pipeline test: create roles → build output rows → detect similarities
        → run role analyzer (no AI) → generate reports.
        """
        client = boto3.client("iam", region_name="us-east-1")

        # Create a realistic set of roles
        create_role_with_policies(client, "WebServer",
            managed_policies=["S3Read", "CloudWatch", "EC2Describe"])
        create_role_with_policies(client, "WebServerV2",
            managed_policies=["S3Read", "CloudWatch", "EC2Describe"])
        create_role_with_policies(client, "DataPipeline",
            managed_policies=["S3Full", "GlueFull", "CloudWatch"])
        create_role_with_policies(client, "ReadOnlyAudit",
            managed_policies=["S3Read", "EC2Describe"])
        create_role_with_policies(client, "LambdaExec",
            managed_policies=["LambdaFull", "SQSFull"])

        # Build output rows (simulating processIam)
        similar = SimilarEntities()
        all_rows = []

        for role in client.list_roles()["Roles"]:
            role_name = role["RoleName"]
            attached = client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            managed = [p["PolicyName"] for p in attached]

            inline_names = client.list_role_policies(RoleName=role_name)["PolicyNames"]
            policy = {}
            for pname in inline_names:
                pdoc = client.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
                policy[pname] = pdoc

            row = IamOutputRow(
                name=role_name,
                account="123456789012",
                entityType="Role",
                managed=managed,
                policy=policy,
            )
            all_rows.append(row)
            similar.add(row)

        # Exact similarity detection
        similarities = similar.extract()

        # Role analyzer (deterministic only)
        analyzer = RoleAnalyzer(threshold=0.70, model_provider=None)
        analyzer.add_entities(all_rows)
        analysis = analyzer.analyze()

        # Verify expected results
        assert analysis["entityCount"] == 5

        # WebServer and WebServerV2 are exact duplicates → should cluster
        assert analysis["clusterCount"] >= 1
        cluster_names = []
        for c in analysis["clusters"]:
            cluster_names.extend([e["name"] for e in c["entities"]])
        assert "WebServer" in cluster_names
        assert "WebServerV2" in cluster_names

        # ReadOnlyAudit is a subset of WebServer
        assert analysis["subsetCount"] >= 1
        subset_names = [s["subset"]["name"] for s in analysis["subsets"]]
        assert "ReadOnlyAudit" in subset_names

        # LambdaExec should not cluster with anything
        assert "LambdaExec" not in cluster_names

        # Generate reports
        catalog_dicts = [r.asDict() for r in all_rows]
        similarity_dicts = [{"similarity": s["similarity"], "by": s["by"], "entities": s["entities"]} for s in similarities]

        html = generate_html(catalog_dicts, similarity_dicts, analysis, "2026-04-03T00:00:00")
        assert "AccessGuard" in html
        assert "WebServer" in html
        assert len(html) > 1000  # Sanity: report has real content

        json_output = generate_json(catalog_dicts, similarity_dicts, analysis, "2026-04-03T00:00:00")
        import json as json_mod
        parsed = json_mod.loads(json_output)
        assert len(parsed["catalog"]) == 5
        assert parsed["analysis"]["clusterCount"] >= 1
