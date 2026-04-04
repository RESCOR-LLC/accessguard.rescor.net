# Copyright (C) 2020-2026 RESCOR LLC. All rights reserved.
#
# This file is part of AccessGuard.
"""
Unit tests for GCP provider.
Mocks GCP SDK classes — no GCP credentials needed.
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch, PropertyMock
from collections import namedtuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

from providers.gcp import GcpProvider
from providers.base import EntityRecord


def _make_provider():
    """Create a GcpProvider without calling __init__."""
    provider = GcpProvider.__new__(GcpProvider)
    provider.region = "global"
    provider._credentials = MagicMock()
    provider._project = "test-project-123"
    provider._current_account = "test-project-123"
    return provider


class MockProject:
    ACTIVE = 1

    def __init__(self, project_id, display_name, state=1):
        self.project_id = project_id
        self.display_name = display_name
        self.state = state


class MockBinding:
    def __init__(self, role, members):
        self.role = role
        self.members = members


class MockPolicy:
    def __init__(self, bindings):
        self.bindings = bindings


class MockIamPolicyResult:
    def __init__(self, resource, bindings):
        self.resource = resource
        self.policy = MockPolicy(bindings)


class TestGcpMemberParsing:

    def test_user(self):
        etype, name = GcpProvider._parse_member("user:alice@example.com")
        assert etype == "User"
        assert name == "alice@example.com"

    def test_group(self):
        etype, name = GcpProvider._parse_member("group:team@example.com")
        assert etype == "Group"
        assert name == "team@example.com"

    def test_service_account(self):
        etype, name = GcpProvider._parse_member("serviceAccount:sa@proj.iam.gserviceaccount.com")
        assert etype == "ServiceAccount"
        assert name == "sa@proj.iam.gserviceaccount.com"

    def test_domain(self):
        etype, name = GcpProvider._parse_member("domain:example.com")
        assert etype == "Domain"
        assert name == "example.com"

    def test_all_users(self):
        etype, name = GcpProvider._parse_member("allUsers")
        assert etype == "PublicAccess"
        assert "anyone" in name.lower() or "internet" in name.lower()

    def test_all_authenticated_users(self):
        etype, name = GcpProvider._parse_member("allAuthenticatedUsers")
        assert etype == "PublicAccess"
        assert "google account" in name.lower() or "authenticated" in name.lower()

    def test_unknown_prefix(self):
        etype, name = GcpProvider._parse_member("newtype:something")
        assert etype == "newtype"
        assert name == "something"


class TestGcpProviderDiscovery:

    @patch("providers.gcp.resourcemanager_v3.ProjectsClient")
    def test_discover_projects(self, mock_projects_cls):
        provider = _make_provider()

        mock_client = MagicMock()
        mock_project1 = MagicMock()
        mock_project1.project_id = "proj-aaa"
        mock_project1.display_name = "Production"
        mock_project1.state = 1  # ACTIVE

        mock_project2 = MagicMock()
        mock_project2.project_id = "proj-bbb"
        mock_project2.display_name = "Staging"
        mock_project2.state = 1  # ACTIVE

        mock_client.search_projects.return_value = [mock_project1, mock_project2]
        mock_projects_cls.return_value = mock_client

        accounts = provider.discover_accounts()
        assert len(accounts) == 2
        assert accounts[0]["id"] == "proj-aaa"
        assert accounts[1]["name"] == "Staging"


class TestGcpProviderScanning:

    def test_scan_inverts_bindings_by_member(self):
        """IAM bindings grouped by resource should be inverted to per-member role sets."""
        provider = _make_provider()

        mock_asset = MagicMock()
        mock_asset.search_all_iam_policies.return_value = [
            MockIamPolicyResult("//storage.googleapis.com/bucket-1", [
                MockBinding("roles/storage.objectViewer", ["user:alice@example.com", "user:bob@example.com"]),
                MockBinding("roles/storage.admin", ["user:alice@example.com"]),
            ]),
            MockIamPolicyResult("//compute.googleapis.com/instance-1", [
                MockBinding("roles/compute.viewer", ["user:bob@example.com"]),
            ]),
        ]

        client = {
            "asset": mock_asset,
            "credentials": MagicMock(),
            "project_id": "test-project",
        }

        with patch.object(provider, '_enrich_service_accounts'):
            results = provider.scan_entities(client, "test-project", "2026-04-04T00:00:00")

        assert len(results) == 2

        alice = next(r for r in results if "alice" in r.name)
        assert "roles/storage.objectViewer" in alice.managed_policies
        assert "roles/storage.admin" in alice.managed_policies
        assert alice.entity_type == "User"
        assert alice.platform == "gcp"

        bob = next(r for r in results if "bob" in r.name)
        assert "roles/storage.objectViewer" in bob.managed_policies
        assert "roles/compute.viewer" in bob.managed_policies

    def test_scan_flags_public_access(self):
        """allUsers and allAuthenticatedUsers should be flagged."""
        provider = _make_provider()

        mock_asset = MagicMock()
        mock_asset.search_all_iam_policies.return_value = [
            MockIamPolicyResult("//storage.googleapis.com/public-bucket", [
                MockBinding("roles/storage.objectViewer", ["allUsers"]),
            ]),
        ]

        client = {
            "asset": mock_asset,
            "credentials": MagicMock(),
            "project_id": "test-project",
        }

        with patch.object(provider, '_enrich_service_accounts'):
            results = provider.scan_entities(client, "test-project", "2026-04-04T00:00:00")

        assert len(results) == 1
        assert results[0].entity_type == "PublicAccess"
        assert results[0].metadata.get("publicAccess") is True

    def test_scan_handles_empty_project(self):
        """Project with no IAM bindings should return empty list."""
        provider = _make_provider()

        mock_asset = MagicMock()
        mock_asset.search_all_iam_policies.return_value = []

        client = {
            "asset": mock_asset,
            "credentials": MagicMock(),
            "project_id": "empty-project",
        }

        with patch.object(provider, '_enrich_service_accounts'):
            results = provider.scan_entities(client, "empty-project", "2026-04-04T00:00:00")

        assert results == []

    def test_scan_handles_asset_api_failure_gracefully(self):
        """Asset API failure should not crash — return empty."""
        provider = _make_provider()

        mock_asset = MagicMock()
        mock_asset.search_all_iam_policies.side_effect = Exception("Permission denied")

        client = {
            "asset": mock_asset,
            "credentials": MagicMock(),
            "project_id": "test-project",
        }

        with patch.object(provider, '_enrich_service_accounts'):
            results = provider.scan_entities(client, "test-project", "2026-04-04T00:00:00")

        assert results == []


class TestGcpPromptContext:

    def test_prompt_contains_key_rules(self):
        provider = _make_provider()
        ctx = provider.system_prompt_context()

        assert "allUsers" in ctx
        assert "allAuthenticatedUsers" in ctx
        assert "RESOURCE-CENTRIC" in ctx
        assert "serviceAccountUser" in ctx
        assert "serviceAccountTokenCreator" in ctx
        assert "roles/editor" in ctx
        assert "orphaned" in ctx.lower()
        assert "Do NOT recommend consolidating" in ctx


class TestGcpEntityRecordCompatibility:

    def test_gcp_records_work_with_similarity_engine(self):
        from accessGuardClasses import SimilarEntities

        se = SimilarEntities()

        r1 = EntityRecord(
            name="alice@example.com", account="proj-1", entity_type="User",
            platform="gcp",
            managed_policies=["roles/storage.objectViewer", "roles/compute.viewer"],
        )
        r2 = EntityRecord(
            name="bob@example.com", account="proj-1", entity_type="User",
            platform="gcp",
            managed_policies=["roles/storage.objectViewer", "roles/compute.viewer"],
        )
        r3 = EntityRecord(
            name="sa@proj.iam.gserviceaccount.com", account="proj-1",
            entity_type="ServiceAccount", platform="gcp",
            managed_policies=["roles/owner"],
        )

        se.add(r1)
        se.add(r2)
        se.add(r3)

        results = se.extract()
        managed_results = [r for r in results if r["similarity"] == "Managed Policies"]

        assert len(managed_results) == 1
        assert len(managed_results[0]["entities"]) == 2

    def test_gcp_records_work_with_role_analyzer(self):
        from roleAnalyzer import RoleAnalyzer

        entities = [
            EntityRecord(name="user-1@ex.com", account="proj-1", entity_type="User",
                         platform="gcp",
                         managed_policies=["roles/viewer", "roles/storage.objectViewer", "roles/compute.viewer"]),
            EntityRecord(name="user-2@ex.com", account="proj-1", entity_type="User",
                         platform="gcp",
                         managed_policies=["roles/viewer", "roles/storage.objectViewer", "roles/compute.viewer"]),
            EntityRecord(name="sa@proj.iam", account="proj-1", entity_type="ServiceAccount",
                         platform="gcp",
                         managed_policies=["roles/editor"]),
        ]

        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(entities)
        result = analyzer.analyze()

        assert result["entityCount"] == 3
        assert result["clusterCount"] >= 1

        cluster_names = []
        for c in result["clusters"]:
            cluster_names.extend([e["name"] for e in c["entities"]])
        assert "user-1@ex.com" in cluster_names
        assert "user-2@ex.com" in cluster_names
        assert "sa@proj.iam" not in cluster_names
