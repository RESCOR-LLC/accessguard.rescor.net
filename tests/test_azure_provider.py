# Copyright (C) 2020-2026 RESCOR LLC. All rights reserved.
#
# This file is part of AccessGuard.
"""
Unit tests for Azure provider.
Mocks Azure SDK classes — no Azure credentials needed.
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

from providers.azure import AzureProvider
from providers.base import EntityRecord


def _make_provider():
    """Create an AzureProvider without calling __init__ (avoids real credential)."""
    provider = AzureProvider.__new__(AzureProvider)
    provider.credential = MagicMock()
    provider.region = "eastus"
    provider._tenant_id = "tenant-123"
    return provider


class MockSubscription:
    def __init__(self, sub_id, name, state="Enabled", tenant_id="tenant-123"):
        self.subscription_id = sub_id
        self.display_name = name
        self.state = state
        self.tenant_id = tenant_id


class MockRoleDefinition:
    def __init__(self, rd_id, role_name):
        self.id = rd_id
        self.role_name = role_name


class MockRoleAssignment:
    def __init__(self, principal_id, role_definition_id, scope, principal_type="User"):
        self.principal_id = principal_id
        self.role_definition_id = role_definition_id
        self.scope = scope
        self.principal_type = principal_type


class TestAzureProviderDiscovery:

    @patch("providers.azure.SubscriptionClient")
    def test_discover_subscriptions(self, mock_sub_cls):
        provider = _make_provider()

        mock_client = MagicMock()
        mock_client.subscriptions.list.return_value = [
            MockSubscription("sub-111", "Production"),
            MockSubscription("sub-222", "Staging"),
        ]
        mock_sub_cls.return_value = mock_client

        accounts = provider.discover_accounts()
        assert len(accounts) == 2
        assert accounts[0]["id"] == "sub-111"
        assert accounts[1]["name"] == "Staging"

    @patch("providers.azure.SubscriptionClient")
    def test_filters_disabled_subscriptions(self, mock_sub_cls):
        provider = _make_provider()

        mock_client = MagicMock()
        mock_client.subscriptions.list.return_value = [
            MockSubscription("sub-1", "Active", "Enabled"),
            MockSubscription("sub-2", "Disabled", "Disabled"),
            MockSubscription("sub-3", "Also Active", "Enabled"),
        ]
        mock_sub_cls.return_value = mock_client

        accounts = provider.discover_accounts()
        assert len(accounts) == 2
        assert accounts[0]["id"] == "sub-1"
        assert accounts[1]["id"] == "sub-3"


class TestAzureProviderRBACScanning:

    def test_scan_rbac_assigns_roles_to_principals(self):
        provider = _make_provider()

        rd1 = MockRoleDefinition("/rd/reader", "Reader")
        rd2 = MockRoleDefinition("/rd/contrib", "Contributor")

        mock_auth = MagicMock()
        mock_auth.role_definitions.list.return_value = [rd1, rd2]
        mock_auth.role_assignments.list_for_scope.return_value = [
            MockRoleAssignment("user-aaa", "/rd/reader", "/subscriptions/sub-1", "User"),
            MockRoleAssignment("user-aaa", "/rd/contrib", "/subscriptions/sub-1", "User"),
            MockRoleAssignment("sp-bbb", "/rd/reader", "/subscriptions/sub-1", "ServicePrincipal"),
        ]

        client = {
            "auth": mock_auth,
            "subscription_id": "sub-1",
            "credential": MagicMock(),
        }

        with patch.object(provider, '_scan_graph', return_value=0):
            results = provider.scan_entities(client, "sub-1", "2026-04-04T00:00:00")

        assert len(results) == 2

        user_rec = next(r for r in results if "user-aaa" in r.name)
        assert "Reader" in user_rec.managed_policies
        assert "Contributor" in user_rec.managed_policies
        assert user_rec.entity_type == "User"
        assert user_rec.platform == "azure"

        sp_rec = next(r for r in results if "sp-bbb" in r.name)
        assert sp_rec.managed_policies == ["Reader"]
        assert sp_rec.entity_type == "ServicePrincipal"

    def test_scan_handles_rbac_failure_gracefully(self):
        provider = _make_provider()

        mock_auth = MagicMock()
        mock_auth.role_definitions.list.side_effect = Exception("Access denied")

        client = {
            "auth": mock_auth,
            "subscription_id": "sub-1",
            "credential": MagicMock(),
        }

        with patch.object(provider, '_scan_graph', return_value=0):
            results = provider.scan_entities(client, "sub-1", "2026-04-04T00:00:00")

        assert results == []


class TestAzurePrincipalTypeMapping:

    def test_maps_known_types(self):
        assert AzureProvider._map_principal_type("User") == "User"
        assert AzureProvider._map_principal_type("Group") == "Group"
        assert AzureProvider._map_principal_type("ServicePrincipal") == "ServicePrincipal"
        assert AzureProvider._map_principal_type("MSI") == "ManagedIdentity"
        assert AzureProvider._map_principal_type("Application") == "ServicePrincipal"
        assert AzureProvider._map_principal_type("ForeignGroup") == "Group"

    def test_passes_through_unknown_types(self):
        assert AzureProvider._map_principal_type("SomethingNew") == "SomethingNew"
        assert AzureProvider._map_principal_type(None) == "Unknown"


class TestAzurePromptContext:

    def test_prompt_context_contains_key_rules(self):
        provider = _make_provider()
        ctx = provider.system_prompt_context()

        assert "Entra ID" in ctx
        assert "ManagedIdentity" in ctx or "Managed Identity" in ctx
        assert "Global Administrator" in ctx
        assert "PIM" in ctx
        assert "ForeignGroup" in ctx
        assert "Do NOT recommend consolidating" in ctx


class TestAzureEntityRecordCompatibility:

    def test_azure_records_work_with_similarity_engine(self):
        from accessGuardClasses import SimilarEntities

        se = SimilarEntities()

        r1 = EntityRecord(
            name="user-alice", account="sub-1", entity_type="User",
            platform="azure", managed_policies=["Reader", "Contributor"],
        )
        r2 = EntityRecord(
            name="user-bob", account="sub-1", entity_type="User",
            platform="azure", managed_policies=["Reader", "Contributor"],
        )
        r3 = EntityRecord(
            name="sp-app", account="sub-1", entity_type="ServicePrincipal",
            platform="azure", managed_policies=["Owner"],
        )

        se.add(r1)
        se.add(r2)
        se.add(r3)

        results = se.extract()
        managed_results = [r for r in results if r["similarity"] == "Managed Policies"]

        assert len(managed_results) == 1
        assert len(managed_results[0]["entities"]) == 2

    def test_azure_records_work_with_role_analyzer(self):
        from roleAnalyzer import RoleAnalyzer

        entities = [
            EntityRecord(name="user-1", account="sub-1", entity_type="User",
                         platform="azure", managed_policies=["Reader", "Contributor", "Backup Operator"]),
            EntityRecord(name="user-2", account="sub-1", entity_type="User",
                         platform="azure", managed_policies=["Reader", "Contributor", "Backup Operator"]),
            EntityRecord(name="sp-unique", account="sub-1", entity_type="ServicePrincipal",
                         platform="azure", managed_policies=["Owner"]),
        ]

        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(entities)
        result = analyzer.analyze()

        assert result["entityCount"] == 3
        assert result["clusterCount"] >= 1

        cluster_names = []
        for c in result["clusters"]:
            cluster_names.extend([e["name"] for e in c["entities"]])
        assert "user-1" in cluster_names
        assert "user-2" in cluster_names
        assert "sp-unique" not in cluster_names
