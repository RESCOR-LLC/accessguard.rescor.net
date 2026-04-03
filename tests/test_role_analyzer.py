"""
Level 1 — Unit tests for roleAnalyzer.py
Tests the deterministic analysis: Jaccard similarity, subset detection,
clustering. No AWS credentials or API keys needed.
"""

import pytest
import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, _ROOT)

from roleAnalyzer import jaccard, is_subset, RoleAnalyzer, RoleCluster
from tests.conftest import MockIamOutputRow


class TestJaccard:

    def test_identical_sets(self):
        assert jaccard({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets(self):
        assert jaccard({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        # {a,b,c} ∩ {b,c,d} = {b,c}, union = {a,b,c,d} → 2/4 = 0.5
        assert jaccard({"a", "b", "c"}, {"b", "c", "d"}) == 0.5

    def test_single_element_overlap(self):
        # {a,b,c} ∩ {c,d,e} = {c}, union = {a,b,c,d,e} → 1/5 = 0.2
        assert jaccard({"a", "b", "c"}, {"c", "d", "e"}) == 0.2

    def test_subset(self):
        # {a,b} ∩ {a,b,c} = {a,b}, union = {a,b,c} → 2/3
        assert abs(jaccard({"a", "b"}, {"a", "b", "c"}) - 2/3) < 0.001

    def test_both_empty(self):
        assert jaccard(set(), set()) == 1.0

    def test_one_empty(self):
        assert jaccard(set(), {"a"}) == 0.0
        assert jaccard({"a"}, set()) == 0.0

    def test_single_element_identical(self):
        assert jaccard({"a"}, {"a"}) == 1.0


class TestIsSubset:

    def test_strict_subset(self):
        assert is_subset({"a", "b"}, {"a", "b", "c"}) is True

    def test_equal_sets_not_strict_subset(self):
        assert is_subset({"a", "b"}, {"a", "b"}) is False

    def test_superset(self):
        assert is_subset({"a", "b", "c"}, {"a", "b"}) is False

    def test_disjoint(self):
        assert is_subset({"a"}, {"b"}) is False

    def test_empty_is_subset_of_nonempty(self):
        assert is_subset(set(), {"a"}) is True

    def test_empty_is_not_subset_of_empty(self):
        assert is_subset(set(), set()) is False


class TestRoleCluster:

    def test_summary(self):
        roles = [
            MockIamOutputRow("Role1", managed=["PolicyA", "PolicyB"]),
            MockIamOutputRow("Role2", managed=["PolicyB", "PolicyC"]),
        ]
        cluster = RoleCluster(roles)
        summary = cluster.summary()

        assert summary["clusterSize"] == 2
        assert "PolicyB" in summary["commonPolicies"]
        assert set(summary["allPolicies"]) == {"PolicyA", "PolicyB", "PolicyC"}

    def test_entity_names(self):
        roles = [MockIamOutputRow("Alpha"), MockIamOutputRow("Beta")]
        cluster = RoleCluster(roles)
        assert cluster.entity_names == ["Alpha", "Beta"]

    def test_entity_arns(self):
        roles = [MockIamOutputRow("Alpha")]
        cluster = RoleCluster(roles)
        assert "arn:aws:iam::" in cluster.entity_arns[0]


class TestRoleAnalyzerClustering:

    def test_exact_duplicates_cluster(self, sample_roles):
        """AppRole1 and AppRole2 have identical policies — should cluster."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        # Find the cluster containing AppRole1/AppRole2
        app_cluster = None
        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            if "AppRole1" in names and "AppRole2" in names:
                app_cluster = cluster
                break

        assert app_cluster is not None, "AppRole1 and AppRole2 should cluster"

    def test_high_overlap_clusters(self, sample_roles):
        """AdminRole1 and AdminRole2 share 4/6 policies (Jaccard 0.667) — should cluster at 60%."""
        analyzer = RoleAnalyzer(threshold=0.60)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        admin_cluster = None
        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            if "AdminRole1" in names and "AdminRole2" in names:
                admin_cluster = cluster
                break

        assert admin_cluster is not None, "AdminRole1 and AdminRole2 should cluster at 60%"

    def test_low_overlap_does_not_cluster_at_high_threshold(self, sample_roles):
        """DataRole1 and DataRole2 share 2/4 (50%) — should NOT cluster at 70%."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            if "DataRole1" in names and "DataRole2" in names:
                pytest.fail("DataRole1 and DataRole2 should not cluster at 70% threshold")

    def test_low_overlap_clusters_at_low_threshold(self, sample_roles):
        """DataRole1 and DataRole2 share 50% — should cluster at 40% threshold."""
        analyzer = RoleAnalyzer(threshold=0.40)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        data_cluster = None
        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            if "DataRole1" in names and "DataRole2" in names:
                data_cluster = cluster
                break

        assert data_cluster is not None, "DataRole1 and DataRole2 should cluster at 40%"

    def test_unique_role_does_not_cluster(self, sample_roles):
        """LambdaRole has no overlap with anything — should not appear in any cluster."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            assert "LambdaRole" not in names, \
                "LambdaRole should not appear in any cluster"

    def test_empty_role_excluded(self, sample_roles):
        """EmptyRole has no managed policies — should be excluded from clustering."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        for cluster in result["clusters"]:
            names = [e["name"] for e in cluster["entities"]]
            assert "EmptyRole" not in names, \
                "EmptyRole should not appear in any cluster"

    def test_no_ai_returns_no_recommendations(self, sample_roles):
        """Without a model provider, aiRecommendations should be empty."""
        analyzer = RoleAnalyzer(threshold=0.70, model_provider=None)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        assert result["aiRecommendations"] == []
        assert result["model"] is None

    def test_result_structure(self, sample_roles):
        """Verify the result dict has all expected keys."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        assert "entityCount" in result
        assert "threshold" in result
        assert "clusters" in result
        assert "clusterCount" in result
        assert "subsets" in result
        assert "subsetCount" in result
        assert "aiRecommendations" in result
        assert result["entityCount"] == len(sample_roles)
        assert result["threshold"] == 0.70


class TestRoleAnalyzerSubsets:

    def test_strict_subset_detected(self, sample_roles):
        """ReadOnlyRole (S3ReadOnly, EC2Describe) is a strict subset of AppRole1."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        found = False
        for sub in result["subsets"]:
            if sub["subset"]["name"] == "ReadOnlyRole" and \
               sub["superset"]["name"] in ("AppRole1", "AppRole2"):
                found = True
                assert "CloudWatchLogs" in sub["additionalInSuperset"]
                break

        assert found, "ReadOnlyRole should be detected as subset of AppRole1 or AppRole2"

    def test_equal_sets_not_detected_as_subset(self, sample_roles):
        """AppRole1 and AppRole2 are equal — neither is a strict subset."""
        analyzer = RoleAnalyzer(threshold=0.70)
        analyzer.add_entities(sample_roles)
        result = analyzer.analyze()

        for sub in result["subsets"]:
            if sub["subset"]["name"] == "AppRole1" and sub["superset"]["name"] == "AppRole2":
                pytest.fail("Equal sets should not be detected as strict subsets")
            if sub["subset"]["name"] == "AppRole2" and sub["superset"]["name"] == "AppRole1":
                pytest.fail("Equal sets should not be detected as strict subsets")
