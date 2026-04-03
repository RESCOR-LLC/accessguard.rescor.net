"""
Level 1 — Unit tests for reportGenerator.py
Tests HTML and JSON generation with known data. No AWS credentials needed.
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportGenerator import generate_html, generate_json


@pytest.fixture
def sample_catalog():
    return [
        {"type": "Role", "name": "AppRole1", "account": "111111111111", "arn": "arn:aws:iam::111:role/AppRole1", "managed": ["S3ReadOnly"], "policy": {}, "members": []},
        {"type": "Role", "name": "AppRole2", "account": "111111111111", "arn": "arn:aws:iam::111:role/AppRole2", "managed": ["S3ReadOnly"], "policy": {}, "members": []},
        {"type": "User", "name": "AdminUser", "account": "222222222222", "arn": "arn:aws:iam::222:user/AdminUser", "managed": ["AdministratorAccess"], "policy": {}, "members": []},
    ]


@pytest.fixture
def sample_similarities():
    return [
        {"similarity": "Managed Policies", "by": ["S3ReadOnly"], "entities": ["arn:aws:iam::111:role/AppRole1", "arn:aws:iam::111:role/AppRole2"]},
    ]


@pytest.fixture
def sample_analysis():
    return {
        "entityCount": 3,
        "threshold": 0.70,
        "model": "Anthropic(claude-sonnet-4-6)",
        "clusters": [
            {"entities": [{"name": "AppRole1"}, {"name": "AppRole2"}], "commonPolicies": ["S3ReadOnly"], "allPolicies": ["S3ReadOnly"], "clusterSize": 2}
        ],
        "clusterCount": 1,
        "subsets": [],
        "subsetCount": 0,
        "aiRecommendations": [
            {
                "cluster": {"entities": [{"name": "AppRole1"}, {"name": "AppRole2"}], "clusterSize": 2},
                "analysis": {
                    "recommendations": [
                        {
                            "action": "CONSOLIDATE",
                            "targetRole": "AppRole1",
                            "mergeRoles": ["AppRole2"],
                            "additionalPermissions": [],
                            "readOnlyAdditions": True,
                            "risk": "LOW",
                            "riskRationale": "Identical policies",
                            "rationale": "These roles have identical managed policies and can be safely consolidated."
                        }
                    ],
                    "summary": "One consolidation opportunity identified."
                }
            }
        ],
    }


class TestHtmlReport:

    def test_contains_title(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert "AccessGuard" in html
        assert "IAM Role Engineering Report" in html

    def test_contains_entity_counts(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert ">3<" in html  # 3 entities

    def test_contains_duplicate_section(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert "Exact Duplicates" in html
        assert "S3ReadOnly" in html

    def test_contains_ai_recommendations(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert "CONSOLIDATE" in html
        assert "LOW" in html
        assert "AppRole1" in html

    def test_contains_model_info(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert "claude-sonnet" in html

    def test_valid_html_structure(self, sample_catalog, sample_similarities, sample_analysis):
        html = generate_html(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_no_analysis(self, sample_catalog, sample_similarities):
        """Report should still generate without AI analysis."""
        html = generate_html(sample_catalog, sample_similarities, None, "2026-04-03T00:00:00")
        assert "AccessGuard" in html
        assert "Deterministic analysis only" in html

    def test_no_similarities(self, sample_catalog):
        """Report should still generate with no duplicates found. No duplicates table rendered."""
        html = generate_html(sample_catalog, [], None, "2026-04-03T00:00:00")
        assert "AccessGuard" in html
        # The h2 "Exact Duplicates" heading should not appear when list is empty
        assert "<h2>Exact Duplicates</h2>" not in html


class TestJsonReport:

    def test_valid_json(self, sample_catalog, sample_similarities, sample_analysis):
        output = generate_json(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        parsed = json.loads(output)
        assert "catalog" in parsed
        assert "similarities" in parsed
        assert "analysis" in parsed
        assert "reportDate" in parsed

    def test_catalog_contents(self, sample_catalog, sample_similarities, sample_analysis):
        output = generate_json(sample_catalog, sample_similarities, sample_analysis, "2026-04-03T00:00:00")
        parsed = json.loads(output)
        assert len(parsed["catalog"]) == 3

    def test_null_analysis(self, sample_catalog, sample_similarities):
        output = generate_json(sample_catalog, sample_similarities, None, "2026-04-03T00:00:00")
        parsed = json.loads(output)
        assert parsed["analysis"] is None
