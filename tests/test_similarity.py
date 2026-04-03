"""
Level 1 — Unit tests for SimilarEntities and inline policy canonicalization.
No AWS credentials needed.
"""

import pytest
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from accessGuardClasses import SimilarEntities
from tests.conftest import MockIamOutputRow


class TestCanonicalizePolicy:

    def test_identical_content_different_names(self):
        """Two policies with the same content but different names should produce the same key."""
        policy_a = {"MyPolicy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}
        policy_b = {"OtherName": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}

        key_a = SimilarEntities.canonicalizePolicy(policy_a)
        key_b = SimilarEntities.canonicalizePolicy(policy_b)

        assert key_a is not None
        assert key_a == key_b

    def test_different_content(self):
        """Policies with different content should produce different keys."""
        policy_a = {"P": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}
        policy_b = {"P": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}}

        key_a = SimilarEntities.canonicalizePolicy(policy_a)
        key_b = SimilarEntities.canonicalizePolicy(policy_b)

        assert key_a != key_b

    def test_different_key_order(self):
        """Same content with different JSON key order should produce the same key."""
        policy_a = {"P": {"Version": "2012-10-17", "Statement": [{"Action": "s3:*", "Effect": "Allow", "Resource": "*"}]}}
        policy_b = {"P": {"Statement": [{"Resource": "*", "Effect": "Allow", "Action": "s3:*"}], "Version": "2012-10-17"}}

        key_a = SimilarEntities.canonicalizePolicy(policy_a)
        key_b = SimilarEntities.canonicalizePolicy(policy_b)

        assert key_a == key_b

    def test_empty_dict_returns_none(self):
        assert SimilarEntities.canonicalizePolicy({}) is None

    def test_none_returns_none(self):
        assert SimilarEntities.canonicalizePolicy(None) is None

    def test_string_input_parsed(self):
        """JSON string input should be parsed and canonicalized."""
        policy_dict = {"P": {"Version": "2012-10-17", "Statement": []}}
        policy_str = json.dumps(policy_dict)

        key_dict = SimilarEntities.canonicalizePolicy(policy_dict)
        key_str = SimilarEntities.canonicalizePolicy(policy_str)

        assert key_dict == key_str

    def test_invalid_string_returns_none(self):
        assert SimilarEntities.canonicalizePolicy("not json") is None

    def test_multiple_policies_sorted(self):
        """Multiple inline policies should be sorted by canonical content, not by name."""
        policy_a = {
            "Zebra": {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]},
            "Alpha": {"Statement": [{"Effect": "Deny", "Action": "ec2:*"}]},
        }
        policy_b = {
            "First": {"Statement": [{"Effect": "Deny", "Action": "ec2:*"}]},
            "Second": {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]},
        }

        assert SimilarEntities.canonicalizePolicy(policy_a) == \
               SimilarEntities.canonicalizePolicy(policy_b)


class TestSimilarEntitiesThreeDimensions:

    def test_managed_policy_similarity(self):
        """Entities with identical managed policies are detected."""
        se = SimilarEntities()
        se.add(MockIamOutputRow("R1", managed=["P1", "P2"]))
        se.add(MockIamOutputRow("R2", managed=["P1", "P2"]))
        se.add(MockIamOutputRow("R3", managed=["P3"]))

        results = se.extract()
        managed_results = [r for r in results if r["similarity"] == "Managed Policies"]

        assert len(managed_results) == 1
        assert len(managed_results[0]["entities"]) == 2

    def test_group_membership_similarity(self):
        """Groups with identical members are detected."""
        se = SimilarEntities()
        se.add(MockIamOutputRow("G1", entityType="Group", members=["UserA", "UserB"]))
        se.add(MockIamOutputRow("G2", entityType="Group", members=["UserA", "UserB"]))

        results = se.extract()
        member_results = [r for r in results if r["similarity"] == "Group Membership"]

        assert len(member_results) == 1

    def test_inline_policy_similarity(self):
        """Entities with identical inline policies (different names) are detected."""
        se = SimilarEntities()
        policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        se.add(MockIamOutputRow("R1", policy={"PolicyA": policy_doc}))
        se.add(MockIamOutputRow("R2", policy={"PolicyB": policy_doc}))

        results = se.extract()
        inline_results = [r for r in results if r["similarity"] == "Inline Policies"]

        assert len(inline_results) == 1
        assert len(inline_results[0]["entities"]) == 2

    def test_no_false_positives_for_different_inline_policies(self):
        """Entities with different inline policies should not match."""
        se = SimilarEntities()
        se.add(MockIamOutputRow("R1", policy={"P": {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]}}))
        se.add(MockIamOutputRow("R2", policy={"P": {"Statement": [{"Effect": "Deny", "Action": "s3:*"}]}}))

        results = se.extract()
        inline_results = [r for r in results if r["similarity"] == "Inline Policies"]

        assert len(inline_results) == 0

    def test_singletons_not_reported(self):
        """An entity with no match should not appear in results."""
        se = SimilarEntities()
        se.add(MockIamOutputRow("R1", managed=["Unique1"]))
        se.add(MockIamOutputRow("R2", managed=["Unique2"]))

        results = se.extract()
        assert len(results) == 0

    def test_membership_only_for_groups(self):
        """Roles with members should not be compared by membership (only groups)."""
        se = SimilarEntities()
        se.add(MockIamOutputRow("R1", entityType="Role", members=["UserA"]))
        se.add(MockIamOutputRow("R2", entityType="Role", members=["UserA"]))

        results = se.extract()
        member_results = [r for r in results if r["similarity"] == "Group Membership"]

        assert len(member_results) == 0
