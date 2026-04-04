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
#
"""
AI-powered role analysis for AccessGuard.

Performs two stages of analysis:
1. Deterministic pre-clustering using Jaccard similarity on managed policies
2. AI-powered consolidation analysis per cluster (optional, requires a ModelProvider)
"""

import json
import logging
from itertools import combinations

import commonClasses as cc

_LOGGER = logging.getLogger(__name__)


def jaccard(set_a: set, set_b: set) -> float:
    """Jaccard similarity coefficient: |A ∩ B| / |A ∪ B|"""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def is_subset(set_a: set, set_b: set) -> bool:
    """True if set_a is a strict subset of set_b."""
    return set_a < set_b


class RoleCluster:
    """A group of IAM entities with overlapping managed policies."""

    def __init__(self, entities: list):
        self.entities = entities
        self.min_similarity = 0.0

    @property
    def size(self) -> int:
        return len(self.entities)

    @property
    def entity_names(self) -> list:
        return [e.name for e in self.entities]

    @property
    def entity_arns(self) -> list:
        return [e.arn for e in self.entities]

    def summary(self) -> dict:
        """Return a serializable summary of this cluster."""
        all_policies = set()
        common_policies = None

        for entity in self.entities:
            policies = set(entity.managed or [])
            all_policies |= policies
            common_policies = policies if common_policies is None \
                else common_policies & policies

        return {
            "entities": [
                {
                    "name": e.name,
                    "arn": e.arn,
                    "account": e.account,
                    "entityType": e.entityType,
                    "managedPolicies": sorted(e.managed or []),
                    "inlinePolicyNames": sorted(
                        e.policy.keys() if isinstance(e.policy, dict) else []
                    ),
                    "trustPolicy": getattr(e, "trustPolicy", {}),
                    "tags": getattr(e, "tags", {}),
                    "lastUsed": getattr(e, "lastUsed", None),
                    "createDate": getattr(e, "createDate", None),
                }
                for e in self.entities
            ],
            "commonPolicies": sorted(common_policies or set()),
            "allPolicies": sorted(all_policies),
            "clusterSize": self.size,
        }


class RoleAnalyzer:
    """
    Analyzes IAM entities for consolidation opportunities.

    Stage 1 (deterministic): Jaccard similarity clustering
    Stage 2 (AI-powered): Per-cluster consolidation recommendations
    """

    SYSTEM_PROMPT_PREAMBLE = """You are an identity and access management \
security analyst specializing in role engineering and the principle of \
optimal privilege. You analyze groups of identity entities that share \
overlapping permissions and recommend consolidation opportunities.

Your recommendations must balance security with operational practicality. \
Overly granular permissions cause role explosion, audit failure, and \
productivity loss. The goal is the smallest number of well-defined roles \
that let the organization function effectively while remaining auditable.

Always return valid JSON matching the requested schema. Do not include \
explanatory text outside the JSON."""

    USER_PROMPT_TEMPLATE = """Analyze these {n} identity entities that share \
≥{threshold}% of their managed policies for consolidation opportunities.

Each entity includes trust/delegation info, tags (ownership metadata), \
lastUsed (when last active, if available), and createDate. Use these \
to determine whether consolidation is safe or would break existing automation.

{cluster_json}

For each potential consolidation, return JSON with this schema:
{{
  "recommendations": [
    {{
      "action": "CONSOLIDATE | REVIEW | KEEP_SEPARATE",
      "targetRole": "name of the role to keep (the one with the most permissions)",
      "mergeRoles": ["names of roles to merge into the target"],
      "additionalPermissions": ["permissions the merged role would gain that individual roles did not have"],
      "readOnlyAdditions": true/false,
      "risk": "LOW | MEDIUM | HIGH",
      "riskRationale": "brief explanation",
      "rationale": "brief explanation of why these can or cannot be consolidated"
    }}
  ],
  "summary": "one-sentence overall assessment"
}}

Risk ratings:
- LOW: only read-only permissions added, no sensitive service access
- MEDIUM: write permissions added to non-sensitive services
- HIGH: write permissions added to IAM, KMS, STS, Organizations, or other sensitive services"""

    def __init__(self, threshold: float = 0.70, model_provider=None,
                 platform_context: str = ""):
        """
        Args:
            threshold: Jaccard similarity threshold for clustering (0.0 to 1.0)
            model_provider: ModelProvider instance, or None for deterministic-only
            platform_context: Cloud-specific rules for the AI prompt (from provider)
        """
        self.threshold = threshold
        self.model = model_provider
        self.platform_context = platform_context
        self.entities = []

    def add_entities(self, entities: list):
        """Add IamOutputRow objects for analysis."""
        self.entities.extend(entities)

    def _build_clusters(self) -> list:
        """
        Stage 1: Group entities by managed policy overlap using Jaccard similarity.
        Uses single-linkage clustering — if any entity in a cluster has ≥threshold
        similarity with a new entity, the new entity joins that cluster.
        """
        # Build policy sets for each entity
        policy_sets = []
        for entity in self.entities:
            policies = set(entity.managed or [])
            policy_sets.append((entity, policies))

        # Filter out entities with no managed policies (nothing to compare)
        with_policies = [(e, p) for e, p in policy_sets if p]
        without_policies = [e for e, p in policy_sets if not p]

        if without_policies:
            cc.emit("250010", "i",
                f'{len(without_policies)} entities have no managed policies '
                f'and are excluded from clustering')

        # Compute pairwise similarities
        n = len(with_policies)
        clusters = []  # list of sets of indices
        assigned = set()

        for i in range(n):
            if i in assigned:
                continue

            cluster_indices = {i}
            assigned.add(i)

            # Find all entities similar to any member of this cluster
            changed = True
            while changed:
                changed = False
                for j in range(n):
                    if j in assigned:
                        continue
                    # Check if j is similar to any member of the cluster
                    for k in cluster_indices:
                        sim = jaccard(with_policies[j][1], with_policies[k][1])
                        if sim >= self.threshold:
                            cluster_indices.add(j)
                            assigned.add(j)
                            changed = True
                            break

            if len(cluster_indices) > 1:
                cluster_entities = [with_policies[idx][0] for idx in cluster_indices]
                clusters.append(RoleCluster(cluster_entities))

        cc.emit("250020", "i",
            f'identified {len(clusters)} clusters from {n} entities '
            f'at threshold {self.threshold:.0%}')

        return clusters

    def _find_subsets(self) -> list:
        """
        Find entities whose managed policies are strict subsets of another entity.
        These are strong consolidation candidates independent of clustering.
        """
        subsets = []
        entities_with_policies = [
            (e, set(e.managed or [])) for e in self.entities if e.managed
        ]

        for i, (entity_a, set_a) in enumerate(entities_with_policies):
            for j, (entity_b, set_b) in enumerate(entities_with_policies):
                if i == j:
                    continue
                if is_subset(set_a, set_b):
                    subsets.append({
                        "subset": {
                            "name": entity_a.name,
                            "arn": entity_a.arn,
                            "policies": sorted(set_a),
                        },
                        "superset": {
                            "name": entity_b.name,
                            "arn": entity_b.arn,
                            "policies": sorted(set_b),
                        },
                        "additionalInSuperset": sorted(set_b - set_a),
                    })

        cc.emit("250030", "i", f'identified {len(subsets)} subset relationships')
        return subsets

    def _ai_analyze_cluster(self, cluster: RoleCluster) -> dict:
        """
        Stage 2: Send a cluster to the AI model for consolidation analysis.
        Returns the model's recommendation dict.
        """
        if not self.model:
            return None

        cluster_data = cluster.summary()
        threshold_pct = int(self.threshold * 100)

        user_prompt = self.USER_PROMPT_TEMPLATE.format(
            n=cluster.size,
            threshold=threshold_pct,
            cluster_json=json.dumps(cluster_data, indent=2),
        )

        # Assemble system prompt: generic preamble + platform-specific context
        system_prompt = self.SYSTEM_PROMPT_PREAMBLE
        if self.platform_context:
            system_prompt += "\n\n" + self.platform_context

        try:
            result = self.model.analyze(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
            return result
        except Exception as e:
            cc.emit("250040", "e",
                f'AI analysis failed for cluster {cluster.entity_names}: {e}')
            return {"error": str(e), "cluster": cluster.entity_names}

    def analyze(self) -> dict:
        """
        Run the full analysis pipeline and return structured results.
        """
        cc.emit("250050", "i",
            f'analyzing {len(self.entities)} entities '
            f'(threshold={self.threshold:.0%}, '
            f'model={self.model or "none (deterministic only)"})')

        # Stage 1: Deterministic analysis
        clusters = self._build_clusters()
        subsets = self._find_subsets()

        # Stage 2: AI analysis (if model provided)
        ai_recommendations = []
        if self.model and clusters:
            cc.emit("250060", "i",
                f'sending {len(clusters)} clusters to {self.model} for analysis')

            for i, cluster in enumerate(clusters):
                cc.emit("250070", "i",
                    f'analyzing cluster {i+1}/{len(clusters)} '
                    f'({cluster.size} entities)')
                result = self._ai_analyze_cluster(cluster)
                if result:
                    ai_recommendations.append({
                        "cluster": cluster.summary(),
                        "analysis": result,
                    })

        return {
            "entityCount": len(self.entities),
            "threshold": self.threshold,
            "model": str(self.model) if self.model else None,
            "clusters": [c.summary() for c in clusters],
            "clusterCount": len(clusters),
            "subsets": subsets,
            "subsetCount": len(subsets),
            "aiRecommendations": ai_recommendations,
        }
