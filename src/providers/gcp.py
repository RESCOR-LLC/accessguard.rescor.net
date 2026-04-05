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
GCP cloud provider for AccessGuard.

Scans GCP IAM by inverting the resource-centric model:
  1. Cloud Asset API: bulk-scan all IAM policy bindings across the org/project
  2. Invert: group bindings by member to build per-principal role sets
  3. IAM API: resolve role names to permission lists (for custom roles)
  4. IAM API: list service accounts with key metadata

GCP's IAM model attaches policies to resources, not principals. To answer
"what can Alice do?" we must scan all resource-level policies. The Cloud
Asset searchAllIamPolicies API does this efficiently in one call.

Authentication uses Application Default Credentials (ADC):
  - gcloud CLI (`gcloud auth application-default login`)
  - Service account key (GOOGLE_APPLICATION_CREDENTIALS env var)
  - Compute Engine / Cloud Run metadata service
"""

import logging
from collections import defaultdict

from providers.base import CloudProvider, EntityRecord

_LOGGER = logging.getLogger(__name__)


def _emit(code, severity, message):
    """Emit a log message. Uses commonClasses.emit if available."""
    try:
        import commonClasses as cc
        cc.emit(code, severity, message)
    except ImportError:
        level = {"i": logging.INFO, "w": logging.WARNING,
                 "e": logging.ERROR, "d": logging.DEBUG}.get(severity, logging.INFO)
        _LOGGER.log(level, f"{code}{severity} {message}")


class GcpProvider(CloudProvider):

    def __init__(self, region: str = "global", **kwargs):
        """
        Args:
            region: GCP region (informational — IAM is global).
        """
        # Suppress verbose gRPC and Google auth logging
        # grpc._plugin_wrapping uses _LOGGER.exception() for auth callback
        # failures, so it must be set to CRITICAL to suppress
        for name in ("google", "grpc", "urllib3", "google.auth",
                      "google.auth.transport", "grpc._plugin_wrapping",
                      "grpc._cython"):
            logging.getLogger(name).setLevel(logging.CRITICAL)

        # Suppress gRPC stderr output for auth callback errors
        import os
        os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

        try:
            import google.auth
            from google.auth import exceptions as auth_exceptions
        except ImportError:
            raise ImportError(
                "GCP provider requires google-auth. "
                "Install: pip install -r requirements/gcp.txt"
            )

        self.region = region
        try:
            self._credentials, self._project = google.auth.default()
        except google.auth.exceptions.DefaultCredentialsError:
            raise EnvironmentError(
                "GCP credentials not found. Run: gcloud auth application-default login"
            )
        self._current_account = self._project or "unknown"

    @property
    def name(self) -> str:
        return "gcp"

    def discover_accounts(self) -> list:
        """
        List all GCP projects accessible to the current credential.
        Uses Resource Manager API.
        """
        from google.cloud import resourcemanager_v3
        rm_client = resourcemanager_v3.ProjectsClient(
            credentials=self._credentials)
        accounts = []

        try:
            request = resourcemanager_v3.SearchProjectsRequest()
            for project in rm_client.search_projects(request=request):
                if project.state == resourcemanager_v3.Project.State.ACTIVE:
                    accounts.append({
                        "id": project.project_id,
                        "name": project.display_name or project.project_id,
                    })

            _emit("720010", "i", f"Found {len(accounts)} active GCP projects")
        except Exception as e:
            _emit("720011", "w", f"Project discovery failed: {e}")
            # Fall back to default project
            if self._project:
                accounts = [{"id": self._project, "name": self._project}]

        return accounts

    def get_identity_client(self, account_id: str, role: str = None):
        """
        Return a dict of GCP clients for this project.
        Returns None if the project is inaccessible.
        """
        try:
            from google.cloud import asset_v1
            # Test access by creating an asset client scoped to the project
            asset_client = asset_v1.AssetServiceClient(
                credentials=self._credentials)

            return {
                "asset": asset_client,
                "credentials": self._credentials,
                "project_id": account_id,
            }

        except Exception as e:
            _emit("720020", "w",
                  f"Cannot access project {account_id}: {e} - skipping")
            return None

    def scan_entities(self, client, account_id: str,
                      report_date: str) -> list:
        """
        Scan a GCP project (or org) for IAM entities.

        Strategy:
          1. searchAllIamPolicies — get all bindings across all resources
          2. Invert — group by member to build per-principal role sets
          3. List service accounts — get key and metadata details
        """
        results = []
        asset_client = client["asset"]
        scope = f"projects/{account_id}"

        # ─── Step 1: Bulk-scan IAM bindings via Cloud Asset API ─────────
        member_roles = defaultdict(set)       # member → set of role names
        member_resources = defaultdict(set)   # member → set of resource names
        binding_count = 0

        try:
            from google.cloud import asset_v1
            request = asset_v1.SearchAllIamPoliciesRequest(scope=scope)

            for result in asset_client.search_all_iam_policies(request=request):
                resource = result.resource
                if result.policy and result.policy.bindings:
                    for binding in result.policy.bindings:
                        role = binding.role
                        for member in binding.members:
                            member_roles[member].add(role)
                            member_resources[member].add(resource)
                            binding_count += 1

            _emit("720030", "i",
                  f"  {binding_count} IAM bindings across "
                  f"{len(member_roles)} principals")

        except Exception as e:
            err_msg = str(e)
            if "Reauthentication" in err_msg or "RefreshError" in type(e).__name__:
                _emit("720031", "e",
                      "  GCP credentials expired. Run: gcloud auth application-default login")
            else:
                _emit("720031", "w", f"  IAM policy scan failed: {e}")

        # ─── Step 2: Build EntityRecord per principal ───────────────────
        for member, roles in member_roles.items():
            entity_type, display_name = self._parse_member(member)

            # Flag dangerous bindings
            metadata = {}
            if member in ("allUsers", "allAuthenticatedUsers"):
                metadata["publicAccess"] = True

            resources = member_resources.get(member, set())
            metadata["resourceCount"] = len(resources)

            results.append(EntityRecord(
                name=display_name,
                account=account_id,
                entity_type=entity_type,
                platform="gcp",
                identifier=member,
                managed_policies=sorted(roles),
                metadata=metadata,
                report_date=report_date,
            ))

        _emit("720032", "i", f"  {len(results)} principals from IAM bindings")

        # ─── Step 3: Enrich service accounts ────────────────────────────
        try:
            self._enrich_service_accounts(
                client["credentials"], account_id, report_date, results)
        except Exception as e:
            _emit("720040", "w",
                  f"  Service account enrichment failed: {e}")

        return results

    def _enrich_service_accounts(self, credentials, project_id: str,
                                 report_date: str, results: list):
        """
        List service accounts and enrich matching EntityRecords with
        key metadata and creation dates. Also adds service accounts
        that have no IAM bindings (orphaned).
        """
        from google.cloud.iam_admin_v1 import IAMClient, ListServiceAccountsRequest, ListServiceAccountKeysRequest

        iam_client = IAMClient(credentials=credentials)
        sa_count = 0

        try:
            request = ListServiceAccountsRequest(
                name=f"projects/{project_id}")

            for sa in iam_client.list_service_accounts(request=request):
                sa_email = sa.email
                sa_count += 1

                # Find matching record from IAM bindings
                member_key = f"serviceAccount:{sa_email}"
                found = False
                for rec in results:
                    if rec.identifier == member_key:
                        rec.description = sa.display_name
                        rec.create_date = (sa.create_time.isoformat()
                                           if sa.create_time else None)
                        rec.metadata["disabled"] = sa.disabled

                        # Get key info for trust analysis
                        try:
                            keys_request = ListServiceAccountKeysRequest(
                                name=sa.name)
                            keys = list(iam_client.list_service_account_keys(
                                request=keys_request))
                            user_keys = [k for k in keys
                                         if k.key_type == ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
                            rec.trust_info = {
                                "totalKeys": len(keys),
                                "userManagedKeys": len(user_keys),
                            }
                            if user_keys:
                                rec.metadata["hasUserManagedKeys"] = True
                        except Exception:
                            pass

                        found = True
                        break

                # Service account exists but has no IAM bindings — orphaned
                if not found:
                    results.append(EntityRecord(
                        name=sa_email,
                        account=project_id,
                        entity_type="ServiceAccount",
                        platform="gcp",
                        identifier=member_key,
                        description=sa.display_name,
                        create_date=(sa.create_time.isoformat()
                                     if sa.create_time else None),
                        metadata={"disabled": sa.disabled, "orphaned": True},
                        report_date=report_date,
                    ))

            _emit("720041", "i", f"    {sa_count} service accounts enriched")

        except Exception as e:
            _emit("720042", "w", f"    Service account listing failed: {e}")

    @staticmethod
    def _parse_member(member: str) -> tuple:
        """
        Parse a GCP IAM member string into (entity_type, display_name).

        GCP member formats:
          user:alice@example.com
          group:team@example.com
          serviceAccount:sa@project.iam.gserviceaccount.com
          domain:example.com
          allUsers
          allAuthenticatedUsers
        """
        if ":" in member:
            prefix, identity = member.split(":", 1)
            type_map = {
                "user": "User",
                "group": "Group",
                "serviceAccount": "ServiceAccount",
                "domain": "Domain",
                "principal": "Principal",
                "principalSet": "PrincipalSet",
                "principalHierarchy": "PrincipalHierarchy",
            }
            return type_map.get(prefix, prefix), identity

        # Special members without prefix
        if member == "allUsers":
            return "PublicAccess", "allUsers (anyone on the internet)"
        if member == "allAuthenticatedUsers":
            return "PublicAccess", "allAuthenticatedUsers (any Google account)"

        return "Unknown", member

    def system_prompt_context(self) -> str:
        return """CRITICAL CONTEXT for GCP entities:
- GCP IAM is RESOURCE-CENTRIC: policies are attached to resources, not \
principals. The managed_policies list for each entity represents the set of \
roles granted across all resources in the project/org.
- Members with "allUsers" or "allAuthenticatedUsers" are CRITICAL FINDINGS — \
these grant access to anyone on the internet or any Google account respectively.
- ServiceAccount entities with user-managed keys (hasUserManagedKeys=true) are \
higher risk — key material exists outside Google's control and may be leaked.
- Orphaned service accounts (orphaned=true in metadata) have no IAM bindings \
but still exist — they should be reviewed for deletion.
- Basic roles (roles/viewer, roles/editor, roles/owner) are overly broad \
and should almost always be replaced with predefined or custom roles. \
roles/editor is especially dangerous: it includes deploy permissions.
- roles/iam.serviceAccountUser and roles/iam.serviceAccountTokenCreator are \
the GCP equivalents of AWS trust policies — they control who can impersonate \
a service account. These are critical for delegation analysis.
- IAM bindings at the organization or folder level inherit to all child \
projects. Consolidation at higher scopes has wide blast radius.
- Disabled service accounts (disabled=true) are candidates for deletion \
rather than consolidation.

Do NOT recommend consolidating:
- Entities with publicAccess metadata (allUsers/allAuthenticatedUsers)
- Service accounts owned by different projects or applications
- Bindings at different hierarchy levels (org vs folder vs project)
- Google-managed service accounts (ending in @*.gserviceaccount.com with \
specific service agent patterns)"""

    def build_identifier(self, account: str, entity_type: str,
                         name: str) -> str:
        prefix_map = {
            "User": "user",
            "Group": "group",
            "ServiceAccount": "serviceAccount",
            "Domain": "domain",
        }
        prefix = prefix_map.get(entity_type, entity_type.lower())
        return f"{prefix}:{name}"
