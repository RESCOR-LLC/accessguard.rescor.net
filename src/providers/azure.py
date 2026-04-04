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
Azure cloud provider for AccessGuard.

Scans two separate identity/access systems:
  1. Microsoft Entra ID (formerly Azure AD) — users, groups, service principals,
     directory roles. Accessed via Microsoft Graph API.
  2. Azure RBAC — role definitions, role assignments at subscription scope.
     Accessed via Azure Resource Manager (ARM) API.

Authentication uses DefaultAzureCredential, which supports:
  - Azure CLI (`az login`)
  - Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
  - Managed identity (when running on Azure)
"""

import logging

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient

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


class AzureProvider(CloudProvider):

    def __init__(self, region: str = "eastus", **kwargs):
        """
        Args:
            region: Azure region (informational — Entra ID and ARM are global)
        """
        self.region = region
        self.credential = DefaultAzureCredential()
        self._tenant_id = None

    @property
    def name(self) -> str:
        return "azure"

    def discover_accounts(self) -> list:
        """List all Azure subscriptions accessible to the current credential."""
        sub_client = SubscriptionClient(self.credential)
        accounts = []

        for sub in sub_client.subscriptions.list():
            if sub.state and sub.state.lower() == "enabled":
                accounts.append({
                    "id": sub.subscription_id,
                    "name": sub.display_name or sub.subscription_id,
                })
                # Capture tenant ID from first subscription
                if not self._tenant_id and sub.tenant_id:
                    self._tenant_id = sub.tenant_id

        _emit("710010", "i",
              f"Found {len(accounts)} enabled Azure subscriptions")
        return accounts

    def get_identity_client(self, subscription_id: str, role: str = None):
        """
        Return a dict of Azure clients for this subscription.
        Returns None if the subscription is inaccessible.
        """
        try:
            auth_client = AuthorizationManagementClient(
                self.credential, subscription_id)

            # Test access by listing one role definition
            next(auth_client.role_definitions.list(
                scope=f"/subscriptions/{subscription_id}",
            ), None)

            return {
                "auth": auth_client,
                "subscription_id": subscription_id,
                "credential": self.credential,
            }

        except Exception as e:
            _emit("710020", "w",
                  f"Cannot access subscription {subscription_id}: {e} - skipping")
            return None

    def scan_entities(self, client, account_id: str,
                      report_date: str) -> list:
        """
        Scan an Azure subscription for identity entities.

        Collects:
          - Entra ID: users, groups, service principals (via Graph API)
          - Azure RBAC: role assignments resolved to role definitions
        """
        results = []
        subscription_id = client["subscription_id"]
        auth_client = client["auth"]
        scope = f"/subscriptions/{subscription_id}"

        # ─── Azure RBAC: Role Assignments ───────────────────────────────
        role_defs = {}   # cache role_definition_id → role definition
        assignments = []

        try:
            # Cache all role definitions for this subscription
            for rd in auth_client.role_definitions.list(scope=scope):
                role_defs[rd.id] = rd
            _emit("710030", "i",
                  f"  {len(role_defs)} role definitions cached")

            # List all role assignments
            for ra in auth_client.role_assignments.list_for_scope(scope=scope):
                assignments.append(ra)
            _emit("710031", "i",
                  f"  {len(assignments)} role assignments found")

        except Exception as e:
            _emit("710032", "w", f"  RBAC scan failed: {e}")

        # Group assignments by principal
        principal_roles = {}  # principal_id → list of (role_name, scope)
        principal_types = {}  # principal_id → principal_type

        for ra in assignments:
            pid = ra.principal_id
            if pid not in principal_roles:
                principal_roles[pid] = []
                principal_types[pid] = getattr(ra, 'principal_type', 'Unknown')

            rd = role_defs.get(ra.role_definition_id)
            role_name = rd.role_name if rd else ra.role_definition_id
            role_scope = ra.scope or scope
            principal_roles[pid].append(role_name)

        # Build EntityRecord per principal from RBAC assignments
        for pid, roles in principal_roles.items():
            ptype = principal_types.get(pid, "Unknown")
            entity_type = self._map_principal_type(ptype)

            results.append(EntityRecord(
                name=pid,  # Will be enriched by Graph if available
                account=subscription_id,
                entity_type=entity_type,
                platform="azure",
                identifier=f"/subscriptions/{subscription_id}/principals/{pid}",
                managed_policies=sorted(set(roles)),
                report_date=report_date,
                metadata={"principalType": ptype, "assignmentCount": len(roles)},
            ))

        _emit("710033", "i",
              f"  {len(results)} principals from RBAC assignments")

        # ─── Entra ID: Users, Groups, Service Principals ────────────────
        try:
            graph_entities = self._scan_graph(
                client["credential"], subscription_id, report_date,
                principal_roles, results)
            _emit("710040", "i",
                  f"  {graph_entities} entities enriched/added from Graph API")
        except Exception as e:
            _emit("710041", "w",
                  f"  Graph API scan failed (Entra ID entities not enriched): {e}")

        return results

    def _scan_graph(self, credential, subscription_id: str,
                    report_date: str, principal_roles: dict,
                    results: list) -> int:
        """
        Enrich RBAC principals with Entra ID details (display names, group
        members, service principal metadata) and add Entra-only entities
        that have directory roles but no RBAC assignments.
        """
        from msgraph import GraphServiceClient
        import asyncio

        graph_client = GraphServiceClient(credential)
        enriched = 0

        # Get users
        try:
            loop = asyncio.new_event_loop()
            users_response = loop.run_until_complete(
                graph_client.users.get())
            users = users_response.value if users_response else []

            user_map = {}
            for user in users:
                user_map[user.id] = user
                # Enrich existing RBAC record with display name
                for rec in results:
                    if rec.name == user.id and rec.platform == "azure":
                        rec.name = user.display_name or user.user_principal_name or user.id
                        rec.identifier = f"user:{user.user_principal_name}"
                        rec.last_used = None  # Would need sign-in logs (P1/P2)
                        enriched += 1

            _emit("710042", "i", f"    {len(users)} Entra users")
        except Exception as e:
            _emit("710043", "w", f"    Users from Graph failed: {e}")
            users = []

        # Get groups and members
        try:
            groups_response = loop.run_until_complete(
                graph_client.groups.get())
            groups = groups_response.value if groups_response else []

            for group in groups:
                # Get group members
                members = []
                try:
                    members_response = loop.run_until_complete(
                        graph_client.groups.by_group_id(group.id).members.get())
                    if members_response and members_response.value:
                        members = [m.id for m in members_response.value]
                except Exception:
                    pass

                # Enrich existing RBAC record or add new
                found = False
                for rec in results:
                    if rec.name == group.id and rec.platform == "azure":
                        rec.name = group.display_name or group.id
                        rec.identifier = f"group:{group.display_name}"
                        rec.members = members
                        found = True
                        enriched += 1

                if not found and members:
                    # Group exists in Entra but has no RBAC assignments
                    results.append(EntityRecord(
                        name=group.display_name or group.id,
                        account=subscription_id,
                        entity_type="Group",
                        platform="azure",
                        identifier=f"group:{group.display_name}",
                        members=members,
                        report_date=report_date,
                        metadata={"source": "entra-only"},
                    ))
                    enriched += 1

            _emit("710044", "i", f"    {len(groups)} Entra groups")
        except Exception as e:
            _emit("710045", "w", f"    Groups from Graph failed: {e}")

        # Get service principals
        try:
            sp_response = loop.run_until_complete(
                graph_client.service_principals.get())
            sps = sp_response.value if sp_response else []

            for sp in sps:
                for rec in results:
                    if rec.name == sp.id and rec.platform == "azure":
                        rec.name = sp.display_name or sp.app_id or sp.id
                        rec.identifier = f"sp:{sp.app_id}"
                        rec.entity_type = "ServicePrincipal"
                        # Credential info for trust analysis
                        cred_info = []
                        if hasattr(sp, 'password_credentials') and sp.password_credentials:
                            cred_info.append(f"{len(sp.password_credentials)} password credentials")
                        if hasattr(sp, 'key_credentials') and sp.key_credentials:
                            cred_info.append(f"{len(sp.key_credentials)} certificate credentials")
                        if cred_info:
                            rec.trust_info = {"credentials": cred_info}
                        enriched += 1

            _emit("710046", "i", f"    {len(sps)} Entra service principals")
        except Exception as e:
            _emit("710047", "w", f"    Service principals from Graph failed: {e}")

        try:
            loop.close()
        except Exception:
            pass

        return enriched

    @staticmethod
    def _map_principal_type(azure_type: str) -> str:
        """Map Azure principal type strings to AccessGuard entity types."""
        mapping = {
            "User": "User",
            "Group": "Group",
            "ServicePrincipal": "ServicePrincipal",
            "MSI": "ManagedIdentity",
            "Application": "ServicePrincipal",
            "ForeignGroup": "Group",
        }
        return mapping.get(azure_type, azure_type or "Unknown")

    def system_prompt_context(self) -> str:
        return """CRITICAL CONTEXT for Azure entities:
- Azure has TWO separate role systems: Entra ID roles (identity plane) and \
Azure RBAC roles (resource plane). Both must be audited.
- managed_policies for Azure entities are Azure RBAC role names (e.g., \
"Contributor", "Reader", "Storage Blob Data Reader").
- trustInfo for Service Principals shows credential types (password/certificate). \
SPs with password credentials are higher risk than certificate-only.
- ManagedIdentity entities are bound to specific Azure resources and MUST NOT \
be consolidated — they are system-managed.
- Global Administrator in Entra ID can elevate to any Azure subscription — \
this is a critical finding even if the user has no RBAC assignments.
- PIM (Privileged Identity Management) eligible assignments are NOT the same \
as active assignments — eligible means the user CAN activate, not that they HAVE.
- Role assignments inherit downward: Management Group → Subscription → \
Resource Group → Resource. Do not consolidate assignments at different scopes \
without understanding the inheritance impact.
- principalType "ForeignGroup" indicates cross-tenant access — flag for review.

Do NOT recommend consolidating:
- Managed Identities (system-bound)
- Role assignments at different scopes (inheritance risk)
- Service Principals owned by different applications
- Cross-tenant (ForeignGroup) principals with internal principals"""

    def build_identifier(self, account: str, entity_type: str,
                         name: str) -> str:
        return f"/subscriptions/{account}/principals/{name}"
