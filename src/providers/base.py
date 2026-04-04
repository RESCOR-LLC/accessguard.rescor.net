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
Abstract base classes for cloud provider integration.

Each cloud platform (AWS, Azure, GCP) implements CloudProvider to handle
account discovery, authentication, and entity scanning. All providers
produce EntityRecord objects that feed into the cloud-agnostic analysis
pipeline (SimilarEntities, RoleAnalyzer, report generation).
"""

import datetime
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class EntityRecord:
    """
    Cloud-agnostic identity entity.

    Every cloud provider maps its platform-specific entities (IAM roles,
    Entra users, GCP service accounts, etc.) into this common format.
    The analysis pipeline operates exclusively on EntityRecord objects.
    """
    name: str
    account: str
    entity_type: str                         # User, Group, Role, ServicePrincipal, ServiceAccount, etc.
    platform: str = "aws"                    # aws, azure, gcp, zos, ibmi, windows, linux
    identifier: str = ""                     # ARN, Azure resource ID, GCP email, etc.
    managed_policies: list = field(default_factory=list)
    inline_policies: dict = field(default_factory=dict)
    members: list = field(default_factory=list)
    trust_info: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    last_used: str = None
    create_date: str = None
    description: str = None
    metadata: dict = field(default_factory=dict)
    report_date: str = None
    id: str = None

    def __post_init__(self):
        if not self.report_date:
            self.report_date = datetime.datetime.now().isoformat()
        if not self.id:
            digest = hashlib.sha256()
            digest.update(
                (self.identifier or f"{self.platform}:{self.account}:{self.entity_type}:{self.name}")
                .encode("utf-8")
            )
            digest.update(self.report_date.encode("utf-8"))
            self.id = digest.hexdigest()

    def as_dict(self, ttl=None) -> dict:
        """Return a serializable dict (compatible with IamOutputRow.asDict)."""
        import time
        d = {
            "reportDate": self.report_date,
            "id": self.id,
            "account": self.account,
            "type": self.entity_type,
            "name": self.name,
            "arn": self.identifier,         # backward compat with AWS field name
            "platform": self.platform,
            "description": self.description,
            "members": self.members,
            "managed": self.managed_policies,
            "policy": self.inline_policies,
            "trustPolicy": self.trust_info,
            "tags": self.tags,
            "lastUsed": self.last_used,
            "createDate": self.create_date,
            "metadata": self.metadata,
        }
        if ttl:
            d["TTL"] = int(time.time() + ttl)
        return d

    # Compatibility properties for code that still uses IamOutputRow field names
    @property
    def managed(self):
        return self.managed_policies

    @property
    def policy(self):
        return self.inline_policies

    @property
    def arn(self):
        return self.identifier

    @property
    def entityType(self):
        return self.entity_type

    @property
    def trustPolicy(self):
        return self.trust_info

    @property
    def reportDate(self):
        return self.report_date


class CloudProvider(ABC):
    """
    Abstract base class for cloud platform integration.

    Subclass this for each platform: AwsProvider, AzureProvider,
    GcpProvider. Follow the ModelProvider pattern from modelProvider.py.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short platform name: 'aws', 'azure', 'gcp'."""
        ...

    @abstractmethod
    def discover_accounts(self) -> list:
        """
        Discover accounts/subscriptions/projects in the organization.
        Returns list of dicts: [{"id": str, "name": str}, ...]
        """
        ...

    @abstractmethod
    def get_identity_client(self, account_id: str, role: str = None):
        """
        Return an authenticated client for the target account's identity
        service. Returns None if the account is unreachable (with a
        logged warning, not an exception).
        """
        ...

    @abstractmethod
    def scan_entities(self, client, account_id: str,
                      report_date: str) -> list:
        """
        Scan an account and return a list of EntityRecord objects.
        Must handle partial failures gracefully — return whatever
        entities were successfully collected.
        """
        ...

    @abstractmethod
    def system_prompt_context(self) -> str:
        """
        Return cloud-specific rules and context for the AI analysis
        prompt. This is appended to the generic preamble.
        """
        ...

    def build_identifier(self, account: str, entity_type: str,
                         name: str) -> str:
        """
        Build the platform-specific identifier (ARN, resource ID, email).
        Default implementation returns a generic format.
        """
        return f"{self.name}:{account}:{entity_type}/{name}"

    def __repr__(self):
        return f"{self.__class__.__name__}()"
