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
Cloud provider registry for AccessGuard.

Usage:
    from providers import get_provider
    provider = get_provider("aws", region="us-east-1")
"""

from providers.base import CloudProvider, EntityRecord

_REGISTRY = {}


def register(name: str, cls: type):
    """Register a cloud provider implementation."""
    _REGISTRY[name] = cls


def get_provider(name: str, **kwargs) -> CloudProvider:
    """Instantiate a registered cloud provider."""
    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys())) or "none"
        raise ValueError(
            f"Unknown provider '{name}'. Available: {available}")
    return _REGISTRY[name](**kwargs)


def available_providers() -> list:
    """Return list of registered provider names."""
    return sorted(_REGISTRY.keys())


# Auto-register providers on import
try:
    from providers.aws import AwsProvider
    register("aws", AwsProvider)
except ImportError:
    pass  # boto3 not installed — AWS provider unavailable

try:
    from providers.azure import AzureProvider
    register("azure", AzureProvider)
except ImportError:
    pass  # azure-identity not installed — Azure provider unavailable
