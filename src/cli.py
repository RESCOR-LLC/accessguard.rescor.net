#!/usr/bin/env python3
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
AccessGuard CLI — IAM role engineering and RBAC optimization.

Usage:
  python3 src/cli.py                              # current account, deterministic
  python3 src/cli.py --ai                         # current account, AI analysis
  python3 src/cli.py --org                        # all Organization accounts
  python3 src/cli.py --accounts 111,222,333       # specific accounts
  python3 src/cli.py --provider azure --org       # Azure (future)
"""

import argparse
import datetime
import logging
import os
import sys

# Add src/ to path when run directly
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

import commonClasses as cc
from providers import get_provider, available_providers
from providers.base import EntityRecord
from accessGuardClasses import SimilarEntities
from roleAnalyzer import RoleAnalyzer
from reportGenerator import generate_html, generate_json, write_report

logging.basicConfig(level=logging.INFO)


def main():
    parser = argparse.ArgumentParser(
        description="AccessGuard - AI-powered IAM role engineering")

    # Provider selection
    parser.add_argument("--provider", "-p", type=str, default="aws",
        help=f"Cloud provider ({', '.join(available_providers())}; default: aws)")

    # Account selection (mutually exclusive)
    acct_group = parser.add_mutually_exclusive_group()
    acct_group.add_argument("--org", action="store_true",
        help="Scan all accounts/subscriptions/projects in the organization")
    acct_group.add_argument("--accounts", type=str, default=None,
        help="Comma-separated list of account IDs to scan")

    # Role assumption
    parser.add_argument("--role", type=str, default=None,
        help="Role name to assume in target accounts (provider-specific default)")

    # AI options
    parser.add_argument("--ai", action="store_true",
        help="Enable AI-powered consolidation analysis")
    parser.add_argument("--model", type=str, default="sonnet",
        help="AI model: opus, sonnet (default), haiku, or full model ID")
    parser.add_argument("--threshold", type=float, default=0.70,
        help="Jaccard similarity threshold (0.0-1.0, default: 0.70)")

    # Output
    parser.add_argument("--output", "-o", type=str, default=".",
        help="Output directory for reports (default: current directory)")
    parser.add_argument("--format", type=str, default="all",
        choices=["html", "json", "all"],
        help="Report format (default: all)")

    # General
    parser.add_argument("--region", type=str, default="us-east-1",
        help="Cloud region (default: us-east-1)")
    parser.add_argument("--debug", action="store_true",
        help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    report_date = datetime.datetime.now().isoformat()

    # Instantiate the cloud provider
    provider_kwargs = {"region": args.region}
    if args.role:
        provider_kwargs["role_name"] = args.role
    try:
        provider = get_provider(args.provider, **provider_kwargs)
    except ValueError as e:
        cc.emit("800000", "e", str(e))
        sys.exit(1)

    cc.emit("800001", "i", f"Provider: {provider}")

    # Determine which accounts to scan
    if args.org:
        cc.emit("800040", "i",
            f"Discovering {provider.name} accounts/subscriptions...")
        try:
            org_accounts = provider.discover_accounts()
            cc.emit("800041", "i",
                f"Found {len(org_accounts)} active accounts")
            for a in org_accounts:
                cc.emit("800042", "i", f"  {a['id']} ({a['name']})")
            account_ids = [a["id"] for a in org_accounts]
        except Exception as e:
            cc.emit("800043", "e",
                f"Cannot discover accounts: {e}. "
                f"Scanning current credentials only.")
            account_ids = [provider._current_account]
    elif args.accounts:
        account_ids = [a.strip() for a in args.accounts.split(",")]
        cc.emit("800044", "i",
            f"Scanning {len(account_ids)} specified accounts")
    else:
        # Single account — use the provider's current identity
        account_ids = [getattr(provider, '_current_account', 'default')]
        cc.emit("800045", "i", f"Scanning current account {account_ids[0]}")

    # Scan each account
    all_results = []
    similar = SimilarEntities()
    scanned = 0
    skipped = 0

    for account_id in account_ids:
        cc.emit("800050", "i", f"Scanning account {account_id}...")

        client = provider.get_identity_client(account_id, args.role)
        if client is None:
            skipped += 1
            continue

        entities = provider.scan_entities(client, account_id, report_date)

        # Feed into similarity detection
        for entity in entities:
            similar.add(entity)

        all_results.extend(entities)
        scanned += 1

        cc.emit("800060", "i",
            f"Account {account_id}: {len(entities)} entities collected")

    cc.emit("800070", "i",
        f"Scan complete: {scanned} accounts scanned, {skipped} skipped, "
        f"{len(all_results)} total entities")

    # Exact similarity detection
    similarities = similar.extract()
    cc.emit("800080", "i", f"Found {len(similarities)} exact similarity groups")

    # Role analysis
    model_provider = None
    if args.ai:
        from modelProvider import AnthropicProvider
        try:
            model_provider = AnthropicProvider(model_id=args.model)
            cc.emit("800090", "i", f"AI analysis enabled: {model_provider}")
        except EnvironmentError as e:
            cc.emit("800091", "w", f"AI analysis disabled: {e}")

    analyzer = RoleAnalyzer(
        threshold=args.threshold,
        model_provider=model_provider,
        platform_context=provider.system_prompt_context(),
    )
    analyzer.add_entities(all_results)
    analysis = analyzer.analyze()

    # Generate reports
    catalog_dicts = [r.as_dict() for r in all_results]
    similarity_dicts = [
        {"similarity": s["similarity"], "by": s["by"], "entities": s["entities"]}
        for s in similarities
    ]

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    date_slug = report_date[:10]

    if args.format in ("html", "all"):
        html = generate_html(
            catalog_dicts, similarity_dicts, analysis, report_date)
        path = os.path.join(output_dir, f"accessguard-report-{date_slug}.html")
        write_report(path, html, "HTML")

    if args.format in ("json", "all"):
        json_content = generate_json(
            catalog_dicts, similarity_dicts, analysis, report_date)
        path = os.path.join(output_dir, f"accessguard-report-{date_slug}.json")
        write_report(path, json_content, "JSON")

    # Summary
    cc.emit("800100", "i", "=" * 60)
    cc.emit("800101", "i", f"Provider:   {provider.name}")
    cc.emit("800102", "i", f"Accounts:   {scanned} scanned, {skipped} skipped")
    cc.emit("800103", "i", f"Entities:   {analysis['entityCount']}")
    cc.emit("800104", "i", f"Exact dupes:{len(similarities)}")
    cc.emit("800105", "i", f"Clusters:   {analysis['clusterCount']}")
    cc.emit("800106", "i", f"Subsets:    {analysis['subsetCount']}")
    cc.emit("800107", "i", f"Threshold:  {analysis['threshold']:.0%}")
    cc.emit("800108", "i", f"AI Model:   {analysis.get('model', 'none')}")
    if analysis.get("aiRecommendations"):
        total_recs = sum(
            len(r.get("analysis", {}).get("recommendations", []))
            for r in analysis["aiRecommendations"]
            if "error" not in r.get("analysis", {})
        )
        cc.emit("800109", "i", f"AI Recs:    {total_recs}")
    cc.emit("800110", "i", "=" * 60)


if __name__ == "__main__":
    main()
