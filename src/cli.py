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
#
"""
AccessGuard CLI — IAM role engineering and RBAC optimization.

Usage:
  python3 src/cli.py                          # current account, deterministic
  python3 src/cli.py --ai                     # current account, AI analysis
  python3 src/cli.py --org                    # all accounts in the organization
  python3 src/cli.py --accounts 111,222,333   # specific accounts
"""

import argparse
import datetime
import json
import logging
import os
import sys

import boto3
import botocore

# Add src/ to path when run directly
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

import commonClasses as cc
import accessGuardClasses as agc
from roleAnalyzer import RoleAnalyzer
from reportGenerator import generate_html, generate_json, write_report

logging.basicConfig(level=logging.INFO)


def discover_org_accounts(region: str) -> list:
    """
    List all accounts in the AWS Organization. Requires
    organizations:ListAccounts permission (available to the management
    account root or a delegated admin).
    """
    client = boto3.client("organizations", region_name=region)
    accounts = []
    paginator = client.get_paginator("list_accounts")

    for page in paginator.paginate():
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":
                accounts.append({
                    "id": acct["Id"],
                    "name": acct.get("Name", acct["Id"]),
                    "email": acct.get("Email", ""),
                })

    return accounts


def get_iam_client(account_id: str, region: str, role_name: str):
    """
    Get an IAM client for a target account. For the current account,
    returns a direct client. For other accounts, assumes the named role.
    Returns (client, assumed_account_id) or (None, None) on failure.
    """
    sts = boto3.client("sts", region_name=region)
    current_account = sts.get_caller_identity()["Account"]

    if account_id == current_account:
        return boto3.client("iam", region_name=region), account_id

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="accessguard-scan",
        )["Credentials"]

        client = boto3.client(
            "iam",
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        return client, account_id

    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        cc.emit("800010", "w",
            f"Cannot assume {role_arn}: {code} - skipping account {account_id}")
        return None, None

    except Exception as e:
        cc.emit("800020", "w",
            f"Error accessing account {account_id}: {e} - skipping")
        return None, None


def scan_account(iam_client, account_id: str, report_date: str,
                 similar: agc.SimilarEntities) -> list:
    """
    Scan a single account's IAM entities. Returns list of IamOutputRow.
    Handles errors gracefully — returns partial results on failure.
    """
    results = []

    # Users
    try:
        users = agc.IamUsers(client=iam_client).download()
        for entity in users:
            row = agc.IamOutputRow(
                name=entity.userName, account=account_id,
                entityType="User", members=[], managed=entity.managed,
                policy=entity.policies, reportDate=report_date,
            )
            results.append(row)
            similar.add(row)
        cc.emit("800030", "i", f"  {len(users)} users")
    except Exception as e:
        cc.emit("800031", "w", f"  Users failed: {e}")

    # Groups
    try:
        groups = agc.IamGroups(client=iam_client).download()
        for entity in groups:
            row = agc.IamOutputRow(
                name=entity.groupName, account=account_id,
                entityType="Group", members=entity.members,
                managed=entity.managed, policy=entity.policies,
                reportDate=report_date,
            )
            results.append(row)
            similar.add(row)
        cc.emit("800032", "i", f"  {len(groups)} groups")
    except Exception as e:
        cc.emit("800033", "w", f"  Groups failed: {e}")

    # Roles (with trust policy, tags, lastUsed from GetRole)
    try:
        roles = agc.IamRoles(client=iam_client).download()
        for entity in roles:
            trust_policy = {}
            tags = {}
            last_used = None
            create_date = None

            try:
                detail = iam_client.get_role(RoleName=entity.roleName)["Role"]
                trust_policy = detail.get("AssumeRolePolicyDocument", {})
                tags_list = detail.get("Tags", [])
                tags = {t["Key"]: t["Value"] for t in tags_list}
                lu = detail.get("RoleLastUsed", {}).get("LastUsedDate")
                last_used = lu.isoformat() if lu else None
                cd = detail.get("CreateDate")
                create_date = cd.isoformat() if cd else None
            except Exception:
                pass  # GetRole enrichment is best-effort

            row = agc.IamOutputRow(
                name=entity.roleName, account=account_id,
                entityType="Role", members=[], managed=entity.managed,
                policy=entity.policies, reportDate=report_date,
                trustPolicy=trust_policy, tags=tags,
                lastUsed=last_used, createDate=create_date,
            )
            results.append(row)
            similar.add(row)
        cc.emit("800034", "i", f"  {len(roles)} roles")
    except Exception as e:
        cc.emit("800035", "w", f"  Roles failed: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="AccessGuard - AI-powered AWS IAM role engineering")

    # Account selection (mutually exclusive)
    acct_group = parser.add_mutually_exclusive_group()
    acct_group.add_argument("--org", action="store_true",
        help="Scan all accounts in the AWS Organization")
    acct_group.add_argument("--accounts", type=str, default=None,
        help="Comma-separated list of account IDs to scan")

    # Role assumption
    parser.add_argument("--role", type=str,
        default="OrganizationAccountAccessRole",
        help="Role name to assume in target accounts (default: OrganizationAccountAccessRole)")

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
        help="AWS region (default: us-east-1)")
    parser.add_argument("--debug", action="store_true",
        help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    report_date = datetime.datetime.now().isoformat()
    region = args.region

    # Determine which accounts to scan
    sts = boto3.client("sts", region_name=region)
    current_account = sts.get_caller_identity()["Account"]

    if args.org:
        cc.emit("800040", "i", "Discovering Organization accounts...")
        try:
            org_accounts = discover_org_accounts(region)
            cc.emit("800041", "i",
                f"Found {len(org_accounts)} active accounts in Organization")
            account_ids = [a["id"] for a in org_accounts]

            # Log the accounts
            for a in org_accounts:
                cc.emit("800042", "i", f"  {a['id']} ({a['name']})")
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            cc.emit("800043", "e",
                f"Cannot list Organization accounts ({code}). "
                f"Falling back to current account only.")
            account_ids = [current_account]
    elif args.accounts:
        account_ids = [a.strip() for a in args.accounts.split(",")]
        cc.emit("800044", "i",
            f"Scanning {len(account_ids)} specified accounts")
    else:
        account_ids = [current_account]
        cc.emit("800045", "i", f"Scanning current account {current_account}")

    # Scan each account
    all_results = []
    similar = agc.SimilarEntities()
    scanned = 0
    skipped = 0

    for account_id in account_ids:
        cc.emit("800050", "i", f"Scanning account {account_id}...")

        iam_client, resolved_id = get_iam_client(
            account_id, region, args.role)

        if iam_client is None:
            skipped += 1
            continue

        results = scan_account(iam_client, resolved_id, report_date, similar)
        all_results.extend(results)
        scanned += 1

        cc.emit("800060", "i",
            f"Account {account_id}: {len(results)} entities collected")

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
        threshold=args.threshold, model_provider=model_provider)
    analyzer.add_entities(all_results)
    analysis = analyzer.analyze()

    # Generate reports
    catalog_dicts = [r.asDict() for r in all_results]
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
    cc.emit("800101", "i", f"Accounts:   {scanned} scanned, {skipped} skipped")
    cc.emit("800102", "i", f"Entities:   {analysis['entityCount']}")
    cc.emit("800103", "i", f"Exact dupes:{len(similarities)}")
    cc.emit("800104", "i", f"Clusters:   {analysis['clusterCount']}")
    cc.emit("800105", "i", f"Subsets:    {analysis['subsetCount']}")
    cc.emit("800106", "i", f"Threshold:  {analysis['threshold']:.0%}")
    cc.emit("800107", "i", f"AI Model:   {analysis.get('model', 'none')}")
    if analysis.get("aiRecommendations"):
        total_recs = sum(
            len(r.get("analysis", {}).get("recommendations", []))
            for r in analysis["aiRecommendations"]
            if "error" not in r.get("analysis", {})
        )
        cc.emit("800108", "i", f"AI Recs:    {total_recs}")
    cc.emit("800109", "i", "=" * 60)


if __name__ == "__main__":
    main()
