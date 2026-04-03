#!/usr/bin/env python3
"""
Live test harness for AccessGuard against real AWS IAM.
Bypasses the full pipeline (no SSM, no DynamoDB, no S3) and runs
the analysis directly against IAM entities in the current account.
"""

import sys
import os
import json
import datetime
import logging
import boto3

# Add src/ to path
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

import commonClasses as cc
import accessGuardClasses as agc
from roleAnalyzer import RoleAnalyzer
from reportGenerator import generate_html, generate_json, write_report

logging.basicConfig(level=logging.INFO)

def main():
    use_ai = "--ai" in sys.argv
    threshold = 0.70

    for arg in sys.argv:
        if arg.startswith("--threshold="):
            threshold = float(arg.split("=")[1])

    region = "us-east-1"
    report_date = datetime.datetime.now().isoformat()

    # Get current account ID
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    cc.emit("900010", "i", f"Running against account {account_id} in {region}")

    # Create IAM client directly (no role assumption needed — we're already in the account)
    iam_client = boto3.client("iam", region_name=region)

    # Collect entities
    similar = agc.SimilarEntities()
    results = []

    # Users
    cc.emit("900020", "i", "Downloading IAM users...")
    users = agc.IamUsers(client=iam_client).download()
    for entity in users:
        row = agc.IamOutputRow(
            name=entity.userName,
            account=account_id,
            entityType="User",
            members=[],
            managed=entity.managed,
            policy=entity.policies,
            reportDate=report_date,
        )
        results.append(row)
        similar.add(row)

    # Groups
    cc.emit("900030", "i", "Downloading IAM groups...")
    groups = agc.IamGroups(client=iam_client).download()
    for entity in groups:
        row = agc.IamOutputRow(
            name=entity.groupName,
            account=account_id,
            entityType="Group",
            members=entity.members,
            managed=entity.managed,
            policy=entity.policies,
            reportDate=report_date,
        )
        results.append(row)
        similar.add(row)

    # Roles — also fetch trust policy, tags, and lastUsed via GetRole
    cc.emit("900040", "i", "Downloading IAM roles...")
    roles = agc.IamRoles(client=iam_client).download()
    for entity in roles:
        # GetRole returns trust policy, tags, lastUsed that list_roles omits
        try:
            role_detail = iam_client.get_role(RoleName=entity.roleName)["Role"]
            trust_policy = role_detail.get("AssumeRolePolicyDocument", {})
            tags_list = role_detail.get("Tags", [])
            tags = {t["Key"]: t["Value"] for t in tags_list}
            last_used = role_detail.get("RoleLastUsed", {}).get("LastUsedDate")
            last_used = last_used.isoformat() if last_used else None
            create_date = role_detail.get("CreateDate")
            create_date = create_date.isoformat() if create_date else None
        except Exception:
            trust_policy = {}
            tags = {}
            last_used = None
            create_date = None

        row = agc.IamOutputRow(
            name=entity.roleName,
            account=account_id,
            entityType="Role",
            members=[],
            managed=entity.managed,
            policy=entity.policies,
            reportDate=report_date,
            trustPolicy=trust_policy,
            tags=tags,
            lastUsed=last_used,
            createDate=create_date,
        )
        results.append(row)
        similar.add(row)

    cc.emit("900050", "i",
        f"Collected {len(results)} entities ({len(users)} users, "
        f"{len(groups)} groups, {len(roles)} roles)")

    # Exact similarity detection
    similarities = similar.extract()
    cc.emit("900060", "i", f"Found {len(similarities)} exact similarity groups")

    # Role analysis
    model_provider = None
    if use_ai:
        from modelProvider import AnthropicProvider
        model_id = "sonnet"
        for arg in sys.argv:
            if arg.startswith("--model="):
                model_id = arg.split("=")[1]
        try:
            model_provider = AnthropicProvider(model_id=model_id)
            cc.emit("900070", "i", f"AI analysis enabled: {model_provider}")
        except EnvironmentError as e:
            cc.emit("900075", "w", f"AI analysis disabled: {e}")

    analyzer = RoleAnalyzer(threshold=threshold, model_provider=model_provider)
    analyzer.add_entities(results)
    analysis = analyzer.analyze()

    # Generate reports
    catalog_dicts = [r.asDict() for r in results]
    similarity_dicts = [
        {"similarity": s["similarity"], "by": s["by"], "entities": s["entities"]}
        for s in similarities
    ]

    html = generate_html(catalog_dicts, similarity_dicts, analysis, report_date)
    write_report(f"accessguard-report-{report_date[:10]}.html", html, "HTML")

    json_content = generate_json(catalog_dicts, similarity_dicts, analysis, report_date)
    write_report(f"accessguard-report-{report_date[:10]}.json", json_content, "JSON")

    # Summary
    cc.emit("900080", "i", "=" * 60)
    cc.emit("900081", "i", f"Entities:   {analysis['entityCount']}")
    cc.emit("900082", "i", f"Clusters:   {analysis['clusterCount']}")
    cc.emit("900083", "i", f"Subsets:    {analysis['subsetCount']}")
    cc.emit("900084", "i", f"Threshold:  {analysis['threshold']:.0%}")
    cc.emit("900085", "i", f"AI Model:   {analysis.get('model', 'none')}")
    if analysis.get("aiRecommendations"):
        total_recs = sum(
            len(r.get("analysis", {}).get("recommendations", []))
            for r in analysis["aiRecommendations"]
            if "error" not in r.get("analysis", {})
        )
        cc.emit("900086", "i", f"AI Recs:    {total_recs}")
    cc.emit("900090", "i", "=" * 60)


if __name__ == "__main__":
    main()
