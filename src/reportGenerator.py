"""
Report generator for AccessGuard.

Produces HTML, JSON, and CSV output from the combined results of
SimilarEntities (exact matches) and RoleAnalyzer (AI-powered analysis).
"""

import csv
import datetime
import io
import json
import logging
import os

import commonClasses as cc

_LOGGER = logging.getLogger(__name__)


def generate_html(catalog: list, similarities: list, analysis: dict,
                  report_date: str) -> str:
    """
    Generate a self-contained HTML report.

    Args:
        catalog: list of IamOutputRow dicts
        similarities: list of SimilarityOutputRow dicts
        analysis: dict from RoleAnalyzer.analyze() (may be None)
        report_date: ISO date string
    """
    date_display = datetime.datetime.fromisoformat(report_date).strftime(
        "%B %d, %Y")
    year = datetime.datetime.fromisoformat(report_date).year

    # Summary stats
    total_entities = len(catalog)
    exact_dupes = len(similarities)
    clusters = analysis.get("clusterCount", 0) if analysis else 0
    subsets = analysis.get("subsetCount", 0) if analysis else 0
    model_used = analysis.get("model") if analysis else None
    threshold = analysis.get("threshold", 0.7) if analysis else 0.7

    # Count entities by type
    type_counts = {}
    account_counts = {}
    for entry in catalog:
        etype = entry.get("type", entry.get("entityType", "Unknown"))
        type_counts[etype] = type_counts.get(etype, 0) + 1
        acct = entry.get("account", "Unknown")
        account_counts[acct] = account_counts.get(acct, 0) + 1

    # AI recommendations
    ai_recs = analysis.get("aiRecommendations", []) if analysis else []
    total_recs = sum(
        len(r.get("analysis", {}).get("recommendations", []))
        for r in ai_recs if "error" not in r.get("analysis", {})
    )

    # Risk summary from AI recommendations
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    action_counts = {"CONSOLIDATE": 0, "REVIEW": 0, "KEEP_SEPARATE": 0}
    for rec_group in ai_recs:
        recs = rec_group.get("analysis", {}).get("recommendations", [])
        for rec in recs:
            risk = rec.get("risk", "UNKNOWN")
            action = rec.get("action", "UNKNOWN")
            if risk in risk_counts:
                risk_counts[risk] += 1
            if action in action_counts:
                action_counts[action] += 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AccessGuard Report — {date_display}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1.5rem; color: #222; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; border-bottom: 2px solid #1a237e; padding-bottom: 0.5rem; margin-bottom: 0.25rem; }}
  .subtitle {{ font-size: 0.9rem; color: #555; margin-bottom: 2rem; }}
  h2 {{ font-size: 1.2rem; margin-top: 2rem; color: #1a237e; border-bottom: 1px solid #e0e0e0; padding-bottom: 0.25rem; }}
  h3 {{ font-size: 1rem; margin-top: 1.5rem; color: #333; }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.85rem; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border: 1px solid #ddd; }}
  th {{ background: #f5f5f5; font-weight: 600; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }}
  .summary-card {{ background: #f8f9fb; border: 1px solid #e0e3ea; border-radius: 6px; padding: 1rem; text-align: center; }}
  .summary-card .number {{ font-size: 2rem; font-weight: 700; color: #1a237e; }}
  .summary-card .label {{ font-size: 0.8rem; color: #666; margin-top: 0.25rem; }}
  .risk-low {{ color: #2e7d32; font-weight: 600; }}
  .risk-medium {{ color: #e65100; font-weight: 600; }}
  .risk-high {{ color: #c62828; font-weight: 600; }}
  .action-consolidate {{ background: #e8f5e9; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }}
  .action-review {{ background: #fff3e0; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }}
  .action-keep {{ background: #f5f5f5; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }}
  .cluster-box {{ background: #f8f9fb; border: 1px solid #e0e3ea; border-radius: 6px; padding: 1rem; margin: 1rem 0; }}
  .policy-list {{ font-family: monospace; font-size: 0.8rem; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; font-size: 0.8rem; color: #666; }}
  @media print {{ body {{ margin: 0; }} .summary-card {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<h1>AccessGuard — IAM Role Engineering Report</h1>
<p class="subtitle">{date_display}{f' — Model: {model_used}' if model_used else ' — Deterministic analysis only'}</p>

<div class="summary-grid">
  <div class="summary-card"><div class="number">{total_entities}</div><div class="label">IAM Entities</div></div>
  <div class="summary-card"><div class="number">{len(account_counts)}</div><div class="label">AWS Accounts</div></div>
  <div class="summary-card"><div class="number">{exact_dupes}</div><div class="label">Exact Duplicates</div></div>
  <div class="summary-card"><div class="number">{clusters}</div><div class="label">Similar Clusters</div></div>
  <div class="summary-card"><div class="number">{subsets}</div><div class="label">Subset Relationships</div></div>
  <div class="summary-card"><div class="number">{total_recs}</div><div class="label">AI Recommendations</div></div>
</div>

<h2>Entity Summary</h2>
<table>
  <tr><th>Entity Type</th><th>Count</th></tr>
  {''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in sorted(type_counts.items()))}
</table>

<table>
  <tr><th>Account</th><th>Entities</th></tr>
  {''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in sorted(account_counts.items()))}
</table>
"""

    # Exact duplicates
    if similarities:
        html += """
<h2>Exact Duplicates</h2>
<p>Entities with identical managed policies, group membership, or inline policy content.</p>
<table>
  <tr><th>Similarity Type</th><th>Shared By</th><th>Entities</th></tr>
"""
        for sim in similarities:
            sim_type = sim.get("similarity", "")
            by_val = sim.get("by", [])
            if isinstance(by_val, list):
                shared = ", ".join(str(x) for x in by_val[:5])
                if len(by_val) > 5:
                    shared += f" (+{len(by_val) - 5} more)"
            else:
                shared = str(by_val)
            entities_val = sim.get("entities", [])
            entities = "<br>".join(str(x) for x in entities_val) if isinstance(entities_val, list) else str(entities_val)
            html += f'  <tr><td>{sim_type}</td><td class="policy-list">{shared}</td><td>{entities}</td></tr>\n'
        html += "</table>\n"

    # Subset relationships
    if analysis and analysis.get("subsets"):
        html += """
<h2>Subset Relationships</h2>
<p>Entities whose managed policies are a strict subset of another entity — strong consolidation candidates.</p>
<table>
  <tr><th>Subset Role</th><th>Superset Role</th><th>Additional Policies in Superset</th></tr>
"""
        for sub in analysis["subsets"]:
            subset_name = sub["subset"]["name"]
            superset_name = sub["superset"]["name"]
            additional = ", ".join(sub.get("additionalInSuperset", []))
            html += f'  <tr><td>{subset_name}</td><td>{superset_name}</td><td class="policy-list">{additional}</td></tr>\n'
        html += "</table>\n"

    # AI Recommendations
    if ai_recs:
        html += f"""
<h2>AI Consolidation Recommendations</h2>
<p>Analysis by {model_used} at ≥{int(threshold * 100)}% similarity threshold.</p>
"""
        # Risk summary
        if any(v > 0 for v in risk_counts.values()):
            html += """<table>
  <tr><th>Risk Level</th><th>Count</th><th>Action</th><th>Count</th></tr>
"""
            html += f'  <tr><td class="risk-low">LOW</td><td>{risk_counts["LOW"]}</td><td class="action-consolidate">CONSOLIDATE</td><td>{action_counts["CONSOLIDATE"]}</td></tr>\n'
            html += f'  <tr><td class="risk-medium">MEDIUM</td><td>{risk_counts["MEDIUM"]}</td><td class="action-review">REVIEW</td><td>{action_counts["REVIEW"]}</td></tr>\n'
            html += f'  <tr><td class="risk-high">HIGH</td><td>{risk_counts["HIGH"]}</td><td class="action-keep">KEEP SEPARATE</td><td>{action_counts["KEEP_SEPARATE"]}</td></tr>\n'
            html += "</table>\n"

        for i, rec_group in enumerate(ai_recs):
            cluster = rec_group.get("cluster", {})
            analysis_result = rec_group.get("analysis", {})

            if "error" in analysis_result:
                html += f'<div class="cluster-box"><h3>Cluster {i+1} — Error</h3><p>{analysis_result["error"]}</p></div>\n'
                continue

            summary = analysis_result.get("summary", "")
            recs = analysis_result.get("recommendations", [])

            entity_names = [e["name"] for e in cluster.get("entities", [])]
            html += f'<div class="cluster-box">\n<h3>Cluster {i+1}: {", ".join(entity_names)}</h3>\n'
            if summary:
                html += f'<p><em>{summary}</em></p>\n'

            if recs:
                html += '<table>\n<tr><th>Action</th><th>Target</th><th>Merge</th><th>Added Permissions</th><th>Risk</th><th>Rationale</th></tr>\n'
                for rec in recs:
                    action = rec.get("action", "")
                    action_cls = "action-consolidate" if action == "CONSOLIDATE" \
                        else "action-review" if action == "REVIEW" else "action-keep"
                    risk = rec.get("risk", "")
                    risk_cls = f"risk-{risk.lower()}" if risk in ("LOW", "MEDIUM", "HIGH") else ""
                    target = rec.get("targetRole", "")
                    merge = ", ".join(rec.get("mergeRoles", []))
                    added = ", ".join(rec.get("additionalPermissions", [])[:5])
                    if len(rec.get("additionalPermissions", [])) > 5:
                        added += f" (+{len(rec['additionalPermissions']) - 5} more)"
                    rationale = rec.get("rationale", "")

                    html += f'<tr><td><span class="{action_cls}">{action}</span></td>'
                    html += f'<td>{target}</td><td>{merge}</td>'
                    html += f'<td class="policy-list">{added}</td>'
                    html += f'<td class="{risk_cls}">{risk}</td>'
                    html += f'<td>{rationale}</td></tr>\n'
                html += '</table>\n'
            html += '</div>\n'

    # Footer
    html += f"""
<div class="footer">
  <p>Generated by <a href="https://www.rescor.net">RESCOR</a> AccessGuard.
  No data were transmitted to RESCOR during generation.</p>
  <p>&copy; {year} RESCOR LLC — www.rescor.net</p>
</div>
</body>
</html>"""

    return html


def generate_json(catalog: list, similarities: list, analysis: dict,
                  report_date: str) -> str:
    """Generate a JSON report."""
    report = {
        "reportDate": report_date,
        "catalog": catalog,
        "similarities": similarities,
        "analysis": analysis,
    }
    return json.dumps(report, indent=2, default=str)


def write_report(path: str, content: str, format_name: str):
    """Write report content to a local file."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    cc.emit("260010", "i", f'wrote {format_name} report to {path}')
