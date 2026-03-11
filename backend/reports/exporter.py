"""Report exporter - generates HTML, JSON, CSV, and Markdown reports."""
import json
import csv
import io
import html as html_lib
from datetime import datetime


def _esc(text: str) -> str:
    """Escape HTML entities to prevent XSS."""
    return html_lib.escape(str(text)) if text else ""


def _esc_md(text: str) -> str:
    """Escape markdown special characters."""
    if not text:
        return ""
    for ch in ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|']:
        text = str(text).replace(ch, '\\' + ch)
    return text


def export_json(scan_data: dict, target_url: str) -> str:
    report = {
        "tool": "VulnScanner v1.0",
        "target": target_url,
        "generated_at": datetime.now().isoformat(),
        "summary": scan_data.get("summary", {}),
        "total_vulnerabilities": len(scan_data.get("results", [])),
        "vulnerabilities": scan_data.get("results", [])
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def export_csv(scan_data: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "No", "Bug ID", "Severity", "Name", "Category",
        "Description", "Endpoint", "Parameter", "Evidence"
    ])
    for i, vuln in enumerate(scan_data.get("results", []), 1):
        writer.writerow([
            i,
            vuln.get("bug_id", ""),
            vuln.get("severity", ""),
            vuln.get("name", "") or vuln.get("title", ""),
            vuln.get("category", ""),
            vuln.get("description", ""),
            vuln.get("endpoint", ""),
            vuln.get("parameter", ""),
            vuln.get("evidence", ""),
        ])
    return output.getvalue()


def export_markdown(scan_data: dict, target_url: str) -> str:
    results = scan_data.get("results", [])
    summary = scan_data.get("summary", {})
    lines = [
        f"# VulnScanner Report",
        f"",
        f"**Target:** {target_url}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total Vulnerabilities:** {len(results)}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")
    lines.append("## Vulnerabilities")
    lines.append("")

    for i, vuln in enumerate(results, 1):
        sev = (vuln.get("severity", "info")).upper()
        name = _esc_md(vuln.get("name", "") or vuln.get("title", ""))
        lines.append(f"### {i}. [{sev}] {name}")
        lines.append(f"")
        lines.append(f"- **Bug ID:** {_esc_md(vuln.get('bug_id', ''))}")
        lines.append(f"- **Category:** {_esc_md(vuln.get('category', ''))}")
        lines.append(f"- **Endpoint:** {_esc_md(vuln.get('endpoint', ''))}")
        lines.append(f"- **Description:** {_esc_md(vuln.get('description', ''))}")
        if vuln.get("evidence"):
            lines.append(f"- **Evidence:** {_esc_md(vuln.get('evidence', ''))}")
        lines.append("")
    return "\n".join(lines)


def export_html(scan_data: dict, target_url: str) -> str:
    results = scan_data.get("results", [])
    summary = scan_data.get("summary", {})
    sev_colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"
    }

    rows = ""
    for i, vuln in enumerate(results, 1):
        sev = (vuln.get("severity", "info")).lower()
        color = sev_colors.get(sev, "#6b7280")
        name = _esc(vuln.get("name", "") or vuln.get("title", ""))
        rows += f"""<tr>
<td>{i}</td>
<td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{sev.upper()}</span></td>
<td><strong>{name}</strong></td>
<td>{_esc(vuln.get("category",""))}</td>
<td style="max-width:300px">{_esc(vuln.get("description",""))}</td>
<td><code>{_esc(vuln.get("endpoint",""))}</code></td>
<td>{_esc(vuln.get("evidence","")[:100])}</td>
</tr>"""

    summary_cards = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary.get(sev, 0)
        color = sev_colors.get(sev, "#6b7280")
        summary_cards += f'<div style="text-align:center;padding:15px 25px;background:{color}15;border:1px solid {color};border-radius:8px"><div style="font-size:28px;font-weight:bold;color:{color}">{count}</div><div style="font-size:12px;color:#666">{sev.upper()}</div></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnScanner Report - {_esc(target_url)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:40px}}
.container{{max-width:1200px;margin:0 auto}}
h1{{font-size:28px;margin-bottom:5px}}
.meta{{color:#94a3b8;margin-bottom:30px}}
.summary{{display:flex;gap:15px;margin-bottom:30px;flex-wrap:wrap}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}}
th{{background:#334155;text-align:left;padding:12px 15px;font-size:13px;color:#94a3b8;text-transform:uppercase}}
td{{padding:10px 15px;border-bottom:1px solid #334155;font-size:14px}}
tr:hover{{background:#334155}}
code{{background:#0f172a;padding:2px 6px;border-radius:3px;font-size:12px}}
.footer{{margin-top:30px;text-align:center;color:#64748b;font-size:13px}}
</style>
</head>
<body>
<div class="container">
<h1>VulnScanner Report</h1>
<p class="meta">Target: <strong>{_esc(target_url)}</strong> | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Found: {len(results)} vulnerabilities</p>
<div class="summary">{summary_cards}</div>
<table>
<thead><tr><th>#</th><th>Severity</th><th>Name</th><th>Category</th><th>Description</th><th>Endpoint</th><th>Evidence</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<div class="footer">Generated by VulnScanner v1.0 | For educational purposes only</div>
</div>
</body>
</html>"""
    return html
