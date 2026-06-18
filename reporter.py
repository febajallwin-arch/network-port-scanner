"""
reporter.py — Report generation engine
Network Port Scanner | Feba J Allwin
Supports: HTML, JSON, CSV, TXT
"""

import json
import csv
import os
from datetime import datetime
from scanner import ScanResult, PortResult


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Reporter:

    # ─────────────────────────────────────────
    #  JSON
    # ─────────────────────────────────────────
    @staticmethod
    def to_json(result: ScanResult, path: str):
        data = {
            "scan_metadata": {
                "tool": "Network Port Scanner v1.0",
                "author": "Feba J Allwin",
                "github": "github.com/febajallwin-arch",
                "target": result.target,
                "ip": result.ip,
                "hostname": result.hostname,
                "os_hint": result.os_hint,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "duration_sec": result.duration_sec,
            },
            "summary": {
                "total_ports_scanned": result.total_ports,
                "open_ports": len(result.open_ports),
                "closed_ports": result.closed_count,
                "filtered_ports": result.filtered_count,
                "critical": sum(1 for r in result.open_ports if r.severity == "CRITICAL"),
                "high": sum(1 for r in result.open_ports if r.severity == "HIGH"),
                "medium": sum(1 for r in result.open_ports if r.severity == "MEDIUM"),
            },
            "open_ports": [r.to_dict() for r in result.open_ports],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ─────────────────────────────────────────
    #  CSV
    # ─────────────────────────────────────────
    @staticmethod
    def to_csv(result: ScanResult, path: str):
        fields = ["port", "state", "service", "description", "banner", "latency_ms", "severity", "timestamp"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in result.open_ports:
                writer.writerow(r.to_dict())

    # ─────────────────────────────────────────
    #  TXT
    # ─────────────────────────────────────────
    @staticmethod
    def to_txt(result: ScanResult, path: str):
        lines = [
            "=" * 80,
            "  NETWORK PORT SCANNER — SCAN REPORT",
            "  Tool: Network Port Scanner v1.0 | Feba J Allwin",
            "=" * 80,
            f"  Target     : {result.target}",
            f"  IP         : {result.ip}",
            f"  Hostname   : {result.hostname}",
            f"  OS Hint    : {result.os_hint}",
            f"  Start      : {result.start_time}",
            f"  Duration   : {result.duration_sec}s",
            "",
            "  SUMMARY",
            "  " + "-" * 40,
            f"  Total Ports : {result.total_ports:,}",
            f"  Open        : {len(result.open_ports)}",
            f"  Closed      : {result.closed_count:,}",
            f"  Filtered    : {result.filtered_count:,}",
            "",
            "  OPEN PORTS",
            "  " + "-" * 78,
            f"  {'PORT':<7} {'SERVICE':<16} {'SEVERITY':<10} {'LATENCY':>9}  DESCRIPTION",
            "  " + "-" * 78,
        ]
        for r in result.open_ports:
            lines.append(
                f"  {r.port:<7} {r.service:<16} {r.severity:<10} {r.latency_ms:>7.1f}ms  {r.description}"
            )
            if r.banner:
                lines.append(f"  {'':7}  Banner: {r.banner[:70]}")
        lines += ["", "=" * 80, "  END OF REPORT", "=" * 80]
        with open(path, "w") as f:
            f.write("\n".join(lines))

    # ─────────────────────────────────────────
    #  HTML — Full styled report
    # ─────────────────────────────────────────
    @staticmethod
    def to_html(result: ScanResult, path: str):
        crits = sum(1 for r in result.open_ports if r.severity == "CRITICAL")
        highs = sum(1 for r in result.open_ports if r.severity == "HIGH")
        mediums = sum(1 for r in result.open_ports if r.severity == "MEDIUM")
        infos = sum(1 for r in result.open_ports if r.severity == "INFO")

        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH":     "#f97316",
            "MEDIUM":   "#eab308",
            "LOW":      "#06b6d4",
            "INFO":     "#22c55e",
        }

        def badge(sev):
            c = sev_colors.get(sev, "#94a3b8")
            return f'<span style="background:{c}22;color:{c};border:1px solid {c}55;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700">{sev}</span>'

        rows = ""
        for r in result.open_ports:
            banner_row = ""
            if r.banner:
                preview = r.banner[:120].replace('<', '&lt;').replace('>', '&gt;')
                banner_row = f'<tr><td colspan="6" style="padding:4px 12px 8px 12px;font-size:11px;color:#64748b;font-family:monospace;background:#0f172a">↳ {preview}</td></tr>'
            rows += f"""
            <tr>
              <td><strong style="color:#e2e8f0">{r.port}</strong></td>
              <td><span style="color:#22c55e;font-weight:700">OPEN</span></td>
              <td style="color:#06b6d4;font-weight:600">{r.service}</td>
              <td style="color:#94a3b8;font-size:12px">{r.description}</td>
              <td style="color:#64748b;font-size:12px">{r.latency_ms:.1f}ms</td>
              <td>{badge(r.severity)}</td>
            </tr>
            {banner_row}
            """

        risk_level = "CRITICAL" if crits else "HIGH" if highs else "MEDIUM" if mediums else "LOW"
        risk_color = sev_colors.get(risk_level, "#22c55e")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Port Scan Report — {result.target}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#050816;color:#e2e8f0;line-height:1.6}}
  .header{{background:linear-gradient(135deg,#0a0f1e,#0f172a);border-bottom:1px solid rgba(255,255,255,0.08);padding:2rem 2.5rem}}
  .header h1{{font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,#2563eb,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
  .header p{{color:#64748b;font-size:.85rem;margin-top:.25rem}}
  .container{{max-width:1100px;margin:0 auto;padding:2rem 2.5rem}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}}
  .meta-card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:1rem 1.25rem}}
  .meta-label{{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-bottom:.2rem}}
  .meta-value{{font-size:.95rem;font-weight:600;color:#e2e8f0}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:1.2rem;text-align:center;position:relative;overflow:hidden}}
  .stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--c)}}
  .stat-n{{font-size:2rem;font-weight:800;color:var(--c)}}
  .stat-l{{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:.2rem}}
  .risk-bar{{background:rgba(255,255,255,0.04);border:1px solid {risk_color}44;border-radius:12px;padding:1rem 1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:1rem}}
  .risk-icon{{font-size:1.5rem}}
  .risk-text h3{{font-size:.95rem;font-weight:700;color:{risk_color}}}
  .risk-text p{{font-size:.8rem;color:#64748b;margin-top:.15rem}}
  h2{{font-size:1.1rem;font-weight:700;margin-bottom:1rem;color:#e2e8f0}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#0f172a;padding:10px 14px;text-align:left;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:#64748b;border-bottom:1px solid rgba(255,255,255,0.08)}}
  td{{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:.85rem;vertical-align:middle}}
  tr:hover td{{background:rgba(255,255,255,0.03)}}
  .table-wrap{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden}}
  .footer{{text-align:center;padding:2rem;border-top:1px solid rgba(255,255,255,0.06);color:#334155;font-size:.78rem;margin-top:3rem}}
</style>
</head>
<body>
<div class="header">
  <h1>⟨ Network Port Scanner ⟩</h1>
  <p>Scan Report — Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | by Feba J Allwin</p>
</div>
<div class="container">

  <div class="meta-grid">
    <div class="meta-card"><div class="meta-label">Target</div><div class="meta-value">{result.target}</div></div>
    <div class="meta-card"><div class="meta-label">IP Address</div><div class="meta-value">{result.ip}</div></div>
    <div class="meta-card"><div class="meta-label">Hostname</div><div class="meta-value">{result.hostname}</div></div>
    <div class="meta-card"><div class="meta-label">OS Hint</div><div class="meta-value">{result.os_hint}</div></div>
    <div class="meta-card"><div class="meta-label">Scan Duration</div><div class="meta-value">{result.duration_sec}s</div></div>
    <div class="meta-card"><div class="meta-label">Scan Started</div><div class="meta-value">{result.start_time[:19]}</div></div>
  </div>

  <div class="stats">
    <div class="stat" style="--c:#22c55e"><div class="stat-n">{len(result.open_ports)}</div><div class="stat-l">Open Ports</div></div>
    <div class="stat" style="--c:#ef4444"><div class="stat-n">{crits}</div><div class="stat-l">Critical</div></div>
    <div class="stat" style="--c:#f97316"><div class="stat-n">{highs}</div><div class="stat-l">High Risk</div></div>
    <div class="stat" style="--c:#eab308"><div class="stat-n">{mediums}</div><div class="stat-l">Medium</div></div>
    <div class="stat" style="--c:#64748b"><div class="stat-n">{result.total_ports:,}</div><div class="stat-l">Total Scanned</div></div>
    <div class="stat" style="--c:#06b6d4"><div class="stat-n">{result.duration_sec}s</div><div class="stat-l">Duration</div></div>
  </div>

  <div class="risk-bar">
    <div class="risk-icon">{'🔴' if crits else '🟠' if highs else '🟡' if mediums else '🟢'}</div>
    <div class="risk-text">
      <h3>Overall Risk: {risk_level}</h3>
      <p>{'Critical vulnerabilities detected — immediate remediation required.' if crits else 'High severity ports open — review and restrict access.' if highs else 'Medium severity findings — investigate exposed services.' if mediums else 'Low risk — standard open ports detected.'}</p>
    </div>
  </div>

  <h2>Open Ports ({len(result.open_ports)})</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Port</th><th>State</th><th>Service</th><th>Description</th><th>Latency</th><th>Severity</th>
        </tr>
      </thead>
      <tbody>
        {rows if rows else '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:2rem">No open ports found.</td></tr>'}
      </tbody>
    </table>
  </div>

</div>
<div class="footer">
  Generated by Network Port Scanner v1.0 &nbsp;|&nbsp; github.com/febajallwin-arch &nbsp;|&nbsp; Feba J Allwin
  <br>⚠ For authorized security testing only. Do not scan hosts without explicit permission.
</div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)