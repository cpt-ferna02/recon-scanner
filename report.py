SEVERITY_COLOR = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#34c759",
    "N/A":      "#636366",
}

RISKY_SERVICES = {"Telnet", "FTP", "RDP", "VNC", "SMB", "MongoDB", "Elasticsearch"}


def severity_badge(severity):
    color = SEVERITY_COLOR.get(str(severity).upper(), "#636366")
    return f'<span class="badge" style="background:{color}">{severity}</span>'


def generate_report(data, output_file):
    target     = data["target"]
    target_ip  = data["target_ip"]
    timestamp  = data["timestamp"]
    subdomains = data["subdomains"]
    open_ports = data["open_ports"]
    mitre      = data["mitre_mappings"]

    total_cves    = sum(len(p.get("cves") or []) for p in open_ports)
    risky_ports   = [p for p in open_ports if p["service"] in RISKY_SERVICES]
    critical_cves = sum(
        1 for p in open_ports
        for c in (p.get("cves") or [])
        if str(c.get("severity", "")).upper() in ("CRITICAL", "HIGH")
    )

    sub_rows = ""
    for s in subdomains:
        sub_rows += f"""
        <tr>
          <td><span class="mono">{s['subdomain']}</span></td>
          <td><span class="mono ip">{s['ip']}</span></td>
          <td><span class="badge badge-blue">T1596.001</span></td>
        </tr>"""
    if not sub_rows:
        sub_rows = '<tr><td colspan="3" class="empty">No subdomains discovered</td></tr>'

    port_rows = ""
    for p in open_ports:
        svc      = p["service"]
        risk     = "⚠ High Risk" if svc in RISKY_SERVICES else ""
        risk_cls = "risk-warn" if risk else ""
        banner   = (p.get("banner") or "—")[:80]
        cves     = p.get("cves") or []

        cve_html = ""
        for c in cves:
            cve_html += f"""
            <div class="cve-item">
              <span class="cve-id">{c['cve_id']}</span>
              {severity_badge(c['severity'])}
              <span class="cvss">CVSS {c['cvss_score']}</span>
              <p class="cve-desc">{c['description'][:160]}</p>
            </div>"""
        if not cve_html:
            cve_html = '<span class="dim">—</span>'

        port_rows += f"""
        <tr>
          <td><span class="mono port-num">{p['port']}</span></td>
          <td><span class="svc-tag {risk_cls}">{svc}</span> {risk}</td>
          <td><span class="mono dim">{banner}</span></td>
          <td>{cve_html}</td>
        </tr>"""
    if not port_rows:
        port_rows = '<tr><td colspan="4" class="empty">No open ports found</td></tr>'

    mitre_rows = ""
    for key, m in mitre.items():
        mitre_rows += f"""
        <tr>
          <td><span class="badge badge-purple">{m['id']}</span></td>
          <td>{m['name']}</td>
          <td><span class="tactic">{m['tactic']}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — {target}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0c10; --surface: #111318; --border: #1e2230;
    --accent: #00e5ff; --accent2: #7b61ff;
    --text: #c9d1e0; --muted: #4a5068;
    --red: #ff2d55; --orange: #ff6b35;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Barlow', sans-serif; font-weight: 300; }}
  header {{ background: #0d1117; border-bottom: 1px solid var(--border); padding: 40px 48px; }}
  h1 {{ font-size: 32px; font-weight: 700; color: #fff; margin-top: 16px; }}
  h1 span {{ color: var(--accent); }}
  .target-ip {{ font-family: 'Share Tech Mono', monospace; font-size: 13px; color: var(--muted); margin-top: 4px; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); }}
  .stat {{ flex: 1; min-width: 120px; background: var(--surface); padding: 20px 28px; }}
  .stat-val {{ font-size: 32px; font-weight: 700; font-family: 'Share Tech Mono', monospace; color: var(--accent); }}
  .stat-val.red {{ color: var(--red); }}
  .stat-val.orange {{ color: var(--orange); }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }}
  main {{ max-width: 1280px; margin: 0 auto; padding: 40px 32px; display: flex; flex-direction: column; gap: 40px; }}
  .section-title {{ font-size: 11px; text-transform: uppercase; letter-spacing: .14em; color: var(--accent); margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }}
  .section-title::after {{ content: ''; flex: 1; height: 1px; background: var(--border); }}
  .table-wrap {{ border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  thead th {{ background: #0d1117; color: var(--muted); text-transform: uppercase; font-size: 10px; letter-spacing: .12em; padding: 12px 18px; text-align: left; border-bottom: 1px solid var(--border); }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background .15s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: rgba(255,255,255,.025); }}
  td {{ padding: 14px 18px; vertical-align: top; }}
  .empty {{ text-align: center; color: var(--muted); padding: 32px; font-style: italic; }}
  .dim {{ color: var(--muted); }}
  .mono {{ font-family: 'Share Tech Mono', monospace; font-size: 12.5px; }}
  .ip {{ color: #7dd3fc; }}
  .port-num {{ color: var(--accent); font-size: 14px; }}
  .badge {{ display: inline-block; padding: 2px 9px; border-radius: 4px; font-family: 'Share Tech Mono', monospace; font-size: 11px; font-weight: 600; color: #000; }}
  .badge-blue {{ background: var(--accent); }}
  .badge-purple {{ background: var(--accent2); color: #fff; }}
  .tactic {{ font-size: 11px; background: rgba(123,97,255,.18); color: var(--accent2); padding: 2px 8px; border-radius: 4px; }}
  .svc-tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; background: rgba(0,229,255,.08); color: var(--accent); font-size: 12px; font-weight: 600; }}
  .risk-warn {{ background: rgba(255,107,53,.12); color: var(--orange); }}
  .cve-item {{ margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }}
  .cve-item:last-child {{ margin-bottom: 0; border-bottom: none; padding-bottom: 0; }}
  .cve-id {{ font-family: 'Share Tech Mono', monospace; font-size: 12px; color: #fff; margin-right: 6px; }}
  .cvss {{ font-size: 11px; color: var(--muted); margin-left: 6px; }}
  .cve-desc {{ font-size: 12px; color: var(--muted); margin-top: 4px; line-height: 1.5; }}
  footer {{ border-top: 1px solid var(--border); padding: 24px 32px; font-size: 11px; color: var(--muted); }}
</style>
</head>
<body>
<header>
  <div style="font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)">Recon Scanner v1.0</div>
  <h1>Target: <span>{target}</span></h1>
  <div class="target-ip">Resolved IP → {target_ip} &nbsp;|&nbsp; {timestamp}</div>
</header>

<div class="stats">
  <div class="stat"><div class="stat-val">{len(subdomains)}</div><div class="stat-label">Subdomains Found</div></div>
  <div class="stat"><div class="stat-val">{len(open_ports)}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-val orange">{len(risky_ports)}</div><div class="stat-label">High-Risk Services</div></div>
  <div class="stat"><div class="stat-val">{total_cves}</div><div class="stat-label">CVEs Found</div></div>
  <div class="stat"><div class="stat-val red">{critical_cves}</div><div class="stat-label">Critical / High CVEs</div></div>
</div>

<main>
  <section>
    <div class="section-title">Subdomain Enumeration — T1596.001</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Subdomain</th><th>Resolved IP</th><th>MITRE ID</th></tr></thead>
        <tbody>{sub_rows}</tbody>
      </table>
    </div>
  </section>

  <section>
    <div class="section-title">Open Ports, Services & CVEs — T1046 / T1595.002</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Banner</th><th>CVEs</th></tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </div>
  </section>

  <section>
    <div class="section-title">MITRE ATT&CK Techniques</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr></thead>
        <tbody>{mitre_rows}</tbody>
      </table>
    </div>
  </section>
</main>

<footer>Generated by recon-scanner &nbsp;|&nbsp; MITRE ATT&CK® · NVD CVE Data · crt.sh</footer>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report saved: {output_file}")