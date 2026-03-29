import socket
import time
import argparse
import requests
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from report import generate_report

MITRE_MAPPINGS = {
    "subdomain_enum": {"id": "T1596.001", "name": "DNS Passive Reconnaissance",      "tactic": "Reconnaissance"},
    "port_scan":      {"id": "T1046",     "name": "Network Service Discovery",        "tactic": "Discovery"},
    "banner_grab":    {"id": "T1592.002", "name": "Gather Host Information/Software", "tactic": "Reconnaissance"},
    "cve_lookup":     {"id": "T1595.002", "name": "Vulnerability Scanning",           "tactic": "Reconnaissance"},
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443, 27017]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "webmail", "smtp", "blog", "shop",
    "app", "cdn", "secure", "login", "dashboard", "beta", "git"
]

CVE_KEYWORDS = {
    "FTP":     "FTP server vulnerability",
    "SSH":     "OpenSSH vulnerability",
    "Telnet":  "Telnet remote code execution",
    "SMTP":    "SMTP mail server vulnerability",
    "SMB":     "SMB Windows vulnerability",
    "RDP":     "RDP remote desktop vulnerability",
    "MySQL":   "MySQL database vulnerability",
    "MongoDB": "MongoDB unauthorized access",
    "VNC":     "VNC remote desktop vulnerability",
    "HTTP":    "Apache nginx web server vulnerability",
}

def enumerate_subdomains_crtsh(domain):
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        found.add(sub)
    except Exception:
        pass
    return found

def bruteforce_subdomains(domain):
    found = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    def check(sub):
        hostname = f"{sub}.{domain}"
        try:
            resolver.resolve(hostname, "A")
            return hostname
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check, w): w for w in WORDLIST}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.add(result)
    return found

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def enumerate_subdomains(domain):
    print(f"[*] Enumerating subdomains for {domain}...")
    crt = enumerate_subdomains_crtsh(domain)
    bf  = bruteforce_subdomains(domain)
    all_subs = crt | bf
    results = []
    for sub in sorted(all_subs):
        ip = resolve_ip(sub)
        results.append({"subdomain": sub, "ip": ip or "Unresolved"})
        print(f"    [+] {sub} -> {ip or 'Unresolved'}")
    print(f"[*] Found {len(results)} subdomains")
    return results

def scan_port(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port, result == 0
    except Exception:
        return port, False

def scan_ports(host, ports=None):
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    print(f"[*] Scanning {len(ports)} ports on {host}...")
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for f in as_completed(futures):
            port, is_open = f.result()
            if is_open:
                service = PORT_SERVICES.get(port, "Unknown")
                open_ports.append({"port": port, "service": service})
                print(f"    [+] {port}/tcp  OPEN  ({service})")
    open_ports.sort(key=lambda x: x["port"])
    return open_ports

def grab_banner(host, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 443:
                return "HTTPS (use curl for banner)"
            else:
                s.sendall(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:200] if banner else "No banner"
    except Exception:
        return "No banner"

def grab_banners(host, open_ports):
    print(f"[*] Grabbing service banners...")
    results = []
    for entry in open_ports:
        port = entry["port"]
        banner = grab_banner(host, port)
        results.append({**entry, "banner": banner})
        if banner and banner != "No banner":
            print(f"    [+] {port}: {banner[:60]}")
    return results

def lookup_cves(service_name, max_results=3):
    keyword = CVE_KEYWORDS.get(service_name)
    if not keyword:
        return []
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    m = metrics[version][0]
                    cvss_data = m.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A"))
                    break
            cves.append({
                "cve_id": cve_id,
                "description": desc[:200],
                "cvss_score": cvss_score,
                "severity": severity
            })
        return cves
    except Exception:
        return []

def enrich_with_cves(port_data):
    print("[*] Looking up CVEs for discovered services...")
    enriched = []
    seen_services = set()
    for entry in port_data:
        service = entry.get("service", "Unknown")
        if service not in seen_services and service in CVE_KEYWORDS:
            seen_services.add(service)
            cves = lookup_cves(service)
            if cves:
                print(f"    [+] {service}: {len(cves)} CVEs found")
            time.sleep(0.6)
        else:
            cves = []
        enriched.append({**entry, "cves": cves})
    return enriched

def main():
    parser = argparse.ArgumentParser(
        description="Automated Recon & Vulnerability Scanner with MITRE ATT&CK mapping"
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE lookup")
    parser.add_argument("--output", default="report", help="Output file prefix")
    args = parser.parse_args()

    target = args.target.lower().strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*55}")
    print(f"  Recon Scanner | {timestamp}")
    print(f"  Target: {target}")
    print(f"{'='*55}\n")

    subdomains = []
    if not args.no_subdomains:
        subdomains = enumerate_subdomains(target)

    target_ip = resolve_ip(target)
    print(f"\n[*] Resolved {target} -> {target_ip}")
    open_ports = scan_ports(target_ip or target)

    port_data = grab_banners(target_ip or target, open_ports)

    if not args.no_cve:
        port_data = enrich_with_cves(port_data)

    scan_results = {
        "target": target,
        "target_ip": target_ip or "Unresolved",
        "timestamp": timestamp,
        "subdomains": subdomains,
        "open_ports": port_data,
        "mitre_mappings": MITRE_MAPPINGS
    }

    html_file = f"{args.output}.html"
    generate_report(scan_results, html_file)

    print(f"\n{'='*55}")
    print(f"  Scan complete!")
    print(f"  Report: {html_file}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()