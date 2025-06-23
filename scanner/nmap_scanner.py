import nmap
import json
from datetime import datetime
import os

# Load vulnerability database
with open("data/vulnerabilities.json") as f:
    vuln_db = json.load(f)

def scan_target_and_generate_report(target_ip_or_subnet):
    scanner = nmap.PortScanner()
    print(f"[~] Scanning {target_ip_or_subnet}...")

    # Initial host discovery (ping sweep)
    scanner.scan(hosts=target_ip_or_subnet, arguments='-sn')  # Just host discovery

    live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == 'up']

    if not live_hosts:
        return f"No live hosts found in {target_ip_or_subnet}.", None

    full_report_lines = []
    full_report_lines.append(f"Subnet scan: {target_ip_or_subnet}")
    full_report_lines.append(f"Time: {datetime.now()}\n")
    full_report_lines.append(f"Live hosts found: {len(live_hosts)}\n")

    for host in live_hosts:
        report_lines = [f"[+] Host: {host}"]
        scanner.scan(hosts=host, arguments='-sV')

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                info = scanner[host][proto][port]
                service = info['name']
                product = info.get('product', '')
                version = info.get('version', '')

                line = f"    Port {port}/{proto} is open - Service: {service} {product} {version}"
                report_lines.append(line)

                warning = vuln_db.get(str(port)) or vuln_db.get(service)
                if warning:
                    report_lines.append(f"    [⚠] {warning}")

        full_report_lines.extend(report_lines)
        full_report_lines.append("")

    # Save the full report
    filename = f"subnet_report_{target_ip_or_subnet.replace('/', '_').replace('.', '_')}.txt"
    filepath = os.path.join("data", filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("\n".join(full_report_lines))

    return "\n".join(full_report_lines), filepath