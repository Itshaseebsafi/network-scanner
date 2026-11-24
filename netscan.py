#!/usr/bin/env python3
"""
netscan.py - a small network scanner and inventory tool.

What it does:
  1. Takes a subnet (for example 192.168.1.0/24).
  2. Checks every address in it to see which devices are online.
  3. For each live device, looks up its hostname and checks common ports.
  4. Prints a table and can save the results as CSV and/or an HTML report.

It uses only Python's standard library, so there is nothing to install.

Example:
  python netscan.py 192.168.1.0/24 --csv inventory.csv --html report.html
"""

import argparse
import csv
import html
import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

# Ports most worth knowing about on an office network, and what usually runs there.
COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    135: "MS-RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
    9100: "Printer",
}

# Ports that are a security concern when open (old, unencrypted or often attacked).
RISKY_PORTS = {23, 139, 445, 3389}


@dataclass
class Host:
    """Everything we learn about one device."""
    ip: str
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    response_ms: float = None  # how long the ping took, if it answered ping

    @property
    def services(self):
        """Open ports as readable text, e.g. '22/SSH, 443/HTTPS'."""
        return ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in self.open_ports)

    @property
    def risky_ports(self):
        return [p for p in self.open_ports if p in RISKY_PORTS]


# ---------------------------------------------------------------------------
# Step 1: is the device online?
# ---------------------------------------------------------------------------

def ping_command(ip, timeout_s):
    """Build the right ping command for this operating system.

    Windows, Linux and macOS each use different flags for
    'send one packet' and 'how long to wait'.
    """
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]  # -w is milliseconds
    if system == "darwin":  # macOS
        return ["ping", "-c", "1", "-t", str(max(1, int(timeout_s))), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]  # Linux


def ping(ip, timeout_s=1.0):
    """Ping once. Returns the round-trip time in ms, or None if no reply."""
    start = time.perf_counter()
    try:
        result = subprocess.run(
            ping_command(ip, timeout_s),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if result.returncode == 0:
        return round((time.perf_counter() - start) * 1000, 1)
    return None


def port_open(ip, port, timeout_s=0.5):
    """Try a TCP connection. If it connects, the port is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_s)
        return s.connect_ex((ip, port)) == 0  # 0 means the connection worked


# ---------------------------------------------------------------------------
# Step 2: learn about a live device
# ---------------------------------------------------------------------------

def reverse_dns(ip):
    """Ask DNS for the device's name. Many home devices won't have one."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def scan_host(ip, ports, ping_timeout, port_timeout, tcp_fallback):
    """Check one address. Returns a Host if it is online, otherwise None.

    Windows PCs block ping by default, so with tcp_fallback a device
    also counts as online if any port answers.
    """
    rtt = ping(ip, ping_timeout)
    open_ports = [p for p in ports if port_open(ip, p, port_timeout)] if (rtt is not None or tcp_fallback) else []

    if rtt is None and not open_ports:
        return None  # nothing answered: treat as offline

    return Host(ip=ip, hostname=reverse_dns(ip), open_ports=open_ports, response_ms=rtt)


def scan_network(network, ports, workers=100, ping_timeout=1.0, port_timeout=0.5, tcp_fallback=True):
    """Scan every usable address in the subnet at the same time (in threads).

    Checking 254 addresses one by one would take minutes;
    in parallel it takes seconds.
    """
    net = ipaddress.ip_network(network, strict=False)
    addresses = [str(ip) for ip in net.hosts()] or [str(net.network_address)]  # a /32 has no "hosts"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda ip: scan_host(ip, ports, ping_timeout, port_timeout, tcp_fallback), addresses)

    hosts = [h for h in results if h is not None]
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip))


# ---------------------------------------------------------------------------
# Step 3: report
# ---------------------------------------------------------------------------

def print_table(hosts, network, seconds):
    print(f"\nScan of {network}: {len(hosts)} device(s) online ({seconds:.1f}s)\n")
    print(f"{'IP ADDRESS':<16} {'HOSTNAME':<30} {'PING':>8}  OPEN PORTS")
    print("-" * 80)
    for h in hosts:
        rtt = f"{h.response_ms} ms" if h.response_ms is not None else "blocked"
        flag = "  <-- check: " + ", ".join(map(str, h.risky_ports)) if h.risky_ports else ""
        print(f"{h.ip:<16} {(h.hostname or '-')[:30]:<30} {rtt:>8}  {h.services or '-'}{flag}")
    print()


def write_csv(hosts, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "hostname", "ping_ms", "open_ports", "risky_ports"])
        for h in hosts:
            writer.writerow([h.ip, h.hostname, h.response_ms if h.response_ms is not None else "",
                             h.services, " ".join(map(str, h.risky_ports))])


def write_html(hosts, network, seconds, path):
    """A simple, self-contained HTML report you can open in any browser."""
    rows = []
    for h in hosts:
        risk = ", ".join(f"{p}/{COMMON_PORTS[p]}" for p in h.risky_ports)
        rtt = f"{h.response_ms} ms" if h.response_ms is not None else "blocked"
        rows.append(
            f"<tr class='{'risk' if risk else ''}'><td>{html.escape(h.ip)}</td>"
            f"<td>{html.escape(h.hostname or '-')}</td><td>{rtt}</td>"
            f"<td>{html.escape(h.services or '-')}</td><td>{html.escape(risk or '-')}</td></tr>"
        )
    risky_count = sum(1 for h in hosts if h.risky_ports)
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Network inventory - {html.escape(network)}</title>
<style>
 body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1f2933; }}
 h1 {{ margin-bottom: 4px; }} .meta {{ color: #616e7c; margin-bottom: 20px; }}
 .cards {{ display: flex; gap: 16px; margin-bottom: 24px; }}
 .card {{ border: 1px solid #d9e2ec; border-radius: 8px; padding: 12px 20px; }}
 .card b {{ display: block; font-size: 24px; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e4e7eb; }}
 th {{ background: #f5f7fa; }} tr.risk td {{ background: #fff4e5; }}
</style></head><body>
<h1>Network inventory</h1>
<div class="meta">Subnet {html.escape(network)} &middot; scanned {datetime.now():%Y-%m-%d %H:%M} &middot; {seconds:.1f}s</div>
<div class="cards">
 <div class="card"><b>{len(hosts)}</b>devices online</div>
 <div class="card"><b>{risky_count}</b>with risky ports open</div>
</div>
<table><tr><th>IP address</th><th>Hostname</th><th>Ping</th><th>Open ports</th><th>Review</th></tr>
{''.join(rows)}
</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def parse_ports(text):
    """Turn '22,80,443' into [22, 80, 443]."""
    ports = sorted({int(p) for p in text.split(",") if p.strip()})
    if not all(1 <= p <= 65535 for p in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return ports


def main(argv=None):
    parser = argparse.ArgumentParser(description="Find devices on a network and see what ports they have open.")
    parser.add_argument("network", help="subnet to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", type=parse_ports, default=sorted(COMMON_PORTS),
                        help="comma-separated ports to check (default: common office ports)")
    parser.add_argument("--csv", help="save results to this CSV file")
    parser.add_argument("--html", help="save an HTML report to this file")
    parser.add_argument("--workers", type=int, default=100, help="how many addresses to check at once")
    parser.add_argument("--no-tcp-fallback", action="store_true",
                        help="only count devices that answer ping")
    args = parser.parse_args(argv)

    try:
        net = ipaddress.ip_network(args.network, strict=False)
    except ValueError as e:
        parser.error(str(e))
    if net.num_addresses > 4096:
        parser.error("that subnet is very large; scan a /20 or smaller")

    start = time.perf_counter()
    hosts = scan_network(args.network, args.ports, workers=args.workers,
                         tcp_fallback=not args.no_tcp_fallback)
    seconds = time.perf_counter() - start

    print_table(hosts, str(net), seconds)
    if args.csv:
        write_csv(hosts, args.csv)
        print(f"Saved CSV to {args.csv}")
    if args.html:
        write_html(hosts, str(net), seconds, args.html)
        print(f"Saved HTML report to {args.html}")


if __name__ == "__main__":
    main()
