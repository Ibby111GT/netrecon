#!/usr/bin/env python3
"""
NetRecon - Network Reconnaissance & Port Scanner
-------------------------------------------------
A lightweight network scanner for host discovery, port scanning,
service banner grabbing, and basic OS fingerprinting.

Usage:
    python scanner.py -t 192.168.1.1
    python scanner.py -t 192.168.1.0/24 --ports 22,80,443,8080
    python scanner.py -t 10.0.0.1 --full --output report.json
"""

import socket
import argparse
import json
import ipaddress
import concurrent.futures
import time
import sys
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}
BANNER_TIMEOUT = 2.0
CONNECT_TIMEOUT = 1.0

def scan_port(host, port):
    result = {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, "unknown"), "banner": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        if sock.connect_ex((host, port)) == 0:
            result["state"] = "open"
            try:
                sock.settimeout(BANNER_TIMEOUT)
                if port in (80, 8080, 8443):
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner_raw = sock.recv(1024)
                banner = banner_raw.decode("utf-8", errors="ignore").strip()
                result["banner"] = banner[:200] if banner else None
            except Exception:
                pass
        sock.close()
    except Exception:
        pass
    return result

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target if target != ip else "N/A"
        return ip, hostname
    except socket.gaierror as e:
        print(f"[!] Cannot resolve {target}: {e}")
        sys.exit(1)

def ping_host(ip):
    for port in (80, 443, 22):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass
    return False

def scan_host(ip, ports, threads=100):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)
    open_ports.sort(key=lambda x: x["port"])
    return {"ip": ip, "open_ports": open_ports}

def expand_cidr(network):
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [network]

def os_fingerprint_hint(open_ports):
    port_nums = {p["port"] for p in open_ports}
    if 3389 in port_nums: return "Windows (RDP detected)"
    if 22 in port_nums and 111 in port_nums: return "Linux/Unix (SSH + RPC)"
    if 22 in port_nums: return "Likely Linux/Unix (SSH open)"
    if 445 in port_nums: return "Likely Windows (SMB open)"
    return "Unknown"

def print_banner():
    print("""
+------------------------------------------+
|       NetRecon v1.0 - Port Scanner       |
|  Python-based port and service scanner   |
+------------------------------------------+
""")

def print_result(ip, hostname, host_result):
    print(f"\n{'='*50}")
    print(f"  Target  : {ip} ({hostname})")
    print(f"  OS hint : {os_fingerprint_hint(host_result['open_ports'])}")
    print(f"{'='*50}")
    if not host_result["open_ports"]:
        print("  No open ports found.")
    else:
        print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<14} BANNER")
        for p in host_result["open_ports"]:
            banner = (p["banner"] or "")[:40].replace("\n", " ")
            print(f"  {p['port']:<8} {p['state']:<8} {p['service']:<14} {banner}")
    print()

def save_json(results, path):
    with open(path, "w") as f:
        json.dump({"scan_time": datetime.now().isoformat(), "results": results}, f, indent=2)
    print(f"[+] Report saved to {path}")

def parse_ports(port_str):
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="NetRecon - TCP port scanner with banner grabbing")
    parser.add_argument("-t", "--target", required=True, help="Target IP, hostname, or CIDR")
    parser.add_argument("--ports", default=",".join(str(p) for p in COMMON_PORTS), help="Ports to scan")
    parser.add_argument("--full", action="store_true", help="Scan ports 1-1024")
    parser.add_argument("--threads", type=int, default=100, help="Thread count")
    parser.add_argument("--output", default=None, help="Save results to JSON file")
    parser.add_argument("--skip-ping", action="store_true", help="Skip host reachability check")
    args = parser.parse_args()

    ports = list(range(1, 1025)) if args.full else parse_ports(args.ports)
    targets = expand_cidr(args.target)
    print(f"[*] Targets: {len(targets)} | Ports: {len(ports)} | Threads: {args.threads}")

    all_results = []
    start = time.time()
    for target in targets:
        ip, hostname = resolve_host(target)
        if not args.skip_ping and not ping_host(ip):
            print(f"[-] {ip} appears unreachable (use --skip-ping to override)")
            continue
        print(f"\n[*] Scanning {ip} ({hostname}) ...")
        host_result = scan_host(ip, ports, threads=args.threads)
        print_result(ip, hostname, host_result)
        all_results.append({"ip": ip, "hostname": hostname, "os_hint": os_fingerprint_hint(host_result["open_ports"]), **host_result})

    print(f"[+] Scan complete in {time.time()-start:.1f}s - {len(all_results)} host(s) scanned")
    if args.output:
        save_json(all_results, args.output)

if __name__ == "__main__":
    main()
