#!/usr/bin/env python3
"""
NetRecon — TCP Port Scanner

Usage:
    python scanner.py -t 192.168.1.1
    python scanner.py -t 192.168.1.0/24 --ports 22,80,443,8080
    python scanner.py -t 10.0.0.1 --full --output report.json
"""

import argparse
import time

from config    import COMMON_PORTS, MAX_THREADS
from net_utils import expand_cidr, scan_host, resolve_host, os_hint
from output    import print_banner, print_result, print_summary, save_json


def parse_args():
    p = argparse.ArgumentParser(
        description="NetRecon — multi-threaded TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target",  required=True, help="IP, hostname, or CIDR range")
    p.add_argument("--ports", default=None,
                   help="Comma-separated port list (default: common ports)")
    p.add_argument("--full",   action="store_true",
                   help="Scan all 65535 ports (slow)")
    p.add_argument("--threads", type=int, default=MAX_THREADS)
    p.add_argument("--output", default=None, metavar="FILE",
                   help="Save results to JSON file")
    p.add_argument("--demo",   action="store_true",
                   help="Run against localhost in demo mode")
    return p.parse_args()


def resolve_ports(args):
    if args.full:
        return list(range(1, 65536))
    if args.ports:
        return [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    return sorted(COMMON_PORTS.keys())


def main():
    args = parse_args()

    if args.demo:
        args.target = "127.0.0.1"
        args.ports  = "22,80,443,8080,3306"

    ports   = resolve_ports(args)
    hosts   = expand_cidr(args.target)

    print_banner(args.target, ports, args.threads)

    all_results = []
    t0 = time.time()

    for host in hosts:
        ip = resolve_host(host)
        if ip is None:
            print(f"  [!] Could not resolve {host}, skipping")
            continue

        results = scan_host(ip, ports, threads=args.threads)
        for r in results:
            print_result(r)

        hint = os_hint([r for r in results if r["state"] == "open"])
        if hint:
            print(f"      OS hint: {hint}")

        all_results.extend(results)

    elapsed = time.time() - t0
    print_summary(args.target, all_results, elapsed)

    if args.output:
        save_json(all_results, args.output, args.target, elapsed)


if __name__ == "__main__":
    main()
