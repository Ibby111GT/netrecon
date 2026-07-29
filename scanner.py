#!/usr/bin/env python3
"""
NetRecon — TCP Port Scanner

Usage:
    python scanner.py --demo
    python scanner.py -t 127.0.0.1
    python scanner.py -t 192.168.1.0/24 --ports 22,80,443,8080
    python scanner.py -t 127.0.0.1 --ports 1-1024 --output report.json

Only scan hosts you own or have written permission to test.
"""

import argparse
import sys
import time

import demo
from config    import COMMON_PORTS, MAX_THREADS, THREAD_LIMIT
from net_utils import (expand_cidr, os_hint, parse_ports, resolve_host,
                       scan_host, validate_target)
from output    import (print_banner, print_host_header, print_result,
                       print_summary, save_json)


def parse_args():
    p = argparse.ArgumentParser(
        description="NetRecon — multi-threaded TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Only scan hosts you own or have written permission to test.",
    )
    p.add_argument("-t", "--target", default=None,
                   help="IP, hostname, or CIDR range (no wider than /22)")
    p.add_argument("--ports", default=None,
                   help="Ports and ranges, e.g. 22,80,8000-8010 (default: common ports)")
    p.add_argument("--full",   action="store_true",
                   help="Scan all 65535 ports (slow)")
    p.add_argument("--threads", type=int, default=MAX_THREADS,
                   help=f"Concurrent connections, 1-{THREAD_LIMIT} (default: {MAX_THREADS})")
    p.add_argument("--output", default=None, metavar="FILE",
                   help="Save results to JSON file")
    p.add_argument("--demo",   action="store_true",
                   help="Self-contained demo: starts its own listeners and scans localhost")
    return p.parse_args()


def fail(message):
    """One place for user errors, so they all look the same and all exit 2."""
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(2)


def resolve_ports(args):
    if args.full:
        return list(range(1, 65536))
    if args.ports:
        return parse_ports(args.ports)
    return sorted(COMMON_PORTS.keys())


def plan_scan(args):
    """
    Works out exactly what we are scanning before a single socket is opened.
    Returns (target, hosts, ports, services) — services are demo listeners we
    own and have to shut down afterwards.
    """
    if args.threads < 1 or args.threads > THREAD_LIMIT:
        fail(f"--threads must be between 1 and {THREAD_LIMIT} (got {args.threads})")

    if args.demo:
        if args.target and args.target not in demo.LOOPBACK:
            fail(f"--demo only ever scans loopback, and '{args.target}' is not. "
                 f"Drop -t, or drop --demo and scan a host you are allowed to test.")
        if args.ports or args.full:
            fail("--demo picks its own ports; drop --ports/--full.")
        services = demo.start_services()
        return demo.TARGET, [demo.TARGET], demo.port_list(services), services

    if not args.target:
        fail("no target given — use -t/--target, "
             "or --demo to watch it work against localhost")

    try:
        target = validate_target(args.target)
        ports  = resolve_ports(args)
        hosts  = expand_cidr(target)
    except ValueError as exc:
        fail(str(exc))

    return target, hosts, ports, []


def main():
    args = parse_args()
    target, hosts, ports, services = plan_scan(args)

    print_banner(target, ports, args.threads)

    all_results = []
    t0 = time.time()

    try:
        for host in hosts:
            resolved = resolve_host(host)
            if resolved is None:
                print(f"  [!] Could not resolve {host}, skipping")
                continue
            ip, hostname = resolved

            print_host_header(ip, hostname)
            results = scan_host(ip, ports, threads=args.threads)
            for r in results:
                print_result(r)

            hint = os_hint([r for r in results if r["state"] == "open"])
            if hint:
                print(f"      OS hint: {hint}")

            all_results.extend(results)
    except KeyboardInterrupt:
        print("\n  [!] Interrupted — reporting what we found so far")
    finally:
        for service in services:
            service.stop()

    elapsed = time.time() - t0
    print_summary(target, all_results, elapsed)

    if args.output:
        try:
            save_json(all_results, args.output, target, elapsed)
        except OSError as exc:
            fail(f"could not write {args.output}: {exc}")


if __name__ == "__main__":
    main()
