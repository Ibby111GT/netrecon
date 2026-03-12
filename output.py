import json
import sys
from datetime import datetime

# ANSI colour helpers — degrade gracefully if terminal does not support them
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"

def _c(colour, text):
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{_RESET}"


def print_banner(target, ports, threads):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(_c(_BOLD, "=" * 56))
    print(_c(_BOLD, "  NetRecon — TCP Port Scanner"))
    print(f"  Target  : {_c(_CYAN, target)}")
    print(f"  Ports   : {len(ports)} to probe")
    print(f"  Threads : {threads}")
    print(f"  Started : {now}")
    print(_c(_BOLD, "=" * 56))
    print()


def print_result(result):
    port    = result["port"]
    state   = result["state"]
    service = result.get("service", "unknown")
    banner  = result.get("banner", "")

    if state == "open":
        label = _c(_GREEN, "OPEN")
        line  = f"  {port:<6} {label:<20} {_c(_CYAN, service)}"
        if banner:
            line += f"  {_c(_DIM, banner[:60])}"
        print(line)
    elif state == "filtered":
        print(f"  {port:<6} {_c(_YELLOW, "FILTERED"):<20} {service}")
    # closed ports are suppressed by default


def print_summary(target, results, elapsed):
    open_ports = [r for r in results if r["state"] == "open"]
    print()
    print(_c(_BOLD, "-" * 56))
    print(f"  Scan complete in {elapsed:.2f}s")
    print(f"  Host       : {target}")
    print(f"  Open ports : {_c(_GREEN, str(len(open_ports)))}")
    if open_ports:
        nums = ", ".join(str(r["port"]) for r in open_ports)
        print(f"  Ports      : {nums}")
    print(_c(_BOLD, "-" * 56))


def save_json(results, path, target, elapsed):
    data = {
        "target":      target,
        "scan_time":   datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 3),
        "open_count":  sum(1 for r in results if r["state"] == "open"),
        "results":     results,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  Report saved → {path}")
