import re
import socket
import ipaddress
import concurrent.futures
from config import (COMMON_PORTS, CONNECT_TIMEOUT, BANNER_TIMEOUT,
                    MAX_THREADS, MIN_CIDR_PREFIX)


# hostname labels: letters, digits and hyphens, no leading or trailing hyphen
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# digits and dots only — if that is not a valid address it is a typo'd one
_NUMERIC_RE = re.compile(r"^[0-9.]+(/[0-9]+)?$")


def validate_target(target):
    """
    Checks a target looks like an IP, a CIDR block or a hostname *before* we
    start opening sockets. Returns the cleaned target, or raises ValueError
    with something a human can act on.
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("no target given")

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if _NUMERIC_RE.match(target):
        raise ValueError(f"'{target}' is not a valid IP address or CIDR range")

    if len(target) > 253 or not _HOSTNAME_RE.match(target):
        raise ValueError(
            f"'{target}' is not a valid hostname, IP address or CIDR range"
        )

    return target


def parse_ports(spec):
    """
    Turns '22,80,8000-8010' into a sorted list of unique port numbers.
    Anything that is not a port in 1-65535 raises ValueError — the old
    behaviour of silently dropping junk meant you never scanned what you
    thought you were scanning.
    """
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            low, _, high = chunk.partition("-")
            start, end = _port_number(low), _port_number(high)
            if start > end:
                raise ValueError(f"port range '{chunk}' runs backwards")
            ports.update(range(start, end + 1))
        else:
            ports.add(_port_number(chunk))

    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _port_number(text):
    text = text.strip()
    if not text.isdigit():
        raise ValueError(f"'{text}' is not a port number")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} is out of range (1-65535)")
    return port


def resolve_host(target):
    """
    Returns (ip, hostname), or None if the target cannot be resolved.
    A library has no business killing the process, so the caller decides
    what an unresolvable host means.
    """
    try:
        ip = socket.gethostbyname(target)
    except (OSError, UnicodeError):
        return None

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except OSError:
        hostname = target if target != ip else None
    return ip, hostname


def grab_banner(sock, port):
    try:
        sock.settimeout(BANNER_TIMEOUT)
        if port in (80, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        raw = sock.recv(1024)
        # collapse whitespace so a multi-line greeting stays on one row
        return " ".join(raw.decode("utf-8", errors="ignore").split())[:200] or None
    except Exception:
        return None


def scan_port(host, port):
    result = {
        "host":    host,
        "port":    port,
        "state":   "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner":  None,
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        result["state"]  = "open"
        result["banner"] = grab_banner(s, port)
    except TimeoutError:
        # no answer at all — typically a firewall dropping the packet
        result["state"] = "filtered"
    except OSError:
        # refused or unreachable — nothing is listening
        pass
    finally:
        s.close()
    return result


def scan_host(ip, ports, threads=None):
    """Scans one host and returns the interesting results (open + filtered)."""
    threads = threads or MAX_THREADS
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(scan_port, ip, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r["state"] != "closed":
                found.append(r)
    found.sort(key=lambda x: x["port"])
    return found


def expand_cidr(target):
    """
    Returns the list of addresses to scan — a single IP or hostname just gets
    wrapped in a list, a CIDR block gets expanded.

    Blocks wider than MIN_CIDR_PREFIX are refused outright rather than
    quietly queueing millions of hosts.
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]          # a hostname — resolve_host deals with it later

    limit = 2 ** (32 - MIN_CIDR_PREFIX)
    if net.num_addresses > limit:
        raise ValueError(
            f"{target} covers {net.num_addresses} addresses; NetRecon refuses "
            f"anything wider than /{MIN_CIDR_PREFIX} ({limit} addresses). "
            f"Split it into smaller blocks."
        )
    return [str(h) for h in net.hosts()]


def os_hint(open_ports):
    """A guess from the mix of open ports — a hint, not a fingerprint."""
    ports = {p["port"] for p in open_ports}
    if 3389 in ports:                return "Windows (RDP)"
    if 22 in ports and 111 in ports: return "Linux/Unix"
    if 22 in ports:                  return "Likely Linux/Unix"
    if 445 in ports:                 return "Likely Windows"
    return None
