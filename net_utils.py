import socket
import ipaddress
import concurrent.futures
from config import COMMON_PORTS, CONNECT_TIMEOUT, BANNER_TIMEOUT, MAX_THREADS


def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target if target != ip else None
        return ip, hostname
    except socket.gaierror as exc:
        raise SystemExit(f"[!] Cannot resolve {target}: {exc}")


def ping_host(ip, timeout=1.0):
    """quick TCP reachability check — not a real ping, just a connect attempt"""
    for port in (80, 443, 22, 3389):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except OSError:
            pass
    return False


def grab_banner(sock, port):
    try:
        sock.settimeout(BANNER_TIMEOUT)
        if port in (80, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        raw = sock.recv(1024)
        return raw.decode("utf-8", errors="ignore").strip()[:200]
    except Exception:
        return None


def scan_port(host, port):
    result = {
        "port":    port,
        "state":   "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner":  None,
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        if s.connect_ex((host, port)) == 0:
            result["state"]  = "open"
            result["banner"] = grab_banner(s, port)
        s.close()
    except OSError:
        pass
    return result


def scan_host(ip, ports, threads=None):
    threads = threads or MAX_THREADS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(scan_port, ip, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r["state"] == "open":
                open_ports.append(r)
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def expand_cidr(target):
    """returns a list of host IPs — single host just wraps in a list"""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()] or [target]
    except ValueError:
        return [target]


def os_hint(open_ports):
    ports = {p["port"] for p in open_ports}
    if 3389 in ports:              return "Windows (RDP)"
    if 22 in ports and 111 in ports: return "Linux/Unix"
    if 22 in ports:                return "Likely Linux/Unix"
    if 445 in ports:               return "Likely Windows"
    return "Unknown"
