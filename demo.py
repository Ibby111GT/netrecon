"""
Demo mode — proves the scanner really works, without touching anyone else's
network.

We open a couple of real TCP listeners on 127.0.0.1 (ephemeral ports, picked
by the kernel), then scan loopback. That way `--demo` always finds at least
one open port with a live banner, and not a single packet leaves the machine.
"""

import socket
import threading

TARGET   = "127.0.0.1"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

# a handful of well-known ports so the demo looks like a real scan; whatever
# our own listeners land on gets added on top
DEMO_PORTS = [22, 80, 443, 3306, 8080]

_BANNERS = [
    "SSH-2.0-NetRecon_Demo\r\n",
    "HTTP/1.0 200 OK\r\nServer: NetRecon-Demo/1.0\r\n\r\n",
]


class DemoService:
    """
    A throwaway TCP listener that greets whoever connects, then hangs up.
    Bound to loopback on an OS-assigned port, so it cannot clash with a real
    service and cannot be reached from off the host.
    """

    def __init__(self, banner, host=TARGET):
        self.banner = banner
        self._sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))       # port 0 => kernel picks a free one
        self._sock.listen(8)
        self._sock.settimeout(0.25)      # so the loop can notice stop()
        self.host, self.port = self._sock.getsockname()
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break                    # socket closed under us — we are done
            try:
                conn.sendall(self.banner.encode())
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def start_services(banners=None):
    """Starts the demo listeners and returns them. The caller must stop() them."""
    return [DemoService(b).start() for b in (banners or _BANNERS)]


def port_list(services):
    """Common ports plus our own listeners, so the demo always finds something."""
    return sorted(set(DEMO_PORTS) | {s.port for s in services})
