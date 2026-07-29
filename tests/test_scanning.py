"""Socket-level behaviour. Everything here stays on 127.0.0.1."""

import socket
import unittest

import demo
from net_utils import os_hint, resolve_host, scan_host, scan_port


def free_port():
    """Grab a port from the kernel and hand it straight back, so it is shut."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ResolveHostTests(unittest.TestCase):

    def test_loopback_literal(self):
        ip, _ = resolve_host("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    def test_localhost_name(self):
        resolved = resolve_host("localhost")
        self.assertIsNotNone(resolved)
        ip, hostname = resolved
        self.assertTrue(ip.startswith("127."))
        self.assertIsInstance(hostname, (str, type(None)))

    def test_bad_name_returns_none(self):
        # syntactically impossible, so no DNS query ever leaves the machine
        self.assertIsNone(resolve_host("no such host"))

    def test_bad_name_does_not_kill_the_process(self):
        # it used to raise SystemExit from inside the library
        try:
            self.assertIsNone(resolve_host("-not-a-host-"))
        except SystemExit:
            self.fail("resolve_host must not raise SystemExit")


class PortStateTests(unittest.TestCase):

    def test_open_port_is_detected_with_a_banner(self):
        with demo.DemoService("SSH-2.0-NetRecon_Test\r\n") as svc:
            result = scan_port(svc.host, svc.port)
        self.assertEqual(result["state"], "open")
        self.assertIn("NetRecon_Test", result["banner"])
        self.assertEqual(result["host"], "127.0.0.1")

    def test_closed_port_is_detected(self):
        result = scan_port("127.0.0.1", free_port())
        self.assertEqual(result["state"], "closed")
        self.assertIsNone(result["banner"])

    def test_known_port_numbers_get_a_service_name(self):
        self.assertEqual(scan_port("127.0.0.1", 22)["service"], "SSH")

    def test_scan_host_reports_open_and_hides_closed(self):
        with demo.DemoService("hello\r\n") as svc:
            shut = free_port()
            results = scan_host("127.0.0.1", [svc.port, shut], threads=4)
        self.assertEqual([r["port"] for r in results], [svc.port])
        self.assertEqual(results[0]["state"], "open")


class DemoModeTests(unittest.TestCase):

    def test_demo_scan_always_finds_its_own_listeners(self):
        services = demo.start_services()
        try:
            for svc in services:
                self.assertEqual(svc.host, "127.0.0.1")
            ports = demo.port_list(services)
            for svc in services:
                self.assertIn(svc.port, ports)
            results = scan_host(demo.TARGET, ports, threads=8)
        finally:
            for svc in services:
                svc.stop()

        open_ports = {r["port"] for r in results if r["state"] == "open"}
        for svc in services:
            self.assertIn(svc.port, open_ports)
        banners = [r["banner"] for r in results if r["banner"]]
        self.assertTrue(banners, "the demo scan should capture at least one banner")

    def test_demo_target_is_loopback(self):
        self.assertIn(demo.TARGET, demo.LOOPBACK)


class OsHintTests(unittest.TestCase):

    def test_rdp_means_windows(self):
        self.assertEqual(os_hint([{"port": 3389}]), "Windows (RDP)")

    def test_ssh_suggests_unix(self):
        self.assertEqual(os_hint([{"port": 22}]), "Likely Linux/Unix")

    def test_nothing_recognised_gives_no_hint(self):
        self.assertIsNone(os_hint([{"port": 12345}]))


if __name__ == "__main__":
    unittest.main()
