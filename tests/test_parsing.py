"""Everything that turns user input into a scan plan. No sockets in here."""

import argparse
import contextlib
import io
import math
import unittest

import net_utils
import scanner
from config import CONNECT_TIMEOUT, MIN_CIDR_PREFIX, TIMEOUT_LIMIT
from net_utils import expand_cidr, parse_ports, validate_target


class ParsePortsTests(unittest.TestCase):

    def test_plain_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_sorted_and_deduplicated(self):
        self.assertEqual(parse_ports("443, 22 ,443,80"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("20-23,80"), [20, 21, 22, 23, 80])

    def test_boundaries_allowed(self):
        self.assertEqual(parse_ports("1,65535"), [1, 65535])

    def test_port_zero_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_port_above_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_non_numeric_rejected(self):
        # the old parser silently dropped these and scanned the rest
        with self.assertRaises(ValueError):
            parse_ports("22,http,80")

    def test_backwards_range_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("100-20")

    def test_empty_spec_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports(" , ")


class ExpandCidrTests(unittest.TestCase):

    def test_single_ip(self):
        self.assertEqual(expand_cidr("127.0.0.1"), ["127.0.0.1"])

    def test_hostname_passes_straight_through(self):
        self.assertEqual(expand_cidr("localhost"), ["localhost"])

    def test_small_block_expands(self):
        self.assertEqual(expand_cidr("192.168.1.0/30"),
                         ["192.168.1.1", "192.168.1.2"])

    def test_block_at_the_limit_is_allowed(self):
        hosts = expand_cidr(f"10.0.0.0/{MIN_CIDR_PREFIX}")
        self.assertEqual(len(hosts), 2 ** (32 - MIN_CIDR_PREFIX) - 2)

    def test_block_wider_than_the_limit_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            expand_cidr("10.0.0.0/8")
        self.assertIn(f"/{MIN_CIDR_PREFIX}", str(ctx.exception))

    def test_refusal_happens_before_any_expansion(self):
        # a /8 would be 16 million hosts; this must return immediately
        with self.assertRaises(ValueError):
            expand_cidr("0.0.0.0/0")


class ValidateTargetTests(unittest.TestCase):

    def test_plain_ip(self):
        self.assertEqual(validate_target("192.168.1.1"), "192.168.1.1")

    def test_cidr(self):
        self.assertEqual(validate_target("10.0.0.0/24"), "10.0.0.0/24")

    def test_hostname(self):
        self.assertEqual(validate_target("db-01.internal.example.com"),
                         "db-01.internal.example.com")

    def test_surrounding_whitespace_is_trimmed(self):
        self.assertEqual(validate_target("  localhost  "), "localhost")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("")

    def test_octet_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("999.1.1.1")

    def test_short_dotted_quad_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("1.2.3")

    def test_impossible_prefix_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("192.168.1.0/33")

    def test_illegal_characters_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("bad host!")

    def test_leading_hyphen_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("-nope.example.com")

    def test_ipv6_loopback_rejected_with_clear_message(self):
        # ipaddress parses ::1 happily, but the scanner is AF_INET-only, so it
        # has to be turned away here rather than failing to resolve later
        with self.assertRaises(ValueError) as ctx:
            validate_target("::1")
        self.assertIn("IPv6 targets are not supported", str(ctx.exception))

    def test_ipv6_global_address_rejected_with_clear_message(self):
        with self.assertRaises(ValueError) as ctx:
            validate_target("2001:db8::1")
        self.assertIn("IPv4 only", str(ctx.exception))

    def test_ipv4_literal_hostname_and_cidr_still_accepted(self):
        # the IPv6 guard must not turn away anything it used to accept
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(validate_target("localhost"), "localhost")


class TimeoutOptionTests(unittest.TestCase):
    """--timeout is validated before a single socket is opened.

    argparse rejects non-numeric input on its own. What it accepts happily is
    nan, inf, and anything <= 0 — and 0 is the one that matters, because it
    does not crash. It makes every port report closed, so the scan returns a
    confident all-clear that is entirely wrong.
    """

    def plan(self, timeout):
        """Run the planner with only --timeout varied. Never opens a socket."""
        args = argparse.Namespace(
            target="127.0.0.1", ports="22", full=False,
            threads=8, timeout=timeout, output=None, demo=False,
        )
        return scanner.plan_scan(args)

    def assert_rejected(self, timeout):
        # fail() writes the explanation to stderr; swallow it so a passing run
        # stays quiet, but assert the message actually names the option.
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.plan(timeout)
        # fail() exits 2 for every user error, same as --threads and --ports
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--timeout", stderr.getvalue())

    def test_zero_rejected(self):
        # The dangerous case: a 0s budget silently reports everything closed.
        self.assert_rejected(0.0)

    def test_negative_rejected(self):
        self.assert_rejected(-1.0)

    def test_nan_rejected(self):
        self.assert_rejected(float("nan"))

    def test_infinity_rejected(self):
        self.assert_rejected(float("inf"))

    def test_negative_infinity_rejected(self):
        self.assert_rejected(float("-inf"))

    def test_above_limit_rejected(self):
        self.assert_rejected(TIMEOUT_LIMIT + 1)

    def test_small_positive_accepted(self):
        target, hosts, ports, services = self.plan(0.001)
        self.assertEqual(hosts, ["127.0.0.1"])
        self.assertEqual(services, [])

    def test_limit_itself_accepted(self):
        self.plan(TIMEOUT_LIMIT)

    def test_platform_default_is_positive_and_finite(self):
        self.assertTrue(math.isfinite(CONNECT_TIMEOUT))
        self.assertGreater(CONNECT_TIMEOUT, 0)

    def test_rejected_before_demo_listeners_start(self):
        """A bad timeout must not leave demo sockets orphaned."""
        args = argparse.Namespace(
            target=None, ports=None, full=False,
            threads=8, timeout=-1.0, output=None, demo=True,
        )
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                scanner.plan_scan(args)
        self.assertEqual(caught.exception.code, 2)


class TimeoutIsAppliedTests(unittest.TestCase):
    """The value reaches the socket layer rather than being parsed and dropped."""

    def test_scan_port_uses_the_supplied_timeout(self):
        recorded = []

        class FakeSocket:
            def settimeout(self, value):
                recorded.append(value)

            def connect(self, address):
                raise ConnectionRefusedError

            def close(self):
                pass

        original = net_utils.socket.socket
        net_utils.socket.socket = lambda *a, **kw: FakeSocket()
        try:
            result = net_utils.scan_port("127.0.0.1", 9, timeout=2.5)
        finally:
            net_utils.socket.socket = original

        self.assertEqual(recorded, [2.5])
        self.assertEqual(result["state"], "closed")

    def test_scan_port_falls_back_to_the_platform_default(self):
        recorded = []

        class FakeSocket:
            def settimeout(self, value):
                recorded.append(value)

            def connect(self, address):
                raise ConnectionRefusedError

            def close(self):
                pass

        original = net_utils.socket.socket
        net_utils.socket.socket = lambda *a, **kw: FakeSocket()
        try:
            net_utils.scan_port("127.0.0.1", 9)
        finally:
            net_utils.socket.socket = original

        self.assertEqual(recorded, [CONNECT_TIMEOUT])


if __name__ == "__main__":
    unittest.main()
