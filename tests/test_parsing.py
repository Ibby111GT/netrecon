"""Everything that turns user input into a scan plan. No sockets in here."""

import unittest

from config import MIN_CIDR_PREFIX
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


if __name__ == "__main__":
    unittest.main()
