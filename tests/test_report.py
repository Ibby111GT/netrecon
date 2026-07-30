"""The JSON report has to stay machine-readable for whatever comes next."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from output import print_result, print_summary, save_json


SAMPLE = [
    {"host": "127.0.0.1", "port": 22, "state": "open",
     "service": "SSH", "banner": "SSH-2.0-NetRecon_Demo"},
    {"host": "127.0.0.1", "port": 8080, "state": "filtered",
     "service": "HTTP-Alt", "banner": None},
]

ERRORED = {"host": "127.0.0.1", "port": 3306, "state": "error",
           "service": "MySQL", "banner": None,
           "error": "EMFILE: Too many open files"}


class SaveJsonTests(unittest.TestCase):

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

    def tearDown(self):
        os.unlink(self.path)

    def write_and_read(self, results=SAMPLE, target="127.0.0.1", elapsed=1.25):
        with contextlib.redirect_stdout(io.StringIO()):
            save_json(results, self.path, target, elapsed)
        with open(self.path) as fh:
            return json.load(fh)

    def test_file_is_valid_json(self):
        self.assertIsInstance(self.write_and_read(), dict)

    def test_top_level_shape(self):
        self.assertEqual(
            set(self.write_and_read()),
            {"target", "scan_time", "elapsed_sec",
             "open_count", "filtered_count", "error_count", "results"},
        )

    def test_counts_match_the_results(self):
        data = self.write_and_read()
        self.assertEqual(data["open_count"], 1)
        self.assertEqual(data["filtered_count"], 1)
        self.assertEqual(data["error_count"], 0)

    def test_error_state_is_counted(self):
        data = self.write_and_read(results=SAMPLE + [ERRORED])
        self.assertEqual(data["error_count"], 1)
        self.assertEqual(data["open_count"], 1)
        self.assertEqual(data["filtered_count"], 1)

    def test_results_survive_the_round_trip(self):
        self.assertEqual(self.write_and_read()["results"], SAMPLE)

    def test_target_and_elapsed_are_recorded(self):
        data = self.write_and_read(target="192.168.1.0/30", elapsed=1.25)
        self.assertEqual(data["target"], "192.168.1.0/30")
        self.assertEqual(data["elapsed_sec"], 1.25)

    def test_empty_scan_still_writes_a_valid_report(self):
        data = self.write_and_read(results=[])
        self.assertEqual(data["results"], [])
        self.assertEqual(data["open_count"], 0)
        self.assertEqual(data["error_count"], 0)


class TerminalOutputTests(unittest.TestCase):
    """Errored probes have to be visible on the terminal, not just in JSON."""

    def render(self, func, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            func(*args)
        return buf.getvalue()

    def test_summary_reports_errored_ports(self):
        out = self.render(print_summary, "127.0.0.1", SAMPLE + [ERRORED], 1.0)
        self.assertIn("Errored", out)
        self.assertIn("3306", out)

    def test_clean_summary_omits_the_error_line(self):
        out = self.render(print_summary, "127.0.0.1", SAMPLE, 1.0)
        self.assertNotIn("Errored", out)

    def test_error_row_shows_state_and_detail(self):
        out = self.render(print_result, ERRORED)
        self.assertIn("ERROR", out)
        self.assertIn("3306", out)
        self.assertIn("Too many open files", out)


if __name__ == "__main__":
    unittest.main()
