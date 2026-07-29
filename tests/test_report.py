"""The JSON report has to stay machine-readable for whatever comes next."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from output import save_json


SAMPLE = [
    {"host": "127.0.0.1", "port": 22, "state": "open",
     "service": "SSH", "banner": "SSH-2.0-NetRecon_Demo"},
    {"host": "127.0.0.1", "port": 8080, "state": "filtered",
     "service": "HTTP-Alt", "banner": None},
]


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
             "open_count", "filtered_count", "results"},
        )

    def test_counts_match_the_results(self):
        data = self.write_and_read()
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


if __name__ == "__main__":
    unittest.main()
