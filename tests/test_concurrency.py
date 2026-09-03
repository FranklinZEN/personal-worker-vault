"""Local-writer lock and append-prefix concurrency tests."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from tests.helpers import Harness


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_candidates_serialize_into_one_valid_chain(self) -> None:
        harness = Harness()
        try:
            harness.start()
            candidates = [
                harness.candidate(
                    "question.recorded",
                    {"question": f"Invented concurrent question {index}"},
                    session_id=harness.session_id,
                )
                for index in range(20)
            ]
            with ThreadPoolExecutor(max_workers=8) as executor:
                committed = list(executor.map(harness.semantic.append, candidates))
            self.assertEqual(len({event["event_id"] for event in committed}), 20)
            self.assertEqual(harness.semantic.validate_all(), ())
            self.assertEqual(len(harness.semantic.read_all()), 22)
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()

