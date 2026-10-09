from __future__ import annotations

import unittest

from ratgpt.cli import controlled_state, newly_online_controlleds, online_controlled_ids


class ControlledStateTests(unittest.TestCase):
    def test_controlled_state(self) -> None:
        self.assertEqual(controlled_state({"online": True, "busy": False}), "ready")
        self.assertEqual(controlled_state({"online": True, "busy": True}), "busy")
        self.assertEqual(controlled_state({"online": False, "busy": False}), "offline")
        self.assertEqual(controlled_state({}), "offline")

    def test_newly_online_only_returns_transitions(self) -> None:
        items = [
            {"env_id": "env_existing", "online": True},
            {"env_id": "env_new", "online": True},
            {"env_id": "env_offline", "online": False},
            {"online": True},
        ]

        self.assertEqual(online_controlled_ids(items), {"env_existing", "env_new"})
        self.assertEqual(
            newly_online_controlleds({"env_existing"}, items),
            [{"env_id": "env_new", "online": True}],
        )


if __name__ == "__main__":
    unittest.main()
