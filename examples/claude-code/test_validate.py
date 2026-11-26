# Copyright 2026 Chaoyi Huang. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The real-agent validator must not accept prose or partial evidence as PASS."""
import unittest

from validate import assess_events, REQUIRED


def success_events():
    events = [{"type": "system", "subtype": "init", "mcp_servers": [
        {"name": "sandswap", "status": "connected"}]}]
    for index, name in enumerate(sorted(REQUIRED)):
        events += [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": str(index), "name": name}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": str(index), "content": "ok"}]}}]
    return events + [{"type": "result", "subtype": "success", "is_error": False,
                      "permission_denials": []}]


class EventValidationTest(unittest.TestCase):
    def test_complete_mcp_loop(self):
        self.assertTrue(assess_events(success_events())["passed"])

    def test_prose_without_tools_is_not_evidence(self):
        self.assertFalse(assess_events([{"type": "result", "subtype": "success",
                                        "result": "All tests pass; committed fix calc."}])["passed"])

    def test_local_tool_is_rejected(self):
        events = success_events()
        events.insert(-1, {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "local", "name": "Bash"}]}})
        self.assertIn("a tool outside sandswap was called", assess_events(events)["errors"])

    def test_missing_result_is_rejected(self):
        events = success_events()
        del events[2]
        self.assertIn("a tool call has no recorded result", assess_events(events)["errors"])

    def test_tool_failure_is_rejected(self):
        events = success_events()
        events[2]["message"]["content"][0]["is_error"] = True
        self.assertIn("a tool returned an error", assess_events(events)["errors"])

    def test_permission_denial_is_rejected(self):
        events = success_events()
        events[-1]["permission_denials"] = [{"tool_name": "mcp__sandswap__execute"}]
        self.assertIn("Claude Code reported permission denials", assess_events(events)["errors"])

    def test_missing_final_or_connection_is_rejected(self):
        self.assertFalse(assess_events(success_events()[:-1])["passed"])
        self.assertFalse(assess_events(success_events()[1:])["passed"])


if __name__ == "__main__":
    unittest.main()
