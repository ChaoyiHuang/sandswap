# Copyright 2026 Chaoyi Huang. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import analyze_session as analyzer


def row(kind, second, content, message_id=None):
    return {"type": kind, "timestamp": f"2026-01-01T00:00:{second:02d}.000Z",
            "uuid": f"row-{second}", "message": {"id": message_id, "content": content}}


class TranscriptAnalysisTest(unittest.TestCase):
    def test_message_ids_initial_wait_and_parallel_wall_time(self):
        rows = [row("user", 0, "Complete TASK.md"),
                row("assistant", 1, [{"type": "thinking", "thinking": "inspect"}], "one"),
                row("assistant", 2, [{"type": "tool_use", "id": "a", "name": "mcp__sandswap__file_read"}], "one"),
                row("assistant", 3, [{"type": "tool_use", "id": "b", "name": "mcp__sandswap__file_read"}], "one"),
                row("user", 4, [{"type": "tool_result", "tool_use_id": "a", "content": "{}"}]),
                row("user", 5, [{"type": "tool_result", "tool_use_id": "b", "content": "{}"}]),
                row("assistant", 6, [{"type": "text", "text": "done"}], "two")]
        # A resumed/unmatched tool result must not use stale ownership locals.
        rows.insert(1, row("user", 0, [{"type": "tool_result", "tool_use_id": "unknown", "content": "{}"}]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows))
            output = io.StringIO()
            with patch("sys.argv", ["analyze_session.py", str(path)]), \
                    patch.object(analyzer, "measure_exec_floor", return_value=0), \
                    contextlib.redirect_stdout(output):
                analyzer.main()
        text = output.getvalue()
        self.assertIn("turn: 6.00 s, 2 LLM calls, 2 tool calls", text)
        self.assertRegex(text, r"LLM \(all calls\)\s+4.00 s")
        self.assertRegex(text, r"parallel calls counted once\)\s+2.00 s")
        self.assertRegex(text, r"sum of individual durations\)\s+3.00 s")

    def test_exec_floor_uses_tunnel_and_trusted_ca(self):
        connection = MagicMock()
        connection.getresponse.return_value.read.return_value = b'{"exec_duration_ns": 2000000}'
        env = {"CLAUDE_CODE_AGENT_ID": "agent-test", "CLAUDE_CODE_SANDFS_ID": "sandfs-test",
               "CLAUDE_CODE_SANDBOX_API_KEY": "test-only", "NODE_EXTRA_CA_CERTS": "/trusted/ca.crt",
               "CLAUDE_CODE_SANDBOX_MCP_URL": "https://localhost:34443/mcp"}
        with patch.dict(os.environ, env), patch("ssl.create_default_context") as context, \
                patch("http.client.HTTPSConnection", return_value=connection) as factory:
            self.assertEqual(analyzer.measure_exec_floor(), 2.0)
        context.assert_called_once_with(cafile="/trusted/ca.crt")
        factory.assert_called_once_with("localhost", 34443, context=context.return_value, timeout=10)
        self.assertEqual(connection.request.call_count, 30)
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/agent/execute"))
        connection.close.assert_called_once()
        self.assertNotIn("verify_mode", context.return_value.__dict__)
        self.assertNotIn("check_hostname", context.return_value.__dict__)


if __name__ == "__main__":
    unittest.main()
