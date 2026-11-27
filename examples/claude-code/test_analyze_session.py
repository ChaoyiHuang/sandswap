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
    def test_isolated_config_with_special_project_path(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = str(Path(directory) / "work_tree+demo")
            projects = Path(directory) / "config" / "projects"
            project = projects / analyzer.project_key(cwd)
            project.mkdir(parents=True)
            session = project / "task.jsonl"
            session.write_text(json.dumps({**row("user", 0, "Complete TASK.md"), "cwd": cwd}))
            with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(projects.parent)}):
                self.assertEqual(analyzer.newest_task_session(cwd), str(session))

    def test_hashed_project_path_falls_back_to_recorded_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = str(Path(directory) / ("long-project_" * 20))
            projects = Path(directory) / "projects"
            project = projects / "truncated-project-hash"
            project.mkdir(parents=True)
            session = project / "task.jsonl"
            session.write_text(json.dumps({**row("user", 0, "Complete TASK.md"), "cwd": cwd}))
            unrelated = project / "unrelated.jsonl"
            unrelated.write_text(json.dumps({**row("user", 1, "Complete TASK.md"), "cwd": "/another/project"}))
            with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": directory}):
                self.assertEqual(analyzer.newest_task_session(cwd), str(session))

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
        self.assertRegex(text, r"sum of individual durations\)\s+4.00 s")
        self.assertRegex(text, r"union; may overlap model emission\)\s+3.00 s")

    def test_tool_result_before_final_streamed_block(self):
        rows = [row("user", 0, "Complete TASK.md"),
                row("assistant", 1, [{"type": "tool_use", "id": "a", "name": "mcp__sandswap__file_read"}], "one"),
                row("user", 2, [{"type": "tool_result", "tool_use_id": "a", "content": "{}"}]),
                row("assistant", 3, [{"type": "text", "text": "inspected"}], "one"),
                row("assistant", 4, [{"type": "text", "text": "done"}], "two")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows))
            output = io.StringIO()
            with patch("sys.argv", ["analyze_session.py", str(path)]), \
                    patch.object(analyzer, "measure_exec_floor", return_value=0), \
                    contextlib.redirect_stdout(output):
                analyzer.main()
        text = output.getvalue()
        self.assertIn("turn: 4.00 s, 2 LLM calls, 1 tool calls", text)
        self.assertRegex(text, r"LLM \(all calls\)\s+4.00 s")
        self.assertRegex(text, r"parallel calls counted once\)\s+0.00 s")
        self.assertRegex(text, r"sum of individual durations\)\s+1.00 s")
        self.assertRegex(text, r"union; may overlap model emission\)\s+1.00 s")

    def test_union_handles_nested_disjoint_and_empty_intervals(self):
        at = lambda second: analyzer.ts(row("user", second, ""))
        self.assertEqual(analyzer.interval_union_seconds([]), 0)
        self.assertEqual(analyzer.interval_union_seconds([
            (at(5), at(8)), (at(0), at(3)), (at(1), at(2)), (at(4), at(4)), (at(6), at(9))]), 7)

    def test_exec_floor_uses_tunnel_and_trusted_ca(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 200
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

    def test_missing_measurement_reports_refusal_and_closes_connection(self):
        connection = MagicMock()
        connection.getresponse.return_value.status = 401
        connection.getresponse.return_value.read.return_value = b'{"error":"unauthorized"}'
        env = {"CLAUDE_CODE_AGENT_ID": "agent-test", "CLAUDE_CODE_SANDFS_ID": "sandfs-test",
               "CLAUDE_CODE_SANDBOX_API_KEY": "test-only", "CLAUDE_CODE_SANDBOX_MCP_URL": "http://localhost:33001/mcp"}
        with patch.dict(os.environ, env), patch("http.client.HTTPConnection", return_value=connection):
            self.assertEqual(analyzer.measure_exec_floor(), 0)
        self.assertIn("HTTP 401", analyzer.EXEC_FLOOR_WHY)
        self.assertIn("no longer valid", analyzer.EXEC_FLOOR_WHY)
        connection.close.assert_called_once()

    def test_tls_failure_reports_actual_endpoint_without_insecure_fallback(self):
        connection = MagicMock()
        connection.connect.side_effect = OSError("certificate verify failed")
        env = {"CLAUDE_CODE_AGENT_ID": "agent-test", "CLAUDE_CODE_SANDFS_ID": "sandfs-test",
               "CLAUDE_CODE_SANDBOX_API_KEY": "test-only", "CLAUDE_CODE_SANDBOX_MCP_URL": "https://localhost:34443/mcp"}
        with patch.dict(os.environ, env), patch("ssl.create_default_context"), \
                patch("http.client.HTTPSConnection", return_value=connection):
            self.assertEqual(analyzer.measure_exec_floor(), 0)
        self.assertIn("localhost:34443", analyzer.EXEC_FLOOR_WHY)
        self.assertIn("certificate verify failed", analyzer.EXEC_FLOOR_WHY)
        connection.request.assert_not_called()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
