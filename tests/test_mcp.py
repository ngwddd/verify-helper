# -*- coding: utf-8 -*-
"""MCP 协议测试：真的把子进程启起来，走 initialize → tools/list → tools/call。

不 mock 传输层 —— 测的就是协议本身。
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests import fixture  # noqa: E402

SERVER = ROOT / "server.py"


class McpProcess:
    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self._id = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("服务器无响应")
        return json.loads(line)

    def notify(self, method: str):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


class TestMcp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broken = fixture.make_broken()
        cls.clean = fixture.make_clean()
        cls.p = McpProcess()
        init = cls.p.call("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "unittest", "version": "1"}})
        assert "result" in init, init
        cls.p.notify("notifications/initialized")

    @classmethod
    def tearDownClass(cls):
        cls.p.close()
        fixture.cleanup(cls.broken, cls.clean)

    def call_tool(self, name: str, args: dict) -> dict:
        r = self.p.call("tools/call", {"name": name, "arguments": args})
        self.assertIn("result", r, r)
        return r["result"]

    def test_initialize_identifies_itself(self):
        r = self.p.call("tools/list")
        self.assertEqual(r["result"]["tools"][0]["name"], "verify_start")

    def test_reload_baseline_is_recorded_at_import(self):
        """热加载的基线必须在导入时就记下，不能初始化成 0。

        踩过的坑：初始化 0 时，进程启动后第一次调用只会「记基线」不 reload，
        于是改了内核却一直跑旧代码（run-14 报 v1.6.2、实际已是 v1.7.0）。
        """
        sys.path.insert(0, str(ROOT))
        import server as srv
        self.assertNotEqual(srv._CORE_MTIME, 0)
        self.assertEqual(srv._stamp(), srv._CORE_MTIME)

    def test_tools_list_shape(self):
        tools = self.p.call("tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in tools],
                         ["verify_start", "verify_report", "verify_checks"])
        schema = tools[0]["inputSchema"]
        self.assertEqual(schema["required"], ["path"])
        self.assertIn("sarif", schema["properties"]["format"]["enum"])

    def test_checks_carry_risk(self):
        payload = json.loads(self.call_tool("verify_checks", {})["content"][0]["text"])
        self.assertGreaterEqual(payload["count"], 14)
        ids = {c["id"]: c for c in payload["checks"]}
        self.assertEqual(ids["secrets"]["risk"], "critical")
        self.assertTrue(ids["secrets"]["blocking"])
        self.assertFalse(ids["todos"]["blocking"])
        self.assertTrue(ids["secrets"]["remediation"])

    def test_verify_start_detects_bugs(self):
        res = self.call_tool("verify_start", {"path": str(self.broken)})
        self.assertTrue(res["isError"])
        text = res["content"][0]["text"]
        self.assertIn("FAIL", text.splitlines()[0])
        for needle in ("死链", "重复 id", "密钥", "invalid syntax", "不是合法 UTF-8"):
            self.assertIn(needle, text)

    def test_verify_start_json(self):
        res = self.call_tool("verify_start",
                             {"path": str(self.broken), "format": "json"})
        rep = json.loads(res["content"][0]["text"])
        self.assertEqual(rep["verdict"], "FAIL")
        self.assertEqual(rep["version"], __import__("verify_core").VERSION)

    def test_verify_start_sarif(self):
        res = self.call_tool("verify_start",
                             {"path": str(self.broken), "format": "sarif"})
        doc = json.loads(res["content"][0]["text"])
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_fast_skips_tests_but_keeps_runtime(self):
        """fast 只跳过「慢且不一定有入口」的测试/变异，运行时与浏览器照跑。"""
        res = self.call_tool("verify_start",
                             {"path": str(self.clean), "fast": True, "format": "json"})
        rep = json.loads(res["content"][0]["text"])
        by = {c["id"]: c for c in rep["checks"]}
        self.assertFalse(by["tests"]["applicable"])
        self.assertIn("fast", by["tests"]["detail"])
        # runtime-web 在干净项目上应该真跑过（而不是被 fast 跳过）
        self.assertNotIn("fast", by["runtime-web"]["detail"])

    def test_report_roundtrip(self):
        self.call_tool("verify_start", {"path": str(self.clean)})
        res = self.call_tool("verify_report", {})
        rep = json.loads(res["content"][0]["text"])
        self.assertEqual(rep["verdict"], "PASS")

    def test_error_paths(self):
        res = self.call_tool("verify_start", {})
        self.assertTrue(res["isError"])
        res = self.call_tool("verify_start", {"path": "Z:/definitely/not/here"})
        self.assertTrue(res["isError"])
        r = self.p.call("tools/call", {"name": "nope", "arguments": {}})
        self.assertEqual(r["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
