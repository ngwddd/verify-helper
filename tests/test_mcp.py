"""Real stdio and Streamable HTTP requests through the official MCP client."""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
import httpx2

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"


class TestMcp(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        temporary = Path(self.workspace.name)
        self.root = temporary / "workspace"
        self.root.mkdir()
        self.evidence = temporary / "evidence"
        (self.root / "README.md").write_text("Project documentation.", encoding="utf-8")
        broken = self.root / "broken"
        broken.mkdir()
        (broken / "app.py").write_text("def bad(:\n", encoding="utf-8")

    async def call(self, target, mode):
        async with Client(target, mode=mode, read_timeout_seconds=30) as client:
            listed = (await client.list_tools()).tools
            self.assertEqual([tool.name for tool in listed], ["verify_run_full", "verify_get_report",
                                                               "verify_list_capabilities", "verify_cancel"])
            self.assertEqual(set(listed[0].input_schema["properties"]),
                             {"path", "policy_path", "revision", "source_ref"})
            response = await client.call_tool("verify_run_full", {"path": "broken"})
            self.assertFalse(response.is_error, response.content)
            run_id = response.structured_content["run_id"]
            report = await self.wait_for_report(client, run_id)
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["security_status"], "UNAVAILABLE")
            self.assertEqual(report["scope"], "FULL")
            self.assertFalse(report["releasable"])
            self.assertEqual(report["sarif"]["version"], "2.1.0")
            denied = await client.call_tool("verify_run_full", {"path": ".."})
            self.assertTrue(denied.is_error)
            obsolete = await client.call_tool("verify_run_full", {"fast": True})
            self.assertTrue(obsolete.is_error)
            return report, client.protocol_version

    async def wait_for_report(self, client, run_id):
        async with asyncio.timeout(25):
            while True:
                response = await client.call_tool("verify_get_report", {"run_id": run_id})
                self.assertFalse(response.is_error, response.content)
                report = response.structured_content
                if report["status"] in {"COMPLETED", "CANCELLED", "ERROR"}:
                    return report
                await asyncio.sleep(0.05)

    def stdio(self, *, trusted=False):
        return StdioServerParameters(command=sys.executable,
                                     args=[str(SERVER), "--workspace", str(self.root),
                                           "--evidence-dir", str(self.evidence),
                                           *(["--trust-project-code"] if trusted else [])])

    async def test_legacy_stdio(self):
        _, version = await self.call(self.stdio(), "legacy")
        self.assertEqual(version, "2025-11-25")

    async def test_cancel_and_retrieve_run_after_stdio_restart(self):
        slow = self.root / "slow"
        slow.mkdir()
        test = slow / "test_wait.py"
        test.write_text("import time, unittest\nclass T(unittest.TestCase):\n"
                        "    def test_wait(self): time.sleep(90)\n", encoding="utf-8")
        async with Client(self.stdio(trusted=True)) as client:
            started = await client.call_tool("verify_run_full", {"path": "slow"})
            run_id = started.structured_content["run_id"]
            cancel = await client.call_tool("verify_cancel", {"run_id": run_id})
            self.assertEqual(cancel.structured_content["status"], "CANCELLING")
            result = await self.wait_for_report(client, run_id)
            self.assertEqual(result["status"], "CANCELLED")
            self.assertFalse(result["releasable"])
        async with Client(self.stdio(trusted=True)) as client:
            result = await self.wait_for_report(client, run_id)
            self.assertEqual(result["status"], "CANCELLED")

    async def test_modern_stdio_and_http_share_verdict(self):
        stdio, version = await self.call(self.stdio(), "auto")
        self.assertEqual(version, "2026-07-28")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        token = "a" * 48
        with subprocess.Popen([sys.executable, str(SERVER), "--workspace", str(self.root),
                               "--transport", "streamable-http", "--port", str(port),
                               "--evidence-dir", str(self.evidence)],
                              env=dict(os.environ, VERIFY_HTTP_BEARER_TOKEN=token),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as server:
            try:
                async with asyncio.timeout(15):
                    while True:
                        if server.poll() is not None:
                            self.fail(f"HTTP server exited with {server.returncode}")
                        try:
                            _, writer = await asyncio.open_connection("127.0.0.1", port)
                            writer.close()
                            await writer.wait_closed()
                            break
                        except OSError:
                            await asyncio.sleep(0.1)
                url = f"http://127.0.0.1:{port}/mcp"
                pending = set(self.evidence.rglob("*.pending"))
                async with httpx2.AsyncClient(trust_env=False) as unauthenticated:
                    self.assertEqual((await unauthenticated.post(url)).status_code, 401)
                    self.assertEqual(set(self.evidence.rglob("*.pending")), pending)
                async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"},
                                              trust_env=False) as httpx:
                    bad_origin = await httpx.post(url, headers={"Origin": "https://other.invalid"})
                    self.assertEqual(bad_origin.status_code, 403)
                    http, version = await self.call(streamable_http_client(url, http_client=httpx), "auto")
                    self.assertEqual(version, "2026-07-28")
                    self.assertEqual(stdio["snapshot_sha256"], http["snapshot_sha256"])
                    self.assertEqual(stdio["plan"], http["plan"])
                    legacy, version = await self.call(streamable_http_client(url, http_client=httpx), "legacy")
                    self.assertEqual(version, "2025-11-25")
                    self.assertEqual(stdio["verdict"], legacy["verdict"])
            finally:
                server.terminate()
