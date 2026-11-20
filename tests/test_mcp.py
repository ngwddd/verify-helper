"""Real stdio and Streamable HTTP requests through the official MCP client."""
from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"


class TestMcp(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        (self.root / "README.md").write_text("Project documentation.", encoding="utf-8")
        broken = self.root / "broken"
        broken.mkdir()
        (broken / "app.py").write_text("def bad(:\n", encoding="utf-8")

    async def call(self, target, mode):
        async with Client(target, mode=mode, read_timeout_seconds=30) as client:
            listed = (await client.list_tools()).tools
            self.assertEqual([tool.name for tool in listed], ["verify_start"])
            self.assertEqual(set(listed[0].input_schema["properties"]), {"path", "against"})
            response = await client.call_tool("verify_start", {"path": "broken"})
            self.assertFalse(response.is_error, response.content)
            report = response.structured_content
            self.assertEqual(report["verdict"], "FAIL")
            self.assertEqual(report["mode"], "full")
            self.assertEqual(report["sarif"]["version"], "2.1.0")
            denied = await client.call_tool("verify_start", {"path": ".."})
            self.assertTrue(denied.is_error)
            return report, client.protocol_version

    def stdio(self):
        return StdioServerParameters(command=sys.executable,
                                     args=[str(SERVER), "--workspace", str(self.root)])

    async def test_legacy_stdio(self):
        _, version = await self.call(self.stdio(), "legacy")
        self.assertEqual(version, "2025-11-25")

    async def test_modern_stdio_and_http_share_verdict(self):
        stdio, version = await self.call(self.stdio(), "auto")
        self.assertEqual(version, "2026-07-28")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        with subprocess.Popen([sys.executable, str(SERVER), "--workspace", str(self.root),
                               "--transport", "streamable-http", "--port", str(port)],
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
                http, version = await self.call(f"http://127.0.0.1:{port}/mcp", "auto")
                self.assertEqual(version, "2026-07-28")
                self.assertEqual(stdio["snapshot_sha256"], http["snapshot_sha256"])
                self.assertEqual(stdio["plan"], http["plan"])
                legacy, version = await self.call(f"http://127.0.0.1:{port}/mcp", "legacy")
                self.assertEqual(version, "2025-11-25")
                self.assertEqual(stdio["verdict"], legacy["verdict"])
            finally:
                server.terminate()
