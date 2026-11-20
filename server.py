"""Official MCP SDK transports for the full verification engine."""
from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from starlette.responses import Response

from full_verify import full_verify
from verify_core import VERSION


def create_server(workspace: Path, *, trusted: bool = False, evidence_dir: Path | None = None) -> MCPServer:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory")
    server = MCPServer("verify-helper", version=VERSION)
    limit = anyio.CapacityLimiter(2)

    @server.tool(name="verify_start", structured_output=True,
                 annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                             idempotentHint=False, openWorldHint=True))
    async def verify_start(path: str = ".", against: str | None = None) -> dict[str, Any]:
        """Run full verification within the configured workspace and return the verdict and evidence."""
        root = (workspace / path).resolve()
        if not root.is_relative_to(workspace) or not root.is_dir():
            raise ValueError("Project must be a directory in the configured workspace")
        return await anyio.to_thread.run_sync(
            lambda: full_verify(root, trusted=trusted, evidence_dir=evidence_dir, against=against),
            limiter=limit)

    return server


def http_app(server: MCPServer, token: str | None):
    application = server.streamable_http_app(json_response=True)
    if token is None:
        return application
    expected = f"Bearer {token}".encode("ascii")

    async def authenticated(scope, receive, send):
        if scope["type"] == "http":
            supplied = [value for key, value in scope["headers"] if key.lower() == b"authorization"]
            if len(supplied) != 1 or not hmac.compare_digest(supplied[0], expected):
                await Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
                return
        await application(scope, receive, send)

    return authenticated


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="verify-helper-mcp")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--trust-project-code", action="store_true")
    args = parser.parse_args(argv)
    token = os.environ.get("VERIFY_HTTP_BEARER_TOKEN") or None
    if args.transport == "streamable-http":
        if token and (len(token) < 32 or not token.isascii() or not token.isalnum()):
            parser.error("VERIFY_HTTP_BEARER_TOKEN requires at least 32 ASCII letters or digits")
        if args.trust_project_code and not token:
            parser.error("Set VERIFY_HTTP_BEARER_TOKEN to enable authenticated HTTP project execution")
    server = create_server(args.workspace, trusted=args.trust_project_code, evidence_dir=args.evidence_dir)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        import uvicorn

        uvicorn.run(http_app(server, token), host="127.0.0.1", port=args.port, proxy_headers=False)


if __name__ == "__main__":
    main()
