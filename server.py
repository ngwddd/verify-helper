"""Official MCP SDK transports for the full verification engine."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from starlette.responses import Response

from full_verify import full_verify
from run_evidence import json_bytes, read_evidence
from verify_core import VERSION


TOOL_ARGUMENTS = {
    "verify_run_full": {"path", "policy_path", "revision", "source_ref"},
    "verify_get_report": {"run_id"},
    "verify_list_capabilities": set(),
    "verify_cancel": {"run_id"},
}


class StrictServer(MCPServer):
    async def call_tool(self, name, arguments, context=None):
        if name == "verify_start" or "fast" in arguments or "checks" in arguments:
            raise ToolError("Use verify_run_full for complete verification.")
        if name in TOOL_ARGUMENTS and set(arguments) - TOOL_ARGUMENTS[name]:
            raise ToolError("Unexpected arguments for this verification tool.")
        return await super().call_tool(name, arguments, context)


class RunStore:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.lock = threading.Lock()
        self.jobs = {}

    def _failed(self, run_id: str, detail: str) -> dict:
        return {"run_id": run_id, "status": "ERROR", "scope": "FULL",
                "verdict": "UNKNOWN", "releasable": False, "blockers": [detail]}

    def submit(self, project, **options):
        with self.lock:
            active = sum(not future.done() for future, _ in self.jobs.values())
            if active >= 4:
                raise ToolError("The verification queue is full")
            self.jobs = {key: job for key, job in self.jobs.items() if not job[0].done()}
            run_id = "vh2_" + uuid.uuid4().hex
            cancellation = threading.Event()
            (self.root / f"{run_id}.pending").touch(exist_ok=False)
            future = self.pool.submit(full_verify, project, evidence_dir=self.root,
                                      run_id=run_id, cancellation=cancellation, **options)
            self.jobs[run_id] = (future, cancellation)
        return {"run_id": run_id, "status": "QUEUED", "scope": "FULL", "releasable": False}

    def report(self, run_id, *, cancel=False):
        if not re.fullmatch(r"vh2_[a-f0-9]{32}", run_id):
            raise ToolError("Unknown run ID")
        directory = self.root / run_id
        if directory.is_symlink() or not directory.resolve().is_relative_to(self.root):
            raise ToolError("Unknown run ID")
        with self.lock:
            job = self.jobs.get(run_id)
            if job and not job[0].done():
                if cancel:
                    job[1].set()
                if job[1].is_set():
                    status = "CANCELLING"
                else:
                    status = "RUNNING" if job[0].running() else "QUEUED"
                return {"run_id": run_id, "status": status, "scope": "FULL", "releasable": False}
        if directory.is_dir():
            try:
                evidence = read_evidence(directory)
                if evidence["run_id"] != run_id:
                    raise ValueError("Evidence is bound to another run")
                return evidence
            except (OSError, ValueError, TypeError, KeyError):
                return self._failed(run_id, "Evidence is missing or no longer matches its manifest")
        if job:
            try:
                report = job[0].result()
                if report.get("verdict") != "PASS":
                    return report
            except Exception:
                pass
        if (self.root / f"{run_id}.pending").is_file():
            return self._failed(run_id, "The run ended without a verifiable report")
        raise ToolError("Unknown run ID")

    def close(self):
        with self.lock:
            for _, cancellation in self.jobs.values():
                cancellation.set()
        self.pool.shutdown(cancel_futures=True)


def create_server(workspace: Path, *, trusted: bool = False, evidence_dir: Path | None = None,
                  owner: str = "local-stdio") -> MCPServer:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory")
    namespace = hashlib.sha256(json_bytes({"workspace": str(workspace), "owner": owner})).hexdigest()[:32]
    store_root = (evidence_dir or Path.home() / ".verify-helper" / "runs").resolve()
    runs = RunStore(store_root / namespace)
    server = StrictServer("verify-helper", version=VERSION)
    server.runs = runs

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True))
    def verify_run_full(path: str = ".", policy_path: str | None = None, revision: str | None = None,
                        source_ref: str | None = None) -> dict[str, Any]:
        """Queue complete verification. Use source_ref as the merge base for the clean checkout."""
        root = (workspace / path).resolve()
        if not root.is_relative_to(workspace) or not root.is_dir():
            raise ToolError("Project must be a directory in the configured workspace")
        policy = (workspace / policy_path).resolve() if policy_path is not None else None
        if policy is not None and (not policy.is_relative_to(workspace) or not policy.is_file()):
            raise ToolError("Policy must be a JSON file in the configured workspace")
        if revision is not None and not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", revision):
            raise ToolError("Revision must be a full Git SHA")
        return runs.submit(root, trusted=trusted, against=source_ref, revision=revision, policy_path=policy)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def verify_get_report(run_id: str) -> dict[str, Any]:
        """Return progress or the final report after validating its archived evidence."""
        return runs.report(run_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def verify_list_capabilities() -> dict[str, Any]:
        """List supported adapters and detected executables without running project code."""
        return {"scope": "FULL", "trusted_project_execution": trusted,
                "adapters": ["python", "javascript", "typescript", "native", "web", "archives"],
                "tools": {"python": sys.executable, **{name: shutil.which(name) for name in
                          ("node", "npm", "cmake", "ctest", "git", "tsc")}}}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    def verify_cancel(run_id: str) -> dict[str, Any]:
        """Request cancellation and report whether the tracked worker has stopped."""
        return runs.report(run_id, cancel=True)

    return server


def http_app(server: MCPServer, token: str | None):
    application = server.streamable_http_app(json_response=True, max_request_body_size=64 * 1024)
    expected = f"Bearer {token}".encode("ascii") if token else None

    async def authenticated(scope, receive, send):
        if scope["type"] == "http":
            if expected is not None:
                supplied = [value for key, value in scope["headers"] if key.lower() == b"authorization"]
                if len(supplied) != 1 or not hmac.compare_digest(supplied[0], expected):
                    await Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
                    return
            origins = [value for key, value in scope["headers"] if key.lower() == b"origin"]
            if origins and (len(origins) != 1 or not re.fullmatch(
                    rb"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]{1,5})?", origins[0])):
                await Response(status_code=403)(scope, receive, send)
                return
        await application(scope, receive, send)

    return authenticated


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="verify-helper serve")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    parser.add_argument("--host", choices=("127.0.0.1",), default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--trust-project-code", action="store_true")
    args = parser.parse_args(argv)
    token = os.environ.get("VERIFY_HTTP_BEARER_TOKEN") or None
    owner = "local-stdio"
    if args.transport == "streamable-http":
        if token and (len(token) < 32 or not token.isascii() or not token.isalnum()):
            parser.error("VERIFY_HTTP_BEARER_TOKEN requires at least 32 ASCII letters or digits")
        if args.trust_project_code and not token:
            parser.error("Set VERIFY_HTTP_BEARER_TOKEN to enable authenticated HTTP project execution")
        owner = "http:" + (hashlib.sha256(token.encode()).hexdigest() if token else "anonymous-loopback")
    server = create_server(args.workspace, trusted=args.trust_project_code, evidence_dir=args.evidence_dir,
                           owner=owner)
    try:
        if args.transport == "stdio":
            server.run("stdio")
        else:
            import uvicorn

            uvicorn.run(http_app(server, token), host=args.host, port=args.port, proxy_headers=False)
    finally:
        server.runs.close()


if __name__ == "__main__":
    main()
