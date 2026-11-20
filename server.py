"""Official MCP SDK transports for the full verification engine."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from starlette.responses import Response

from full_verify import _evidence_root, full_verify
from isolated_runtime import IMAGE_VARIABLE, provider_available
from private_storage import private_directory, require_private
from report_export import mcp_report
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
        self.root = _evidence_root(root)
        private_directory(self.root, exist_ok=True)
        self.key = self._load_key()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.lock = threading.Lock()
        self.jobs = {}

    def _load_key(self):
        key_path = self.root / ".manifest-key"
        flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | flags, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
        require_private(key_path)
        with os.fdopen(os.open(key_path, os.O_RDONLY | flags), "rb") as stream:
            entry = os.fstat(stream.fileno())
            if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
                    or getattr(entry, "st_file_attributes", 0) & 1024
                    or (os.name != "nt" and (entry.st_uid != os.geteuid() or entry.st_mode & 0o077))):
                raise ValueError("Evidence key permissions are invalid")
            key = stream.read(33)
        if len(key) != 32:
            raise ValueError("Evidence key is unavailable")
        return key

    def _failed(self, run_id: str, detail: str) -> dict:
        return {"run_id": run_id, "status": "ERROR", "scope": "FULL",
                "verdict": "UNKNOWN", "security_status": "UNAVAILABLE", "releasable": False,
                "blockers": [detail]}

    def submit(self, project, **options):
        with self.lock:
            active = sum(not future.done() for future, _ in self.jobs.values())
            if active >= 4:
                raise ToolError("The verification queue is full")
            self.jobs = {key: job for key, job in self.jobs.items() if not job[0].done()}
            run_id = "vh2_" + uuid.uuid4().hex
            cancellation = threading.Event()
            (self.root / f"{run_id}.pending").touch(exist_ok=False)
            future = self.pool.submit(full_verify, project, evidence_dir=self.root, sealed=True, evidence_key=self.key,
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
                evidence = read_evidence(directory, key=self.key)
                if evidence["run_id"] != run_id:
                    raise ValueError("Evidence is bound to another run")
                return mcp_report(evidence, run_id, VERSION)
            except (OSError, ValueError, TypeError, KeyError):
                return self._failed(run_id, "Evidence is missing or no longer matches its manifest")
        if job:
            try:
                report = job[0].result()
                if report.get("verdict") != "PASS":
                    return mcp_report(report, run_id, VERSION)
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


def create_server(workspace: Path, *, evidence_dir: Path | None = None,
                  owner: str = "local-stdio") -> MCPServer:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Workspace must be a directory")
    namespace = hashlib.sha256(json_bytes({"workspace": str(workspace), "owner": owner,
                                          "storage": "private-v1"})).hexdigest()[:32]
    store_root = _evidence_root(evidence_dir or Path.home() / ".verify-helper" / "runs")
    if store_root.is_relative_to(workspace):
        raise ValueError("MCP evidence storage must be outside the verified workspace")
    runs = RunStore(store_root / namespace)
    server = StrictServer("verify-helper", version=VERSION)
    server.runs = runs

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                            idempotentHint=False, openWorldHint=True))
    def verify_run_full(path: str = ".", policy_path: str | None = None, revision: str | None = None,
                        source_ref: str | None = None) -> dict[str, Any]:
        """Queue full verification of the current project. 验证助手：完整验证指定项目，随后轮询报告。"""
        root = (workspace / path).resolve()
        if not root.is_relative_to(workspace) or not root.is_dir():
            raise ToolError("Project must be a directory in the configured workspace")
        policy = (workspace / policy_path).resolve() if policy_path is not None else None
        if policy is not None and (not policy.is_relative_to(workspace) or not policy.is_file()):
            raise ToolError("Policy must be a JSON file in the configured workspace")
        if revision is not None and not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", revision):
            raise ToolError("Revision must be a full Git SHA")
        if path == "." and not _has_project_anchor(root):
            candidates = sum(1 for child in root.iterdir() if not child.is_symlink() and child.is_dir()
                             and _has_project_anchor(child))
            if candidates > 1:
                raise ToolError("Multiple projects found. Specify the relative project path.")
        return runs.submit(root, against=source_ref, revision=revision, policy_path=policy)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def verify_get_report(run_id: str) -> dict[str, Any]:
        """Return progress or the final report after validating its archived evidence."""
        return runs.report(run_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def verify_list_capabilities() -> dict[str, Any]:
        """List supported adapters and detected executables without running project code."""
        image = os.environ.get(IMAGE_VARIABLE)
        available = provider_available(image)
        return {"scope": "FULL", "trusted_project_execution": False,
                "isolation_configured": IMAGE_VARIABLE in os.environ,
                "isolation_available": available,
                "isolation_attested": False,
                "isolated_adapters": ["python-unittest"] if available else [],
                "tools": {"python": True, **{name: shutil.which(name) is not None for name in
                          ("node", "npm", "cmake", "ctest", "git", "tsc")}}}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    def verify_cancel(run_id: str) -> dict[str, Any]:
        """Request cancellation and report whether the tracked worker has stopped."""
        return runs.report(run_id, cancel=True)

    return server


def _has_project_anchor(path: Path) -> bool:
    return any((path / name).exists() for name in (".git", "pyproject.toml", "package.json",
                                                   "CMakeLists.txt", "verify.toml", "index.html"))


def http_app(server: MCPServer, token: str):
    application = server.streamable_http_app(json_response=True, max_request_body_size=64 * 1024)
    expected = f"Bearer {token}".encode("ascii")

    async def authenticated(scope, receive, send):
        if scope["type"] == "http":
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
    args = parser.parse_args(argv)
    token = os.environ.get("VERIFY_HTTP_BEARER_TOKEN") or None
    owner = "local-stdio"
    if args.transport == "streamable-http":
        if token and (len(token) < 32 or not token.isascii() or not token.isalnum()):
            parser.error("VERIFY_HTTP_BEARER_TOKEN requires at least 32 ASCII letters or digits")
        if not token:
            parser.error("Set VERIFY_HTTP_BEARER_TOKEN to enable authenticated HTTP verification")
        owner = "http:" + hashlib.sha256(token.encode()).hexdigest()
    server = create_server(args.workspace, evidence_dir=args.evidence_dir,
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
