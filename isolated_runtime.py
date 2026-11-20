"""Offline Linux execution using an operator-provisioned local Docker image."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path


IMAGE_VARIABLE = "VERIFY_HELPER_SANDBOX_IMAGE"
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
PATH = "/usr/local/bin:/usr/bin:/bin"
SOCKET = "/var/run/docker.sock"
UID = "65532"
MEMORY = 384 * 1024 ** 2
WORKSPACE = "/workspace:rw,nosuid,nodev,size=192m,mode=0700,uid=65532,gid=65532"
TEMP = "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid=65532,gid=65532"
ENTRY = (
    'cd /workspace && /bin/tar --no-same-owner --no-same-permissions -xf - '
    '&& cd -- "$1" && shift && exec "$@"'
)


class BoundaryUnavailable(ValueError):
    """The host could not establish or verify the execution boundary."""


def _stage(root: Path, archive) -> None:
    total = 0
    with tarfile.open(fileobj=archive, mode="w") as package:
        for path in sorted(root.rglob("*")):
            entry = path.lstat()
            if stat.S_ISDIR(entry.st_mode):
                continue
            if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                raise BoundaryUnavailable("Snapshot contains unsupported entries")
            total += entry.st_size
            if total > 128 * 1024 ** 2:
                raise BoundaryUnavailable("Isolated snapshot exceeds its input limit")
            with path.open("rb") as stream:
                member = tarfile.TarInfo(path.relative_to(root).as_posix())
                member.mode = 0o700 if entry.st_mode & stat.S_IXUSR else 0o600
                member.size = entry.st_size
                package.addfile(member, stream)
    archive.seek(0)


def _check_container(container: dict, image: str) -> str:
    host = container["HostConfig"]
    config = container["Config"]
    mode = host.get("PidMode")
    if (container["Image"] != image or container["State"]["Status"] != "created"
            or config["User"] != f"{UID}:{UID}" or config.get("Volumes")
            or config["Entrypoint"] != ["/usr/bin/env"]
            or host["NetworkMode"] != "none" or host["IpcMode"] != "none"
            or mode not in ("", "private") or host.get("UTSMode") == "host"
            or host.get("CgroupnsMode") != "private" or host["Privileged"]
            or host.get("Binds") or host.get("Mounts") or host.get("VolumesFrom")
            or host.get("Devices") or host.get("DeviceRequests") or host.get("DeviceCgroupRules")
            or host.get("CapAdd") or host["CapDrop"] != ["ALL"]
            or host["SecurityOpt"] != ["no-new-privileges=true"]
            or host["LogConfig"]["Type"] != "none" or not host["ReadonlyRootfs"]
            or host["PidsLimit"] != 64 or host["Memory"] != MEMORY
            or host["MemorySwap"] != MEMORY or host["NanoCpus"] != 1_000_000_000
            or host["Init"] is not True or host["RestartPolicy"]["Name"] != "no"
            or host["Tmpfs"] != dict(item.split(":", 1) for item in (WORKSPACE, TEMP))
            or any(mount["Type"] != "tmpfs" or mount["Destination"] not in {"/workspace", "/tmp"}
                   for mount in container["Mounts"])
            or set(container["NetworkSettings"]["Networks"]) != {"none"}):
        raise BoundaryUnavailable("Docker did not apply the mandatory isolation settings")
    identity = container["Id"]
    if not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise BoundaryUnavailable("Docker did not provide an immutable container ID")
    return identity


def run_isolated(root: Path, scope: Path, command: list[str], image: str, cancelled) -> int:
    """Return a coarse, daemon-observed exit result without retaining guest output."""
    if sys.platform != "linux" or not IMAGE_ID.fullmatch(image):
        raise BoundaryUnavailable("Isolated execution requires Linux and a local image ID")
    if scope.is_absolute() or ".." in scope.parts:
        raise BoundaryUnavailable("Isolated command scope must stay within the snapshot")
    if not stat.S_ISSOCK(Path(SOCKET).stat().st_mode):
        raise BoundaryUnavailable("The local Docker socket is unavailable")
    docker = Path("/usr/bin/docker")
    if not docker.is_file():
        docker = Path("/usr/local/bin/docker")
    name = "vh-isolated-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="vh-docker-") as config, tempfile.TemporaryFile() as archive:
        _stage(root, archive)
        env = {"PATH": PATH, "HOME": config, "LC_ALL": "C"}
        base = [str(docker), "--host", f"unix://{SOCKET}", "--config", config]

        def invoke(*args, capture=False, check=True):
            return subprocess.run([*base, *args], env=env, cwd=config, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=10, check=check)

        def inspect(*args):
            return json.loads(invoke(*args, capture=True).stdout)

        info = inspect("info", "--format", "{{json .}}")
        if (info["OSType"] != "linux" or info["DefaultRuntime"] != "runc"
                or "name=seccomp,profile=builtin" not in info.get("SecurityOptions", [])
                or not all(info.get(key) for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"))):
            raise BoundaryUnavailable("The local Docker daemon does not meet the isolation requirements")
        metadata, = inspect("image", "inspect", image)
        if metadata["Id"] != image or metadata["Config"].get("Volumes"):
            raise BoundaryUnavailable("The configured image is unsuitable for isolation")
        if cancelled():
            raise BoundaryUnavailable("Isolated execution was cancelled")
        identity = name
        try:
            invoke("create", "--name", name, "--pull=never", "--interactive", "--init", "--network=none",
                   "--ipc=none", "--cgroupns=private", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
                   f"--user={UID}:{UID}", "--read-only", "--pids-limit=64", "--cpus=1",
                   f"--memory={MEMORY}", f"--memory-swap={MEMORY}", "--log-driver=none", "--restart=no",
                   "--no-healthcheck", "--runtime=runc", "--tmpfs", WORKSPACE, "--tmpfs", TEMP,
                   "--workdir", "/workspace", "--entrypoint=/usr/bin/env", image,
                   "-i", f"PATH={PATH}", "HOME=/tmp", "TMPDIR=/tmp", "LC_ALL=C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/timeout", "--kill-after=2", "20",
                   "/bin/sh", "-c", ENTRY, "verify-helper", scope.as_posix(), *command)
            container, = inspect("container", "inspect", name)
            identity = _check_container(container, image)
            with subprocess.Popen([*base, "start", "--attach", "--interactive", identity],
                                  cwd=config, env=env, stdin=archive, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL) as process:
                deadline = time.monotonic() + 25
                while process.poll() is None:
                    if cancelled() or time.monotonic() >= deadline:
                        process.kill()
                        raise BoundaryUnavailable("Isolated execution was cancelled or exceeded its time limit")
                    time.sleep(0.1)
            state = inspect("container", "inspect", "--format", "{{json .State}}", identity)
            code = state["ExitCode"]
            if state["Status"] != "exited" or state["OOMKilled"] or process.returncode != code or code not in (0, 1):
                raise BoundaryUnavailable("The isolated command did not complete normally")
            return code
        finally:
            removed = invoke("container", "rm", "--force", "--volumes", identity, check=False)
            if removed.returncode:
                raise BoundaryUnavailable("Isolated container removal could not be confirmed")
