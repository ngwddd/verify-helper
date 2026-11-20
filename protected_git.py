"""Read immutable Git objects without opening the project's Git configuration."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path, PurePosixPath

SHA = re.compile(r"[a-f0-9]{40}")
REF = re.compile(r"refs/heads/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*")
PACK = re.compile(r"pack-[a-f0-9]{40}\.(?:pack|idx)")
FANOUT = re.compile(r"[a-f0-9]{2}")
LOOSE = re.compile(r"[a-f0-9]{38}")
MAX_OBJECT_STORE = 512 * 1024 ** 2
MAX_TREE = 1024 ** 3
MAX_ENTRIES = 200_000
RESERVED = re.compile(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", re.I)


class ProtectedMergeConflict(ValueError):
    """The isolated metadata repository reported a merge conflict."""


class ObjectRepository:
    def __init__(self, project: Path, work: Path, copy):
        self.project = project
        self.work = work
        self.copy = copy
        self.repo = work / "verified-objects"
        executable = shutil.which("git")
        if not executable:
            raise ValueError("Git object reader is unavailable")
        self.git = Path(executable).resolve(strict=True)
        if self.git.is_relative_to(project):
            raise ValueError("Git executable must be provided by the host toolchain")
        self.env = {key: value for key, value in os.environ.items()
                    if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}}
        self.env.update(PATH=str(self.git.parent), HOME=str(work), USERPROFILE=str(work),
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_TEMPLATE_DIR=str(work / "empty-template"), LC_ALL="C",
                        GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1")
        (work / "empty-template").mkdir()
        self.invoke("init", "--bare", "--object-format=sha1", str(self.repo))
        self._import_objects()

    def invoke(self, *args: str, check=True):
        return subprocess.run([str(self.git), "-c", f"core.hooksPath={self.work / 'empty-template'}",
                               *args], cwd=self.work, env=self.env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=check, timeout=30)

    def in_repo(self, *args: str, check=True):
        return self.invoke(f"--git-dir={self.repo}", *args, check=check)

    def _import_objects(self):
        root = self.project / ".git" / "objects"
        for directory in (root.parent, root):
            entry = directory.lstat()
            if not stat.S_ISDIR(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 1024:
                raise ValueError("Only ordinary local Git object stores are supported")
        total = 0
        for directory in root.iterdir():
            if directory.name != "pack" and not FANOUT.fullmatch(directory.name):
                continue
            entry = directory.lstat()
            if not stat.S_ISDIR(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 1024:
                raise ValueError("Git object directory is not a regular directory")
            target = self.repo / "objects" / directory.name
            target.mkdir(exist_ok=True)
            pattern = PACK if directory.name == "pack" else LOOSE
            for item in directory.iterdir():
                if not pattern.fullmatch(item.name):
                    continue
                metadata = item.lstat()
                total += metadata.st_size
                if total > MAX_OBJECT_STORE:
                    raise ValueError("Git object store exceeded its verification budget")
                self.copy(self.project, item.relative_to(self.project), target / item.name, metadata)

    def _metadata(self, name: str, limit: int) -> str:
        path = self.project / ".git" / name
        entry = path.lstat()
        if entry.st_size > limit:
            raise ValueError("Git reference metadata exceeded its verification budget")
        with tempfile.TemporaryDirectory(dir=self.work) as directory:
            target = Path(directory) / "ref-data"
            self.copy(self.project, path.relative_to(self.project), target, entry)
            return target.read_text(encoding="ascii").strip()

    def resolve(self, reference: str) -> str:
        if SHA.fullmatch(reference):
            commit = reference
        else:
            if reference == "HEAD":
                head = self._metadata("HEAD", 1024)
                if SHA.fullmatch(head):
                    return self.resolve(head)
                if not head.startswith("ref: "):
                    raise ValueError("Invalid Git HEAD")
                reference = head[5:]
            elif not reference.startswith("refs/heads/"):
                reference = "refs/heads/" + reference
            if not REF.fullmatch(reference) or ".." in reference or reference.endswith(".lock"):
                raise ValueError("Only exact Git revisions and local branch names are supported")
            try:
                commit = self._metadata(reference, 1024)
            except FileNotFoundError:
                entries = self._metadata("packed-refs", 1024 ** 2).splitlines()
                matches = [entry.split(" ", 1)[0] for entry in entries if entry.endswith(" " + reference)]
                if len(matches) != 1:
                    raise ValueError("Git reference is unavailable")
                commit = matches[0]
        if not SHA.fullmatch(commit):
            raise ValueError("Git reference does not contain a full object ID")
        obj = self.in_repo("cat-file", "commit", commit).stdout
        if hashlib.sha1(f"commit {len(obj)}\0".encode() + obj).hexdigest() != commit:
            raise ValueError("Git commit does not match its object ID")
        return commit

    def checkpoint(self, commit: str) -> str:
        result = self.in_repo("rev-parse", "--verify", commit + "^{tree}").stdout.decode("ascii").strip()
        if not SHA.fullmatch(result):
            raise ValueError("Git commit did not yield a tree")
        return result

    def merge(self, head: str, base: str) -> str:
        result = self.in_repo("merge-tree", "--write-tree", head, base, check=False)
        if result.returncode == 1:
            raise ProtectedMergeConflict("Git reported a merge conflict")
        lines = result.stdout.decode("ascii").splitlines()
        if result.returncode or len(lines) != 1 or not SHA.fullmatch(lines[0]):
            raise ValueError("Git could not establish the merged tree")
        return lines[0]

    def materialize(self, tree: str, target: Path) -> None:
        import tarfile

        target.mkdir()
        with tempfile.TemporaryFile(dir=self.work) as archive:
            command = [str(self.git), f"--git-dir={self.repo}", "archive", "--format=tar", tree]
            with subprocess.Popen(command, cwd=self.work, env=self.env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                timeout = threading.Timer(60, process.kill)
                timeout.start()
                size = 0
                try:
                    while chunk := process.stdout.read(256 * 1024):
                        size += len(chunk)
                        if size > MAX_TREE + 128 * 1024 ** 2:
                            process.kill()
                            raise ValueError("Git archive exceeded its streaming budget")
                        archive.write(chunk)
                    if process.wait() != 0:
                        raise ValueError("Git archive did not complete")
                finally:
                    timeout.cancel()
            archive.seek(0)
            entries = self.in_repo("ls-tree", "-r", "-z", tree).stdout.rstrip(b"\0").split(b"\0")
            files = {}
            for row in filter(None, entries):
                meta, raw_name = row.split(b"\t", 1)
                mode, kind, oid = meta.decode("ascii").split()
                if mode not in {"100644", "100755"} or kind != "blob":
                    raise ValueError("Git tree contains a link, submodule or unsupported entry")
                name = raw_name.decode("utf-8")
                _path(name)
                if len(files) >= MAX_ENTRIES:
                    raise ValueError("Git tree exceeded its file count budget")
                files[name] = (oid, mode)
            total = 0
            with tarfile.open(fileobj=archive) as package:
                seen = set()
                for item in package:
                    parts = _path(item.name.rstrip("/"))
                    if item.isdir():
                        continue
                    if not item.isfile() or item.name not in files or item.name in seen:
                        raise ValueError("Git archive contains an unexpected entry")
                    total += item.size
                    if total > MAX_TREE:
                        raise ValueError("Git tree exceeded its snapshot budget")
                    oid, mode = files[item.name]
                    destination = target.joinpath(*parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    hashed = hashlib.sha1(f"blob {item.size}\0".encode())
                    with destination.open("xb") as output, package.extractfile(item) as stream:
                        while chunk := stream.read(256 * 1024):
                            hashed.update(chunk)
                            output.write(chunk)
                    if hashed.hexdigest() != oid:
                        raise ValueError("Git archive changed a committed file")
                    destination.chmod(0o700 if mode == "100755" else 0o600)
                    seen.add(item.name)
                if seen != files.keys():
                    raise ValueError("Git archive excluded committed files")


def _path(name: str):
    parts = PurePosixPath(name).parts
    if (not name or not parts or any(not part or part in (".", "..", "/")
            or part.lower() == ".git" or part[-1] in {" ", "."}
            or RESERVED.fullmatch(part) or any(ord(char) < 32 or char in '\\:*?"<>|' for char in part)
            for part in parts) or "/".join(parts) != name):
        raise ValueError("Git tree contains an unsupported path")
    return parts
