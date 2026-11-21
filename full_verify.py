"""Plan and execute full verification, then issue a fail-closed verdict."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack, suppress
from pathlib import Path

import check_specs
import protected_git
import report_export
import sarif
import verification_adapters as adapters
import verify_core as core
from process_boundary import contain_worker
from private_storage import private_directory, private_write
from run_evidence import digest as evidence_digest, plan_digest, read_evidence, resolve_local_finding, set_gate_fields, write_manifest

SCHEMA_VERSION = 2
DYNAMIC = {"tests", "browser", "interaction", "mutation", "runtime-web"}
SNAPSHOT_EXCLUDES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
                     ".verify-artifacts", ".verify-noise.json", ".verify-accept.json",
                     ".verify-python", ".pytest_cache", ".mypy_cache", ".tox"}
EXEC_ENV = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL",
            "VERIFY_HELPER_TEST_PYTHON", "VERIFY_TSC", "VERIFY_PLAYWRIGHT_ROOT", "PLAYWRIGHT_BROWSERS_PATH",
            "VERIFY_NATIVE_FIXTURE", "VERIFY_SCRATCH_DIRECTORY", "CC", "CXX", "CMAKE_GENERATOR",
            "INCLUDE", "LIB", "LIBPATH",
            "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "PROGRAMDATA", "SYSTEMDRIVE",
            "PROCESSOR_ARCHITECTURE", "ZIG_GLOBAL_CACHE_DIR"}
PRIVATE_INPUTS = {".ssh", ".aws", ".azure", ".kube", ".gnupg", ".docker", ".netrc",
                  ".git-credentials", ".npmrc", ".pypirc", ".env"}


def scrub(value):
    if isinstance(value, str):
        value = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
                       "[REDACTED PRIVATE KEY]", value)
        for _, pattern in [*core.SECRET_PATTERNS, core.CRED_PATTERN]:
            value = pattern.sub("[REDACTED]", value)
        value = re.sub(r"(?i)\bBearer[ \t]+[a-z0-9_.~+/=-]+", "Bearer [REDACTED]", value)
        return value
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, dict):
        return {scrub(key): scrub(item) for key, item in value.items()}
    return value


def _copy_open_file(fd: int, destination: Path, expected) -> str:
    actual = os.fstat(fd)
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or
            (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
        raise ValueError("Snapshot source changed before it could be opened")
    checksum = hashlib.sha256()
    with os.fdopen(fd, "rb", closefd=False) as stream, destination.open("xb") as target:
        remaining = expected.st_size
        while remaining:
            chunk = stream.read(min(remaining, 256 * 1024))
            if not chunk:
                raise ValueError("Snapshot source shrank while being copied")
            target.write(chunk)
            checksum.update(chunk)
            remaining -= len(chunk)
        if stream.read(1):
            raise ValueError("Snapshot source grew while being copied")
    destination.chmod(0o700 if actual.st_mode & stat.S_IXUSR else 0o600)
    return checksum.hexdigest()


def _protected_copy(source: Path, relative: Path, destination: Path, expected) -> str:
    if os.name == "nt":
        import msvcrt
        import win32file

        fd = os.open(source / relative, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
        try:
            name = win32file.GetFinalPathNameByHandle(msvcrt.get_osfhandle(fd), 0)
            if Path(name) != Path("\\\\?\\" + str(source / relative)):
                raise ValueError("Snapshot file handle resolved outside its expected path")
            return _copy_open_file(fd, destination, expected)
        finally:
            os.close(fd)
    with ExitStack() as handles:
        directory_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY
        parent = os.open(source, directory_flags)
        handles.callback(os.close, parent)
        for name in relative.parent.parts:
            parent = os.open(name, directory_flags, dir_fd=parent)
            handles.callback(os.close, parent)
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        handles.callback(os.close, fd)
        return _copy_open_file(fd, destination, expected)


def _snapshot(source: Path, destination: Path, *, protected: bool = False,
              inventory: dict | None = None) -> tuple[str, list[str]]:
    digest = hashlib.sha256()
    omitted = []
    total = 0
    counts = {"included_files": 0, "fixed_exclusions": 0, "private_exclusions": 0, "unsafe_or_changed": 0}

    def walk_error(error):
        raise error

    for folder, dirs, files in os.walk(source, onerror=walk_error):
        current = Path(folder)
        relative = current.relative_to(source)
        (destination / relative).mkdir(parents=True, exist_ok=True)
        counts["fixed_exclusions"] += sum(name.lower() in SNAPSHOT_EXCLUDES for name in [*dirs, *files])
        dirs[:] = sorted(name for name in dirs if name.lower() not in SNAPSHOT_EXCLUDES)
        for name in [*dirs, *sorted(files)]:
            if name.lower() in SNAPSHOT_EXCLUDES:
                continue
            path = current / name
            entry = path.lstat()
            display = (relative / name).as_posix()
            private = protected and (name.lower() in PRIVATE_INPUTS or name.lower().startswith(".env."))
            if private or stat.S_ISLNK(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 1024:
                counts["private_exclusions" if private else "unsafe_or_changed"] += 1
                omitted.append(display)
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            total += entry.st_size
            if total > 1024 ** 3:
                raise ValueError("Snapshot exceeds the 1 GiB verification limit")
            if not stat.S_ISREG(entry.st_mode) or (protected and entry.st_nlink != 1):
                counts["unsafe_or_changed"] += 1
                omitted.append(display)
                continue
            copied = destination / relative / name
            if protected and (os.name == "nt" or sys.platform == "linux"):
                checksum = _protected_copy(source, relative / name, copied, entry)
            else:
                shutil.copy2(path, copied)
                with copied.open("rb") as stream:
                    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            latest = path.lstat()
            if (entry.st_mode, entry.st_size, entry.st_mtime_ns, entry.st_ino) != (
                    latest.st_mode, latest.st_size, latest.st_mtime_ns, latest.st_ino):
                counts["unsafe_or_changed"] += 1
                omitted.append(display)
            digest.update(json.dumps([display, checksum], ensure_ascii=True).encode())
            counts["included_files"] += 1
    if inventory is not None:
        inventory.update(counts)
    return digest.hexdigest(), omitted


def _snapshot_single_file(path: Path, destination: Path, inventory: dict) -> tuple[str, list[str]]:
    name = path.name
    entry = path.lstat()
    private = name.lower() in PRIVATE_INPUTS or name.lower().startswith(".env.")
    inventory.update(included_files=0, fixed_exclusions=0, private_exclusions=int(private), unsafe_or_changed=0)
    if private or not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_size > 1024 ** 3:
        inventory["unsafe_or_changed"] = int(not private)
        return evidence_digest(b""), [name]
    copied = destination / name
    if os.name == "nt" or sys.platform == "linux":
        checksum = _protected_copy(path.parent, Path(name), copied, entry)
    else:
        shutil.copy2(path, copied)
        with copied.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    latest = path.lstat()
    if (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns) != (
            entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns):
        inventory["unsafe_or_changed"] = 1
        return evidence_digest(b""), [name]
    inventory["included_files"] = 1
    return evidence_digest(json.dumps([name, checksum], ensure_ascii=True).encode()), []


def _source_git(root: Path) -> dict:
    if not (root / ".git").exists():
        return {}
    head, revision = core._run(["git", "rev-parse", "HEAD"], root, 10)
    status, output = core._run(["git", "status", "--porcelain"], root, 15)
    return {"head": revision.strip() if head == 0 else None,
            "dirty": bool(output.strip()) if status == 0 else None}


def _scope(root: Path, files: list[Path]) -> list[Path]:
    manifests = {"pyproject.toml", "package.json", "CMakeLists.txt", "pytest.ini"}
    return [root, *sorted({file.parent for file in files
                           if file.name in manifests and file.parent != root})]


def _link_dependencies(stack: ExitStack, target: Path, source: Path, scopes) -> None:
    for scope in scopes:
        original = source / scope
        dependencies = original / "node_modules"
        if (not dependencies.is_dir() or not original.resolve().is_relative_to(source.resolve())
                or not dependencies.resolve().is_relative_to(original.resolve())):
            continue
        link = target / scope / "node_modules"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(dependencies), str(link))
            stack.callback(_remove_junction, link)
        else:
            link.symlink_to(dependencies, target_is_directory=True)
            stack.callback(link.unlink, missing_ok=True)


def _remove_junction(path: Path) -> None:
    with suppress(FileNotFoundError):
        path.rmdir()


def _declared_smoke(config: dict) -> frozenset[str]:
    declared = set()
    for row in (config.get("build"), config.get("runtime"), *config.get("contracts", [])):
        argv = row.get("argv") if isinstance(row, dict) else None
        if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
            continue
        command = Path(argv[0]).stem.lower()
        if command not in {"python", "python3"}:
            continue
        for index, value in enumerate(argv[1:], 1):
            if value == "-m" and index + 1 < len(argv):
                declared.add(argv[index + 1].replace(".", "/") + ".py")
                break
            if value == "-c":
                break
            if not value.startswith("-"):
                declared.add(Path(value.replace("\\", "/")).as_posix())
                break
    return frozenset(declared)


def _run_plan(root: Path, trusted: bool, policy_required: tuple[str, ...] = (),
              single_file: bool = False, source_root: Path | None = None) -> dict:
    files, _, large, _ = core.scan_files(root, project_ignores=False)
    selected = next(root.iterdir(), None) if single_file else None
    archive_target = selected if selected and selected.name.lower().endswith((".zip", ".whl", ".tar.gz", ".tgz")) else None
    ctx = core.Ctx(core.Cache(False))
    config_error = None
    try:
        config = {} if single_file else adapters.read_config(root)
    except (ValueError, OSError) as error:
        config = {}
        config_error = adapters.check("configuration", str(error), "FAIL")

    static = [identifier for identifier in check_specs.ordered_ids()
              if identifier not in DYNAMIC | {"git"} and (not single_file or identifier != "custom")]
    report = core._verify_checks(str(root), checks=static, use_cache=False, artifacts=False,
                         review_md=False, allow_host_tools=True, project_ignores=False)
    required = {}
    tasks = []
    rows = report["checks"]
    if single_file:
        links = next(row for row in rows if row["id"] == "links")
        if links["applicable"]:
            links.update(state="UNKNOWN", applicable=False, findings=[], detail="Verify the containing project to check links")
    for row in rows:
        if row["applicable"] and (row["blocking"] or row["id"] == "custom"):
            required[row["id"]] = "Applicable source and configuration checks"

    def record(result: core.Check, identifier: str | None = None):
        if identifier is not None:
            result.id = identifier
        result.applicable = True
        rows.append(result.as_dict())

    def add(result: core.Check, reason: str):
        required[result.id] = reason
        record(result)

    def run(identifier: str, description: str, action, *, requires_trust: bool = True,
            copy_project: bool = True):
        required[identifier] = description
        tasks.append((identifier, action, requires_trust, copy_project))

    def execute(identifier, action, requires_trust, copy_project):
        if core._worker_cancelled():
            result = adapters.check(identifier, "Verification was cancelled")
        elif requires_trust and (not trusted or config_error is not None or any(
                row["id"] == "secrets" and row["state"] == "FAIL" for row in rows)):
            result = adapters.check(identifier, "Project code execution is unavailable")
            if not trusted:
                result.reason_code = "EXECUTION_NOT_RUN"
        else:
            try:
                if requires_trust and copy_project:
                    with tempfile.TemporaryDirectory(prefix="vh-check-") as directory:
                        target = Path(directory) / "project"
                        shutil.copytree(root, target, ignore=shutil.ignore_patterns(*SNAPSHOT_EXCLUDES))
                        result = action(target)
                else:
                    result = action(root)
            except (OSError, ValueError) as error:
                result = adapters.check(identifier, f"{type(error).__name__}: {error}")
        record(result, identifier)

    if config_error is not None:
        add(config_error, "Verification configuration must parse")
    if (large and archive_target is None) or len(files) >= 200_000:
        add(adapters.check("scan-coverage", "The source scan reached a size or file count limit"),
            "All applicable project inputs must be inventoried")

    html = any(file.suffix.lower() in core.HTML_EXT for file in files)
    if html and not single_file:
        run("runtime-web", "HTML pages must be served over HTTP",
            lambda target: core.check_runtime_web(target, files, ctx), copy_project=False)
        run("browser", "HTML pages must load in a browser",
            lambda target: core.check_browser(target, files, ctx, source_root=source_root), copy_project=False)
    try:
        flow_data = core.tomllib.loads((root / "verify.toml").read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        flow_data = {}
    if "flows" in flow_data and not single_file:
        run("interaction", "Configured browser flow assertions must execute",
            lambda target: core.check_interaction(target, files, ctx, source_root=source_root),
            copy_project=False)

    scopes = [] if single_file else _scope(root, files)
    relative_scopes = [scope.relative_to(root) for scope in scopes]
    original = source_root or root
    registered_smoke = _declared_smoke(config)

    def with_dependencies(target, scopes, action):
        with ExitStack() as stack:
            _link_dependencies(stack, target, original, scopes)
            return action()

    def contract(target, name, declaration):
        return with_dependencies(target, relative_scopes,
                                 lambda: adapters.contract(name, declaration, target, source_root=source_root))

    for scope in scopes:
        prefix = "" if scope == root else scope.relative_to(root).as_posix() + ":"
        subfiles = [file for file in files if file.is_relative_to(scope) and
                    not any(other != root and other != scope and other.is_relative_to(scope)
                            and file.is_relative_to(other) for other in scopes)]
        extensions = {file.suffix.lower() for file in subfiles}
        has_python = bool(extensions & core.PY_EXT)
        has_js = bool(extensions & core.JS_EXT)
        has_native = bool(extensions & adapters.NATIVE)
        cmake = (scope / "CMakeLists.txt").is_file()
        relative_scope = scope.relative_to(root)
        relative_files = [path.relative_to(root) for path in subfiles]
        if cmake:
            native_tests = prefix + "tests-native"
            required[native_tests] = "Native runtime and tests must execute"

            def native(target, relative_scope=relative_scope, native_tests=native_tests):
                source = target / relative_scope
                build = target.parent / "native-build"
                result = adapters.chain("build-native", [
                    ["cmake", "-S", str(source), "-B", str(build)],
                    ["cmake", "--build", str(build), "--config", "Release"],
                ], source)
                if result.state == "FAIL" and adapters.cmake_environment_missing(result.output):
                    result.state = "UNKNOWN"
                    result.detail = "CMake could not locate the required compiler or build tool"
                if result.state == "PASS":
                    record(adapters.ctest(source, build), native_tests)
                return result

            run(prefix + "build-native", "CMake sources must compile", native)
        elif has_native and (scope != root or "build" not in config):
            add(adapters.check(prefix + "build-native", "Configure a native build contract or CMake"),
                "Native sources must compile")
        if has_native and not cmake and (scope != root or "runtime" not in config):
            add(adapters.check(prefix + "runtime-native", "Configure a native runtime contract"),
                "Native runtime assertions must execute")
        if extensions & adapters.TYPESCRIPT:
            configs = sorted(file.relative_to(scope) for file in subfiles if file.name == "tsconfig.json")
            sources = [file.relative_to(scope) for file in subfiles
                       if file.suffix.lower() in adapters.TYPESCRIPT]
            run(prefix + "typescript", "TypeScript and JSX require a compiler check",
                lambda target, scope=relative_scope, configs=configs, sources=sources:
                with_dependencies(target, {Path("."), scope},
                                  lambda: adapters.typescript(target / scope, configs, sources)))
        languages = []
        if has_python:
            languages.append("python")
        if has_js and (not html or (scope / "package.json").is_file()
                       or core.node_test_files(scope, subfiles, root)
                       or core._detect_test_command(scope, "javascript")[0] is not None):
            languages.append("javascript")
        for language in languages:
            suffix = f"tests-{language}" if len(languages) > 1 else "tests"

            def local_tests(target, scope=relative_scope, files=relative_files, language=language):
                target_scope = target / scope
                result = with_dependencies(target, {Path("."), scope} if language == "javascript" else (),
                    lambda: core.check_tests(target_scope, [target / p for p in files], ctx, language,
                                             allow_npm=config.get("npm_test", False), source_root=original / scope,
                                             project_root=target, unittest_patterns=config.get("unittest_patterns"),
                                             registered_smoke=registered_smoke))
                for finding in result.findings:
                    if finding.get("line", 0) > 0:
                        finding["file"] = (scope / finding["file"]).as_posix()
                if language == "javascript" and result.exit_code is not None and not result.runtime_version:
                    code, version = core._run(["node", "--version"], target_scope, 5)
                    version = version.strip().removeprefix("v")
                    if code == 0 and re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version):
                        result.runtime_version = version
                return result

            run(prefix + suffix, f"{language} code requires test evidence",
                local_tests)

    if config.get("mutation"):
        def mutation(target):
            tests = next((row for row in rows if row["id"] in {"tests", "tests-python"}
                          and row.get("reason_code") != "NOT_APPLICABLE"), None)
            coverage = tests.get("coverage") if tests else None
            if not tests or tests["state"] != "PASS" or not coverage or coverage["planned"] != coverage["observed"]:
                return adapters.check("mutation", "Passing baseline test evidence is unavailable")
            return core.check_mutation(target, [target / p.relative_to(root) for p in files], ctx)

        run("mutation", "Project requires mutation checks", mutation)
    for name in ("build", "runtime"):
        if name in config:
            run(name, f"Project {name} assertion",
                lambda target, name=name: contract(target, name, config[name]))
    for index, row in enumerate(config.get("contracts", []), 1):
        identifier = f"contract-{index}"
        run(identifier, "Project business contract assertion",
            lambda target, identifier=identifier, row=row:
                contract(target, identifier, row))
    for index, row in enumerate(config.get("delivery", []), 1):
        identifier = f"delivery-{index}"
        run(identifier, "Delivery archive contents and digest",
            lambda target, identifier=identifier, row=row:
            adapters.archive(identifier, adapters.relative_path(target, row.get("path")), row),
            requires_trust=False)
    if not config.get("delivery") and (root / "dist").is_dir():
        for index, path in enumerate(sorted((root / "dist").iterdir()), 1):
            if not path.is_file() or path.name.startswith("."):
                continue
            identifier = f"delivery-{index}"
            run(identifier, "Detected delivery file", lambda target, identifier=identifier, path=path:
                adapters.archive(identifier, path),
                requires_trust=False)
    if archive_target is not None:
        run("delivery-1", "Selected archive integrity", lambda target: adapters.archive("delivery-1", archive_target),
            requires_trust=False)
    if selected is not None and selected.suffix.lower() in adapters.TYPESCRIPT:
        add(adapters.check("typescript", "Select the project to verify TypeScript with its compiler configuration"),
            "TypeScript source requires compiler evidence")

    for identifier in policy_required:
        required.setdefault(identifier, "Required by operator policy")
    report["static_only"] = not any(task[2] for task in tasks)
    report["plan"] = required
    report["plan_digest"] = plan_digest(required)
    for task in tasks:
        execute(*task)
    by_id = {row["id"]: row for row in rows}
    for identifier in required:
        if identifier in by_id:
            by_id[identifier]["applicable"] = True
        else:
            record(adapters.check(identifier, "Required check unavailable"))
    return report


def _worker(root: Path, trusted: bool, result_path: Path, policy_required: tuple[str, ...] = (),
            sealed: bool = False, local_locations: bool = False, single_file: bool = False,
            source_root: Path | None = None) -> None:
    report = _run_plan(root, trusted, policy_required, single_file, source_root)
    for row in report["checks"]:
        evidence = row.get("evidence") or {}
        source = evidence.get("dir")
        if not source:
            continue
        destination = result_path.parent / "media" / hashlib.sha256(row["id"].encode()).hexdigest()
        destination.mkdir(parents=True, exist_ok=True)
        for path in sorted(Path(source).glob("*.png"))[:100]:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024:
                name = hashlib.sha256(path.name.encode()).hexdigest() + ".png"
                shutil.copy2(path, destination / name)
        row["evidence"] = {"dir": str(destination), "count": len(list(destination.iterdir()))}
    if sealed:
        locations = {} if local_locations else None
        public = report_export.project_receipts(report, locations=locations)
        public["static_only"] = report["static_only"]
        for receipt, row in zip(public["checks"], report["checks"], strict=True):
            if "evidence" in row:
                receipt["evidence"] = row["evidence"]
        if locations:
            private_write(result_path.with_name("locations.json"), json.dumps(locations).encode())
        result_path.write_text(json.dumps(public), encoding="utf-8")
        return
    result_path.write_text(json.dumps(scrub(report), ensure_ascii=False), encoding="utf-8")


def _wait_for_launch(marker: Path) -> None:
    deadline = time.monotonic() + 30
    while not marker.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("Process containment was not established")
        time.sleep(0.05)


def decide(report: dict) -> str:
    """Compute the independent verdict from a required-check ledger and evidence."""
    rows = {row["id"]: row for row in report["checks"]}
    required = report["plan"]
    if (report.get("security_status") == "VIOLATED" or report.get("merge_conflict") or
            report.get("lifecycle", {}).get("security", {}).get("blocked") or
            any(rows.get(key, {}).get("state") == "FAIL" for key in required)):
        return "FAIL"
    if (not required
            or report.get("blockers") or report.get("lifecycle_error")
            or report.get("plan_digest") != plan_digest(required)):
        return "UNKNOWN"
    for key in required:
        row = rows.get(key, {})
        if (row.get("state") != "PASS" or not row.get("applicable")
                or not row.get("evidence_ref") or not row.get("evidence_sha256")):
            return "UNKNOWN"
        coverage = row.get("coverage")
        if coverage and (coverage["planned"] <= 0 or coverage["observed"] != coverage["planned"]):
            return "UNKNOWN"
        if key == "browser" and not row.get("media"):
            return "UNKNOWN"
    return "PASS"


def _record_checks(report: dict, output: Path, work: Path) -> None:
    private_directory(output)
    for index, row in enumerate(report["checks"], 1):
        evidence = row.pop("evidence", None)
        if evidence:
            picture_dir = Path(evidence["dir"]).resolve()
            if picture_dir.is_relative_to(work / "media"):
                row["media"] = []
                for path in sorted(picture_dir.glob("*.png")):
                    target = output / f"{index:03d}-{path.name}"
                    private_write(target, path.read_bytes())
                    with target.open("rb") as stream:
                        row["media"].append({"path": target.name,
                                             "sha256": hashlib.file_digest(stream, "sha256").hexdigest()})
        row["evidence_ref"] = f"check-{index:03d}.json"
        record = json.dumps(row, ensure_ascii=False, indent=2).encode()
        private_write(output / row["evidence_ref"], record)
        row["evidence_sha256"] = hashlib.sha256(record).hexdigest()


def _finalize(report: dict, output: Path | None, *, evidence_key: bytes | None = None) -> None:
    report.setdefault("plan_digest", plan_digest(report["plan"]))
    report["verdict"] = decide(report)
    set_gate_fields(report)
    lifecycle = report.get("lifecycle")
    if lifecycle and "stage" in lifecycle:
        lifecycle["stage"]["verdict"] = report["verdict"]
    report["sarif"] = json.loads(sarif.dumps(report, core.VERSION))
    if output is None:
        report.pop("evidence_manifest", None)
        return
    private_write(output / "results.sarif", json.dumps(report["sarif"], ensure_ascii=False).encode())
    write_manifest(report, output, key=evidence_key)


def _stable_findings(report: dict, locations: Path, key: bytes) -> None:
    if not locations.is_file():
        return
    lookup = json.loads(locations.read_bytes())
    for row in report["checks"]:
        for finding in row.get("findings", ()):
            relative = lookup[finding["file"]]
            identity = json.dumps([report["target_identity"], os.path.normcase(relative)]).encode()
            finding["file"] = "source-h" + hmac.digest(key, identity, "sha256").hex()[:32]


def _evidence_root(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        try:
            entry = part.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(entry.st_mode) or
                getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError("Evidence directory may not traverse a link or junction")
    # A Windows short name can resolve to the same directory under a longer spelling.
    return path.resolve()


class MergeConflict(ValueError):
    """The requested Git merge has a confirmed conflict."""


def full_verify(project: str | Path, *, unsafe_local: bool = False, evidence_dir: Path | None = None,
                against: str | None = None, revision: str | None = None,
                policy_path: Path | None = None, run_id: str | None = None, cancellation=None,
                sealed: bool = False, evidence_key: bytes | None = None, progress=None,
                local_locations: bool = False) -> dict:
    root = Path(project).expanduser().resolve()
    single_file = root.is_file()
    run_id = run_id or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
        raise ValueError("Invalid verification run ID")
    host_execution = not single_file
    sealed = sealed or not unsafe_local or single_file or evidence_key is not None
    local_locations = local_locations and sealed and evidence_key is None
    context = {"schema_version": SCHEMA_VERSION, "run_id": run_id, "version": core.VERSION,
               "target_kind": "file" if single_file else "project", "mode": "full",
               "execution_mode": "local-host" if host_execution else "static",
               "security_assurance": "NOT_PROVIDED", "isolation_enforced": False,
               "platform": platform.system(), "python": platform.python_version(),
               "target_identity": evidence_digest(os.path.normcase(str(root)).encode()),
               "policy_digest": "sha256:" + evidence_digest(f"{core.VERSION}:{host_execution}".encode())}
    if sealed:
        context["export_policy"] = "sealed"
    else:
        context["project"] = str(root)
    report = {**context, "checks": [], "plan": {}, "blockers": []}
    if not single_file and not root.is_dir():
        report["blockers"].append("Verification target is unavailable")
        _finalize(report, None)
        return report

    git = {}
    run_output = None
    try:
        if progress:
            progress("SNAPSHOTTING")
        scratch = Path(os.environ.get("VERIFY_SCRATCH_DIRECTORY", tempfile.gettempdir())).resolve()
        if scratch.is_relative_to(root):
            raise ValueError("Scratch directory must be outside the project")
        with tempfile.TemporaryDirectory(prefix="vh-", dir=scratch) as directory:
            work = Path(directory).resolve()
            snapshot = work / "project"
            source = root
            if single_file and (revision or against):
                raise ValueError("Git revision and merge checks require a project directory")
            if revision or against:
                source, git_context = _protected_git_source(root, work, revision, against)
                context.update(git_context)
                context["dependency_assurance"] = "HOST_UNPINNED"
            inventory = {}
            if single_file:
                snapshot.mkdir()
                digest, omitted = _snapshot_single_file(root, snapshot, inventory)
            else:
                digest, omitted = _snapshot(source, snapshot, protected=True, inventory=inventory)
            config = snapshot / "verify.toml"
            policy_material = {"engine": core.VERSION, "execution_mode": context["execution_mode"],
                               "project_contract": evidence_digest(config.read_bytes()) if config.is_file() else None}
            policy_required = []
            if policy_path is not None:
                policy_bytes = policy_path.read_bytes()
                policy = json.loads(policy_bytes)
                if (not isinstance(policy, dict) or set(policy) != {"required_checks"}
                        or not isinstance(policy["required_checks"], list)
                        or len(policy["required_checks"]) > 128
                        or any(not isinstance(item, str) or not item or len(item) > 128
                               for item in policy["required_checks"])):
                    raise ValueError("Policy must declare a required_checks list")
                policy_required = policy["required_checks"]
                policy_material["policy"] = evidence_digest(policy_bytes)
            context["policy_digest"] = "sha256:" + evidence_digest(json.dumps(policy_material, sort_keys=True).encode())
            result_path = work / "result.json"
            stop_path = work / "cancel"
            home = work / "home"
            home.mkdir()
            env = {key: value for key, value in os.environ.items() if key.upper() in EXEC_ENV}
            env.update({"HOME": str(home), "USERPROFILE": str(home), "LOCALAPPDATA": str(home),
                        "APPDATA": str(home), "TEMP": str(work), "TMP": str(work),
                        "TMPDIR": str(work), "VERIFY_SCRATCH_DIRECTORY": str(scratch),
                        "VERIFY_HELPER_CANCEL_FILE": str(stop_path),
                        "PYTHONUTF8": "1", "PYTHONNOUSERSITE": "1",
                        "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                        "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_AUDIT": "false"})
            if os.name == "nt" and os.environ.get("USERPROFILE"):
                # Installed Chrome and Edge need the account profile to start their own browser sandbox.
                env["USERPROFILE"] = os.environ["USERPROFILE"]
            if "PLAYWRIGHT_BROWSERS_PATH" not in env:
                default = (Path(os.environ["LOCALAPPDATA"]) / "ms-playwright"
                           if os.name == "nt" and "LOCALAPPDATA" in os.environ else
                           Path.home() / ".cache" / "ms-playwright")
                if default.is_dir():
                    env["PLAYWRIGHT_BROWSERS_PATH"] = str(default)
            launch = work / "launch"
            if progress:
                progress("VERIFYING")
            with ExitStack() as stack:
                worker = stack.enter_context(subprocess.Popen([sys.executable, "-I", "-c",
                            "import json,sys; sys.path.insert(0,sys.argv[1]); "
                            "from pathlib import Path; from full_verify import _wait_for_launch,_worker; "
                            "_wait_for_launch(Path(sys.argv[6])); "
                            "_worker(Path(sys.argv[2]),sys.argv[3]=='True',Path(sys.argv[4]),json.loads(sys.argv[5]),"
                            "sys.argv[7]=='True',sys.argv[8]=='True',sys.argv[9]=='True',Path(sys.argv[10]))",
                            str(Path(__file__).resolve().parent), str(snapshot),
                            str(host_execution and not omitted), str(result_path),
                            json.dumps(policy_required), str(launch), str(sealed),
                            str(local_locations or evidence_key is not None), str(single_file),
                            str(root)],
                           cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           start_new_session=os.name != "nt",
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
                context["process_boundary"] = stack.enter_context(contain_worker(worker))
                launch.touch()
                deadline = time.monotonic() + 1800
                while worker.poll() is None:
                    if cancellation is not None and cancellation.is_set() and not stop_path.exists():
                        stop_path.touch()
                        deadline = min(deadline, time.monotonic() + 30)
                    try:
                        worker.wait(timeout=min(0.25, max(0, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= deadline:
                            core._terminate_process(worker)
                            raise
                if worker.returncode:
                    raise subprocess.CalledProcessError(worker.returncode, worker.args)
            report.update(json.loads(result_path.read_text(encoding="utf-8")))
            if sealed and report.pop("static_only", False):
                context["security_status"] = "NOT_REQUIRED"
                context.pop("reason_code", None)
            report.update(context, snapshot_sha256=digest)
            report["snapshot_inventory"] = inventory
            if not sealed:
                report.setdefault("git", git)
                report["omitted"] = omitted
            if omitted:
                report["blockers"].append("Source snapshot contains omitted or changed entries")
                if sealed:
                    report["protected_input"] = {"reason_code": "PROTECTED_INPUT_EXCLUDED",
                                                 "excluded_count": len(omitted)}
            if stop_path.exists() or (cancellation is not None and cancellation.is_set()):
                report["status"] = "CANCELLED"
                report["blockers"].append("Verification was cancelled")
            if report.get("notes"):
                report["notes"] = [note.replace(str(snapshot), str(root)) for note in report["notes"]]
            if progress:
                progress("SEALING")
            output = _evidence_root(evidence_dir or Path.home() / ".verify-helper" / "cli-runs")
            run_output = output / run_id
            if not sealed:
                report["evidence_dir"] = str(run_output)
                report = scrub(report)
            location_data = work / "locations.json"
            if evidence_key is not None:
                _stable_findings(report, location_data, evidence_key)
            _record_checks(report, run_output, work)
            if local_locations and location_data.is_file():
                private_write(run_output / location_data.name, location_data.read_bytes())
                report["local_finding_index"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, (MergeConflict, protected_git.ProtectedMergeConflict)):
            report["merge_conflict"] = True
        elif (revision or against) and not context.get("git"):
            report["reason_code"] = "GIT_SNAPSHOT_UNAVAILABLE"
        report["blockers"].append(f"Verification infrastructure failed ({type(error).__name__})")
        if sealed and (revision or against) and not context.get("git") and run_output is None:
            conflict = report.get("merge_conflict") is True
            row = adapters.check("git-snapshot", "Git object verification did not produce a source snapshot",
                                 "FAIL" if conflict else "UNKNOWN")
            row.reason_code = "GIT_MERGE_CONFLICT" if conflict else "GIT_SNAPSHOT_UNAVAILABLE"
            report["checks"] = report_export.project_receipts(
                {"checks": [row.as_dict()], "plan": {row.id: "Verified Git snapshot"}}
            )["checks"]
            report["plan"] = {row.id: "Verified Git snapshot"}
            try:
                output = _evidence_root(evidence_dir or Path.home() / ".verify-helper" / "cli-runs")
                run_output = output / run_id
                _record_checks(report, run_output, output)
            except (OSError, ValueError):
                report["blockers"].append("Git snapshot evidence could not be written")
    try:
        _finalize(report, run_output if run_output and run_output.is_dir() else None,
                  evidence_key=evidence_key)
    except (OSError, ValueError) as error:
        report["blockers"].append(f"Cannot finalize evidence ({type(error).__name__})")
        _finalize(report, None)
    return scrub(report)


def _protected_git_source(root: Path, work: Path, revision: str | None, against: str | None):
    repo = protected_git.ObjectRepository(root, work, _protected_copy)
    head = repo.resolve("HEAD")
    if revision is not None and revision != head:
        raise ValueError("Requested revision differs from the checked-out commit")
    head_tree = repo.checkpoint(head)
    committed = work / "committed"
    repo.materialize(head_tree, committed)
    index = root / ".git" / "index"
    _protected_copy(root, index.relative_to(root), repo.repo / "index", index.lstat())
    if repo.in_repo("diff-index", "--cached", "--quiet", head, "--", check=False).returncode:
        raise ValueError("Git index differs from the selected commit or could not be checked")
    for entry in committed.rglob("*"):
        if not entry.is_file():
            continue
        relative = entry.relative_to(committed)
        original = root / relative
        metadata = original.lstat()
        with tempfile.TemporaryDirectory(dir=work) as directory:
            comparison = Path(directory) / "tracked"
            _protected_copy(root, relative, comparison, metadata)
            if (comparison.stat().st_size != entry.stat().st_size
                    or (os.name != "nt" and bool(metadata.st_mode & stat.S_IXUSR) !=
                        bool(entry.stat().st_mode & stat.S_IXUSR))):
                raise ValueError("A tracked Git file differs from the selected commit")
            with comparison.open("rb") as live, entry.open("rb") as saved:
                if hashlib.file_digest(live, "sha256").digest() != hashlib.file_digest(saved, "sha256").digest():
                    raise ValueError("A tracked Git file differs from the selected commit")
    live_digest, live_omitted = _snapshot(root, work / "worktree-input", protected=True)
    committed_digest, committed_omitted = _snapshot(committed, work / "commit-input", protected=True)
    if live_omitted or committed_omitted or live_digest != committed_digest:
        raise ValueError("Working copy differs from the verified committed input")
    context = {"git": {"head": head, "tree": head_tree, "dirty": False}}
    if not against:
        return committed, context
    base = repo.resolve(against)
    merged_tree = repo.merge(head, base)
    merged = work / "merged"
    repo.materialize(merged_tree, merged)
    context["merge"] = {"base_commit": base, "tree": merged_tree}
    return merged, context


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        from server import main as serve
        serve(argv[1:])
        return 0
    if argv and argv[0] == "resolve-finding":
        resolver = argparse.ArgumentParser(prog="verify-helper resolve-finding")
        resolver.add_argument("run_directory", type=Path)
        resolver.add_argument("source_alias")
        options = resolver.parse_args(argv[1:])
        try:
            print(json.dumps({"relative_path": resolve_local_finding(options.run_directory, options.source_alias)},
                             ensure_ascii=False))
        except (OSError, ValueError, KeyError, TypeError):
            resolver.error("The local finding could not be verified")
        return 0
    if argv and argv[0] == "unsafe-local-run":
        print("unsafe-local-run is deprecated. Use verify-helper run for local execution.", file=sys.stderr)
    if argv and argv[0] in {"run", "unsafe-local-run"}:
        argv.pop(0)
    parser = argparse.ArgumentParser(prog="verify-helper", description="Run full project verification")
    if any(arg.split("=", 1)[0] in {"--fast", "--checks", "--stage"} for arg in argv):
        parser.error("Selective and fast verification were removed. Use verify-helper run PROJECT.")
    parser.add_argument("project", nargs="?")
    parser.add_argument("--evidence-dir", type=Path, help="Directory for per-run evidence")
    parser.add_argument("--against", help="Verify the Git merge result against this ref")
    parser.add_argument("--revision", help="Require this exact clean Git checkout")
    parser.add_argument("--policy-path", type=Path, help="JSON policy that can add required checks")
    parser.add_argument("--json", nargs="?", const="-", metavar="FILE")
    parser.add_argument("--sarif", type=Path)
    parser.add_argument("--list-checks", action="store_true")
    parser.add_argument("--local-finding-index", action="store_true",
                        help="Keep an authenticated-by-manifest source index in the local evidence directory")
    options = parser.parse_args(argv)
    if options.list_checks:
        print(core.list_checks_text())
        return 0
    if not options.project:
        parser.error("project is required")
    report = full_verify(options.project,
                         evidence_dir=options.evidence_dir, against=options.against,
                         revision=options.revision, policy_path=options.policy_path,
                         local_locations=options.local_finding_index)
    if options.sarif:
        private_write(options.sarif, json.dumps(report["sarif"]).encode())
    if options.json:
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        if options.json == "-":
            print(encoded)
        else:
            private_write(Path(options.json), (encoded + "\n").encode())
    else:
        print(f"{report['verdict']}  {report.get('project', 'FULL')}  v{core.VERSION}")
        for row in report["checks"]:
            if row["id"] in report["plan"]:
                print(f"  {row['state']:7} {row['id']} — {row.get('detail') or row.get('reason_code') or row['title']}")
        for reason in report["blockers"]:
            print(f"  {reason}")
        if report.get("evidence_dir"):
            print(f"  Evidence {report['evidence_dir']}")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
