"""Plan and execute full verification, then issue a fail-closed verdict."""
from __future__ import annotations

import argparse
import hashlib
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
from contextlib import ExitStack
from pathlib import Path

import check_specs
import isolated_runtime
import report_export
import sarif
import verification_adapters as adapters
import verify_core as core
from process_boundary import contain_worker
from run_evidence import digest as evidence_digest, plan_digest, read_evidence, set_gate_fields, write_manifest

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


def _protected_copy(source: Path, relative: Path, destination: Path, expected) -> None:
    with ExitStack() as handles:
        directory_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY
        parent = os.open(source, directory_flags)
        handles.callback(os.close, parent)
        for name in relative.parent.parts:
            parent = os.open(name, directory_flags, dir_fd=parent)
            handles.callback(os.close, parent)
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(fd)
            if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
                    or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
                raise ValueError("Snapshot source changed before it could be opened")
            with destination.open("xb") as target:
                remaining = expected.st_size
                while remaining:
                    chunk = stream.read(min(remaining, 256 * 1024))
                    if not chunk:
                        raise ValueError("Snapshot source shrank while being copied")
                    target.write(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    raise ValueError("Snapshot source grew while being copied")
            destination.chmod(0o700 if actual.st_mode & stat.S_IXUSR else 0o600)


def _snapshot(source: Path, destination: Path, *, protected: bool = False) -> tuple[str, list[str]]:
    digest = hashlib.sha256()
    omitted = []
    total = 0

    def walk_error(error):
        raise error

    for folder, dirs, files in os.walk(source, onerror=walk_error):
        current = Path(folder)
        relative = current.relative_to(source)
        (destination / relative).mkdir(parents=True, exist_ok=True)
        dirs[:] = sorted(name for name in dirs if name.lower() not in SNAPSHOT_EXCLUDES)
        for name in [*dirs, *sorted(files)]:
            if name.lower() in SNAPSHOT_EXCLUDES:
                continue
            path = current / name
            entry = path.lstat()
            display = (relative / name).as_posix()
            private = protected and (name.lower() in PRIVATE_INPUTS or name.lower().startswith(".env."))
            if private or stat.S_ISLNK(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 1024:
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
                omitted.append(display)
                continue
            copied = destination / relative / name
            if protected and sys.platform == "linux":
                _protected_copy(source, relative / name, copied, entry)
            else:
                shutil.copy2(path, copied)
            with copied.open("rb") as stream:
                checksum = hashlib.file_digest(stream, "sha256").hexdigest()
            latest = path.lstat()
            if (entry.st_mode, entry.st_size, entry.st_mtime_ns, entry.st_ino) != (
                    latest.st_mode, latest.st_size, latest.st_mtime_ns, latest.st_ino):
                omitted.append(display)
            digest.update(json.dumps([display, checksum], ensure_ascii=True).encode())
    return digest.hexdigest(), omitted


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


def _run_plan(root: Path, trusted: bool, policy_required: tuple[str, ...] = (),
              sandbox_image: str | None = None) -> dict:
    files, _, large, _ = core.scan_files(root)
    ctx = core.Ctx(core.Cache(False))
    config_error = None
    try:
        config = adapters.read_config(root)
    except (ValueError, OSError) as error:
        config = {}
        config_error = adapters.check("configuration", str(error), "FAIL")

    static = [identifier for identifier in check_specs.ordered_ids()
              if identifier not in DYNAMIC | {"git"}]
    report = core._verify_checks(str(root), checks=static, use_cache=False, artifacts=False,
                         review_md=False, allow_host_tools=trusted and sandbox_image is None)
    required = {}
    tasks = []
    rows = report["checks"]
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

    def run(identifier: str, description: str, action, *, requires_trust: bool = True, isolated=None):
        required[identifier] = description
        tasks.append((identifier, action, requires_trust, isolated))

    def execute(identifier, action, requires_trust, isolated):
        if core._worker_cancelled():
            result = adapters.check(identifier, "Verification was cancelled")
        elif requires_trust and (not trusted or any(
                row["id"] == "secrets" and row["state"] == "FAIL" for row in rows)):
            result = adapters.check(identifier, "Project code execution is unavailable")
        elif requires_trust and sandbox_image is not None:
            result = adapters.check(identifier, "Adapter is unavailable under the isolated execution policy")
            result.reason_code = "UNSUPPORTED_ISOLATED_ADAPTER"
            if isolated is not None:
                result = _isolated_unittest(root, isolated, identifier, sandbox_image)
        else:
            try:
                if requires_trust:
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
    if sandbox_image is not None:
        boundary = adapters.check("execution-isolation", "Isolation requires platform attestation")
        boundary.reason_code = "ISOLATION_UNAVAILABLE"
        add(boundary, "The configured isolation boundary must be independently attested")
    if large or len(files) >= 200_000:
        add(adapters.check("scan-coverage", "The source scan reached a size or file count limit"),
            "All applicable project inputs must be inventoried")

    html = any(file.suffix.lower() in core.HTML_EXT for file in files)
    if html:
        run("runtime-web", "HTML pages must be served over HTTP",
            lambda target: core.check_runtime_web(target, [target / p.relative_to(root) for p in files], ctx))
        run("browser", "HTML pages must load in a browser",
            lambda target: core.check_browser(target, [target / p.relative_to(root) for p in files], ctx))
    try:
        flow_data = core.tomllib.loads((root / "verify.toml").read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        flow_data = {}
    if "flows" in flow_data:
        run("interaction", "Configured browser flow assertions must execute",
            lambda target: core.check_interaction(target, [target / p.relative_to(root) for p in files], ctx))

    scopes = _scope(root, files)
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
                adapters.typescript(target / scope, configs, sources))
        languages = []
        if has_python:
            languages.append("python")
        if has_js and (not html or (scope / "package.json").is_file()
                       or core._detect_test_command(scope, "javascript")[0] is not None):
            languages.append("javascript")
        for language in languages:
            suffix = f"tests-{language}" if len(languages) > 1 else "tests"
            run(prefix + suffix, f"{language} code requires test evidence",
                lambda target, scope=relative_scope, files=relative_files, language=language:
                core.check_tests(target / scope, [target / p for p in files], ctx, language),
                isolated=relative_scope if language == "python" else None)

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
                lambda target, name=name: adapters.contract(name, config[name], target))
    for index, row in enumerate(config.get("contracts", []), 1):
        identifier = f"contract-{index}"
        run(identifier, "Project business contract assertion",
            lambda target, identifier=identifier, row=row: adapters.contract(identifier, row, target))
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

    for identifier in policy_required:
        required.setdefault(identifier, "Required by operator policy")
    report["plan"] = required
    report["plan_digest"] = plan_digest(required)
    for identifier, action, requires_trust, isolated in tasks:
        execute(identifier, action, requires_trust, isolated)
    by_id = {row["id"]: row for row in rows}
    for identifier in required:
        if identifier in by_id:
            by_id[identifier]["applicable"] = True
        else:
            record(adapters.check(identifier, "Required check unavailable"))
    return report


def _isolated_unittest(root: Path, scope: Path, identifier: str, image: str) -> core.Check:
    command, _, _ = core._detect_test_command(root / scope, "python")
    result = adapters.check(identifier, "A supported isolated test adapter is required")
    result.reason_code = "UNSUPPORTED_ISOLATED_ADAPTER"
    if not command or command[1:3] != ["-m", "unittest"]:
        return result
    try:
        code = isolated_runtime.run_isolated(root, scope, ["/usr/local/bin/python", *command[1:]],
                                             image, core._worker_cancelled)
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError):
        result.reason_code = "ISOLATION_UNAVAILABLE"
    else:
        result.reason_code = "ISOLATED_TEST_ORACLE_UNVERIFIED" if code == 0 else "ISOLATED_PROCESS_NONZERO"
    return result


def _worker(root: Path, trusted: bool, result_path: Path, policy_required: tuple[str, ...] = (),
            sandbox_image: str | None = None, sealed: bool = False) -> None:
    report = _run_plan(root, trusted, policy_required, sandbox_image)
    if sealed:
        result_path.write_text(json.dumps(report_export.project_receipts(report)), encoding="utf-8")
        return
    for row in report["checks"]:
        evidence = row.get("evidence") or {}
        source = evidence.get("dir")
        if not source:
            continue
        destination = result_path.parent / "media" / hashlib.sha256(row["id"].encode()).hexdigest()
        destination.mkdir(parents=True, exist_ok=True)
        for path in Path(source).glob("*.png"):
            if path.is_file() and not path.is_symlink():
                name = hashlib.sha256(path.name.encode()).hexdigest() + ".png"
                shutil.copy2(path, destination / name)
        row["evidence"] = {"dir": str(destination), "count": len(list(destination.iterdir()))}
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
    if (report.get("merge_conflict") or
            report.get("lifecycle", {}).get("security", {}).get("blocked") or
            any(rows.get(key, {}).get("state") == "FAIL" for key in required)):
        return "FAIL"
    if (not required or report.get("blockers") or report.get("lifecycle_error")
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
    output.mkdir(parents=True, exist_ok=False)
    for index, row in enumerate(report["checks"], 1):
        evidence = row.pop("evidence", None)
        if evidence:
            picture_dir = Path(evidence["dir"]).resolve()
            if picture_dir.is_relative_to(work / "media"):
                row["media"] = []
                for path in sorted(picture_dir.glob("*.png")):
                    target = output / f"{index:03d}-{path.name}"
                    shutil.copy2(path, target)
                    with target.open("rb") as stream:
                        row["media"].append({"path": target.name,
                                             "sha256": hashlib.file_digest(stream, "sha256").hexdigest()})
        row["evidence_ref"] = f"check-{index:03d}.json"
        record = json.dumps(row, ensure_ascii=False, indent=2).encode()
        (output / row["evidence_ref"]).write_bytes(record)
        row["evidence_sha256"] = hashlib.sha256(record).hexdigest()


def _finalize(report: dict, output: Path | None) -> None:
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
    (output / "results.sarif").write_text(json.dumps(report["sarif"], ensure_ascii=False), encoding="utf-8")
    write_manifest(report, output)


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


def full_verify(project: str | Path, *, trusted: bool = False, evidence_dir: Path | None = None,
                against: str | None = None, revision: str | None = None,
                policy_path: Path | None = None, run_id: str | None = None, cancellation=None,
                sealed: bool = False) -> dict:
    root = Path(project).expanduser().resolve()
    run_id = run_id or uuid.uuid4().hex
    image = os.environ.get(isolated_runtime.IMAGE_VARIABLE)
    host_execution = trusted and image is None and not sealed
    sealed = not host_execution
    sandbox_image = image if trusted else "" if image is not None else None
    context = {"schema_version": SCHEMA_VERSION, "run_id": run_id, "version": core.VERSION,
               "mode": "full", "isolation": "linux-container-candidate" if image is not None
               else "temporary-source-snapshot",
               "trusted_project_code": host_execution, "platform": platform.system(),
               "python": platform.python_version(),
               "policy_digest": "sha256:" + evidence_digest(f"{core.VERSION}:{trusted}".encode())}
    if sealed:
        context["export_policy"] = "sealed"
    else:
        context["project"] = str(root)
    report = {**context, "checks": [], "plan": {}, "blockers": []}
    if not root.is_dir():
        report["blockers"].append("Project directory is unavailable")
        _finalize(report, None)
        return report

    git = _source_git(root) if host_execution else {}
    run_output = None
    try:
        scratch = Path(os.environ.get("VERIFY_SCRATCH_DIRECTORY", tempfile.gettempdir())).resolve()
        if scratch.is_relative_to(root):
            raise ValueError("Scratch directory must be outside the project")
        with tempfile.TemporaryDirectory(prefix="vh-", dir=scratch) as directory:
            work = Path(directory).resolve()
            snapshot = work / "project"
            source = root
            if (revision or against) and not host_execution:
                raise ValueError("Git verification is unavailable under the protected execution policy")
            if revision and (revision != git.get("head") or git.get("dirty") is not False):
                raise ValueError("Requested revision does not match a clean Git checkout")
            if against:
                if not git.get("head") or git.get("dirty") is not False:
                    raise ValueError("Merge verification requires a clean Git worktree")
                source, merge = _merge_snapshot(root, against, work)
                context["merge"] = merge
            digest, omitted = _snapshot(source, snapshot, protected=not host_execution)
            config = snapshot / "verify.toml"
            policy_material = {"engine": core.VERSION, "trusted": host_execution,
                               "sandbox_image": image if image and isolated_runtime.IMAGE_ID.fullmatch(image) else None,
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
            if "PLAYWRIGHT_BROWSERS_PATH" not in env:
                default = (Path(os.environ["LOCALAPPDATA"]) / "ms-playwright"
                           if os.name == "nt" and "LOCALAPPDATA" in os.environ else
                           Path.home() / ".cache" / "ms-playwright")
                if default.is_dir():
                    env["PLAYWRIGHT_BROWSERS_PATH"] = str(default)
            launch = work / "launch"
            with ExitStack() as stack:
                worker = stack.enter_context(subprocess.Popen([sys.executable, "-I", "-c",
                            "import json,sys; sys.path.insert(0,sys.argv[1]); "
                            "from pathlib import Path; from full_verify import _wait_for_launch,_worker; "
                            "_wait_for_launch(Path(sys.argv[6])); "
                            "_worker(Path(sys.argv[2]),sys.argv[3]=='True',Path(sys.argv[4]),json.loads(sys.argv[5]),"
                            "json.loads(sys.argv[7]),sys.argv[8]=='True')",
                            str(Path(__file__).resolve().parent), str(snapshot),
                            str(host_execution or sandbox_image is not None), str(result_path),
                            json.dumps(policy_required), str(launch),
                            json.dumps("" if omitted and sandbox_image is not None else sandbox_image), str(sealed)],
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
            report.update(context, snapshot_sha256=digest)
            if not sealed:
                report.update(git=git, omitted=omitted)
            if omitted:
                report["blockers"].append("Source snapshot contains omitted or changed entries")
            if stop_path.exists() or (cancellation is not None and cancellation.is_set()):
                report["status"] = "CANCELLED"
                report["blockers"].append("Verification was cancelled")
            if report.get("notes"):
                report["notes"] = [note.replace(str(snapshot), str(root)) for note in report["notes"]]
            output = _evidence_root(evidence_dir or Path.home() / ".verify-helper" / "cli-runs")
            run_output = output / run_id
            if not sealed:
                report["evidence_dir"] = str(run_output)
                report = scrub(report)
            _record_checks(report, run_output, work)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, MergeConflict):
            report["merge_conflict"] = True
        report["blockers"].append(f"Verification infrastructure failed ({type(error).__name__})")
    try:
        _finalize(report, run_output if run_output and run_output.is_dir() else None)
    except (OSError, ValueError) as error:
        report["blockers"].append(f"Cannot finalize evidence ({type(error).__name__})")
        _finalize(report, None)
    return scrub(report)


def _merge_snapshot(root: Path, base: str, work: Path) -> tuple[Path, dict]:
    import tarfile

    def git(*arguments):
        return subprocess.run(["git", *arguments], cwd=root, capture_output=True, timeout=60, check=True)

    commit = git("rev-parse", "--verify", "--end-of-options", base + "^{commit}").stdout.decode().strip()
    try:
        tree = git("merge-tree", "--write-tree", "HEAD", commit).stdout.decode().splitlines()[0]
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            raise MergeConflict("Git reported a merge conflict") from error
        raise
    archive = work / "merge.tar"
    with archive.open("wb") as stream:
        subprocess.run(["git", "archive", tree], cwd=root, stdout=stream,
                       stderr=subprocess.DEVNULL, timeout=60, check=True)
    destination = work / "merged"
    destination.mkdir()
    with tarfile.open(archive) as package:
        package.extractall(destination, filter="data")
    entries = git("ls-tree", "-r", "-z", tree).stdout.split(b"\0")
    for entry in filter(None, entries):
        meta, filename = entry.split(b"\t", 1)
        mode, kind, digest = meta.decode("ascii").split()
        file = destination / os.fsdecode(filename)
        if mode == "120000":
            continue  # Snapshot validation records symbolic links as omissions.
        if kind != "blob" or not file.is_file():
            raise ValueError("Git archive did not provide every merged file")
        with file.open("rb") as stream:
            hash_ = hashlib.new("sha1" if len(digest) == 40 else "sha256")
            hash_.update(f"blob {file.stat().st_size}\0".encode())
            while chunk := stream.read(256 * 1024):
                hash_.update(chunk)
        if hash_.hexdigest() != digest:
            raise ValueError("Git archive changed a file from the merged tree")
    return destination, {"base_commit": commit, "tree": tree}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        from server import main as serve
        serve(argv[1:])
        return 0
    if argv and argv[0] == "run":
        argv.pop(0)
    parser = argparse.ArgumentParser(prog="verify-helper", description="Run full project verification")
    if any(arg.split("=", 1)[0] in {"--fast", "--checks", "--stage"} for arg in argv):
        parser.error("Selective and fast verification were removed. Use verify-helper run PROJECT.")
    parser.add_argument("project", nargs="?")
    parser.add_argument("--trust-project-code", action="store_true",
                        help="Permit execution of code from a project you trust")
    parser.add_argument("--evidence-dir", type=Path, help="Directory for per-run evidence")
    parser.add_argument("--against", help="Verify the Git merge result against this ref")
    parser.add_argument("--revision", help="Require this exact clean Git checkout")
    parser.add_argument("--policy-path", type=Path, help="JSON policy that can add required checks")
    parser.add_argument("--json", nargs="?", const="-", metavar="FILE")
    parser.add_argument("--sarif", type=Path)
    parser.add_argument("--list-checks", action="store_true")
    options = parser.parse_args(argv)
    if options.list_checks:
        print(core.list_checks_text())
        return 0
    if not options.project:
        parser.error("project is required")
    report = full_verify(options.project, trusted=options.trust_project_code,
                         evidence_dir=options.evidence_dir, against=options.against,
                         revision=options.revision, policy_path=options.policy_path)
    if options.sarif:
        options.sarif.write_text(json.dumps(report.get("sarif") or
                                             json.loads(sarif.dumps(report, core.VERSION))),
                                 encoding="utf-8")
    if options.json:
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        if options.json == "-":
            print(encoded)
        else:
            Path(options.json).write_text(encoded + "\n", encoding="utf-8")
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
