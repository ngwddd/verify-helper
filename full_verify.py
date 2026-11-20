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
import uuid
from pathlib import Path

import check_specs
import sarif
import verification_adapters as adapters
import verify_core as core

SCHEMA_VERSION = 1
DYNAMIC = {"tests", "browser", "interaction", "mutation", "runtime-web"}
SNAPSHOT_EXCLUDES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
                     ".verify-artifacts", ".verify-noise.json", ".verify-accept.json",
                     ".verify-python", ".pytest_cache", ".mypy_cache", ".tox"}
EXEC_ENV = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL",
            "VERIFY_TEST_PYTHON", "VERIFY_TSC", "VERIFY_PLAYWRIGHT_ROOT", "PLAYWRIGHT_BROWSERS_PATH",
            "VERIFY_NATIVE_FIXTURE", "CC", "CXX", "CMAKE_GENERATOR", "INCLUDE", "LIB", "LIBPATH"}


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


def _snapshot(source: Path, destination: Path) -> tuple[str, list[str]]:
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
            if stat.S_ISLNK(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 1024:
                omitted.append(display)
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            total += entry.st_size
            if total > 1024 ** 3:
                raise ValueError("Snapshot exceeds the 1 GiB verification limit")
            if not stat.S_ISREG(entry.st_mode):
                omitted.append(display)
                continue
            copied = destination / relative / name
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


def _run_plan(root: Path, trusted: bool) -> dict:
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
                         review_md=False)
    required = {}
    rows = report["checks"]
    for row in rows:
        if row["applicable"] and (row["blocking"] or row["id"] == "custom"):
            required[row["id"]] = "Applicable source and configuration checks"

    def add(result: core.Check, reason: str, identifier: str | None = None):
        if identifier is not None:
            result.id = identifier
        result.applicable = True
        required[result.id] = reason
        rows.append(result.as_dict())

    def run(identifier: str, description: str, action, *, requires_trust: bool = True):
        if requires_trust and (not trusted or any(
                row["id"] == "secrets" and row["state"] == "FAIL" for row in rows)):
            result = adapters.check(identifier, "Project code execution is unavailable")
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
        add(result, description, identifier)

    if config_error is not None:
        add(config_error, "Verification configuration must parse")
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

            def native(target):
                source = target / relative_scope
                build = target.parent / "native-build"
                result = adapters.chain("build-native", [
                    ["cmake", "-S", str(source), "-B", str(build)],
                    ["cmake", "--build", str(build), "--config", "Release"],
                ], source)
                if result.state == "PASS":
                    add(adapters.ctest(source, build), "Native runtime and tests must execute", native_tests)
                return result

            run(prefix + "build-native", "CMake sources must compile", native)
            if native_tests not in required:
                add(adapters.check(native_tests, "Native build is unavailable"),
                    "Native runtime and tests must execute")
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
                lambda target: adapters.typescript(target / relative_scope, configs, sources))
        languages = []
        if has_python:
            languages.append("python")
        if has_js and (not html or (scope / "package.json").is_file()):
            languages.append("javascript")
        for language in languages:
            suffix = f"tests-{language}" if len(languages) > 1 else "tests"
            run(prefix + suffix, f"{language} code requires test evidence",
                lambda target: core.check_tests(target / relative_scope,
                                                [target / p for p in relative_files], ctx, language))

    if config.get("mutation"):
        tests = next((row for row in rows if row["id"] in {"tests", "tests-python"}), None)
        if tests and tests["state"] == "PASS":
            run("mutation", "Project requires mutation checks",
                lambda target: core.check_mutation(target, [target / p.relative_to(root) for p in files], ctx))
        else:
            add(adapters.check("mutation", "Passing baseline test evidence is unavailable"),
                "Project requires mutation checks")
    for name in ("build", "runtime"):
        if name in config:
            run(name, f"Project {name} assertion",
                lambda target: adapters.contract(name, config[name], target))
    for index, row in enumerate(config.get("contracts", []), 1):
        identifier = f"contract-{index}"
        run(identifier, "Project business contract assertion",
            lambda target: adapters.contract(identifier, row, target))
    for index, row in enumerate(config.get("delivery", []), 1):
        identifier = f"delivery-{index}"
        run(identifier, "Delivery archive contents and digest",
            lambda target: adapters.archive(identifier, adapters.relative_path(target, row.get("path")), row),
            requires_trust=False)
    if not config.get("delivery") and (root / "dist").is_dir():
        for index, path in enumerate(sorted((root / "dist").iterdir()), 1):
            if not path.is_file() or path.name.startswith("."):
                continue
            identifier = f"delivery-{index}"
            run(identifier, "Detected delivery file", lambda target: adapters.archive(identifier, path),
                requires_trust=False)

    report["plan"] = required
    return report


def _worker(root: Path, trusted: bool, result_path: Path) -> None:
    report = _run_plan(root, trusted)
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


def decide(report: dict) -> str:
    """Compute the independent verdict from a required-check ledger and evidence."""
    rows = {row["id"]: row for row in report["checks"]}
    required = report["plan"]
    if (report.get("lifecycle", {}).get("security", {}).get("blocked") or
            any(rows.get(key, {}).get("state") == "FAIL" for key in required)):
        return "FAIL"
    if not required or report.get("blockers"):
        return "UNKNOWN"
    for key in required:
        row = rows.get(key, {})
        if row.get("state") != "PASS" or not row.get("applicable") or not row.get("evidence_ref"):
            return "UNKNOWN"
        coverage = row.get("coverage")
        if coverage and (coverage["planned"] <= 0 or coverage["observed"] != coverage["planned"]):
            return "UNKNOWN"
        if key == "browser" and not row.get("media"):
            return "UNKNOWN"
    return "PASS"


def _record(report: dict, output: Path, work: Path) -> None:
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
    report["verdict"] = decide(report)
    lifecycle = report.get("lifecycle")
    if lifecycle and "stage" in lifecycle:
        lifecycle["stage"]["verdict"] = report["verdict"]
    report["sarif"] = json.loads(sarif.dumps(report, core.VERSION))
    (output / "results.sarif").write_text(json.dumps(report["sarif"], ensure_ascii=False), encoding="utf-8")
    pending = output / "report.json.tmp"
    pending.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    pending.replace(output / "report.json")


def full_verify(project: str | Path, *, trusted: bool = False, evidence_dir: Path | None = None,
                against: str | None = None) -> dict:
    root = Path(project).expanduser().resolve()
    run_id = uuid.uuid4().hex
    context = {"schema_version": SCHEMA_VERSION, "run_id": run_id, "version": core.VERSION,
               "project": str(root), "mode": "full", "isolation": "temporary-source-snapshot",
               "trusted_project_code": trusted, "platform": platform.system(),
               "python": platform.python_version()}
    report = {**context, "checks": [], "plan": {}, "blockers": []}
    if not root.is_dir():
        report.update(verdict="UNKNOWN", blockers=["Project directory is unavailable"])
        return report

    git = _source_git(root)
    try:
        with tempfile.TemporaryDirectory(prefix="verify-helper-") as directory:
            work = Path(directory).resolve()
            snapshot = work / "project"
            source = root
            if against:
                if not git.get("head") or git.get("dirty") is not False:
                    raise ValueError("Merge verification requires a clean Git worktree")
                source, merge = _merge_snapshot(root, against, work)
                context["merge"] = merge
            digest, omitted = _snapshot(source, snapshot)
            result_path = work / "result.json"
            home = work / "home"
            home.mkdir()
            env = {key: value for key, value in os.environ.items() if key.upper() in EXEC_ENV}
            env.update({"HOME": str(home), "USERPROFILE": str(home), "LOCALAPPDATA": str(home),
                        "APPDATA": str(home), "TEMP": str(work), "TMP": str(work),
                        "TMPDIR": str(work), "PYTHONUTF8": "1", "PYTHONNOUSERSITE": "1",
                        "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                        "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_AUDIT": "false"})
            if "PLAYWRIGHT_BROWSERS_PATH" not in env:
                default = (Path(os.environ["LOCALAPPDATA"]) / "ms-playwright"
                           if os.name == "nt" and "LOCALAPPDATA" in os.environ else
                           Path.home() / ".cache" / "ms-playwright")
                if default.is_dir():
                    env["PLAYWRIGHT_BROWSERS_PATH"] = str(default)
            subprocess.run([sys.executable, "-I", "-c",
                            "import sys; sys.path.insert(0,sys.argv[1]); "
                            "from pathlib import Path; from full_verify import _worker; "
                            "_worker(Path(sys.argv[2]),sys.argv[3]=='True',Path(sys.argv[4]))",
                            str(Path(__file__).resolve().parent), str(snapshot), str(trusted), str(result_path)],
                           cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=1800)
            report.update(json.loads(result_path.read_text(encoding="utf-8")))
            report.update(context, git=git, snapshot_sha256=digest, omitted=omitted)
            if omitted:
                report["blockers"].append("Source snapshot contains omitted or changed entries")
            if report.get("notes"):
                report["notes"] = [note.replace(str(snapshot), str(root)) for note in report["notes"]]
            output = (evidence_dir or root / ".verify-artifacts").absolute()
            if output.resolve() != output:
                raise ValueError("Evidence directory may not traverse a symbolic link")
            report["evidence_dir"] = str(output / run_id)
            report = scrub(report)
            _record(report, output / run_id, work)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["blockers"].append(f"Verification infrastructure failed ({type(error).__name__})")
        report["verdict"] = decide(report)
        lifecycle = report.get("lifecycle")
        if lifecycle and "stage" in lifecycle:
            lifecycle["stage"]["verdict"] = report["verdict"]
    return scrub(report)


def _merge_snapshot(root: Path, base: str, work: Path) -> tuple[Path, dict]:
    import tarfile

    def git(*arguments):
        return subprocess.run(["git", *arguments], cwd=root, capture_output=True, timeout=60, check=True)

    commit = git("rev-parse", "--verify", "--end-of-options", base + "^{commit}").stdout.decode().strip()
    tree = git("merge-tree", "--write-tree", "HEAD", commit).stdout.decode().splitlines()[0]
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
    parser = argparse.ArgumentParser(prog="verify-helper", description="Run full project verification")
    parser.add_argument("project", nargs="?")
    parser.add_argument("--trust-project-code", action="store_true",
                        help="Permit execution of code from a project you trust")
    parser.add_argument("--evidence-dir", type=Path, help="Directory for per-run evidence")
    parser.add_argument("--against", help="Verify the Git merge result against this ref")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", type=Path)
    parser.add_argument("--list-checks", action="store_true")
    options = parser.parse_args(argv)
    if options.list_checks:
        print(core.list_checks_text())
        return 0
    if not options.project:
        parser.error("project is required")
    report = full_verify(options.project, trusted=options.trust_project_code,
                         evidence_dir=options.evidence_dir, against=options.against)
    if options.sarif:
        options.sarif.write_text(json.dumps(report.get("sarif") or
                                             json.loads(sarif.dumps(report, core.VERSION))),
                                 encoding="utf-8")
    if options.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"{report['verdict']}  {report['project']}  v{core.VERSION}")
        for row in report["checks"]:
            if row["id"] in report["plan"]:
                print(f"  {row['state']:7} {row['id']} — {row['detail']}")
        for reason in report["blockers"]:
            print(f"  {reason}")
        if report.get("evidence_dir"):
            print(f"  Evidence {report['evidence_dir']}")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
