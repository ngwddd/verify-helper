"""Full verification adapters for toolchains, contracts and delivery files."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version

import verify_core as core

NATIVE = core.NATIVE_EXT
TYPESCRIPT = {".ts", ".tsx", ".mts", ".cts", ".jsx"}


def check(identifier: str, detail: str, state: str = "UNKNOWN") -> core.Check:
    return core.Check(identifier, identifier, state=state, risk="high", detail=detail)


def command(identifier: str, argv: list[str], root: Path, timeout: int = 180) -> core.Check:
    result = check(identifier, "Command completed")
    executable = argv[0]
    local = root / executable
    resolved = shutil.which(executable)
    if local.is_file() and Path(executable).parent != Path("."):
        resolved = str(local)
    if not resolved and local.is_file():
        resolved = str(local)
    if not resolved:
        result.detail = f"Required command is unavailable: {executable}"
        return result
    result.command = " ".join(argv)
    result.exit_code, output = core._run([resolved, *argv[1:]], root, timeout)
    result.output = output[-16000:]
    if result.exit_code in {124, 125, 126, 127, 9009} or result.exit_code < 0:
        result.detail = f"Execution unavailable (exit {result.exit_code})"
    else:
        result.state = "PASS" if result.exit_code == 0 else "FAIL"
        result.coverage = {"planned": 1, "observed": 1}
    return result


def chain(identifier: str, commands: list[list[str]], root: Path) -> core.Check:
    log = []
    for index, argv in enumerate(commands, 1):
        result = command(identifier, argv, root)
        log.append(f"$ {result.command}\n{result.output}")
        if result.state != "PASS":
            break
    result.output = "\n".join(log)
    result.coverage = {"planned": len(commands), "observed": index if result.state == "PASS" else index - 1}
    return result


def cmake_environment_missing(output: str) -> bool:
    return bool(re.search(r"CMAKE_(?:C|CXX)_COMPILER not set|"
                          r"No CMAKE_(?:C|CXX)_COMPILER could be found|"
                          r"CMake was unable to find a build program|"
                          r"Could not find the compiler specified", output, re.I))


def ctest(root: Path, build: Path) -> core.Check:
    # CTest reports "No tests were found" with exit 0 in older installations.
    result = command("tests-native", ["ctest", "--test-dir", str(build), "--build-config",
                                      "Release", "--no-tests=error", "--output-on-failure"], root)
    if "No tests were found" in result.output:
        result.state = "UNKNOWN"
        result.detail = "CTest did not discover native tests"
    if result.state == "PASS":
        summary = re.search(r"^100% tests passed(?:, 0 tests failed)? out of (\d+)",
                            result.output, re.M)
        if summary:
            skipped = len(re.findall(r"^\s*\d+/\d+ Test .*?(?:Skipped|Not Run|Disabled)",
                                     result.output, re.M))
            planned = int(summary[1])
            result.coverage = {"planned": planned, "observed": max(0, planned - skipped)}
            if not planned or skipped:
                result.state = "UNKNOWN"
                result.detail = "CTest did not execute every discovered case"
        else:
            result.state = "UNKNOWN"
            result.detail = "CTest did not report a completed test count"
    return result


def typescript(root: Path, configs: list[Path], sources: list[Path]) -> core.Check:
    if not configs:
        return check("typescript", "No tsconfig.json covers these sources")
    tsc = os.environ.get("VERIFY_TSC", "tsc")
    observed = set()
    logs = []
    for config in configs:
        result = command("typescript", [tsc, "--noEmit", "--listFiles", "--pretty", "false",
                                       "-p", config.as_posix()], root)
        if result.state != "PASS":
            return result
        logs.append(result.output)
        for line in result.output.splitlines():
            path = Path(line.strip())
            if path.is_absolute() and path.is_relative_to(root):
                observed.add(path.relative_to(root))
    missing = sorted(set(sources) - observed)
    result.coverage = {"planned": len(sources), "observed": len(sources) - len(missing)}
    result.output = "\n".join(logs)[-16000:]
    if missing:
        result.state = "UNKNOWN"
        result.detail = f"Compiler evidence is missing for {len(missing)} source files"
        result.findings = [{"file": path.as_posix(), "message": "Source was outside the compiler evidence"}
                           for path in missing]
    return result


def contract(identifier: str, row: object, root: Path) -> core.Check:
    if not isinstance(row, dict):
        return check(identifier, "No executable contract configured")
    argv = row.get("argv")
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(part, str) or not part for part in argv)):
        return check(identifier, "Contract argv must be a nonempty array of strings", "FAIL")
    if argv[0] == "python":
        argv = [core._py_for(root), *argv[1:]]
    marker = row.get("expect_output")
    if not isinstance(marker, str) or not marker.strip():
        return check(identifier, "Contract must declare a nonempty expect_output line", "FAIL")
    result = command(identifier, argv, root)
    if result.state == "PASS" and marker not in result.output.splitlines():
        result.state = "FAIL"
        result.detail = "Output did not contain the expected assertion line"
    return result


def _validate_names(names: list[str]) -> None:
    if not names:
        raise ValueError("Archive is empty")
    normalized = set()
    reserved = {"con", "prn", "aux", "nul",
                *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    for name in names:
        path = PurePosixPath(name)
        if (not name or path == PurePosixPath(".") or path.is_absolute() or
                ".." in path.parts or "\\" in name or ":" in name or
                any(part.rstrip(" .") != part or part.split(".")[0].casefold() in reserved
                    for part in path.parts) or any(ord(char) < 32 for char in name)):
            raise ValueError("Archive contains an unsafe path")
        canonical = path.as_posix().casefold()
        if canonical in normalized:
            raise ValueError("Archive contains duplicated or case-colliding paths")
        normalized.add(canonical)


def _metadata_identity(data: bytes) -> tuple[str, Version]:
    metadata = BytesParser().parsebytes(data, headersonly=True)
    if not metadata["Name"] or not metadata["Version"]:
        raise ValueError("Delivery metadata has no project name or version")
    return canonicalize_name(metadata["Name"]), Version(metadata["Version"])


def _check_wheel(archive: zipfile.ZipFile, files: set[str], path: Path) -> None:
    records = [name for name in files if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ValueError("Wheel requires exactly one RECORD")
    record = records[0]
    directory = record.rsplit("/", 1)[0]
    if not {f"{directory}/METADATA", f"{directory}/WHEEL"}.issubset(files):
        raise ValueError("Wheel metadata is incomplete")
    expected_name, expected_version, _, _ = parse_wheel_filename(path.name)
    actual_name, actual_version = _metadata_identity(archive.read(f"{directory}/METADATA"))
    if (actual_name, actual_version) != (expected_name, expected_version):
        raise ValueError("Wheel name or version differs from METADATA")
    seen = set()
    rows = csv.reader(io.TextIOWrapper(archive.open(record), encoding="utf-8", newline=""))
    for path, digest, size in rows:
        if path in seen or path not in files:
            raise ValueError("Wheel RECORD contains duplicate or missing members")
        seen.add(path)
        if path == record:
            if digest or size:
                raise ValueError("Wheel RECORD describes itself with a checksum")
            continue
        if not digest.startswith("sha256="):
            raise ValueError("Wheel file has no SHA-256 digest")
        with archive.open(path) as stream:
            hashed = hashlib.file_digest(stream, "sha256").digest()
        actual = base64.urlsafe_b64encode(hashed).decode().rstrip("=")
        if digest != f"sha256={actual}" or str(archive.getinfo(path).file_size) != size:
            raise ValueError("Wheel member checksum or size differs from RECORD")
    if seen != files:
        raise ValueError("Wheel contains files missing from RECORD")


def archive(identifier: str, path: Path, expected: object = None) -> core.Check:
    result = check(identifier, "Delivery file is unavailable")
    if not path.is_file():
        return result
    if expected is not None and (not isinstance(expected, dict)
            or not isinstance(expected.get("sha256"), str)
            or not isinstance(expected.get("members"), list)
            or not expected["members"]
            or any(not isinstance(name, str) for name in expected["members"])):
        return check(identifier, "Delivery contract requires sha256 and a nonempty members array", "FAIL")
    try:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected and digest.lower() != expected["sha256"].lower():
            raise ValueError("Delivery hash differs from declared SHA-256")
        if path.suffix.lower() in {".zip", ".whl"}:
            with zipfile.ZipFile(path) as package:
                members = package.infolist()
                _validate_names([entry.filename for entry in members])
                if any(stat.S_ISLNK(entry.external_attr >> 16) for entry in members):
                    raise ValueError("ZIP contains a symbolic link")
                if sum(entry.file_size for entry in members) > 512 * 1024 * 1024:
                    return check(identifier, "ZIP exceeds verified uncompressed size limit")
                if package.testzip() is not None:
                    raise ValueError("ZIP CRC verification failed")
                names = {entry.filename for entry in members if not entry.is_dir()}
                if path.suffix.lower() == ".whl":
                    _check_wheel(package, names, path)
        elif path.name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(path, "r:gz") as package:
                members = []
                total = 0
                for entry in package:
                    total += entry.size
                    if total > 512 * 1024 * 1024 or len(members) >= 200_000:
                        return check(identifier, "Tar exceeds verified size or member limit")
                    members.append(entry)
                _validate_names([entry.name for entry in members])
                if any(not (e.isfile() or e.isdir()) for e in members):
                    raise ValueError("Tar contains a link or special file")
                names = {entry.name for entry in members if entry.isfile()}
                for entry in members:
                    if entry.isfile():
                        with package.extractfile(entry) as stream:
                            hashlib.file_digest(stream, "sha256")
                metadata = sorted(name for name in names if PurePosixPath(name).match("*/PKG-INFO")
                                  and len(PurePosixPath(name).parts) == 2)
                if metadata and path.name.endswith(".tar.gz"):
                    with package.extractfile(metadata[0]) as stream:
                        identity = _metadata_identity(stream.read())
                    if len(metadata) != 1 or identity != parse_sdist_filename(path.name):
                        raise ValueError("Source distribution name or version differs from PKG-INFO")
        else:
            return check(identifier, "Delivery format is unsupported")
        if not names or (expected and not set(expected["members"]).issubset(names)):
            raise ValueError("Delivery package is empty or missing required members")
        result.state = "PASS"
        result.detail = f"Validated {len(names)} members; SHA-256 {digest}"
        result.coverage = {"planned": len(names), "observed": len(names)}
    except (OSError, ValueError, UnicodeError, csv.Error, KeyError, EOFError,
            RuntimeError, zipfile.BadZipFile, tarfile.TarError) as error:
        result.state = "FAIL"
        result.detail = f"Unable to verify delivery: {error}"
    return result


def read_config(root: Path) -> dict:
    config = root / "verify.toml"
    if not config.is_file():
        return {}
    document = core.tomllib.loads(config.read_text(encoding="utf-8-sig"))
    data = document.get("verification", {})
    if not isinstance(data, dict):
        raise ValueError("verification must be a TOML table")
    extra = set(data) - {"contracts", "delivery", "build", "runtime", "mutation", "npm_test"}
    if "npm_test" in data and type(data["npm_test"]) is not bool:
        raise ValueError("npm_test must be a boolean")
    if extra:
        raise ValueError("Unknown verification configuration fields")
    for key in ("contracts", "delivery"):
        rows = data.get(key, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"verification.{key} must contain an array of tables")
    if "mutation" in data and not isinstance(data["mutation"], bool):
        raise ValueError("verification.mutation must be boolean")
    return data


def relative_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("A project-relative path is required")
    path = Path(value)
    if path.is_absolute() or path.drive or ".." in path.parts:
        raise ValueError("A project-relative path is required")
    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Path is outside the project")
    return candidate
