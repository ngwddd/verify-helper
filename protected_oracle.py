"""Run operator-authored behavioral assertions outside the tested process."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path, PurePosixPath

from isolated_runtime import OUTPUT_LIMIT, run_isolated
from private_storage import require_private

POLICY_VARIABLE = "VERIFY_HELPER_ORACLE_POLICY"
ENTRY = re.compile(r"(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*"
                   r"\.(?:py|js|mjs|cjs|c|cc|cpp|cxx)")
POLICY_LIMIT = 128 * 1024
NATIVE_ENTRY = (
    'bin_dir=$(/usr/bin/mktemp -d /workspace/.verify-native.XXXXXXXX) || exit 125\n'
    'compiler=$1; source=$2; shift 2\n'
    '"$compiler" "$source" -o "$bin_dir/program" || exit "$?"\n'
    'exec "$bin_dir/program" "$@"'
)


def load(path: Path, project: Path, snapshot_digest: str):
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_relative_to(project):
        raise ValueError("Oracle policy must be outside the project")
    require_private(path)
    with path.open("rb") as stream:
        raw = stream.read(POLICY_LIMIT + 1)
    if len(raw) > POLICY_LIMIT:
        raise ValueError("Oracle policy exceeds its input budget")
    policy = json.loads(raw)
    if (not isinstance(policy, dict) or set(policy) != {"project", "snapshot_sha256", "entry", "cases"}
            or not isinstance(policy["project"], str)
            or Path(policy["project"]) != project or policy["snapshot_sha256"] != snapshot_digest):
        raise ValueError("Oracle policy must bind the exact project and snapshot")
    entry = policy["entry"]
    cases = policy["cases"]
    if not isinstance(entry, str) or not ENTRY.fullmatch(entry) or not isinstance(cases, list) or not 2 <= len(cases) <= 8:
        raise ValueError("Oracle policy must describe a supported source entry and two to eight cases")
    inputs, outputs = set(), set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"argv", "stdout", "exit_code"}:
            raise ValueError("Oracle policy has an invalid case")
        argv, stdout, code = case["argv"], case["stdout"], case["exit_code"]
        if (not isinstance(argv, list) or len(argv) > 16
                or not all(isinstance(arg, str) and len(arg.encode("utf-8")) <= 1024 and "\0" not in arg for arg in argv)
                or not isinstance(stdout, str) or not 0 < len(stdout.encode("utf-8")) <= OUTPUT_LIMIT
                or type(code) is not int or code not in (0, 1)):
            raise ValueError("Oracle policy has invalid inputs or expectations")
        inputs.add(tuple(argv))
        outputs.add((stdout, code))
    if len(inputs) != len(cases) or len(outputs) < 2:
        raise ValueError("Oracle cases require distinct inputs and at least two expected outcomes")
    return raw, {"entry": entry, "cases": cases}


def run(root, policy, image, cancelled):
    """Return only counts and fixed status codes to the evidence writer."""
    entry = PurePosixPath(policy["entry"])
    suffix = entry.suffix
    native = suffix in {".c", ".cc", ".cpp", ".cxx"}
    if suffix == ".py":
        runner = ["/usr/local/bin/python", "-I", "-S"]
    elif suffix in {".js", ".mjs", ".cjs"}:
        runner = ["/usr/local/bin/node"]
    else:
        compiler = "/usr/local/bin/gcc" if suffix == ".c" else "/usr/local/bin/g++"
        runner = ["/bin/sh", "-c", NATIVE_ENTRY, "verify-native", compiler]
    cases = policy["cases"]
    completed = failed = 0
    for case in cases:
        if cancelled():
            break
        command = [*runner, "/workspace/" + entry.as_posix(), *case["argv"]]
        try:
            result = run_isolated(root, Path("."), command, image, cancelled,
                                  expected_output=case["stdout"].encode("utf-8"), allow_guest_executable=native)
        except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError):
            break
        completed += 1
        if not result.output_matches or result.exit_code != case["exit_code"]:
            failed += 1
    coverage = {"planned": len(cases), "observed": completed}
    if failed:
        return "FAIL", "BEHAVIOR_CONTRACT_MISMATCH", coverage
    if completed != len(cases):
        return "UNKNOWN", "BEHAVIOR_CONTRACT_INCOMPLETE", coverage
    return "PASS", "BEHAVIOR_CONTRACT_MATCHED", coverage
