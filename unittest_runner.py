"""Run project Python tests and report collected and executed coverage."""
import importlib.util
import json
import sys
import traceback
import unittest
from pathlib import Path


def run_unittest(names):
    root = Path.cwd()
    sys.path.insert(0, str(root))
    if (root / "src").is_dir():
        sys.path.insert(1, str(root / "src"))
    suite = unittest.TestSuite()
    collected = missing = errors = 0
    for index, name in enumerate(names):
        path = root / name
        parents = []
        parent = path.parent
        while parent != root and (parent / "__init__.py").is_file():
            parents.insert(0, parent.name)
            parent = parent.parent
        sys.path.insert(0, str(parent))
        try:
            module_name = ".".join([*parents, path.stem]) if parents else f"_vh_case_{index}_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            loader = unittest.TestLoader()
            tests = loader.loadTestsFromModule(module)
            if loader.errors:
                errors += 1
            elif tests.countTestCases():
                suite.addTests(tests)
                collected += 1
        except ModuleNotFoundError:
            missing += 1
        except Exception:
            errors += 1
            traceback.print_exc()
        finally:
            sys.path.pop(0)
    planned = suite.countTestCases()
    result = unittest.TextTestRunner().run(suite)
    data = {"files": collected, "planned": planned, "executed": result.testsRun,
            "skipped": len(result.skipped) + len(result.expectedFailures),
            "failed": len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses),
            "missing": missing, "errors": errors}
    return int(bool(data["failed"] or errors)), data


def run_pytest(names):
    data = dict.fromkeys(("files", "planned", "executed", "skipped", "failed", "missing", "errors"), 0)
    try:
        import pytest
    except ModuleNotFoundError:
        data["missing"] = 1
        return 4, data

    class Coverage:
        def __init__(self):
            self.items = {}
            self.finished = set()
            self.skipped = set()
            self.failed = set()
            self.collection_errors = 0

        def pytest_collection_finish(self, session):
            self.items = {item.nodeid: Path(item.path) for item in session.items}

        def pytest_collectreport(self, report):
            if report.failed:
                self.collection_errors += 1

        def pytest_runtest_logreport(self, report):
            if report.when == "call" or report.skipped or report.failed:
                self.finished.add(report.nodeid)
            if report.skipped or hasattr(report, "wasxfail"):
                self.skipped.add(report.nodeid)
            if report.failed:
                self.failed.add(report.nodeid)

    coverage = Coverage()
    sys.path.insert(0, str(Path.cwd()))
    code = pytest.main(["-q"], plugins=[coverage])
    inventory = {Path.cwd() / name for name in names}
    data.update(files=len({coverage.items[item] for item in coverage.finished & coverage.items.keys()} & inventory),
                planned=len(coverage.items), executed=len(coverage.finished), skipped=len(coverage.skipped),
                failed=len(coverage.failed), missing=coverage.collection_errors)
    return int(code), data


if __name__ == "__main__":
    mode, inventory_path = sys.argv[1:]
    files = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    exit_code, receipt = (run_pytest if mode == "pytest" else run_unittest)(files)
    print("VH_PY_TEST " + json.dumps(receipt), flush=True)
    sys.exit(exit_code)
