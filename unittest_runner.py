"""Run project Python tests and report collected and executed coverage."""
import importlib.util
import fnmatch
import json
import re
import sys
import tomllib
import traceback
import unittest
from pathlib import Path


def missing_dependency(error, dependencies):
    # A missing submodule of an installed package is an import error.
    return (isinstance(error, ModuleNotFoundError) and error.name
            and error.name.lower().replace("_", "-") in dependencies)


def declared_dependencies(roots):
    declarations = []
    for root in roots:
        try:
            config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, ValueError):
            config = {}
        project = config.get("project", {})
        declarations.extend(project.get("dependencies", []))
        for group in (*project.get("optional-dependencies", {}).values(),
                      *config.get("dependency-groups", {}).values()):
            if isinstance(group, list):
                declarations.extend(group)
        for requirements in root.glob("requirements*.txt"):
            declarations.extend(requirements.read_text(encoding="utf-8-sig", errors="replace").splitlines())
    requirement_name = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9_-]*)(?=[\s\[<>=!~;@]|$)")
    return {match[1].lower().replace("_", "-") for line in declarations if isinstance(line, str)
            if (match := requirement_name.match(line))}


def empty_receipt(**updates):
    fields = ("planned_files", "files", "planned", "collected", "executed", "deselected",
              "skipped", "failed", "missing", "errors")
    return {**dict.fromkeys(fields, 0), **updates}


def run_unittest(names, dependencies):
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
        except Exception as error:
            if missing_dependency(error, dependencies):
                missing += 1
            else:
                errors += 1
                traceback.print_exc()
        finally:
            sys.path.pop(0)
    planned = suite.countTestCases()
    result = unittest.TextTestRunner().run(suite)
    data = empty_receipt(planned_files=len(names), files=collected, planned=planned, collected=planned,
                         executed=result.testsRun, skipped=len(result.skipped) + len(result.expectedFailures),
                         failed=len(result.failures) + len(result.errors) + len(result.unexpectedSuccesses),
                         missing=missing, errors=errors)
    return int(bool(data["failed"] or errors)), data


def run_pytest(names, dependencies):
    try:
        import pytest
    except ModuleNotFoundError:
        return 4, empty_receipt(missing=1)

    class Coverage:
        def __init__(self):
            self.items = {}
            self.discovered = set()
            self.deselected = set()
            self.finished = set()
            self.skipped = set()
            self.failed = set()
            self.collection_errors = set()
            self.missing = set()
            self.inventory = set()

        @pytest.hookimpl(hookwrapper=True, tryfirst=True)
        def pytest_collection_modifyitems(self, items):
            self.discovered.update(item.nodeid for item in items)
            yield

        def pytest_deselected(self, items):
            self.deselected.update(item.nodeid for item in items)

        def pytest_collection_finish(self, session):
            self.items = {item.nodeid: Path(item.path) for item in session.items}
            patterns = session.config.getini("python_files")
            self.inventory = {Path.cwd() / name for name in names
                              if any(fnmatch.fnmatchcase(Path(name).name, pattern) for pattern in patterns)}

        def pytest_collectreport(self, report):
            if report.failed:
                self.collection_errors.add(report.nodeid)

        def pytest_exception_interact(self, node, call, report):
            error = call.excinfo.value
            if missing_dependency(error, dependencies) or missing_dependency(error.__cause__, dependencies):
                self.missing.add(report.nodeid)

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
    finished = (coverage.finished & coverage.items.keys()) - coverage.missing
    executed_files = {coverage.items[item] for item in finished}
    planned_items = coverage.discovered | coverage.deselected | coverage.items.keys()
    data = empty_receipt(planned_files=len(coverage.inventory), files=len(executed_files & coverage.inventory),
                         planned=len(planned_items), collected=len(coverage.items), executed=len(finished),
                         deselected=len(planned_items - coverage.items.keys()),
                         skipped=len(coverage.skipped & finished), failed=len(coverage.failed - coverage.missing),
                         missing=len(coverage.missing), errors=len(coverage.collection_errors - coverage.missing))
    return int(code), data


if __name__ == "__main__":
    mode, inventory_path, project_root = sys.argv[1:]
    files = json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    dependencies = declared_dependencies(dict.fromkeys((Path.cwd(), Path(project_root))))
    exit_code, receipt = (run_pytest if mode == "pytest" else run_unittest)(files, dependencies)
    receipt["python_version"] = ".".join(map(str, sys.version_info[:3]))
    print("VH_PY_TEST " + json.dumps(receipt), flush=True)
    sys.exit(exit_code)
