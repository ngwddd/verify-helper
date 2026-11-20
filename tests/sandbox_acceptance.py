"""Execute boundary checks against a real Linux Docker daemon."""
from pathlib import Path
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from full_verify import full_verify
from isolated_runtime import IMAGE_VARIABLE, TIME_VARIABLE, BoundaryUnavailable, run_isolated
from run_evidence import read_evidence


class LinuxIsolationAcceptance(unittest.TestCase):
    def setUp(self):
        self.image = os.environ[IMAGE_VARIABLE]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "snapshot"
        self.source.mkdir()

    def protected(self, script, cancelled=lambda: False):
        return run_isolated(self.source, Path("."), ["/usr/local/bin/python", "-c", script],
                            self.image, cancelled).exit_code

    def test_host_file_environment_and_identity(self):
        sentinel = self.base / "host-only"
        sentinel.write_text("synthetic-private-input", encoding="utf-8")
        (self.source / "allowed.txt").write_text("snapshot-input", encoding="utf-8")
        os.environ["VH_FIXTURE_PRIVATE"] = "synthetic-private-input"
        self.addCleanup(os.environ.pop, "VH_FIXTURE_PRIVATE", None)
        code = self.protected(f"""
import os
from pathlib import Path
assert Path('allowed.txt').read_text() == 'snapshot-input'
assert not Path({str(sentinel)!r}).exists()
assert not Path('/proc/1/root' + {str(sentinel)!r}).exists()
assert not Path('/var/run/docker.sock').exists()
assert 'VH_FIXTURE_PRIVATE' not in os.environ
assert os.geteuid() == 65532
status = Path('/proc/self/status').read_text()
assert 'CapEff:\\t0000000000000000' in status
assert 'NoNewPrivs:\\t1' in status
assert 'Seccomp:\\t2' in status
""")
        self.assertEqual(code, 0)

    def test_default_network_has_no_host_listener_or_external_route(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            code = self.protected(f"""
import os, socket
from pathlib import Path
assert [name for _, name in socket.if_nameindex()] == ['lo']
assert not Path('/proc/net/route').read_text().splitlines()[1:]
assert not any('proxy' in name.lower() for name in os.environ)
with socket.socket() as client:
    assert client.connect_ex(('127.0.0.1', {port})) != 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    try:
        client.connect(('192.0.2.1', 53))
    except OSError:
        pass
    else:
        raise AssertionError('Unexpected IPv4 DNS route')
with socket.socket(socket.AF_INET6) as client:
    client.settimeout(1)
    try:
        client.connect(('2001:db8::1', 53))
    except OSError:
        pass
    else:
        raise AssertionError('Unexpected IPv6 route')
""")
        self.assertEqual(code, 0)

    def test_root_is_read_only_and_temporary_paths_are_writable(self):
        code = self.protected("""
import errno
from pathlib import Path
assert Path('/tmp').is_dir()
Path('/tmp/local-test').write_text('ok')
Path('workspace-test').write_text('ok')
try:
    Path('/etc/hosts').write_text('fixture')
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EROFS)
else:
    raise AssertionError('System file is writable')
""")
        self.assertEqual(code, 0)

    def test_cancellation_removes_container(self):
        baseline = self.containers()
        deadline = time.monotonic() + 20

        def cancelled():
            return time.monotonic() >= deadline or bool(self.containers(running=True) - baseline)

        with self.assertRaisesRegex(BoundaryUnavailable, "cancelled"):
            self.protected("import time; time.sleep(60)", cancelled)
        self.assertEqual(self.containers(), baseline)

    def test_timeout_removes_container(self):
        baseline = self.containers()
        with patch.dict(os.environ, {TIME_VARIABLE: "5"}):
            with self.assertRaises(BoundaryUnavailable):
                self.protected("import time; time.sleep(60)")
        self.assertEqual(self.containers(), baseline)

    @staticmethod
    def containers(running=False):
        args = [] if running else ["-a"]
        listing = subprocess.check_output(["docker", "ps", *args, "--filter", "name=vh-isolated-",
                                           "--format={{.Names}}"], text=True, timeout=10)
        return set(listing.splitlines())

    def test_full_engine_discards_guest_output_and_withholds_release(self):
        marker = "c2VhbGVkLXRlc3Qtb3V0cHV0LWN1c3RvbQ"
        (self.source / "test_suite.py").write_text(
            "import unittest\nclass TestSuite(unittest.TestCase):\n"
            f"    def test_runtime(self): print({marker!r}); self.assertEqual(2, 2)\n", encoding="utf-8")
        store = self.base / "receipts"
        report = full_verify(self.source, evidence_dir=store)
        self.assertEqual(report["verdict"], "UNKNOWN")
        self.assertFalse(report["releasable"])
        tests = next(row for row in report["checks"] if row["id"] == "tests")
        self.assertEqual(tests["reason_code"], "ISOLATED_TEST_ORACLE_UNVERIFIED")
        self.assertEqual(tests["isolation_receipt"]["image_digest"], self.image)
        self.assertFalse(tests["isolation_receipt"]["verified"])
        archive = store / report["run_id"]
        self.assertEqual(read_evidence(archive), report)
        for path in archive.iterdir():
            self.assertNotIn(marker.encode(), path.read_bytes())

    def test_second_unprivileged_user_cannot_read_receipts(self):
        self.base.chmod(0o755)
        store = self.base / "receipts"
        (self.source / "README.md").write_text("Public test input.\n", encoding="utf-8")
        report = full_verify(self.source, evidence_dir=store)
        archive = store / report["run_id"]
        for filename in ("report.json", "manifest.json", "results.sarif"):
            path = archive / filename
            self.assertTrue(path.is_file())
            other = subprocess.run(["sudo", "-n", "-u", "nobody", "/usr/bin/stat", str(path)],
                                   capture_output=True, env={**os.environ, "LC_ALL": "C"}, timeout=5)
            self.assertNotEqual(other.returncode, 0)
            self.assertIn(b"Permission denied", other.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
