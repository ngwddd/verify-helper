# -*- coding: utf-8 -*-
"""验证助手 · 符合性测试（conformance）

不是单元测试，是「喂一整个项目进去，看结论对不对」。

每个用例自己生成一个小项目（临时目录），跑一次 verify()，
把「总判定 + 关注的检查状态」和预期比对。

覆盖三件事：
  ① 真阳性：每个检查能抓到它该抓的
  ② 假阳性抵抗：看起来像问题、其实不是的，不能报
  ③ 三态：UNKNOWN 不能被当成 PASS；非阻断失败不能把总判定拉成 FAIL

跑法：python .dev/conformance.py [--verbose]
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import traceback
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import verify_core as V       # noqa: E402
import sarif as SARIF         # noqa: E402

CUR_USER = sorted(V._CURRENT_USERS)[0] if V._CURRENT_USERS else "someone"

# 夹具用的假密钥在运行期拼出来：源码里不留可被 secrets 规则命中的字面量
# （否则工具扫自己这个目录时会把测试夹具当成真凭据，属于典型的自我触发）。
FAKE_KEY = "sk-" + "abcdefghij" * 3

# 同理：夹具里的 Windows 家目录也在运行期拼，源码里不留可被 paths 规则命中的字面量
W = "C:" + chr(92) + "Users" + chr(92)


# ── 用例 ────────────────────────────────────────────────────────────
# files: {相对路径: str 或 bytes}
# checks: None = 跑默认全集；否则只跑列出的
# expect: {verdict: "...", states: {"check_id": "STATE"}, findings_at_least: {...}}

CASES = [
    # ① 干净项目
    dict(id="clean-py",
         files={"main.py": "import os\nprint(os.getcwd())\n",
                "tests/test_main.py": "import unittest\n\n"
                                      "class T(unittest.TestCase):\n"
                                      "    def test_x(self):\n"
                                      "        self.assertTrue(True)\n"},
         expect=dict(verdict="PASS", states={"syntax": "PASS", "imports": "PASS",
                                             "secrets": "PASS", "tests": "PASS"})),

    dict(id="empty-dir", files={},
         expect=dict(verdict="UNKNOWN")),

    dict(id="readme-only", files={"README.md": "# hi\n"},
         # 只有文档、没有源文件 -> 语法检查无对象可查，记 UNKNOWN 而不是 PASS
         expect=dict(verdict="PASS", states={"syntax": "UNKNOWN"})),

    # ② 每个检查的真阳性（只跑那一项，判定要干脆）
    dict(id="bad-syntax", files={"a.py": "def broken(:\n    pass\n"},
         checks=["syntax"],
         expect=dict(verdict="FAIL", states={"syntax": "FAIL"}, findings_at_least={"syntax": 1})),

    dict(id="dead-link", files={"index.html":
         '<!doctype html><html lang="zh"><head><title>t</title></head>'
         '<body><h1>x</h1><a href="nope.html">a</a></body></html>'},
         checks=["links"],
         expect=dict(verdict="FAIL", states={"links": "FAIL"}, findings_at_least={"links": 1})),

    dict(id="unclosed-tag", files={"index.html":
         '<!doctype html><html lang="zh"><head><title>t</title></head>'
         '<body><h1>x</h1><div><p>a</div></body></html>'},
         checks=["html"],
         expect=dict(verdict="FAIL", states={"html": "FAIL"}, findings_at_least={"html": 1})),

    dict(id="fake-secret", files={"a.py": f'API_KEY = "{FAKE_KEY}"\n'},
         checks=["secrets"],
         expect=dict(verdict="FAIL", states={"secrets": "FAIL"}, findings_at_least={"secrets": 1})),

    dict(id="gbk-bytes", files={"note.txt": "中文内容\n".encode("gbk")},
         checks=["encoding"],
         expect=dict(verdict="FAIL", states={"encoding": "FAIL"}, findings_at_least={"encoding": 1})),

    dict(id="bom-file", files={"style.css": b"\xef\xbb\xbfbody{margin:0}\n"},
         checks=["bom"],
         expect=dict(verdict="UNKNOWN", states={"bom": "FAIL"}, findings_at_least={"bom": 1})),

    dict(id="a11y-img", files={"index.html":
         '<!doctype html><html lang="zh"><head><title>t</title></head>'
         '<body><h1>x</h1><img src="a.png"></body></html>'},
         checks=["a11y"],
         expect=dict(verdict="UNKNOWN", states={"a11y": "FAIL"}, findings_at_least={"a11y": 1})),

    dict(id="unused-import", files={"a.py": "import json\nx = 1\n"},
         checks=["imports"],
         expect=dict(verdict="UNKNOWN", states={"imports": "FAIL"}, findings_at_least={"imports": 1})),

    dict(id="failing-test",
         files={"tests/test_x.py": "import unittest\n\n"
                                   "class T(unittest.TestCase):\n"
                                   "    def test_bad(self):\n"
                                   "        self.assertEqual(1, 2)\n"},
         checks=["tests"],
         expect=dict(verdict="FAIL", states={"tests": "FAIL"})),

    # ③ 假阳性抵抗
    dict(id="path-placeholder", files={"a.py": f'X = r"{W}<you>\\proj"\n'},
         checks=["paths"],
         expect=dict(verdict="UNKNOWN", states={"paths": "PASS"})),

    dict(id="path-other-user", files={"a.py": f'X = r"{W}someoneelse\\proj"\n'},
         checks=["paths"],
         expect=dict(verdict="UNKNOWN", states={"paths": "PASS"})),

    dict(id="path-own-user", files={"a.py": f'X = r"{W}{CUR_USER}\\proj"\n'},
         checks=["paths"],
         expect=dict(verdict="UNKNOWN", states={"paths": "FAIL"})),

    dict(id="single-quote-href", files={"index.html":
         "<!doctype html><html lang='zh'><head><title>t</title></head>"
         "<body><h1>x</h1><a href='nope.html'>a</a></body></html>"},
         checks=["links"],
         expect=dict(verdict="FAIL", states={"links": "FAIL"})),

    dict(id="ignored-dir",
         files={".verifyignore": "_sp/\n", "_sp/broken.py": "def (:\n", "main.py": "x = 1\n"},
         checks=["syntax"],
         expect=dict(verdict="PASS", states={"syntax": "PASS"})),

    dict(id="generated-dir",
         files={"main.py": "x = 1\n", "build/bad.py": "def (:\n"},
         checks=["syntax"],
         expect=dict(verdict="PASS", states={"syntax": "PASS"})),

    # ④ 三态规则
    dict(id="only-nonblocking-selected",
         files={"a.py": f'X = r"{W}{CUR_USER}\\proj"\n'},
         checks=["paths"],
         expect=dict(verdict="UNKNOWN")),

    dict(id="no-source-files", files={"data.bin": b"\x00\x01\x02"},
         checks=["syntax"],
         expect=dict(verdict="UNKNOWN")),

    # ⑤ 刁难它：外部链接 / 锚点 / 坏配置 / 奇怪文件名 / 二进制 / 嵌套 ignore
    dict(id="html-external+anchor", files={"index.html":
         '<!doctype html><html lang="zh"><head><title>t</title></head><body>'
         '<h1 id="top">x</h1>'
         '<a href="https://example.com">外链</a>'
         '<a href="mailto:a@b.c">邮件</a>'
         '<a href="#top">回顶部</a>'
         '<a href="javascript:void(0)">js</a>'
         '</body></html>'},
         checks=["links"],
         expect=dict(verdict="PASS", states={"links": "PASS"})),

    dict(id="html-broken-anchor", files={"index.html":
         '<!doctype html><html lang="zh"><head><title>t</title></head>'
         '<body><h1>x</h1><a href="#nope">坏锚点</a></body></html>'},
         checks=["links"],
         expect=dict(verdict="FAIL", states={"links": "FAIL"}, findings_at_least={"links": 1})),

    dict(id="broken-verify-toml", files={"a.py": "x = 1\n",
                                         "verify.toml": "[[rules]]\nid = \n"},
         checks=["custom"],
         # 配置坏了要报出来（而不是假装没配），custom 是中等风险所以不阻断总判定
         expect=dict(verdict="UNKNOWN", states={"custom": "FAIL"},
                     findings_at_least={"custom": 1})),

    dict(id="flow-without-steps", files={"a.py": "x = 1\n",
                                         "verify.toml": '[[flows]]\nname = "空"\n'},
         checks=["interaction"],
         expect=dict(verdict="UNKNOWN", states={"interaction": "UNKNOWN"})),

    dict(id="crlf-text", files={"a.txt": "line1\r\nline2\r\n"},
         checks=["encoding"],
         expect=dict(verdict="PASS", states={"encoding": "PASS"})),

    dict(id="empty-py", files={"a.py": ""},
         checks=["syntax"],
         expect=dict(verdict="PASS", states={"syntax": "PASS"})),

    dict(id="chinese+space-filename", files={
        "我的 站点/index.html":
            '<!doctype html><html lang="zh"><head><title>t</title></head>'
            '<body><h1>x</h1><a href="笔记 页.html">下一页</a></body></html>',
        "我的 站点/笔记 页.html":
            '<!doctype html><html lang="zh"><head><title>n</title></head>'
            '<body><h1>n</h1></body></html>'},
         checks=["links"],
         expect=dict(verdict="PASS", states={"links": "PASS"})),

    dict(id="invalid-utf8-bytes", files={"a.py": b"x = 1\n\xff\xfe\n"},
         checks=["encoding"],
         expect=dict(verdict="FAIL", states={"encoding": "FAIL"})),

    dict(id="nested-verifyignore",
         files={"sub/.verifyignore": "bad.py\n", "sub/bad.py": "def (:\n",
                "main.py": "x = 1\n"},
         checks=["syntax"],
         expect=dict(verdict="PASS", states={"syntax": "PASS"})),

    dict(id="custom-rule-hit",
         files={"a.py": "print('debug')\n",
                "verify.toml": '[[rules]]\nid = "no-print"\nseverity = "high"\n'
                               'pattern = "print\\\\("\nmessage = "不要留 print"\n'},
         checks=["custom"],
         expect=dict(verdict="FAIL", states={"custom": "FAIL"}, findings_at_least={"custom": 1})),

    dict(id="no-index-site", files={
        "notes.html": '<!doctype html><html lang="zh"><head><title>a</title></head>'
                      '<body><h1>x</h1></body></html>'},
         checks=["runtime-web"],
         expect=dict(verdict="UNKNOWN", states={"runtime-web": "UNKNOWN"})),

    dict(id="unknown-check-id", files={"a.py": "x = 1\n"},
         checks=["no-such-check"],
         expect=dict(verdict="UNKNOWN")),
]

# 输出契约类用例：单独跑
EXTRA = ["sarif_valid", "direction_gates", "determinism", "fail_on_exit", "render_version"]


def make_case(tmp: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8", newline="\n")
    return tmp


def run_cases(verbose: bool):
    rows, fails = [], []
    for c in CASES:
        tmp = Path(tempfile.mkdtemp(prefix=f"vh-cf-{c['id']}-"))
        try:
            make_case(tmp, c["files"])
            rep = V.verify(str(tmp), checks=c.get("checks"), fast=False, use_cache=False)
            got = {"verdict": rep["verdict"]}
            states = {x["id"]: x["state"] for x in rep["checks"]}
            ok = got["verdict"] == c["expect"]["verdict"]
            detail = []
            for cid, want in (c["expect"].get("states") or {}).items():
                actual = states.get(cid, "?")
                if actual != want:
                    ok = False
                    detail.append(f"{cid}: 期望 {want} 实际 {actual}")
            for cid, n in (c["expect"].get("findings_at_least") or {}).items():
                gotn = len(next((x["findings"] for x in rep["checks"] if x["id"] == cid), []))
                if gotn < n:
                    ok = False
                    detail.append(f"{cid}: 期望至少 {n} 条 finding，实际 {gotn}")
            if got["verdict"] != c["expect"]["verdict"]:
                detail.append(f"verdict: 期望 {c['expect']['verdict']} 实际 {got['verdict']}")
            rows.append((c["id"], c["expect"]["verdict"], got["verdict"], "✓" if ok else "✗"))
            if not ok:
                fails.append((c["id"], detail))
        except Exception:
            rows.append((c["id"], c["expect"]["verdict"], "异常", "✗"))
            fails.append((c["id"], [traceback.format_exc(limit=2)]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return rows, fails


def run_extra(verbose: bool):
    """输出契约：SARIF / 方向卡四闸 / 幂等 / 退出码 / 版本行。"""
    out = []

    def check(name, cond, detail=""):
        out.append((name, "✓" if cond else "✗", detail))

    tmp = Path(tempfile.mkdtemp(prefix="vh-cf-extra-"))
    try:
        make_case(tmp, {"index.html":
                        '<!doctype html><html lang="zh"><head><title>t</title></head>'
                        '<body><h1>x</h1><a href="nope.html">a</a></body></html>',
                        "a.py": "import json\n"})
        rep = V.verify(str(tmp), checks=["links", "imports"], use_cache=False)

        # SARIF
        try:
            s = SARIF.dumps(SARIF.to_sarif(rep))
            import json as J
            sd = J.loads(s)
            check("SARIF 合法", sd.get("version") == "2.1.0" and isinstance(sd.get("runs"), list))
            check("SARIF 只含未通过项",
                  all(r["level"] in ("error", "warning", "note")
                      for run in sd["runs"] for r in run.get("results", [])))
        except Exception as e:
            check("SARIF 合法", False, str(e)[:80])

        # 方向卡四闸
        links = next(x for x in rep["checks"] if x["id"] == "links")
        f0 = links["findings"][0] if links["findings"] else {}
        d = f0.get("direction") or {}
        check("失败项带方向卡", bool(d))
        check("方向卡四段齐全",
              all(k in d for k in ("class", "root_cause", "action", "must_not_touch", "verify")))
        check("方向卡引用了位置", bool(d.get("evidence")) and d["evidence"] in d.get("root_cause", ""))
        check("方向卡给了可执行验证", "verify_start(" in d.get("verify", "") and "--checks" in d.get("verify", ""))

        # 幂等：同目录跑两次签名一致
        r2 = V.verify(str(tmp), checks=["links", "imports"], use_cache=False)
        sig = lambda r: (r["verdict"], tuple((x["id"], x["state"], len(x["findings"])) for x in r["checks"]))
        check("两次运行结果一致", sig(rep) == sig(r2))

        # 渲染首行带版本
        check("报告首行带版本", f"v{V.VERSION}" in V.render(rep).splitlines()[0])

        # 退出码语义（--fail-on 收的是风险等级，不是 "fail" 这个词）
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(tmp),
                            "--checks", "links", "--fail-on", "high"],
                           capture_output=True, text=True, encoding="utf-8")
        check("有阻断失败时退出码 1", r.returncode == 1, f"exit={r.returncode}")
        r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(ROOT),
                            "--checks", "syntax", "--fail-on", "high"],
                           capture_output=True, text=True, encoding="utf-8")
        check("全过时退出码 0", r.returncode == 0, f"exit={r.returncode}")

        # --json 输出可被解析
        r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(tmp),
                            "--checks", "links,imports", "--json"],
                           capture_output=True, text=True, encoding="utf-8")
        try:
            import json as J
            jd = J.loads(r.stdout)
            check("--json 输出可解析", "checks" in jd and "verdict" in jd)
        except Exception as e:
            check("--json 输出可解析", False, str(e)[:60])

        # --sarif 会落盘且内容合法
        sfile = tmp / "out.sarif"
        subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(tmp),
                        "--checks", "links", "--sarif", str(sfile)],
                       capture_output=True, text=True, encoding="utf-8")
        try:
            import json as J
            check("--sarif 写出合法文件", sfile.exists() and J.loads(sfile.read_text(encoding="utf-8"))["version"] == "2.1.0")
        except Exception as e:
            check("--sarif 写出合法文件", False, str(e)[:60])

        # 大文件不能让工具崩，也不能误判成 FAIL
        big = Path(tempfile.mkdtemp(prefix="vh-cf-big-"))
        try:
            (big / "big.py").write_text("x = 1\n" * 400000, encoding="utf-8")   # ~3MB
            rb = V.verify(str(big), checks=["syntax"], use_cache=False)
            check("3MB 文件不崩且不误判", rb["verdict"] in ("PASS", "UNKNOWN"), f"verdict={rb['verdict']}")
        finally:
            shutil.rmtree(big, ignore_errors=True)

        # 只有低风险提示时：判定 PASS，但 --fail-on 决定退出码
        # 注意要同时跑一个阻断项，否则只跑 paths 会得到 UNKNOWN（没有能定性的检查）
        low = Path(tempfile.mkdtemp(prefix="vh-cf-low-"))
        try:
            make_case(low, {"a.py": f'X = r"{W}{CUR_USER}\\proj"\n',
                            "ok.py": "y = 1\n"})
            r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(low),
                                "--checks", "syntax,paths", "--fail-on", "low"],
                               capture_output=True, text=True, encoding="utf-8")
            check("--fail-on low 时低风险也算失败", r.returncode == 1, f"exit={r.returncode}")
            r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(low),
                                "--checks", "syntax,paths", "--fail-on", "high"],
                               capture_output=True, text=True, encoding="utf-8")
            check("同一项目 --fail-on high 时不算失败", r.returncode == 0, f"exit={r.returncode}")

            # UNKNOWN 的退出码：不该当成成功
            r = subprocess.run([sys.executable, str(ROOT / "verify_core.py"), str(low),
                                "--checks", "paths", "--fail-on", "critical"],
                               capture_output=True, text=True, encoding="utf-8")
            check("UNKNOWN 时退出码非 0（fail-closed）", r.returncode == 1, f"exit={r.returncode}")
        finally:
            shutil.rmtree(low, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def main():
    verbose = "--verbose" in sys.argv
    rows, fails = run_cases(verbose)
    extra = run_extra(verbose)

    print("=" * 74)
    print(f"{'用例':<26}{'预期':<9}{'实际':<9}")
    print("-" * 74)
    for cid, want, got, mark in rows:
        print(f"{mark} {cid:<24}{want:<9}{got:<9}")
    print("-" * 74)
    for name, mark, detail in extra:
        print(f"{mark} {name:<24}{'':<9}{detail:<9}")
    print("=" * 74)

    total = len(rows) + len(extra)
    bad = len(fails) + sum(1 for _, m, _ in extra if m == "✗")
    print(f"\n共 {total} 项：通过 {total - bad}，失败 {bad}")
    for cid, detail in fails:
        print(f"\n✗ {cid}")
        for d in detail:
            print("   ", d)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
