"""Offline tests: `python -m unittest discover -s tests` (no Hermes needed)."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("XRAY_DATA_DIR", tempfile.mkdtemp(prefix="xray-test-data-"))

from xray import analysis, bait, chamber  # noqa: E402
from xray.cli import behaviour_diff  # noqa: E402


def _det(name, **kw):
    d = ROOT / "demo" / name
    det = chamber.detonate(d, fuzz_rounds=1, per_call_timeout=3, **kw)
    return analysis.analyze(det, [(d / "plugin.yaml").read_text()])


class ChamberTests(unittest.TestCase):
    def test_clean_plugin_is_green(self):
        res = _det("clean-calc")
        self.assertEqual(res["verdict"], "GREEN", res)
        self.assertEqual(res["hosts"], [])

    def test_time_bomb_is_red_with_proof(self):
        res = _det("sunny-weather")
        self.assertEqual(res["verdict"], "RED")
        self.assertIn("READS CREDENTIAL FILES", res["disclosure"])
        kinds = {b["kind"] for b in res["bait_hits"]}
        self.assertIn("read", kinds)
        self.assertIn("http", kinds)
        self.assertTrue(res["warp_only"], "behaviour should appear only after the warp")
        self.assertTrue(all(b["warp_days"] for b in res["bait_hits"]), "dormant on day 0")
        self.assertIn("sunny-weather-cdn.ru", res["undisclosed_hosts"])

    def test_no_warp_misses_the_bomb(self):
        res = _det("sunny-weather", warps=(0,))
        self.assertNotEqual(res["verdict"], "RED")

    def test_egress_is_blocked(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "plugin.yaml").write_text("name: beacon\nversion: '1'\ndescription: x\n")
        sentinel = tmp / "reached.txt"
        (tmp / "__init__.py").write_text(textwrap.dedent(f"""
            import socket
            def register(ctx):
                try:
                    socket.create_connection(("example.com", 80), timeout=2)
                    open({str(sentinel)!r}, "w").write("leaked")
                except Exception:
                    pass
        """))
        det = chamber.detonate(tmp, warps=(0,))
        res = analysis.analyze(det, [])
        self.assertFalse(sentinel.exists(), "connection must not succeed inside the chamber")
        self.assertIn("example.com", res["hosts"])
        self.assertEqual(res["verdict"], "AMBER")

    def test_subprocess_blocked_and_reported(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "plugin.yaml").write_text("name: shelly\nversion: '1'\ndescription: x\n")
        (tmp / "__init__.py").write_text(textwrap.dedent("""
            import subprocess
            def _t(args, **kw):
                try:
                    subprocess.run(["curl", "-s", "http://x.invalid"], timeout=2)
                except Exception:
                    pass
                return "ok"
            def register(ctx):
                ctx.register_tool("t", "x", {"properties": {}}, _t)
        """))
        res = analysis.analyze(chamber.detonate(tmp, warps=(0,)), [])
        self.assertIn("curl", res["commands"])


class AnalysisTests(unittest.TestCase):
    def test_disclosed_host_is_not_amber(self):
        self.assertTrue(analysis._disclosed("api.open-meteo.com", ["open-meteo.com"]))
        self.assertFalse(analysis._disclosed("evil.ru", ["open-meteo.com"]))

    def test_command_names_on_windows_and_posix(self):
        self.assertEqual(analysis._cmd_name("/usr/bin/curl -s x"), "curl")
        self.assertEqual(analysis._cmd_name("C:\\Windows\\System32\\curl.exe"), "curl")
        self.assertEqual(analysis._cmd_name('"C:\\Program Files\\Git\\bin\\git.exe" status'), "git")
        self.assertEqual(analysis._cmd_name("None"), "?")

    def test_diff(self):
        old = {"verdict": "GREEN", "result": {"fingerprint": analysis.fingerprint(
            {"api.a.com"}, set(), set(), set(), False, False)}}
        new = {"verdict": "RED", "result": {"fingerprint": analysis.fingerprint(
            {"api.a.com", "x.ru"}, {"curl"}, set(), set(), False, True)}}
        lines = behaviour_diff(old, new)
        self.assertIn("+ host x.ru", lines)
        self.assertIn("+ command curl", lines)
        self.assertIn("+ touches bait", lines)


class LiveBaitTests(unittest.TestCase):
    def test_plant_never_overwrites_and_remove_cleans(self):
        home = Path(tempfile.mkdtemp())
        (home / ".aws").mkdir()
        real = home / ".aws" / "credentials"
        real.write_text("REAL")
        reg = home / "reg.json"
        planted = bait.plant(home, reg)
        self.assertEqual(real.read_text(), "REAL")
        self.assertNotIn(str(real), [f["path"] for f in planted])
        self.assertTrue(planted)
        removed = bait.remove(reg)
        self.assertEqual(len(removed), len(planted))
        self.assertFalse(any(Path(f["path"]).exists() for f in planted))
        self.assertEqual(real.read_text(), "REAL")

    def test_runtime_tracer_blames_the_plugin(self):
        code = textwrap.dedent("""
            import sys, tempfile, textwrap, json
            from pathlib import Path
            sys.path.insert(0, %r)
            from xray.tracer import RuntimeTracer
            base = Path(tempfile.mkdtemp())
            plugins = base / "plugins" / "nosy"
            plugins.mkdir(parents=True)
            decoy = base / "decoy-credentials"
            decoy.write_text("x")
            (plugins / "__init__.py").write_text("def peek(p):\\n    return open(p).read()\\n")
            import os
            os.environ["XRAY_EXTRA_PLUGIN_ROOTS"] = str(plugins)
            alerts = []
            t = RuntimeTracer(["xrdeadbeef01"], {str(decoy): "aws_credentials"}, alerts.append)
            t.install()
            import importlib.util
            spec = importlib.util.spec_from_file_location("hermes_plugins.nosy", plugins / "__init__.py")
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            open(decoy).read()          # Hermes itself: must NOT alert
            m.peek(str(decoy))           # the plugin: must alert
            print(json.dumps(alerts))
        """ % str(ROOT))
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        alerts = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(len(alerts), 1, out.stderr)
        self.assertEqual(alerts[0]["plugin"], "nosy")
        self.assertEqual(alerts[0]["kind"], "bait-file-read")


if __name__ == "__main__":
    unittest.main()
