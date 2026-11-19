import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "audit_swarm.py"


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, text=True, capture_output=True)


class SwarmDemoTest(unittest.TestCase):
    def test_sample_runs_and_has_findings(self):
        p = run("samples/agent-config.json", "samples/workflow.yaml")
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        ids = {f["rule_id"] for f in r["findings"]}
        self.assertTrue({"MCP_SHELL_PIPE", "TOKEN_IN_CONFIG", "AUTO_APPROVE", "WILDCARD_PERMISSION", "UNPINNED_MODEL", "INSECURE_WEBHOOK"}.issubset(ids))
        self.assertEqual(r["verdict"], "block")
        self.assertEqual(r["workers"], ["exposure", "identity", "supply-chain"])

    def test_clean_config_passes(self):
        p = run("samples/clean.json")
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["verdict"], "pass")
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["findings"], [])

    def test_deterministic(self):
        a = run("samples/agent-config.json", "samples/workflow.yaml")
        b = run("samples/agent-config.json", "samples/workflow.yaml")
        self.assertEqual(a.stdout, b.stdout)

    def test_secret_is_redacted(self):
        p = run("samples/agent-config.json")
        self.assertNotIn("sk-EXAMPLETOKEN", p.stdout)
        self.assertIn("[REDACTED]", p.stdout)

    def test_no_network_imports(self):
        src = SCRIPT.read_text(encoding="utf-8")
        for banned in ["import requests", "import socket", "import urllib", "from http", "subprocess", "os.system"]:
            self.assertNotIn(banned, src)

    def test_fail_on_critical_flag(self):
        p = run("samples/agent-config.json", "--fail-on-critical")
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
