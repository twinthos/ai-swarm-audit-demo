#!/usr/bin/env python3
"""Offline supervisor/worker demo for auditing local agent configuration.

No network. No model calls. No writes. Deterministic JSON on stdout.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}

RULES = [
    ("MCP_SHELL_PIPE", "exposure", "critical", r"curl[^\n]*\|\s*sh", "Shell pipe installs code without review.", "Pin a reviewed installer and verify its checksum."),
    ("TOKEN_IN_CONFIG", "identity", "critical", r"sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|api[_-]?key\s*[:=]\s*\S+", "A credential literal sits in config.", "Move the value to an environment secret and rotate it."),
    ("AUTO_APPROVE", "exposure", "high", r"auto_approve\s*[:=]\s*true", "Actions are approved without a human.", "Require a named approver for consequential actions."),
    ("WILDCARD_PERMISSION", "exposure", "high", r"([\"'])\*\1|permissions\s*[:=]\s*all", "Permissions are unrestricted.", "Grant only the tools the workflow needs."),
    ("UNPINNED_MODEL", "supply-chain", "medium", r"model\s*[:=]\s*[\"']?latest|@latest|pip install [A-Za-z0-9_-]+\s*$", "A dependency or model is unpinned.", "Pin the exact version or model ID."),
    ("INSECURE_WEBHOOK", "supply-chain", "high", r"http://[^\s\"']+", "An outbound endpoint uses plain HTTP.", "Use HTTPS and an allowlisted destination."),
    ("SHARED_IDENTITY", "identity", "medium", r"shared[-_ ]?(account|inbox|user)", "Several agents share one identity.", "Give each agent a separate scoped identity."),
    ("NO_SANDBOX", "exposure", "high", r"(no_sandbox|dangerously|disable_sandbox)\s*[:=]?\s*true", "A tool runs outside its sandbox.", "Keep the sandbox on and scope the tool call."),
]

SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|api[_-]?key\s*[:=]\s*\S+",
    re.I,
)


def redact(line: str) -> str:
    return SECRET_RE.sub("[REDACTED]", line)


def read_sources(paths: Iterable[str]) -> list[dict]:
    docs = []
    for item in paths:
        path = Path(item)
        if not path.is_file():
            raise SystemExit(f"not a file: {item}")
        docs.append({"file": str(path), "lines": path.read_text(encoding="utf-8").splitlines()})
    return docs


def run_worker(name: str, docs: list[dict]) -> list[dict]:
    out = []
    for rule_id, owner, severity, pattern, why, fix in RULES:
        if owner != name:
            continue
        rx = re.compile(pattern, re.I)
        for doc in docs:
            for number, line in enumerate(doc["lines"], 1):
                if rx.search(line):
                    out.append({
                        "rule_id": rule_id,
                        "worker": owner,
                        "severity": severity,
                        "file": doc["file"],
                        "line": number,
                        "why": why,
                        "fix": fix,
                        "evidence": redact(line.strip())[:160],
                    })
    return out


def supervise(findings: list[dict]) -> dict:
    seen = set()
    unique = []
    for f in findings:
        key = (f["rule_id"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    order = {s: i for i, s in enumerate(["critical", "high", "medium", "low"])}
    unique.sort(key=lambda f: (order[f["severity"]], f["file"], f["line"], f["rule_id"]))
    counts = {s: 0 for s in order}
    for f in unique:
        counts[f["severity"]] += 1
    score = max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in unique))
    verdict = "block" if counts["critical"] else "review" if counts["high"] else "pass"
    return {
        "tool": "twinthos-ai-swarm-audit-demo",
        "mode": "offline-supervisor-worker-simulation",
        "verdict": verdict,
        "score": score,
        "counts": counts,
        "workers": ["exposure", "identity", "supply-chain"],
        "findings": unique,
        "limits": [
            "Rule-based simulation, not an LLM and not a full security audit.",
            "No network, no model calls, no file writes, no execution of target code.",
            "Findings are evidence from text patterns and can be false positives.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", help="Config files to audit; defaults to samples/")
    ap.add_argument("--fail-on-critical", action="store_true")
    args = ap.parse_args()
    paths = args.paths or sorted(str(p) for p in Path("samples").glob("*") if p.is_file())
    docs = read_sources(paths)
    findings = []
    for worker in ("exposure", "identity", "supply-chain"):
        findings.extend(run_worker(worker, docs))
    report = supervise(findings)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.fail_on_critical and report["counts"]["critical"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
