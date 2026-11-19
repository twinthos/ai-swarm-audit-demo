# Twinthos AI Swarm Audit Demo

[![tests](https://github.com/twinthos/ai-swarm-audit-demo/actions/workflows/tests.yml/badge.svg)](https://github.com/twinthos/ai-swarm-audit-demo/actions/workflows/tests.yml)

An offline, deterministic demonstration of a supervisor / worker agent pattern for AI security audit.

A supervisor splits a local configuration audit into three workers. Each worker reads the same files, emits evidence with file and line references, and the supervisor merges, deduplicates, ranks and scores the result. No model is called and nothing leaves the machine.

## What it proves

- Task decomposition: one supervisor, three independent workers.
- Evidence ledger: every finding carries file, line, rule ID and redacted source text.
- Determinism: the same input always produces the same JSON.
- Human control: a `--fail-on-critical` flag lets a pipeline block on real risk.
- Defensive design: no network, no model calls, no file writes, no execution of target code.

## Run

```bash
python3 audit_swarm.py samples/agent-config.json samples/workflow.yaml
python3 audit_swarm.py samples/clean.json
```

## Expected output

```json
{
  "tool": "twinthos-ai-swarm-audit-demo",
  "mode": "offline-supervisor-worker-simulation",
  "verdict": "block",
  "score": 0,
  "counts": {"critical": 2, "high": 3, "medium": 3, "low": 0},
  "workers": ["exposure", "identity", "supply-chain"]
}
```

The full run emits eight findings with file, line, rule ID, severity and redacted evidence.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

This is a rule-based simulation, not a language model and not a full security audit. It demonstrates the control pattern, not production threat detection. Pattern matches can produce false positives. It reads local text only and never executes the configuration it inspects.


