# Live demo script

Run these commands in front of the interviewer.

```bash
python3 -m unittest discover -s tests -v
python3 audit_swarm.py samples/agent-config.json samples/workflow.yaml
python3 audit_swarm.py samples/clean.json
```

What to say while the first command runs:

"This is the control pattern I use for agent work. One supervisor splits the job, three workers produce evidence, and the supervisor merges it. It is deterministic and offline so you can inspect every step."

After the second command:

"Eight findings, block verdict, score 0, two critical, three high and three medium. Every finding points to a file and line. The token is redacted in the output."

After the third command:

"Clean config, pass verdict, score 100."

Then say the gap before they ask: "This is rule-based. In production I would add model calls behind the same evidence schema, plus an eval set and human approval gates."
