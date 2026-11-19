# Security policy

This project is defensive. It reads local text and emits JSON.

- No network calls.
- No model calls.
- No file writes.
- No execution of target configuration.
- Tokens matching the built-in pattern are redacted before output.

Do not submit real secrets as sample data. Report issues through a private GitHub security advisory, not a public issue.
