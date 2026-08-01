# Safe AI Mailroom

`POST /` accepts the `propose` and `commit` envelopes.  It stores all state in
`DATA_DIR/mailroom.json`; use a durable mounted volume in deployment.

```powershell
$env:DATA_DIR = "$PWD/data"
$env:MODEL_BASE_URL = "https://your-openai-compatible-provider/v1"
$env:MODEL_API_KEY = "..."
$env:MODEL_NAME = "..."
node server.js
```

The model is optional for local contract tests, but production should set all
three model variables. The model only returns a bounded classification; normal
code validates action fields, computes hashes/call IDs, validates receipts,
and persists state.

For public deployment, build the included Dockerfile, mount `/data` as a
durable volume, set `DATA_DIR=/data` plus the model variables, and point the
grader at the provider's HTTPS URL (without a query string or credentials).
