# Software inventory

Authoritative pins are in Compose, Dockerfiles, and each service's `requirements.lock`. Components include Archestra (identity/agents/MCP), Caddy (HTTPS), PostgreSQL (policy data), FastAPI (policy API), Mem0 (memory), and Ollama (default inference).

Research tools use MCP, HTTP retrieval/parsing, weather lookup, OCR, and barcode helpers. Upstream names and licensing remain intact; custom branding assets are absent. Pins identify this source baseline rather than the newest available versions. Validate upgrades through the same tests.
