# Deployment setup

Compose provides Archestra, Caddy, policy PostgreSQL, the policy service, and governed research, with optional external-provider profiles. Authoritative image/dependency pins are in Compose, Dockerfiles, and requirements locks.

## Prepare

1. Copy `.env.example` to the target's untracked `.env`. Replace `192.0.2.10` and `gateway.example.com` in `.env`, `Caddyfile`, and operator inputs with the actual LAN address/hostname. Align frontend/API URLs, trusted origins, and session origin.
2. Configure build contexts and the local Ollama endpoint/model. The bundle installer uses `/opt/ai-gateway` by default.
3. Retrieve policy/admin/database/HMAC/provider/memory credentials through your Bitwarden Secrets Manager workflow. Keep durable credential ownership there; never commit populated environments.
4. Choose memory sharing/scope and actual team/agent IDs. Synthetic UUID defaults are examples only. Additional trusted read scopes default to empty.
5. Configure HTTPS trust, restricted roles, teams, and provider bindings. Optional Entra setup requires explicit tenant/domain/client inputs.

## Commission

Verify the base stack and local inference. Create the team-scoped managed agent/provider, run `configure-dlp-profile.py`, `configure-team-dlp-identity.py`, and `configure-managed-agent-baseline.py` with your actual IDs/credentials. Prove restricted access and guardrails before issuing client keys. See [guardrail setup](../../docs/guardrail-administration.md).

External-provider commissioning stages an isolated route, validates it, activates managed routing, checks usage, and rolls back on failure. Existing `commission-company-openai` filenames distinguish managed provider billing from the optional subscription canary; no organization account data is included. See [routing](../../docs/routing.md).

## Verify and recover

`verify.sh`, `verify-dlp.py`, `verify-rbac.sh`, and `verify-end-user.py` are target acceptance tools. Set actual endpoints/identity inputs first. `verify-rbac.sh` requires `ARCHESTRA_MANAGED_AGENT_ID` and `ENTRA_GROUP_ID`.

`build-deployment-bundle.sh` packages tracked source with a commit/workflow manifest. `install-deployment.sh` validates and installs with rollback checks; inspect its argument/confirmation requirements before use. Preserve persistent volumes and deployment-specific backups. Source rollback alone cannot restore lost data. No live deployment is performed by this repository copy.
