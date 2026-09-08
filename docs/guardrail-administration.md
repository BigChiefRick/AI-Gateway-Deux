# Guardrail setup and acceptance

## 1. Establish identity

Create the restricted role, managed team, and team-scoped agent in Archestra. The HTTPS console at `https://gateway.example.com/guardrails/admin` reuses the browser session and checks admin-only `identityProvider:read` permission. Restricted users should receive HTTP 403; state-changing session requests require the canonical origin.

Optional Entra setup uses `configure-gateway-entra.py --tenant-id <tenant-id> --domain <domain> --client-id <client-id> --confirmation CONFIGURE_GATEWAY_ENTRA`. Supply `admin_password` and `client_secret` as JSON on stdin. The Windows wrapper takes explicit tenant/domain inputs and Bitwarden secret references. Keep the team-sync template `{{json groups}}` and map your actual group ID to the intended team. `manage-end-user.ps1` requires explicit tenant/group IDs.

## 2. Bootstrap policy and signed identity

Configure actual `ARCHESTRA_ACCEPTANCE_AGENT_ID`, acceptance URL/origin, and credentials through the supported secret-input paths. Run `configure-dlp-profile.py`, then `configure-team-dlp-identity.py`. The latter binds the team-scoped provider, signs identity headers, replaces broad agent assignment with group assignment, and verifies chat/audit before retaining the route.

In **Profiles**, review input/output blocked categories, model/tool allowlists, input/completion limits, routing mode, external permission, classifier threshold, fallback, monthly budget, token prices, and memory read/write. Email and phone detection require an explicit blocking decision. Start with `local_only` until external commissioning succeeds.

## 3. Assign and resolve

Assign the profile to actual users, groups, or agents and preview effective policy for representative identities. Signed team identity is authoritative for managed chat. Never distribute internal policy/admin/HMAC keys to end users.

Issue one credential per user/client through **Managed client credentials**. Its plaintext is shown once; only its hash and identity binding are stored. Test independent revocation.

## 4. Govern tools

In Archestra **Studio > Guardrails**, review tools before assignment. The baseline allowlists six research tools under `gateway_web_research__`: `search_web`, `fetch_webpage`, `scrape_webpage`, `get_weather`, `ocr_document`, and `scan_qr_codes`. Match these names to the discovered registration.

Exercise **Block always**, **Require approval**, and sensitive-context handling with synthetic canary tools. Inspect recorded call state; assistant prose is not proof of enforcement. Mem0 middleware is separate from model-callable tools.

## 5. Verify and preserve

- Safe managed requests succeed; synthetic sensitive input and output are blocked at the correct stage.
- Spoofed identity and unauthorized administrator/client requests fail.
- Tool allow/block/approval matches policy.
- Local default, approved external escalation, and exhausted-budget denial behave correctly.
- Usage already incurred remains accounted when output is blocked.
- Memory scope and read/write match the intended audience.

Inspect corresponding audit decisions, then export the secret-free configuration. Restore validates and merges rather than deleting unrelated records. Keep operational exports and backups outside this repository. See [detailed operations](../deploy/archestra/guardrails.md) and [routing](routing.md).
