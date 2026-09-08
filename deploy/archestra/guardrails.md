# Guardrail operations

Archestra is the gateway's deterministic tool-governance control plane. Operators
manage it under **Studio > Guardrails** and set organization defaults under
**Settings > Security**.

## Secure defaults

- New MCP tools: Require approval
- New tool results: Sensitive
- Existing tools retain their explicit policies when defaults change.
- The managed `AI Gateway Assistant` agent uses a custom allowlist of six
  public-web, weather, OCR, and QR/barcode tools.
- Mem0 runs automatically in DLP middleware and is not exposed as model-callable
  tools.

`Require approval` pauses an interactive chat until the user approves or
declines. In unattended execution contexts, the call is blocked. `Block in
sensitive context` denies a tool after a prior tool result has marked the
conversation sensitive. `Block always` prevents execution in every context.

## Repeatable acceptance test

Use the isolated `Guardrail Canary` agent. It has no business-system access.

1. Send `Run the blocked canary.`
2. Confirm the tool state is `Denied` and the reason names the `Block always`
   policy.
3. Send `Run the approval canary.`
4. Confirm the tool state is `Approval requested` and no result appears before
   a decision.
5. Select **Decline** and confirm the tool state changes to `Denied`.

The policy badge and recorded tool-call state are authoritative. Do not accept
model prose as proof that a tool executed or was blocked.

## Adding a business tool

1. Register and connect the MCP server without assigning it broadly.
2. Review every discovered tool in **Studio > Guardrails**.
3. Mark read-only or untrusted outputs Sensitive unless there is a narrower
   trusted-data condition.
4. Use Block always for operations no gateway user needs.
5. Use Require approval for destructive or externally visible changes.
6. Use Block in sensitive context for outbound actions that must not follow
   private or untrusted data.
7. Add input conditions for known-safe destinations where appropriate.
8. Assign only the reviewed tools to a test agent, run block/approval canaries,
   inspect **Studio > Logs**, and only then assign the tools to an end-user
   agent or team.

## End-user administration

New self-signup and ChatOps users receive the `AI Gateway User` role. That role
can read assigned agents, manage the user's own chats, and manage chat files.
It cannot select providers or API keys, edit agents, inspect logs, manage MCP
servers or policies, execute code, or administer the platform.

Add gateway users to `AI Gateway Users`. Identity-provider users follow IdP
role mapping rather than the email/password default role, so validate those
mappings separately before enabling SSO.

For existing local users, run `manage-end-user.py status|grant|revoke
user@example.com` with the administrator password supplied only through
`ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD`. The command is idempotent, verifies the
restricted organization role, changes only the managed-team membership, and
refuses to remove a membership synchronized from SSO.

### Managed desktop, IDE, CLI, and agent credentials

Use **Managed client credentials** in the HTTPS guardrail console for any
OpenAI-compatible client that cannot reuse the Archestra browser session. Issue
one credential per user and per client installation. Bind it to the stable
Archestra user ID, a descriptive client/agent ID such as `vscode` or `msty`,
and the authorized team IDs. The console shows the plaintext key once and the
database retains only its SHA-256 hash and a non-secret prefix.

Configure clients with base URL `https://gateway.example.com/gateway/v1`, model
`gateway-auto`, and the one-time key. The key's server-side identity overrides all
client-supplied user, agent, and group identity headers. Revocation
is immediate and affects only that credential. The internal Archestra provider
continues using its separate policy key plus signed team identity.

The client workstation must trust the Gateway gateway CA. Port 4200 remains the
LAN recovery and internal-provider path; do not send managed end-user bearer
keys to it over plaintext HTTP.

Never give end users `DLP_POLICY_API_KEY`, `DLP_ADMIN_API_KEY`, the identity
signing key, an Ollama credential, or a paid-provider credential. Managed client
credentials are intentionally excluded from policy exports and cannot be
recovered after issuance; issue a replacement and revoke the old credential.

## Cost limits

Set the organization default under **Settings > LLM > Default user limits**.
The value is a dollar-denominated token-cost cap and can reset by calendar
interval. Add narrower overrides under **Studio > Costs & Limits > Limits** for
teams, agents, individual users, virtual keys, models, or environments.

Do not publish a paid provider to end users until its model price is present,
the default user cap is set, and one non-admin account has been tested through
the full chat and blocked-limit paths.

## Prompt and response DLP

The managed `AI Gateway Assistant` agent is routed through the OpenAI-compatible
`DLP-Guarded Ollama` provider before requests reach Ollama. The policy service
runs as `ai-gateway/policy:0.8.5` on the configured gateway host and stores profiles, assignments, managed client credentials, and
audit events in its own PostgreSQL volume.

Operators manage content policies at
`https://gateway.example.com/guardrails/admin`. The canonical console reuses the
Archestra browser session and validates it against the admin-only
`identityProvider:read` permission on every API request. Restricted users fail
closed with HTTP 403, and state-changing session requests must originate from
the canonical HTTPS origin. The direct `http://192.0.2.10:4200/admin` route
is the recovery path; it accepts `DLP_ADMIN_API_KEY` from the VM's root-owned
`/opt/ai-gateway/archestra/.env` and keeps it only in browser session storage.

The `0.8.5` console exposes policy settings as structured controls rather than
requiring hand-written JSON. Operators can select request and response
categories, edit model and tool allowlists, set prompt/completion limits,
control external routing and Mem0 read/write access, clone profiles, manage
user/team/agent assignments, resolve the effective profile for a proposed
identity, filter audit decisions, and see readiness and policy counts. Resolve
the effective policy before assigning an agent to additional end users.

Select **Download configuration** after policy or assignment changes. The JSON
contains the schema version, service version, profiles, and assignments only;
it excludes API keys, administrator credentials, prompts, model responses, and
audit events. Store exports in an approved encrypted operations location, not
in this repository. **Restore configuration (merge)** validates that file,
requires an enabled default profile, and atomically upserts its profiles and
assignments without deleting unrelated live records. The export is a recovery
record, while `configure-dlp-profile.py` remains the repeatable baseline
bootstrap.

The `archestra-managed` profile is assigned to the Archestra team ID for
`AI Gateway Users`. The managed agent is pinned to a team-scoped provider
record that adds the team ID and its HMAC signature as server-managed upstream
headers. DLP rejects incomplete or invalid signed identity with HTTP 403 and
does not trust ordinary client-supplied identity headers in production. This
lets an administrator manage different profiles by end-user team without
giving end users provider-key administration or a way to select another
team's policy.

The profile allows only `granite4.1:3b` and the six read-only Gateway
web/search/scrape/OCR/QR tools assigned to the managed Archestra agent. It
enables automatic read/write against the intentionally shared Mem0 team
namespace. It blocks configured
PII/secret categories on both request and response, enforces payload and token
limits, and writes allow/block/error decisions to the audit store. Email and
phone detection are available but are not enabled as blocking categories by
default because their false-positive policy still requires a company decision.

Run `python3 ./configure-dlp-profile.py` after a fresh DLP database deployment,
then run `python3 ./configure-team-dlp-identity.py` with the administrator
password supplied through an environment variable or a mode-0600 password
file. The second command creates or updates the team-scoped provider, signs the
team header, binds the agent to that provider, replaces the broad agent
assignment with the group assignment, runs a managed chat, verifies the audit
row, and restores the prior route if acceptance fails. Finally run
`./verify.sh`. The verifier proves the signed group assignment, exact managed
tool allowlist, safe local inference, and a synthetic SSN block before the upstream
model. Keep real credentials, customer records, and regulated data out
of canary prompts.

Archestra still owns user/team RBAC, tool policies, provider selection, and
cost limits. The DLP service deliberately uses the stable shared memory
identity `gateway-deux`. Archestra does not forward each authenticated user as
a signed provider header in version 1.3.29, but that is acceptable for the
team-memory design. Per-user access and cost attribution remain authoritative
in Archestra, while DLP policy and durable context apply to the managed team
route.
