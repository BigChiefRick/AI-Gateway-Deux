# Model routing

## One managed client route

Every managed client uses the same OpenAI-compatible gateway endpoint. Clients
do not choose between a local agent and a cloud agent:

```text
Archestra chat / VS Code / approved API client
  -> AI Gateway HTTPS endpoint (/gateway/v1)
  -> input DLP and effective team policy
  -> Granite local routing classifier
  -> local Ollama/Granite by default
     OR reviewed OpenAI model when escalation is required
  -> output DLP
  -> audit, spend ledger, and shared-team Mem0
```

The managed route searches Mem0 automatically. Eligible portal contributions are
written with contributor provenance to the shared organization namespace.
Reads also search every project and topic in each explicitly trusted Mem0 user
scope (`MEM0_TRUSTED_READ_USER_IDS`; empty by default). Work-history
questions are memory requests even when they contain temporal words such as
"yesterday"; current weather, scores, news, and similar live-data questions
still bypass durable recall and use governed research tools. Explicit memory
recall uses the larger `MEM0_EXPLICIT_TOP_K` result budget and deduplicates
repeated Codex session/turn entries before provider synthesis. Today/yesterday
work recaps additionally constrain Mem0 `created_at` to the matching full day
in `GATEWAY_TIMEZONE`.
Memory intent takes precedence over the current-data research rule, so temporal
phrasing such as "yesterday" cannot relabel a tool-free Mem0 synthesis request
as web research in the audit trail.

The `gateway-auto` model alias is the canonical choice for generic clients. The
Archestra managed agent can be bound to `granite4.1:3b`: the
managed `local_first` profile applies the same routing decision to that local
alias, so both aliases follow the effective policy.

Clients that connect directly to Ollama or OpenAI bypass the gateway and cannot
be governed by these controls. Managed client configuration must therefore use
the gateway URL, the `gateway-auto` alias, and a separately issued per-user,
per-client credential only. Those credentials are hashed at rest, bind a
server-side user/client/team identity, ignore spoofable identity headers, and
can be revoked independently in the guardrail console.

## Decision order

The gateway always scans the input before any provider call. For an accepted
request it then evaluates, in order:

1. a disabled-by-default administrator route override;
2. required tool use, configured complexity threshold, and managed task hints;
3. the local Granite classifier using a bounded JSON-only contract;
4. local inference when confidence is low, the classifier is unavailable, or
   the paid provider is disabled;
5. paid inference only when the profile allows it, the credential/model passed
   canary validation, reviewed prices are non-zero, and the monthly budget has
   room.

The external budget is reserved transactionally before the provider call and
reconciled to reported token usage afterward. Output is scanned before the
client receives it. A paid response blocked by output DLP is still recorded as
spend because the provider already performed the work.

## Fail-safe states

- A new or recovered deployment is `local_only` unless commissioned settings
  are present.
- Missing external credentials, model, prices, or budget fail closed.
- Failed commissioning restores the original environment and live local route.
- Local provider errors may fall through to the external provider only when the
  managed profile explicitly enables that behavior and the budget gate passes.
- End users cannot override routing under the managed profile.

## Commissioning

Use the single Windows operator helper after placing the company OpenAI key in
Bitwarden Secrets Manager:

```powershell
.\clients\windows\commission-company-openai.ps1 `
  -GatewayAddress '<gateway-hostname>' `
  -IdentityFile '<ssh-key-path>' `
  -Model '<approved-model-id>' `
  -MonthlyExternalBudgetDollars <approved-amount> `
  -InputPricePerMillionDollars <current-input-price> `
  -OutputPricePerMillionDollars <current-output-price> `
  -Confirm COMMISSION_COMPANY_OPENAI
```

The transaction validates the key/model on the isolated port-4202 canary,
keeps port 4200 unchanged until that succeeds, restarts the existing managed
route with external capability, verifies the protected stack, then proves one
local request, one deterministic cloud escalation, and spend accounting. It
removes the canary after success.

The current company OpenAI model and pricing must be reviewed at commissioning
time. They are operational inputs, not hard-coded assumptions.
