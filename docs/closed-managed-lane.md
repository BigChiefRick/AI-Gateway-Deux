# Closed managed-lane security contract

## Required user experience

An authorized user may connect their own approved ChatGPT or Claude account,
but the only chat, agent, model, tool, and memory path exposed to them is the
gateway policy chain.

Normal users:

- see one assigned team-scoped managed agent;
- can chat and use only approved managed clients;
- can connect only their own approved personal provider credential;
- may view only their own permitted logs and usage;
- cannot create, edit, delete, publish, or share agents or system prompts;
- cannot create or edit LLM proxies, provider routes, virtual keys, OAuth
  clients, raw API endpoints, models, pricing, limits, or environments;
- cannot create or install MCP gateways, servers, registries, tools, policies,
  skills, knowledge connectors, or autonomous triggers;
- cannot expose provider/model or agent selectors that create an unguarded
  route; and
- cannot read, export, or use another user's provider credential.

## Archestra configuration contract

1. Create a custom `AI Gateway User` role. Do not assign normal users the built-in
   `Member` role.
2. Grant only chat access, read access to the assigned agent, approved own-log
   access, and the minimum personal-provider credential actions proven necessary
   by the release-specific connection test.
3. Omit `chatAgentPicker:enable` and `chatProviderSettings:enable`.
4. Deny all agent, LLM proxy, virtual-key, OAuth-client, MCP, policy, registry,
   model, environment, team, identity-provider, and organization management.
5. If subscription connection requires `llmProviderApiKey:create`, prove it
   creates personal-only records and cannot publish, share, or retrieve another
   user's credential before granting it.
6. Turn off every unapproved provider, connector, messaging channel, and
   knowledge source in administrator-only availability settings.
7. Limit approved models and the managed agent to the assigned Entra-synchronized
   teams.
8. Use strict Entra role mapping. An unmatched user is denied rather than
   receiving a default role.
9. Preserve individual identity through provider routing, memory provenance,
   MCP OBO/token exchange, audit, and cost attribution.

## Managed client contract

- Portal and custom clients use the user-bound Archestra OAuth/model-router
  route, never a raw provider endpoint.
- Codex/IDE and Claude Code configurations are centrally managed where the
  platform supports it.
- A connection health/startup guard is not considered anti-bypass enforcement.
- Direct provider API destinations are denied from managed user endpoints where
  feasible, while required device-authorization endpoints and the gateway proxy
  remain usable.
- Endpoint/browser/network policy governs provider websites and unmanaged
  clients outside the Archestra path.

## Ordered policy chain

The trace for every accepted managed request must show:

1. authenticated user and provider entitlement;
2. deterministic input DLP;
3. schema-valid local classifier result or restrictive fallback;
4. deterministic MCP allow, deny, or approval decision;
5. governed tool execution and inspected result, when applicable;
6. approved Mem0 retrieval with provenance;
7. entitled provider and allowed model;
8. deterministic output DLP;
9. sanitized Mem0 write decision; and
10. correlation across policy, provider, MCP, memory, cost, and client events.

## Acceptance tests

Test at least four non-administrator identities: OpenAI-only, Claude-only, both,
and neither.

For each identity, prove:

- clean Entra sign-in, team mapping, and the exact visible navigation;
- one visible managed agent and no agent/provider picker;
- permitted route success and unentitled route denial;
- no agent, proxy, raw endpoint, key, MCP, tool, policy, model, or environment
  GUI/API escape path;
- input, output, and tool-result DLP decisions;
- cross-user approved organizational-memory reuse with contributor provenance;
- provider/account isolation and no cross-user credential selection;
- usage/cost/audit attribution;
- credential, gateway-key, and user revocation;
- altered client base URL and raw provider call denial; and
- native provider activity governed by the separately approved provider and
  Purview controls.
