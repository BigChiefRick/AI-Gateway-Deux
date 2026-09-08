# AI Gateway Deux

A generic reference for AI request processing, routing, and guardrail setup, with no custom branding or organization-specific deployment data.

## Start with the process

1. Authenticate the user and resolve provider entitlement.
2. Apply deterministic input DLP.
3. Obtain advisory local risk, intent, and candidate-tool classification.
4. Apply deterministic MCP allow, deny, or approval policy.
5. Execute approved tools and inspect results.
6. Retrieve authorized organizational memory with provenance.
7. Route to the user's permitted provider and model.
8. Apply deterministic output DLP.
9. Decide whether sanitized knowledge may be written to memory.
10. Correlate policy, provider, tool, memory, and cost events.

The classifier advises; deterministic policy grants or denies access.

## Design and setup guides

- [Architecture and provider-routing decision](docs/architecture-decision.md)
- [Ordered managed-path and guardrail contract](docs/closed-managed-lane.md)
- [Phased deployment and acceptance](docs/proxmox-deployment-plan.md)
- [Environment worksheet](docs/environment-worksheet.md)
- [Target design versus included implementation](docs/implementation-status.md)

## Reusable code guides

- [Reference request lifecycle](docs/architecture.md)
- [Local/external routing and commissioning](docs/routing.md)
- [Guardrail configuration and verification](docs/guardrail-administration.md)
- [Detailed guardrail operations](deploy/archestra/guardrails.md)
- [Reference deployment setup](deploy/archestra/README.md)
- [Validation and recovery](docs/operational-readiness.md)

**The target design is not fully implemented by the example stack.** The code uses Mem0 Cloud and local routing classification; self-hosted memory, the separate vLLM risk classifier, governed per-user multi-provider entitlements, and external bypass controls require additional implementation and acceptance. See the implementation-status table before deployment.

## Implementation

`services/policy` implements identity resolution, effective policy, input/output scanning, routing, budget reservations, memory handling, and decision audit. `services/web-research` exposes governed public-web, weather, OCR, and QR tools. `deploy/archestra` contains Compose, HTTPS proxy configuration, commissioning transactions, and verifiers. `clients/windows` contains PowerShell helpers with Bitwarden Secrets Manager credential inputs.

Archestra is the upstream authentication, team, agent, provider, and MCP control plane. Its name and image digest are preserved. This repository contains the integration/deployment layer, not a vendored copy of the platform.

## Configuration boundary

This is a sanitized source baseline, not an already commissioned deployment. `192.0.2.10`, `gateway.example.com`, all-zero-prefix UUIDs, and example identities are placeholders. Configure your endpoint, tenant, group, agent IDs, memory scope, and secret references before running operator scripts. Historical deployment records, credentials, exports, and Git history are excluded. Cloning this repository changes no existing installation.

The default route is `local_only`. External inference requires commissioning and effective-policy permission. The included memory integration uses a shared team namespace; review that choice for your installation. Extra trusted read scopes default to empty.

## Validation

GitHub Actions compiles programs, parses Windows helpers, runs policy/PostgreSQL tests, exercises commissioning and rollback transactions, validates the proxy, and builds a commit-tagged deployment bundle. Passing CI validates source and synthetic cases; target acceptance remains a separate step.
