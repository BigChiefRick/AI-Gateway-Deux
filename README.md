# AI Gateway Deux

A generic reference implementation for authenticated AI request processing, local and external model routing, prompt/response guardrails, governed tools, and durable memory. The application uses the neutral name **AI Gateway** and has no custom branding assets.

- [Request lifecycle and architecture](docs/architecture.md)
- [Model routing and commissioning](docs/routing.md)
- [Guardrail setup and acceptance](docs/guardrail-administration.md)
- [Detailed guardrail operations](deploy/archestra/guardrails.md)
- [Deployment setup](deploy/archestra/README.md)
- [Validation and recovery](docs/operational-readiness.md)
- [Client configuration](docs/end-user-guide.md)

## Implementation

`services/policy` implements identity resolution, effective policy, input/output scanning, routing, budget reservations, memory handling, and decision audit. `services/web-research` exposes governed public-web, weather, OCR, and QR tools. `deploy/archestra` contains Compose, HTTPS proxy configuration, commissioning transactions, and verifiers. `clients/windows` contains PowerShell helpers with Bitwarden Secrets Manager credential inputs.

Archestra is the upstream authentication, team, agent, provider, and MCP control plane. Its name and image digest are preserved. This repository contains the integration/deployment layer, not a vendored copy of the platform.

## Configuration boundary

This is a sanitized source baseline, not an already commissioned deployment. `192.0.2.10`, `gateway.example.com`, all-zero-prefix UUIDs, and example identities are placeholders. Configure your endpoint, tenant, group, agent IDs, memory scope, and secret references before running operator scripts. Historical deployment records, credentials, exports, and Git history are excluded. Cloning this repository changes no existing installation.

The default route is `local_only`. External inference requires commissioning and effective-policy permission. The included memory integration uses a shared team namespace; review that choice for your installation. Extra trusted read scopes default to empty.

## Validation

GitHub Actions compiles programs, parses Windows helpers, runs policy/PostgreSQL tests, exercises commissioning and rollback transactions, validates the proxy, and builds a commit-tagged deployment bundle. Passing CI validates source and synthetic cases; target acceptance remains a separate step.
