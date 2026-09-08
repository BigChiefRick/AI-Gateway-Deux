# Source and migration boundaries

This repository has fresh history and generic documentation. Environment-specific organization names, deployment records, private identities, live addresses, branding assets, and credentials are excluded. The target process documents and the reusable implementation have different scopes; [implementation status](implementation-status.md) records the gaps explicitly.

Before target deployment, configure actual endpoints, tenant/group/agent IDs, namespaces, models, budgets, and secret references. Verify all proposed self-hosted memory, provider-entitlement, classifier, identity, MCP, and bypass controls through the target acceptance matrix. Reference tests alone do not prove these integrations.

Preserve upstream attribution and dependency pins. Deployment bundles must identify source commit, workflow, checksums, and rollback procedure. Keep operational evidence, exports, prompt logs, host inventories, backups, and credentials outside Git. If a credential exposure occurs, use the deployment owner's incident process; history removal does not revoke a credential.
