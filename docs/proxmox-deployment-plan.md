# Generic Proxmox deployment plan

## Status and scope

**Planned; not deployed.**

The pilot uses two full QEMU VMs. It does not use LXC containers. Optional GPU
installation and PCI passthrough are deferred until after the CPU-only control
plane and provider routes pass acceptance.

## Initial VM specification

These are starting allocations for the pilot and require measurement before
production sizing.

| VM | Starting resources | Storage | Role |
| --- | --- | --- | --- |
| `ai-gateway-01` | <TBD: measure workload> | <TBD: size for workload> | Archestra, managed portal, policy/DLP, routing, tools, policy database, future GPU/vLLM |
| `ai-memory-01` | <TBD: measure workload> | <TBD: separate OS and data> | Self-hosted Mem0 OSS, PostgreSQL/pgvector, memory administration |

Both VMs use:

- Q35 machine type and OVMF/UEFI;
- CPU type `host`;
- VirtIO SCSI single with discard and I/O thread where supported;
- VirtIO NIC on the approved VLAN/bridge;
- QEMU guest agent installed, enabled, and verified;
- the approved Linux server baseline, patching, EDR, NTP, DNS, logging, vulnerability
  management, and key-only administration; and
- separate Proxmox Backup Server jobs and isolated restore tests.

Keep Mem0 independent of the future GPU host so organizational memory does not
become unavailable during GPU maintenance.

## Network zones and access

| Surface | Source | Destination | Policy |
| --- | --- | --- | --- |
| User portal/API | Approved user networks and managed clients | Gateway HTTPS FQDN | Entra authentication; TLS; rate and payload limits |
| Gateway administration | Administrative network | Gateway management route | Restricted administrators; MFA; audited |
| Gateway to Mem0 | Gateway VM | Mem0 internal HTTPS API | Dedicated revocable service credential; TLS validation |
| Mem0 administration | Memory administrators | Mem0 internal dashboard | Restricted management network; MFA where supported |
| Provider egress | Gateway VM | Approved OpenAI/ChatGPT, Anthropic/Claude, Azure/Foundry endpoints | Explicit allowlist or approved proxy |
| MCP egress | Gateway/tool runtime | Approved tool destinations | Per-environment allowlist and deterministic tool policy |
| Database/model ports | Application VMs only | Internal services | Never exposed to user VLANs |
| Telemetry | Both VMs | Approved SIEM/monitoring | Metadata/policy events; body retention by separate approval |

Direct provider inference from managed user endpoints must be denied where
feasible. Required provider device-authorization endpoints remain available so
users can connect their own credentials through the managed lane.

## Deployment phases

### Phase 0: governance and product acceptance

1. Approve the architecture, data classes, supported clients, providers, models,
   retention, memory policy, budgets, network zones, backup, RPO, and RTO.
2. Confirm the Archestra production license for the expected company-wide user
   count and required SSO, RBAC, retention, and encryption features.
3. Confirm ChatGPT and Claude enterprise/workspace controls, provider terms,
   Compliance API availability, and personal-subscription routing support.
4. Confirm Purview/Defender licensing and the endpoint/browser/network controls
   used for native-provider and bypass traffic.
5. Decide whether Mem0 extraction and embeddings may use an approved cloud model.
   Self-hosted storage alone does not mean zero model egress.
6. Review upstream component licenses and required vendor attribution. No custom branding is needed.

### Phase 1: company identity and secrets

1. Create a dedicated Bitwarden Secrets Manager project.
2. Create separate least-privilege machine accounts for deployment, gateway
   runtime, Mem0 runtime, and CI/CD when their access differs.
3. Approve the gateway and Mem0 FQDNs before creating identity callbacks or
   certificates.
4. Register a single-tenant Entra application with only the approved
   redirect URIs and claims.
5. Create Entra groups for gateway users, administrators, OpenAI entitlement,
   Claude entitlement, memory administrators, and any required model tiers.
6. Configure strict role mapping and team synchronization. Unmatched users are
   denied.

### Phase 2: create and baseline the VMs

1. Complete the [environment worksheet](environment-worksheet.md).
2. Create both VMs with the approved IDs, storage, VLANs, addresses, and sizing.
3. Install the approved Ubuntu Server LTS release.
4. Install and verify `qemu-guest-agent` before application deployment.
5. Apply the approved server, EDR, firewall, logging, SSH, patch, and monitoring
   baselines.
6. Take a clean post-baseline snapshot and add both VMs to backup policy.
7. Prove a no-application restore into an isolated network.

### Phase 3: deploy self-hosted Mem0

1. Pin the approved Mem0 source commit and container digests.
2. Deploy the authenticated Mem0 REST API/dashboard and PostgreSQL/pgvector.
3. Keep API and dashboard ports internal behind trusted TLS.
4. Issue one dedicated, revocable gateway service credential. Normal users do
   not receive direct Mem0 credentials.
5. Configure the approved organizational namespace and required contributor/source
   metadata.
6. Apply DLP before memory writes and after retrieval. Never store credentials,
   prohibited PII, hidden prompts, or unverified model output as fact.
7. Prevent extraction/embedding recursion by using a dedicated route with memory
   middleware disabled.
8. Prove add, search, update, delete, key revocation, restart, audit, backup, and
   restore behavior.

### Phase 4: deploy the gateway control plane

1. Build from an approved company commit and secret-free manifest-bearing
   bundle.
2. Deploy the pinned Archestra release, gateway policy/DLP service, policy database,
   reverse proxy, governed tools, and disabled-by-default vLLM profile.
3. Use generic application presentation and retain required vendor/license attribution.
4. Configure Entra SSO, strict role mapping, team sync, and signed internal
   identity.
5. Create the custom `AI Gateway User` role from the
   [closed managed-lane contract](closed-managed-lane.md).
6. Expose only the assigned team agent. Hide agent/provider selectors and deny
   normal-user agent, proxy, MCP, policy, model, and environment management.
7. Turn off every unapproved provider and integration.

### Phase 5: commission providers side by side

1. Prove a company OpenAI/Azure/Foundry route through input/output DLP, model
   allowlist, budget reservation, attribution, hard denial, and rollback.
2. Prove a company Anthropic/Foundry/Bedrock/Vertex route through the same gates.
3. Using non-administrator users, separately prove per-user ChatGPT subscription
   and Claude credential/passthrough flows on the exact approved Archestra
   release.
4. Verify personal-only credential isolation, device authorization, revocation,
   audit attribution, DLP interception, and failure behavior.
5. Keep company provider routes as deterministic fallback/service paths even if
   subscription routing is accepted.
6. Present one managed route to clients; never expose raw provider credentials or an
   unguarded model endpoint.

### Phase 6: commission MCP, memory, and ordered routing

1. Publish the exact approved MCP/tool inventory.
2. Configure deterministic tool call/result policies and approvals.
3. Scan tool results for sensitive content and prompt injection before context
   assembly.
4. Enable shared organizational Mem0 retrieval across authorized projects and
   topics with contributor/source provenance.
5. Prove user A contributes reviewed code and user B receives it for a relevant
   problem without obtaining user A's identity secrets or private provider data.
6. Trace the complete ordered policy chain from identity through output DLP and
   sanitized memory write.

### Phase 7: acceptance and handoff

1. Test OpenAI-only, Claude-only, both, and neither identities.
2. Execute every GUI/API escape and direct-client bypass test from the security
   contract.
3. Prove Entra deprovisioning, session revocation, provider revocation, client-key
   revocation, and memory-access revocation.
4. Correlate synthetic actions across Entra, Purview, provider, Archestra, DLP,
   MCP, Mem0, and infrastructure logs.
5. Prove application-consistent backup and isolated restore of both VMs.
6. Publish owner, support, patch, upgrade, retention, incident, recovery, and
   rollback runbooks.

## Optional GPU phase

Do not attach the GPU during the initial deployment.

Before the later change window:

1. Validate the exact server, slot/riser, power, cooling, BIOS, firmware, and GPU
   qualification.
2. Capture Proxmox/kernel versions, IOMMU state, `lspci -nnk`, all device
   functions, the IOMMU group, and host driver bindings.
3. Create a Proxmox PCI resource mapping and prove no-GPU boot/rollback.
4. Back up the accepted CPU-only gateway.
5. Attach the mapped PCIe device only after VFIO isolation is proven.
6. Install the supported NVIDIA data-center driver and Container Toolkit in the
   guest, then prove `nvidia-smi` and a GPU container workload.
7. Deploy a pinned, license-approved classifier model through vLLM with
   schema-constrained output and restrictive failure behavior.
8. Record model source, revision, license, tokenizer, quantization, context
   length, and hashes.
9. Re-run the complete safety, prompt-injection, MCP, DLP, memory, provider,
   latency, throughput, restart, backup, and recovery matrix.

Full PCI passthrough makes the gateway VM node-bound for ordinary live
migration. Plan cold migration to an equivalent mapped-GPU host or an approved
degraded mode without local GPU classification.

## Completion gate

The pilot is complete only when release provenance, both VM baselines, Entra,
least-privilege GUI state, provider/account isolation, ordered routing, DLP,
MCP, budgets, self-hosted memory, bypass prevention, telemetry, backup, and
isolated restore all pass through the same endpoints intended for users.
