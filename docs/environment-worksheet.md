# Environment worksheet

Complete and approve this worksheet before creating any VM, DNS record,
certificate, Entra object, firewall rule, provider route, or secret.

## Ownership and change

| Item | Approved value |
| --- | --- |
| Business owner | `<TBD>` |
| Technical owner | `<TBD>` |
| Security owner | `<TBD>` |
| Privacy/compliance owner | `<TBD>` |
| Change/request ID | `<TBD>` |
| Pilot user count | `<TBD>` |
| Production user estimate | `<TBD>` |
| Support escalation | `<TBD>` |

## Proxmox and VM placement

| Item | Gateway VM | Mem0 VM |
| --- | --- | --- |
| Cluster and Proxmox version | `<TBD>` | `<TBD>` |
| Target node or HA group | `<TBD>` | `<TBD>` |
| VM ID | `<TBD>` | `<TBD>` |
| Hostname | `ai-gateway-01` | `ai-memory-01` |
| CPU and memory | `<TBD>` | `<TBD>` |
| OS disk/storage | `<TBD>` | `<TBD>` |
| Data disk/storage | `<TBD>` | `<TBD>` |
| Bridge and VLAN | `<TBD>` | `<TBD>` |
| Static address/prefix | `<TBD>` | `<TBD>` |
| Default gateway | `<TBD>` | `<TBD>` |
| DNS servers/search suffix | `<TBD>` | `<TBD>` |
| Backup target/retention | `<TBD>` | `<TBD>` |
| Monitoring/log destination | `<TBD>` | `<TBD>` |

## Names and certificates

| Item | Approved value |
| --- | --- |
| User portal/API FQDN | `<TBD>` |
| Gateway management FQDN | `<TBD>` |
| Mem0 API FQDN | `<TBD>` |
| Mem0 dashboard FQDN | `<TBD>` |
| Certificate authority/profile | `<TBD>` |
| Certificate owner and renewal method | `<TBD>` |
| TLS minimum/cipher policy | `<TBD>` |

## Entra identity

Record object IDs and ownership, not credential values.

| Item | Approved value |
| --- | --- |
| Tenant ID | `<TBD>` |
| Application display name | `<TBD>` |
| Application/client ID | `<TBD>` |
| Redirect URI | `<TBD>` |
| Gateway users group ID | `<TBD>` |
| Gateway administrators group ID | `<TBD>` |
| OpenAI entitlement group ID | `<TBD>` |
| Claude entitlement group ID | `<TBD>` |
| Memory administrators group ID | `<TBD>` |
| Break-glass owner and process | `<TBD>` |
| Access review cadence | `<TBD>` |

## Provider and model policy

| Item | OpenAI/ChatGPT | Claude/Anthropic |
| --- | --- | --- |
| Workspace/account owner | `<TBD>` | `<TBD>` |
| Contracted plan | `<TBD>` | `<TBD>` |
| Subscription passthrough approved | `<TBD>` | `<TBD>` |
| Company API/fallback owner | `<TBD>` | `<TBD>` |
| Approved models | `<TBD>` | `<TBD>` |
| Approved region/endpoints | `<TBD>` | `<TBD>` |
| Retention/data settings | `<TBD>` | `<TBD>` |
| User/team budget | `<TBD>` | `<TBD>` |
| Compliance/audit integration | `<TBD>` | `<TBD>` |

## DLP, clients, and bypass controls

| Item | Approved value |
| --- | --- |
| Data classifications in scope | `<TBD>` |
| Sensitive information types/labels | `<TBD>` |
| Input actions: warn/block/override | `<TBD>` |
| Output actions | `<TBD>` |
| Prompt/response body retention | `<TBD>` |
| Approved browser/client list | `<TBD>` |
| Purview Endpoint DLP policy | `<TBD>` |
| Edge Browser Data Security policy | `<TBD>` |
| Network/Defender control | `<TBD>` |
| Direct provider endpoint policy | `<TBD>` |
| Personal account policy | `<TBD>` |

## Mem0 organizational memory

| Item | Approved value |
| --- | --- |
| Retention and deletion policy | `<TBD>` |
| Approved projects/topics | `<TBD>` |
| User-authored knowledge policy | `<TBD>` |
| Model-output verification policy | `<TBD>` |
| Extraction model/route | `<TBD>` |
| Embedding model/route | `<TBD>` |
| Cloud egress allowed | `<TBD>` |
| Gateway service-key reference | `<TBD>` |
| Backup target, RPO, and RTO | `<TBD>` |

## MCP and egress

| Item | Approved value |
| --- | --- |
| MCP/tool inventory | `<TBD>` |
| Read/write/approval policy | `<TBD>` |
| Downstream OBO/token exchange | `<TBD>` |
| Allowed web/egress destinations | `<TBD>` |
| Approved outbound proxy | `<TBD>` |
| Package/container registries | `<TBD>` |

## Deferred optional GPU

| Item | Approved value |
| --- | --- |
| Server/service tag | `<TBD>` |
| Target node and PCI mapping name | `<TBD>` |
| Qualified slot/riser/power/cooling | `<TBD>` |
| BIOS/IOMMU state | `<TBD>` |
| Driver/toolkit versions | `<TBD>` |
| vLLM model and revision | `<TBD>` |
| Change window and rollback owner | `<TBD>` |
