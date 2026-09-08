# Target design versus reference implementation

The architecture decision and managed-path contract describe the intended process. They are design requirements, not an assertion that cloning or deploying the bundled example enforces the entire contract.

| Capability | Target design | Included implementation |
| --- | --- | --- |
| Identity | Strict Entra entitlement and unmatched-user denial | Generic Entra transaction and signed team/client identity; target role/entitlement behavior needs acceptance |
| DLP | Input, output, and governed tool-result controls | Policy scanner, profiles, assignments, buffered output scanning; test complete tool/result interception on target |
| Classifier | Local vLLM risk/intent/tool advice with deterministic authority | Local inference routing classifier; separate vLLM risk classifier is not deployed by Compose |
| Provider routing | Isolated per-user OpenAI/Claude entitlement and managed fallback | Local inference and managed OpenAI commissioning; subscription canary is separate, not proof of governed per-user multi-provider routing |
| Tools | Deterministic allow/deny/approval and inspected results | Archestra integration and a six-tool governed research baseline |
| Memory | Self-hosted Mem0, sanctioned retrieval/write, provenance | Mem0 Cloud middleware; self-hosted REST/TLS/auth integration remains target work |
| Bypass controls | Endpoint/network/provider-native controls | External to this repository; require independent configuration and testing |
| Acceptance | Four identities: OpenAI-only, Claude-only, both, neither | Synthetic implementation tests; full target matrix remains deployment acceptance |

Start with [architecture decision](architecture-decision.md), [ordered policy chain](closed-managed-lane.md), and [phased setup](proxmox-deployment-plan.md). Use [reference request lifecycle](architecture.md), [routing implementation](routing.md), and [guardrail configuration](guardrail-administration.md) to examine the reusable code. Do not infer full design compliance from its passing CI.
