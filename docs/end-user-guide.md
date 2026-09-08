# Managed client configuration

Use your deployment's HTTPS portal and assigned agent. Approved OpenAI-compatible clients use:

```text
Base URL: https://gateway.example.com/gateway/v1
Model: gateway-auto
Authorization: Bearer <individually-issued-client-key>
```

Replace the hostname and trust the deployment's HTTPS CA. Obtain one credential per user/client installation. The gateway binds identity server-side and supports independent revocation. Routing follows effective policy; direct Ollama/provider URLs bypass it.

Investigate denials using decision/correlation metadata without disclosing secrets. Memory may be shared with the configured team; retrieved context does not grant resource permissions.
