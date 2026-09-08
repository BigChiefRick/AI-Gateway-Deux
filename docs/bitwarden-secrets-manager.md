# Credential inputs

Keep durable credentials in Bitwarden Secrets Manager. Windows helpers accept secret IDs through parameters/environment and use `bws`. No inherited project IDs or credential values are supplied.

Common references include `AI_GATEWAY_ADMIN_PASSWORD_SECRET_ID` and `AI_GATEWAY_ENTRA_CLIENT_SECRET_ID`. Review each helper for other required inputs. `ai-gateway-secrets.ps1` supports the configured CLI or local Credential Manager-backed launcher. Secure prompts are explicit opt-in.

Keep runtime `.env`, private keys, database dumps, configuration exports, and prompt logs out of Git. Use deployment-specific credentials and identity scopes.
