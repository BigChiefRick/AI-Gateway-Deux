# Validation and recovery checklist

This is a checklist, not a live acceptance record.

| Area | Evidence |
| --- | --- |
| Source/package | CI success for exact commit; bundle manifest and SHA-256 |
| HTTPS | Fresh client trust, correct hostname and canonical origin |
| Identity | Restricted/admin separation and intended membership |
| Signed identity | Tampered/missing identity denied; correct effective policy |
| DLP | Safe and blocked input/output cases with audit evidence |
| Client credentials | Issue, server-side identity binding, independent revocation |
| Routing/budget | Local default, allowed escalation, reservation and exhausted-budget denial |
| Tools | Recorded block/approval/sensitive-result behavior |
| Memory | Authorized scope and read/write behavior |
| Recovery | Code rollback plus data/configuration restore procedure |

GitHub Actions runs unit, PostgreSQL, and transaction suites. Database suites use separate interpreters because runtime initialization reads configuration at import. Deployment tests require Linux/Docker. Keep operational evidence outside Git when it contains runtime identities. Never infer live success from a build alone.
