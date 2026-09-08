# Contributing

## Workflow

1. Start from current `main`.
2. Create a focused feature branch.
3. Make one logical change at a time.
4. Run `python scripts/validate_repository.py` and `git diff --check`.
5. Push each validated commit promptly.
6. Open a pull request with scope, security impact, validation evidence, and
   rollback notes.
7. Merge only after required review and successful validation.

## Deployment-affecting changes

A deployment-affecting pull request must identify:

- exact source and upstream versions;
- configuration and migration impact;
- secret names/references without values;
- Entra, network, DLP, provider, MCP, memory, and retention impact;
- tests and acceptance evidence;
- backup/recovery impact; and
- rollback procedure.

Do not describe a package or release as ready until its source commit, tag,
workflow result, image digests, manifest, and published artifact are verified.
