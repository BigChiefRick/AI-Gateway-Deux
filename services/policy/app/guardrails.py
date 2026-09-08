from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool


DEFAULT_BLOCKED_CATEGORIES = [
    "private_key",
    "bearer_token",
    "openai_style_key",
    "github_token",
    "aws_access_key",
    "us_ssn",
    "payment_card",
]


class GuardrailSettings(BaseModel):
    input_block_categories: list[str] = Field(
        default_factory=lambda: list(DEFAULT_BLOCKED_CATEGORIES)
    )
    output_block_categories: list[str] = Field(
        default_factory=lambda: list(DEFAULT_BLOCKED_CATEGORIES)
    )
    allowed_models: list[str] = Field(
        default_factory=lambda: ["local-chat", "external-chat", "auto-chat"]
    )
    routing_mode: Literal["local_only", "local_first", "external_only"] = "local_only"
    allow_external: bool = False
    classifier_enabled: bool = True
    classifier_confidence_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    allow_user_route_override: bool = False
    fallback_on_local_error: bool = True
    # Tool availability alone is not an escalation signal. Local tool-capable
    # models get the first attempt; normal classifier, task-hint, and provider
    # fallback policy still govern paid-provider use.
    external_for_tools: bool = False
    external_complexity_threshold_chars: int = Field(default=8_000, ge=0, le=2_000_000)
    external_task_hints: list[str] = Field(
        default_factory=lambda: [
            "architecture",
            "code review",
            "review this code",
            "debug",
            "deep research",
            "legal analysis",
            "medical analysis",
            "security review",
        ]
    )
    external_monthly_budget_usd: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    external_input_cost_per_million_usd: float = Field(
        default=0.0, ge=0.0, le=10_000.0
    )
    external_output_cost_per_million_usd: float = Field(
        default=0.0, ge=0.0, le=10_000.0
    )
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["search_web", "fetch_url"]
    )
    max_input_chars: int = Field(default=20_000, ge=1, le=2_000_000)
    local_max_completion_tokens: int = Field(default=128, ge=1, le=32_768)
    external_max_completion_tokens: int = Field(default=1_024, ge=1, le=32_768)
    memory_read: bool = True
    memory_write: bool = True

    @field_validator(
        "input_block_categories",
        "output_block_categories",
        "allowed_models",
        "allowed_tools",
        "external_task_hints",
    )
    @classmethod
    def unique_nonempty_values(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            item = item.strip()
            if item and item not in cleaned:
                cleaned.append(item)
        return cleaned


class GuardrailProfileInput(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1_000)
    enabled: bool = True
    settings: GuardrailSettings = Field(default_factory=GuardrailSettings)


class GuardrailProfile(GuardrailProfileInput):
    created_at: datetime
    updated_at: datetime


class GuardrailAssignmentInput(BaseModel):
    subject_type: Literal["user", "agent", "group"]
    subject_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,128}$")
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    priority: int = Field(default=100, ge=-10_000, le=10_000)


class GuardrailAssignment(GuardrailAssignmentInput):
    id: int
    created_at: datetime


class ClientCredentialCreateInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    user_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,128}$")
    agent_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,128}$")
    groups: list[str] = Field(default_factory=list, max_length=100)
    expires_at: datetime | None = None

    @field_validator("groups")
    @classmethod
    def validated_groups(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            item = item.strip()
            if not item:
                continue
            if len(item) > 128 or not all(
                character.isalnum() or character in "._:@-" for character in item
            ):
                raise ValueError("group IDs must use gateway identifier characters")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned


class ClientCredential(BaseModel):
    id: str
    name: str
    user_id: str
    agent_id: str
    groups: list[str]
    key_prefix: str
    enabled: bool
    expires_at: datetime | None = None
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ClientCredentialIssue(BaseModel):
    credential: ClientCredential
    api_key: str


class GuardrailSettingsImport(GuardrailSettings):
    model_config = ConfigDict(extra="forbid")


class GuardrailProfileImport(GuardrailProfileInput):
    settings: GuardrailSettingsImport
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = ConfigDict(extra="forbid")


class GuardrailAssignmentImport(GuardrailAssignmentInput):
    id: int | None = None
    created_at: datetime | None = None

    model_config = ConfigDict(extra="forbid")


class GuardrailConfigurationImport(BaseModel):
    schema_version: Literal[1, 2]
    service_version: str = Field(min_length=1, max_length=64)
    profiles: list[GuardrailProfileImport] = Field(min_length=1, max_length=1_000)
    assignments: list[GuardrailAssignmentImport] = Field(
        default_factory=list, max_length=10_000
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_portable_configuration(self) -> GuardrailConfigurationImport:
        profile_ids = [profile.id for profile in self.profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("profile IDs must be unique")
        default = next((profile for profile in self.profiles if profile.id == "default"), None)
        if default is None or not default.enabled:
            raise ValueError("an enabled default profile is required")
        assignment_keys = [
            (item.subject_type, item.subject_id, item.profile_id)
            for item in self.assignments
        ]
        if len(assignment_keys) != len(set(assignment_keys)):
            raise ValueError("assignment subjects and profiles must be unique")
        unknown_profiles = sorted(
            {item.profile_id for item in self.assignments} - set(profile_ids)
        )
        if unknown_profiles:
            raise ValueError(
                "assignments reference profiles absent from the import: "
                + ", ".join(unknown_profiles)
            )
        return self


class EffectiveGuardrail(BaseModel):
    profile_id: str
    profile_name: str
    settings: GuardrailSettings
    assignment_id: int | None = None
    assignment_subject: str = "default"


class AuditEventInput(BaseModel):
    request_id: str
    user_id: str
    agent_id: str
    profile_id: str
    stage: str
    decision: Literal["allow", "block", "error"]
    categories: list[str] = Field(default_factory=list)
    route_model: str | None = None
    route_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExternalUsageInput(BaseModel):
    request_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,64}$")
    user_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,128}$")
    agent_id: str = Field(pattern=r"^[A-Za-z0-9._:@-]{1,128}$")
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)


class GuardrailStore:
    def __init__(
        self,
        database_url: str,
        default_settings: GuardrailSettings | None = None,
    ) -> None:
        self.database_url = database_url
        self.default_settings = default_settings or GuardrailSettings()
        self.pool = AsyncConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=10,
            open=False,
            kwargs={"row_factory": dict_row},
        )

    async def open(self) -> None:
        await self.pool.open(wait=True, timeout=30)
        await self._initialize_schema()

    async def close(self) -> None:
        await self.pool.close()

    async def check(self) -> bool:
        try:
            async with self.pool.connection() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute("SELECT 1")
                    row = await cursor.fetchone()
                    return bool(row)
        except Exception:
            return False

    async def _initialize_schema(self) -> None:
        default = GuardrailProfileInput(
            id="default",
            name="Default guarded access",
            description="Baseline policy applied when no user, group, or agent assignment exists.",
            settings=self.default_settings,
        )
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS guardrail_profiles (
                        id VARCHAR(64) PRIMARY KEY,
                        name VARCHAR(128) NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        settings JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS guardrail_assignments (
                        id BIGSERIAL PRIMARY KEY,
                        subject_type VARCHAR(16) NOT NULL
                            CHECK (subject_type IN ('user', 'agent', 'group')),
                        subject_id VARCHAR(128) NOT NULL,
                        profile_id VARCHAR(64) NOT NULL
                            REFERENCES guardrail_profiles(id) ON DELETE CASCADE,
                        priority INTEGER NOT NULL DEFAULT 100,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (subject_type, subject_id, profile_id)
                    );
                    CREATE INDEX IF NOT EXISTS guardrail_assignments_subject_idx
                        ON guardrail_assignments(subject_type, subject_id, priority DESC);
                    CREATE TABLE IF NOT EXISTS guardrail_audit_events (
                        id BIGSERIAL PRIMARY KEY,
                        occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        request_id VARCHAR(64) NOT NULL,
                        user_id VARCHAR(128) NOT NULL,
                        agent_id VARCHAR(128) NOT NULL,
                        profile_id VARCHAR(64) NOT NULL,
                        stage VARCHAR(32) NOT NULL,
                        decision VARCHAR(16) NOT NULL
                            CHECK (decision IN ('allow', 'block', 'error')),
                        categories JSONB NOT NULL DEFAULT '[]'::jsonb,
                        route_model VARCHAR(128),
                        route_reason VARCHAR(128),
                        metadata JSONB NOT NULL DEFAULT '{}'::jsonb
                    );
                    CREATE INDEX IF NOT EXISTS guardrail_audit_occurred_idx
                        ON guardrail_audit_events(occurred_at DESC);
                    CREATE INDEX IF NOT EXISTS guardrail_audit_subject_idx
                        ON guardrail_audit_events(user_id, agent_id, occurred_at DESC);
                    CREATE TABLE IF NOT EXISTS external_usage_events (
                        request_id VARCHAR(64) PRIMARY KEY,
                        occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        user_id VARCHAR(128) NOT NULL,
                        agent_id VARCHAR(128) NOT NULL,
                        profile_id VARCHAR(64) NOT NULL,
                        provider VARCHAR(64) NOT NULL,
                        model VARCHAR(128) NOT NULL,
                        prompt_tokens BIGINT NOT NULL DEFAULT 0,
                        completion_tokens BIGINT NOT NULL DEFAULT 0,
                        cost_microusd BIGINT NOT NULL DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS external_usage_profile_period_idx
                        ON external_usage_events(profile_id, occurred_at DESC);
                    CREATE INDEX IF NOT EXISTS external_usage_user_period_idx
                        ON external_usage_events(user_id, occurred_at DESC);
                    CREATE TABLE IF NOT EXISTS client_credentials (
                        id UUID PRIMARY KEY,
                        name VARCHAR(128) NOT NULL,
                        user_id VARCHAR(128) NOT NULL,
                        agent_id VARCHAR(128) NOT NULL,
                        groups JSONB NOT NULL DEFAULT '[]'::jsonb,
                        key_prefix VARCHAR(24) NOT NULL,
                        key_hash CHAR(64) NOT NULL UNIQUE,
                        enabled BOOLEAN NOT NULL DEFAULT TRUE,
                        expires_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_used_at TIMESTAMPTZ,
                        revoked_at TIMESTAMPTZ
                    );
                    CREATE INDEX IF NOT EXISTS client_credentials_subject_idx
                        ON client_credentials(user_id, agent_id, created_at DESC);
                    CREATE INDEX IF NOT EXISTS client_credentials_active_idx
                        ON client_credentials(enabled, expires_at)
                        WHERE revoked_at IS NULL;
                    """
                )
                await cursor.execute(
                    """
                    INSERT INTO guardrail_profiles (id, name, description, enabled, settings)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (
                        default.id,
                        default.name,
                        default.description,
                        default.enabled,
                        Jsonb(default.settings.model_dump(mode="json")),
                    ),
                )
            await connection.commit()

    @staticmethod
    def _profile(row: dict[str, Any]) -> GuardrailProfile:
        return GuardrailProfile(**row)

    async def list_profiles(self) -> list[GuardrailProfile]:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM guardrail_profiles ORDER BY id"
                )
                return [self._profile(row) for row in await cursor.fetchall()]

    async def get_profile(self, profile_id: str) -> GuardrailProfile | None:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM guardrail_profiles WHERE id = %s",
                    (profile_id,),
                )
                row = await cursor.fetchone()
                return self._profile(row) if row else None

    async def upsert_profile(self, profile: GuardrailProfileInput) -> GuardrailProfile:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO guardrail_profiles
                        (id, name, description, enabled, settings)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        enabled = EXCLUDED.enabled,
                        settings = EXCLUDED.settings,
                        updated_at = NOW()
                    RETURNING *
                    """,
                    (
                        profile.id,
                        profile.name,
                        profile.description,
                        profile.enabled,
                        Jsonb(profile.settings.model_dump(mode="json")),
                    ),
                )
                row = await cursor.fetchone()
            await connection.commit()
        return self._profile(row)

    async def delete_profile(self, profile_id: str) -> bool:
        if profile_id == "default":
            raise ValueError("the default profile cannot be deleted")
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "DELETE FROM guardrail_profiles WHERE id = %s RETURNING id",
                    (profile_id,),
                )
                deleted = await cursor.fetchone()
            await connection.commit()
        return deleted is not None

    async def list_assignments(self) -> list[GuardrailAssignment]:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT * FROM guardrail_assignments ORDER BY subject_type, subject_id, priority DESC, id"
                )
                return [GuardrailAssignment(**row) for row in await cursor.fetchall()]

    async def add_assignment(
        self, assignment: GuardrailAssignmentInput
    ) -> GuardrailAssignment:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO guardrail_assignments
                        (subject_type, subject_id, profile_id, priority)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (subject_type, subject_id, profile_id) DO UPDATE SET
                        priority = EXCLUDED.priority
                    RETURNING *
                    """,
                    (
                        assignment.subject_type,
                        assignment.subject_id,
                        assignment.profile_id,
                        assignment.priority,
                    ),
                )
                row = await cursor.fetchone()
            await connection.commit()
        return GuardrailAssignment(**row)

    async def delete_assignment(self, assignment_id: int) -> bool:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "DELETE FROM guardrail_assignments WHERE id = %s RETURNING id",
                    (assignment_id,),
                )
                deleted = await cursor.fetchone()
            await connection.commit()
        return deleted is not None

    @staticmethod
    def _client_credential(row: dict[str, Any]) -> ClientCredential:
        return ClientCredential(**row)

    async def create_client_credential(
        self,
        credential_id: str,
        credential: ClientCredentialCreateInput,
        key_prefix: str,
        key_hash: str,
    ) -> ClientCredential:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO client_credentials
                        (id, name, user_id, agent_id, groups, key_prefix, key_hash,
                         expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id::text AS id, name, user_id, agent_id, groups,
                              key_prefix, enabled, expires_at, created_at,
                              last_used_at, revoked_at
                    """,
                    (
                        credential_id,
                        credential.name,
                        credential.user_id,
                        credential.agent_id,
                        Jsonb(credential.groups),
                        key_prefix,
                        key_hash,
                        credential.expires_at,
                    ),
                )
                row = await cursor.fetchone()
            await connection.commit()
        return self._client_credential(row)

    async def list_client_credentials(self) -> list[ClientCredential]:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    SELECT id::text AS id, name, user_id, agent_id, groups,
                           key_prefix, enabled, expires_at, created_at,
                           last_used_at, revoked_at
                    FROM client_credentials
                    ORDER BY created_at DESC, id
                    """
                )
                rows = await cursor.fetchall()
        return [self._client_credential(row) for row in rows]

    async def authenticate_client_credential(
        self, key_hash: str
    ) -> ClientCredential | None:
        """Resolve a random bearer key without ever storing or returning plaintext."""
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    UPDATE client_credentials
                    SET last_used_at = NOW()
                    WHERE key_hash = %s
                      AND enabled = TRUE
                      AND revoked_at IS NULL
                      AND (expires_at IS NULL OR expires_at > NOW())
                    RETURNING id::text AS id, name, user_id, agent_id, groups,
                              key_prefix, enabled, expires_at, created_at,
                              last_used_at, revoked_at
                    """,
                    (key_hash,),
                )
                row = await cursor.fetchone()
            await connection.commit()
        return self._client_credential(row) if row else None

    async def revoke_client_credential(self, credential_id: str) -> ClientCredential | None:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    UPDATE client_credentials
                    SET enabled = FALSE,
                        revoked_at = COALESCE(revoked_at, NOW())
                    WHERE id = %s
                    RETURNING id::text AS id, name, user_id, agent_id, groups,
                              key_prefix, enabled, expires_at, created_at,
                              last_used_at, revoked_at
                    """,
                    (credential_id,),
                )
                row = await cursor.fetchone()
            await connection.commit()
        return self._client_credential(row) if row else None

    async def merge_configuration(
        self,
        profiles: list[GuardrailProfileInput],
        assignments: list[GuardrailAssignmentInput],
    ) -> tuple[int, int]:
        """Atomically upsert validated policy state without deleting live records."""
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                for profile in profiles:
                    await cursor.execute(
                        """
                        INSERT INTO guardrail_profiles
                            (id, name, description, enabled, settings)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            enabled = EXCLUDED.enabled,
                            settings = EXCLUDED.settings,
                            updated_at = NOW()
                        """,
                        (
                            profile.id,
                            profile.name,
                            profile.description,
                            profile.enabled,
                            Jsonb(profile.settings.model_dump(mode="json")),
                        ),
                    )
                for assignment in assignments:
                    await cursor.execute(
                        """
                        INSERT INTO guardrail_assignments
                            (subject_type, subject_id, profile_id, priority)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (subject_type, subject_id, profile_id) DO UPDATE SET
                            priority = EXCLUDED.priority
                        """,
                        (
                            assignment.subject_type,
                            assignment.subject_id,
                            assignment.profile_id,
                            assignment.priority,
                        ),
                    )
            await connection.commit()
        return len(profiles), len(assignments)

    async def effective_policy(
        self, user_id: str, agent_id: str, groups: list[str] | None = None
    ) -> EffectiveGuardrail:
        groups = groups or []
        subjects: list[tuple[str, str, int]] = [
            ("user", user_id, 300),
            ("agent", agent_id, 200),
        ]
        subjects.extend(("group", group, 100) for group in groups)

        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                if subjects:
                    clauses = " OR ".join(
                        "(a.subject_type = %s AND a.subject_id = %s)"
                        for _ in subjects
                    )
                    parameters: list[Any] = []
                    rank_parts: list[str] = []
                    for subject_type, subject_id, rank in subjects:
                        parameters.extend((subject_type, subject_id))
                        rank_parts.append(
                            f"WHEN a.subject_type = '{subject_type}' AND a.subject_id = %s THEN {rank}"
                        )
                    rank_parameters = [subject_id for _, subject_id, _ in subjects]
                    await cursor.execute(
                        f"""
                        SELECT p.id AS profile_id, p.name AS profile_name, p.settings,
                               a.id AS assignment_id,
                               a.subject_type || ':' || a.subject_id AS assignment_subject
                        FROM guardrail_assignments a
                        JOIN guardrail_profiles p ON p.id = a.profile_id
                        WHERE p.enabled = TRUE AND ({clauses})
                        ORDER BY CASE {' '.join(rank_parts)} ELSE 0 END DESC,
                                 a.priority DESC,
                                 a.id ASC
                        LIMIT 1
                        """,
                        tuple(parameters + rank_parameters),
                    )
                    row = await cursor.fetchone()
                    if row:
                        return EffectiveGuardrail(**row)

                await cursor.execute(
                    """
                    SELECT id AS profile_id, name AS profile_name, settings,
                           NULL::BIGINT AS assignment_id,
                           'default' AS assignment_subject
                    FROM guardrail_profiles
                    WHERE id = 'default' AND enabled = TRUE
                    """
                )
                row = await cursor.fetchone()
                if not row:
                    raise RuntimeError("enabled default guardrail profile is missing")
                return EffectiveGuardrail(**row)

    async def add_audit_event(self, event: AuditEventInput) -> None:
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    INSERT INTO guardrail_audit_events
                        (request_id, user_id, agent_id, profile_id, stage, decision,
                         categories, route_model, route_reason, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event.request_id,
                        event.user_id,
                        event.agent_id,
                        event.profile_id,
                        event.stage,
                        event.decision,
                        Jsonb(event.categories),
                        event.route_model,
                        event.route_reason,
                        Jsonb(event.metadata),
                    ),
                )
            await connection.commit()

    async def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 1_000)
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    SELECT id, occurred_at, request_id, user_id, agent_id, profile_id,
                           stage, decision, categories, route_model, route_reason, metadata
                    FROM guardrail_audit_events
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                return await cursor.fetchall()

    async def reserve_external_usage(
        self, usage: ExternalUsageInput, budget_microusd: int
    ) -> bool:
        """Atomically reserve worst-case provider cost against a profile budget."""
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))", (usage.profile_id,)
                )
                await cursor.execute(
                    """
                    SELECT COALESCE(SUM(cost_microusd), 0)::BIGINT AS spent
                    FROM external_usage_events
                    WHERE profile_id = %s
                      AND occurred_at >= date_trunc('month', NOW())
                    """,
                    (usage.profile_id,),
                )
                current = await cursor.fetchone()
                if current["spent"] + usage.cost_microusd > budget_microusd:
                    await connection.rollback()
                    return False
                await cursor.execute(
                    """
                    INSERT INTO external_usage_events
                        (request_id, user_id, agent_id, profile_id, provider, model,
                         prompt_tokens, completion_tokens, cost_microusd)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (request_id) DO NOTHING
                    RETURNING request_id
                    """,
                    (
                        usage.request_id,
                        usage.user_id,
                        usage.agent_id,
                        usage.profile_id,
                        usage.provider,
                        usage.model,
                        usage.prompt_tokens,
                        usage.completion_tokens,
                        usage.cost_microusd,
                    ),
                )
                reserved = await cursor.fetchone()
            await connection.commit()
        return reserved is not None

    async def finalize_external_usage(
        self,
        request_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_microusd: int,
    ) -> None:
        """Replace a worst-case reservation with provider-reported actual usage."""
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    """
                    UPDATE external_usage_events
                    SET prompt_tokens = %s,
                        completion_tokens = %s,
                        cost_microusd = %s
                    WHERE request_id = %s
                    """,
                    (prompt_tokens, completion_tokens, cost_microusd, request_id),
                )
            await connection.commit()

    async def release_external_usage(self, request_id: str) -> None:
        """Release a reservation when no paid-provider response was accepted."""
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    "DELETE FROM external_usage_events WHERE request_id = %s",
                    (request_id,),
                )
            await connection.commit()

    async def external_usage_summary(
        self, profile_id: str, user_id: str | None = None
    ) -> dict[str, Any]:
        """Return calendar-month paid-provider usage without prompt content."""
        parameters: list[Any] = [profile_id]
        user_filter = ""
        if user_id:
            user_filter = " AND user_id = %s"
            parameters.append(user_id)
        async with self.pool.connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.execute(
                    f"""
                    SELECT date_trunc('month', NOW()) AS period_start,
                           COUNT(*)::BIGINT AS requests,
                           COALESCE(SUM(prompt_tokens), 0)::BIGINT AS prompt_tokens,
                           COALESCE(SUM(completion_tokens), 0)::BIGINT AS completion_tokens,
                           COALESCE(SUM(cost_microusd), 0)::BIGINT AS cost_microusd
                    FROM external_usage_events
                    WHERE profile_id = %s
                      AND occurred_at >= date_trunc('month', NOW())
                      {user_filter}
                    """,
                    tuple(parameters),
                )
                row = await cursor.fetchone()
        return {
            **row,
            "profile_id": profile_id,
            "user_id": user_id,
            "cost_usd": row["cost_microusd"] / 1_000_000,
        }
