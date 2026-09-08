#!/usr/bin/env bash
set -euo pipefail

: "${ARCHESTRA_MANAGED_AGENT_ID:?Set actual managed agent ID}"
: "${ENTRA_GROUP_ID:?Set actual Entra group ID}"

mapfile -t checks < <(
  sudo docker exec -i -u postgres archestra \
    psql -X -v ON_ERROR_STOP=1 -v agent_id="${ARCHESTRA_MANAGED_AGENT_ID}" -v group_id="${ENTRA_GROUP_ID}" -d archestra_dev -At <<'SQL'
select count(*)
from organization_role
where role = 'ai_gateway_user'
  and permission::jsonb = '{"agent":["read"],"chat":["read","create","update","delete"],"file":["manage"],"llmModel":["read"],"llmProviderApiKey":["read"],"skill":["read"]}'::jsonb;

select count(*)
from identity_provider
where provider_id = 'gateway-entra'
  and team_sync_config::jsonb = '{"enabled":true,"groupsExpression":"{{json groups}}"}'::jsonb;

select count(*)
from team_external_group teg
join team t on t.id = teg.team_id
where t.name = 'AI Gateway Users'
  and teg.group_identifier = :'group_id';

select count(*)
from team_member tm
join team t on t.id = tm.team_id
where t.name = 'AI Gateway Users'
  and tm.synced_from_sso = true;

select coalesce(default_member_role, '') from organization limit 1;

select count(*)
from agents a
join agent_team at on at.agent_id = a.id
join team t on t.id = at.team_id
where a.id = :'agent_id'
  and a.scope = 'team'
  and t.name = 'AI Gateway Users';

select count(*)
from agents a
join chat_api_keys k on k.id = a.llm_api_key_id
join models m on m.id = a.model_id
join agent_team at on at.agent_id = a.id
join team t on t.id = at.team_id
where a.id = :'agent_id'
  and m.model_id = 'gateway-auto'
  and m.provider = 'vllm'
  and k.team_id = t.id
  and k.name = 'DLP-Guarded Ollama - AI Gateway Users'
  and k.provider = 'vllm'
  and k.scope = 'team'
  and k.base_url = 'http://192.0.2.10:4200/v1'
  and k.extra_headers->>'X-AI-Gateway-Groups' = t.id::text
  and k.extra_headers ? 'X-AI-Gateway-Identity-Signature';

select count(*)
from agent_tools at
join tools t on t.id = at.tool_id
where at.agent_id = :'agent_id'
  and t.name like 'mem0_cloud__%';

select count(*)
from agent_tools at
join tools t on t.id = at.tool_id
where at.agent_id = :'agent_id'
  and t.name in (
    'gateway_web_research__fetch_webpage',
    'gateway_web_research__get_weather',
    'gateway_web_research__ocr_document',
    'gateway_web_research__scan_qr_codes',
    'gateway_web_research__scrape_webpage',
    'gateway_web_research__search_web'
  );

select count(*)
from agent_tools at
join tools t on t.id = at.tool_id
where at.agent_id = :'agent_id'
  and t.name like 'gateway_web_research__%'
  and t.name not in (
    'gateway_web_research__fetch_webpage',
    'gateway_web_research__get_weather',
    'gateway_web_research__ocr_document',
    'gateway_web_research__scan_qr_codes',
    'gateway_web_research__scrape_webpage',
    'gateway_web_research__search_web'
  );

select count(*)
from agent_tools
where agent_id = :'agent_id';
SQL
)

if [[ "${checks[0]:-}" != "1" ]]; then
  echo "FAIL: AI Gateway User role permissions differ from the restricted baseline" >&2
  exit 1
fi

if [[ "${checks[1]:-}" != "1" ]]; then
  echo "FAIL: gateway Entra team sync is not using the JSON-array Handlebars template" >&2
  exit 1
fi

if [[ "${checks[2]:-}" != "1" ]]; then
  echo "FAIL: Entra POC group is not mapped to AI Gateway Users" >&2
  exit 1
fi

if [[ "${checks[3]:-0}" -lt 1 ]]; then
  echo "FAIL: AI Gateway Users has no SSO-synchronized end user" >&2
  exit 1
fi

if [[ "${checks[4]:-}" != "ai_gateway_user" ]]; then
  echo "FAIL: default member role is ${checks[4]:-(blank)}, expected ai_gateway_user" >&2
  exit 1
fi

if [[ "${checks[5]:-}" != "1" ]]; then
  echo "FAIL: managed agent is not scoped to AI Gateway Users" >&2
  exit 1
fi

if [[ "${checks[6]:-}" != "1" ]]; then
  echo "FAIL: managed agent is not using the signed team-scoped DLP route" >&2
  exit 1
fi

if [[ "${checks[7]:-}" != "0" ]]; then
  echo "FAIL: managed agent exposes direct Mem0 tools instead of DLP-managed shared memory" >&2
  exit 1
fi

if [[ "${checks[8]:-}" != "6" || "${checks[9]:-}" != "0" ]]; then
  echo "FAIL: managed agent does not expose the exact six approved research/OCR/QR tools" >&2
  exit 1
fi

if [[ "${checks[10]:-}" != "6" ]]; then
  echo "FAIL: managed agent exposes tools outside the exact governed six-tool set" >&2
  exit 1
fi

actual_prompt="$({
  sudo docker exec -i -u postgres archestra \
    psql -X -v ON_ERROR_STOP=1 -v agent_id="${ARCHESTRA_MANAGED_AGENT_ID}" -v group_id="${ENTRA_GROUP_ID}" -d archestra_dev -At <<'SQL'
select system_prompt
from agents
where id = :'agent_id';
SQL
} )"
expected_prompt="$(cat ./managed-agent-system-prompt.txt)"

if [[ -z "${actual_prompt}" || "${actual_prompt}" != "${expected_prompt}" ]]; then
  echo "FAIL: managed agent system prompt differs from the versioned shared-team baseline" >&2
  exit 1
fi

echo "PASS: restricted chat role, Entra group team sync with a real SSO member, team-only signed DLP route, automatic shared-team memory, exact six research/OCR/QR tools, and versioned prompt verified"
