#!/usr/bin/env python3
"""Apply the versioned prompt and exact governed-tool set to the managed agent."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess


AGENT_ID = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_AGENT_ID", "00000000-0000-4000-8000-000000001003"
)
PROMPT_PATH = Path(__file__).with_name("managed-agent-system-prompt.txt")
EXPECTED_TOOLS = [
    "gateway_web_research__fetch_webpage",
    "gateway_web_research__get_weather",
    "gateway_web_research__ocr_document",
    "gateway_web_research__scan_qr_codes",
    "gateway_web_research__scrape_webpage",
    "gateway_web_research__search_web",
]
EXPECTED_MODEL = os.environ.get("DLP_AUTO_MODEL_ALIAS", "gateway-auto")


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


prompt = PROMPT_PATH.read_text(encoding="utf-8").rstrip("\r\n")
prompt_b64 = base64.b64encode(prompt.encode()).decode()
agent = sql_literal(AGENT_ID)
tools = ", ".join(sql_literal(item) for item in EXPECTED_TOOLS)
model = sql_literal(EXPECTED_MODEL)

sql = f"""
begin;

do $$
begin
  if not exists (select 1 from agents where id = {agent}::uuid and deleted_at is null) then
    raise exception 'managed agent not found';
  end if;
  if (select count(*) from tools where name in ({tools})) <> {len(EXPECTED_TOOLS)} then
    raise exception 'not all governed web-research tools are registered';
  end if;
  if (select count(*) from models where provider = 'vllm' and model_id = {model}) <> 1 then
    raise exception 'managed auto-routing model not found';
  end if;
end $$;

update agents
set system_prompt = convert_from(decode({sql_literal(prompt_b64)}, 'base64'), 'UTF8'),
    model_id = (select id from models where provider = 'vllm' and model_id = {model}),
    access_all_tools = false,
    updated_at = now()
where id = {agent}::uuid;

delete from agent_tools
where agent_id = {agent}::uuid
  and tool_id not in (select id from tools where name in ({tools}));

insert into agent_tools (agent_id, tool_id, credential_resolution_mode)
select {agent}::uuid, id, 'dynamic'
from tools
where name in ({tools})
on conflict (agent_id, tool_id) do update
set credential_resolution_mode = 'dynamic', updated_at = now();

commit;

select
  (select count(*) from agent_tools where agent_id = {agent}::uuid),
  (select count(*) from agent_tools at join tools t on t.id = at.tool_id
   where at.agent_id = {agent}::uuid and t.name like 'gateway_web_research__%'),
  (select count(*) from agent_tools at join tools t on t.id = at.tool_id
   where at.agent_id = {agent}::uuid and t.name like 'mem0_cloud__%'),
  (select (system_prompt = convert_from(decode({sql_literal(prompt_b64)}, 'base64'), 'UTF8'))::int
   from agents where id = {agent}::uuid),
  (select (m.model_id = {model})::int
   from agents a join models m on m.id = a.model_id where a.id = {agent}::uuid);
"""

completed = subprocess.run(
    [
        "sudo",
        "docker",
        "exec",
        "-i",
        "-u",
        "postgres",
        "archestra",
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-At",
        "-F",
        "|",
        "-d",
        "archestra_dev",
    ],
    input=sql,
    text=True,
    capture_output=True,
    check=False,
)
if completed.returncode != 0:
    raise SystemExit("Managed agent baseline failed: " + completed.stderr.strip())

lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
if not lines or lines[-1] != "6|6|0|1|1":
    raise SystemExit("Managed agent baseline verification failed")

print(
    "PASS: managed agent uses gateway-auto, the versioned prompt, exactly six "
    "governed research/OCR/QR tools, and zero direct Mem0 tools"
)
