#!/usr/bin/env python3
"""Synchronize a managed user's default chat agent in Archestra 1.3.29.

Archestra exposes the member default-agent field through its read API but does
not expose a write operation in 1.3.29. This helper performs the smallest
possible database update and fails closed unless the organization role, team,
managed agent, and member identity all match the POC baseline.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any


DATABASE = os.environ.get("ARCHESTRA_DATABASE", "archestra_dev")
CONTAINER = os.environ.get("ARCHESTRA_CONTAINER", "archestra")
EXPECTED_ROLE = os.environ.get("ARCHESTRA_ACCEPTANCE_ROLE", "ai_gateway_user")
TEAM_NAME = os.environ.get("ARCHESTRA_ACCEPTANCE_TEAM", "AI Gateway Users")
MANAGED_AGENT_ID = os.environ.get(
    "ARCHESTRA_MANAGED_AGENT_ID", "00000000-0000-4000-8000-000000001003"
)
MANAGED_AGENT_NAME = os.environ.get("ARCHESTRA_MANAGED_AGENT_NAME", "AI Gateway Assistant")


STATE_SQL = r"""
select json_build_object(
  'member_id', m.id,
  'user_id', m.user_id,
  'organization_id', m.organization_id,
  'organization_role', m.role,
  'team_access', exists (
    select 1
    from team_member tm
    join team t on t.id = tm.team_id
    where tm.user_id = m.user_id and t.name = :'team_name'
  ),
  'managed_agent_valid', exists (
    select 1
    from agents a
    join agent_team at on at.agent_id = a.id
    join team t on t.id = at.team_id
    where a.id = :'managed_agent_id'::uuid
      and a.name = :'managed_agent_name'
      and a.scope = 'team'
      and a.deleted_at is null
      and t.name = :'team_name'
  ),
  'default_agent_id', m.default_agent_id,
  'default_agent_name', current_agent.name,
  'managed_default', m.default_agent_id = :'managed_agent_id'::uuid
)::text
from member m
join "user" u on u.id = m.user_id
left join agents current_agent on current_agent.id = m.default_agent_id
where lower(u.email) = lower(:'target_email');
"""


GRANT_SQL = r"""
begin;
update member m
set default_agent_id = :'managed_agent_id'::uuid
where m.id = :'member_id'
  and m.user_id = :'user_id'
  and m.organization_id = :'organization_id'
  and m.role = :'expected_role'
  and exists (
    select 1
    from team_member tm
    join team t on t.id = tm.team_id
    where tm.user_id = m.user_id and t.name = :'team_name'
  )
  and exists (
    select 1
    from agents a
    join agent_team at on at.agent_id = a.id
    join team t on t.id = at.team_id
    where a.id = :'managed_agent_id'::uuid
      and a.name = :'managed_agent_name'
      and a.scope = 'team'
      and a.deleted_at is null
      and t.name = :'team_name'
  );
select case when count(*) = 1 then 'SYNC_OK' else 'SYNC_FAILED' end
from member
where id = :'member_id'
  and default_agent_id = :'managed_agent_id'::uuid;
commit;
"""


REVOKE_SQL = r"""
begin;
update member m
set default_agent_id = (
  select a.id
  from agents a
  where a.author_id = m.user_id
    and a.scope = 'personal'
    and a.name = 'My Assistant'
    and a.deleted_at is null
  order by a.created_at asc
  limit 1
)
where m.id = :'member_id'
  and m.user_id = :'user_id'
  and m.organization_id = :'organization_id'
  and m.role = :'expected_role'
  and m.default_agent_id = :'managed_agent_id'::uuid;
select case when count(*) = 1 then 'SYNC_OK' else 'SYNC_FAILED' end
from member
where id = :'member_id'
  and default_agent_id is distinct from :'managed_agent_id'::uuid;
commit;
"""


def psql(sql: str, variables: dict[str, str]) -> list[str]:
    command = [
        "docker",
        "exec",
        "-i",
        "-u",
        "postgres",
        CONTAINER,
        "psql",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        DATABASE,
        "-At",
    ]
    for key, value in variables.items():
        if "\x00" in value or "\n" in value or "\r" in value:
            raise RuntimeError(f"invalid control character in {key}")
        command.extend(("-v", f"{key}={value}"))
    result = subprocess.run(
        command,
        input=sql,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"Archestra member-default database operation failed{suffix}")
    return [line for line in result.stdout.splitlines() if line]


def variables(email: str) -> dict[str, str]:
    return {
        "target_email": email,
        "expected_role": EXPECTED_ROLE,
        "team_name": TEAM_NAME,
        "managed_agent_id": MANAGED_AGENT_ID,
        "managed_agent_name": MANAGED_AGENT_NAME,
    }


def load_state(email: str) -> dict[str, Any]:
    rows = psql(STATE_SQL, variables(email))
    if len(rows) != 1:
        raise RuntimeError("expected exactly one organization member for the exact email")
    try:
        state = json.loads(rows[0])
    except json.JSONDecodeError as error:
        raise RuntimeError("member-default database query returned invalid JSON") from error
    if not isinstance(state, dict):
        raise RuntimeError("member-default database query returned an unexpected shape")
    if state.get("organization_role") != EXPECTED_ROLE:
        raise RuntimeError(
            f"user role is {state.get('organization_role')!r}, expected {EXPECTED_ROLE!r}"
        )
    if not state.get("managed_agent_valid"):
        raise RuntimeError("managed Gateway agent is missing or differs from the team baseline")
    for key in ("member_id", "user_id", "organization_id"):
        if not isinstance(state.get(key), str) or not state[key]:
            raise RuntimeError(f"member-default state is missing {key}")
    return state


def mutate(action: str, email: str, before: dict[str, Any]) -> dict[str, Any]:
    if action == "grant" and not before.get("team_access"):
        raise RuntimeError("refusing to set the managed default without managed-team access")
    values = variables(email) | {
        "member_id": before["member_id"],
        "user_id": before["user_id"],
        "organization_id": before["organization_id"],
    }
    lines = psql(GRANT_SQL if action == "grant" else REVOKE_SQL, values)
    if "SYNC_OK" not in lines:
        raise RuntimeError("member default-agent update did not satisfy its postcondition")
    after = load_state(email)
    expected = action == "grant"
    if bool(after.get("managed_default")) is not expected:
        raise RuntimeError("member default-agent verification failed")
    return after


def result(action: str, email: str, state: dict[str, Any], changed: bool) -> dict[str, Any]:
    return {
        "status": "PASS",
        "action": action,
        "email": email,
        "team_access": bool(state.get("team_access")),
        "default_agent_id": state.get("default_agent_id"),
        "default_agent_name": state.get("default_agent_name"),
        "managed_default": bool(state.get("managed_default")),
        "changed": changed,
    }


def sync(action: str, email: str) -> dict[str, Any]:
    before = load_state(email)
    if action == "status":
        return result(action, email, before, False)
    expected = action == "grant"
    if bool(before.get("managed_default")) is expected:
        return result(action, email, before, False)
    after = mutate(action, email, before)
    return result(action, email, after, True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Synchronize a managed user's default Gateway chat agent."
    )
    parser.add_argument("action", choices=("status", "grant", "revoke"))
    parser.add_argument("email")
    args = parser.parse_args()
    print(json.dumps(sync(args.action, args.email), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
