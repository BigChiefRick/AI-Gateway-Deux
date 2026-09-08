#!/usr/bin/env python3
"""Isolated tests for guarded member default-agent synchronization."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("sync-member-default-agent.py")
SPEC = importlib.util.spec_from_file_location("sync_member_default_agent", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load member default-agent helper")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def state(*, managed: bool, team: bool = True, role: str = "ai_gateway_user") -> dict:
    return {
        "member_id": "member-1",
        "user_id": "user-1",
        "organization_id": "org-1",
        "organization_role": role,
        "team_access": team,
        "managed_agent_valid": True,
        "default_agent_id": MODULE.MANAGED_AGENT_ID if managed else "personal-agent",
        "default_agent_name": "AI Gateway Assistant" if managed else "My Assistant",
        "managed_default": managed,
    }


def run_transition(action: str, before: dict, after: dict) -> dict:
    calls = 0

    def fake_psql(sql: str, _variables: dict[str, str]) -> list[str]:
        nonlocal calls
        calls += 1
        if sql == MODULE.STATE_SQL:
            return [json.dumps(before if calls == 1 else after)]
        return ["BEGIN", "SYNC_OK", "COMMIT"]

    with patch.object(MODULE, "psql", fake_psql):
        return MODULE.sync(action, "user@example.com")


def main() -> None:
    granted = run_transition("grant", state(managed=False), state(managed=True))
    if not granted["managed_default"] or not granted["changed"]:
        raise AssertionError(granted)

    revoked = run_transition("revoke", state(managed=True), state(managed=False))
    if revoked["managed_default"] or not revoked["changed"]:
        raise AssertionError(revoked)

    with patch.object(MODULE, "psql", return_value=[json.dumps(state(managed=True))]) as mocked:
        unchanged = MODULE.sync("grant", "user@example.com")
        if unchanged["changed"] or mocked.call_count != 1:
            raise AssertionError(unchanged)

    with patch.object(
        MODULE,
        "psql",
        return_value=[json.dumps(state(managed=False, team=False))],
    ):
        try:
            MODULE.sync("grant", "user@example.com")
        except RuntimeError as error:
            if "without managed-team access" not in str(error):
                raise
        else:
            raise AssertionError("grant without managed-team access was accepted")

    with patch.object(
        MODULE,
        "psql",
        return_value=[json.dumps(state(managed=False, role="admin"))],
    ):
        try:
            MODULE.sync("status", "user@example.com")
        except RuntimeError as error:
            if "expected 'ai_gateway_user'" not in str(error):
                raise
        else:
            raise AssertionError("unexpected organization role was accepted")

    print("MEMBER_DEFAULT_AGENT_SYNC_TEST_OK")


if __name__ == "__main__":
    main()
