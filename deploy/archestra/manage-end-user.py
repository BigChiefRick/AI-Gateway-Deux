#!/usr/bin/env python3
"""Grant, inspect, or revoke an existing user's managed POC team access.

This tool never creates or deletes an account and never changes an organization
role. The administrator password is read only from
ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD or standard input with --password-stdin and
is never printed.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


BASE_URL = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_URL", "https://192.0.2.10"
).rstrip("/")
ORIGIN = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_ORIGIN", "https://192.0.2.10"
).rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD", "")
EXPECTED_ROLE = os.environ.get("ARCHESTRA_ACCEPTANCE_ROLE", "ai_gateway_user")
TEAM_NAME = os.environ.get("ARCHESTRA_ACCEPTANCE_TEAM", "AI Gateway Users")
DEFAULT_AGENT_HELPER = Path(
    os.environ.get(
        "ARCHESTRA_MEMBER_DEFAULT_HELPER",
        str(Path(__file__).with_name("sync-member-default-agent.py")),
    )
)


@dataclass
class Result:
    status: int
    data: Any


class Client:
    def __init__(self) -> None:
        cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookies)
        )

    def call(self, path: str, method: str = "GET", payload: dict | None = None) -> Result:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {
            "Accept": "application/json",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            BASE_URL + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                text = response.read().decode(errors="replace")
                return Result(response.status, json.loads(text) if text else None)
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return Result(error.code, data)


def require_status(result: Result, expected: tuple[int, ...], action: str) -> Any:
    if result.status not in expected:
        raise RuntimeError(
            f"{action} returned HTTP {result.status}, expected "
            + "/".join(str(value) for value in expected)
        )
    return result.data


def list_data(value: Any, action: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [item for item in value["data"] if isinstance(item, dict)]
    raise RuntimeError(f"{action} returned an unexpected response shape")


def exact_email(items: list[dict[str, Any]], email: str) -> dict[str, Any] | None:
    normalized = email.casefold()
    matches = [
        item
        for item in items
        if isinstance(item.get("email"), str)
        and item["email"].casefold() == normalized
    ]
    if len(matches) > 1:
        raise RuntimeError("multiple organization members matched the exact email")
    return matches[0] if matches else None


def sign_in(client: Client) -> None:
    require_status(
        client.call(
            "/api/auth/sign-in/email",
            "POST",
            {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        ),
        (200,),
        "administrator sign in",
    )


def load_state(client: Client, email: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    members = list_data(
        require_status(
            client.call(
                "/api/members?name="
                + urllib.parse.quote(email, safe="")
                + "&limit=100"
            ),
            (200,),
            "organization member lookup",
        ),
        "organization member lookup",
    )
    member = exact_email(members, email)
    if member is None:
        raise RuntimeError(
            "user does not exist in the active organization; have the user sign up "
            "or complete the approved invitation first"
        )
    if member.get("role") != EXPECTED_ROLE:
        raise RuntimeError(
            f"user role is {member.get('role')!r}, expected {EXPECTED_ROLE!r}; "
            "refusing to change organization roles"
        )
    user_id = member.get("userId")
    if not isinstance(user_id, str) or not user_id:
        raise RuntimeError("organization member has no stable user ID")

    teams = list_data(
        require_status(client.call("/api/teams?limit=100"), (200,), "team lookup"),
        "team lookup",
    )
    matching_teams = [item for item in teams if item.get("name") == TEAM_NAME]
    if len(matching_teams) != 1 or not isinstance(matching_teams[0].get("id"), str):
        raise RuntimeError(f"expected exactly one managed team named {TEAM_NAME!r}")
    team = matching_teams[0]
    team_id = team["id"]
    team_members = list_data(
        require_status(
            client.call(f"/api/teams/{urllib.parse.quote(team_id, safe='')}/members"),
            (200,),
            "team member lookup",
        ),
        "team member lookup",
    )
    membership = next(
        (item for item in team_members if item.get("userId") == user_id), None
    )
    return member, team, membership


def sync_default_agent(action: str, email: str) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, str(DEFAULT_AGENT_HELPER), action, email],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"managed default-agent synchronization failed{suffix}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "managed default-agent synchronization returned invalid JSON"
        ) from error
    if not isinstance(payload, dict) or payload.get("status") != "PASS":
        raise RuntimeError(
            "managed default-agent synchronization returned an unexpected result"
        )
    return payload


def summary(
    action: str,
    member: dict[str, Any],
    membership: dict[str, Any] | None,
    default_state: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "PASS",
        "action": action,
        "email": member["email"],
        "organization_role": member["role"],
        "team": TEAM_NAME,
        "team_access": membership is not None,
        "team_role": membership.get("role") if membership else None,
        "synced_from_sso": bool(membership and membership.get("syncedFromSso")),
        "default_agent": default_state.get("default_agent_name"),
        "managed_default": bool(default_state.get("managed_default")),
    }


def main() -> int:
    global ADMIN_PASSWORD
    parser = argparse.ArgumentParser(
        description="Manage an existing restricted user's AI Gateway team access."
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the administrator password from standard input",
    )
    parser.add_argument("action", choices=("status", "grant", "revoke"))
    parser.add_argument("email", help="Exact organization-member email address")
    args = parser.parse_args()
    if args.password_stdin:
        if ADMIN_PASSWORD:
            raise SystemExit(
                "use either ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD or --password-stdin, not both"
            )
        ADMIN_PASSWORD = sys.stdin.read()
        if ADMIN_PASSWORD.endswith("\r\n"):
            ADMIN_PASSWORD = ADMIN_PASSWORD[:-2]
        elif ADMIN_PASSWORD.endswith("\n"):
            ADMIN_PASSWORD = ADMIN_PASSWORD[:-1]
    if not ADMIN_PASSWORD:
        raise SystemExit(
            "ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD or --password-stdin is required"
        )

    client = Client()
    sign_in(client)
    member, team, membership = load_state(client, args.email)
    team_id = urllib.parse.quote(team["id"], safe="")
    user_id = urllib.parse.quote(member["userId"], safe="")

    if args.action == "grant":
        membership_added = membership is None
        if membership is None:
            require_status(
                client.call(
                    f"/api/teams/{team_id}/members",
                    "POST",
                    {"userId": member["userId"], "role": "member"},
                ),
                (200, 201),
                "grant managed-team access",
            )
        elif membership.get("role") != "member":
            raise RuntimeError(
                f"existing team role is {membership.get('role')!r}; refusing to downgrade it"
            )
        member, team, membership = load_state(client, args.email)
        if membership is None or membership.get("role") != "member":
            raise RuntimeError("managed-team access was not persisted")
        try:
            default_state = sync_default_agent("grant", args.email)
        except RuntimeError:
            if membership_added:
                client.call(f"/api/teams/{team_id}/members/{user_id}", "DELETE")
            raise

    elif args.action == "revoke":
        if membership is not None and membership.get("syncedFromSso"):
            raise RuntimeError(
                "team membership is synchronized from SSO; revoke it in the identity provider"
            )
        default_state = sync_default_agent("revoke", args.email)
        if membership is not None:
            try:
                require_status(
                    client.call(
                        f"/api/teams/{team_id}/members/{user_id}", "DELETE"
                    ),
                    (200, 204),
                    "revoke managed-team access",
                )
            except RuntimeError:
                sync_default_agent("grant", args.email)
                raise
        member, team, membership = load_state(client, args.email)
        if membership is not None:
            raise RuntimeError("managed-team access still exists after revoke")
        default_state = sync_default_agent("status", args.email)

    else:
        default_state = sync_default_agent("status", args.email)

    print(
        json.dumps(
            summary(args.action, member, membership, default_state),
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
