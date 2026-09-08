#!/usr/bin/env python3
"""Prove a real invitation-created non-admin session, then remove it.

The administrator password is read only from ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD.
The generated end-user password, cookies, and invitation are process-local and
are never printed. Removing the user's last organization membership makes
Archestra delete the synthetic user and invalidate its sessions.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
ROLE = os.environ.get("ARCHESTRA_ACCEPTANCE_ROLE", "ai_gateway_user")
TEAM_NAME = os.environ.get("ARCHESTRA_ACCEPTANCE_TEAM", "AI Gateway Users")
AGENT_ID = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_AGENT_ID", "00000000-0000-4000-8000-000000001003"
)
HIDDEN_AGENT_ID = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_HIDDEN_AGENT_ID", "00000000-0000-4000-8000-000000001007"
)


if not ADMIN_PASSWORD:
    raise SystemExit("ARCHESTRA_ACCEPTANCE_ADMIN_PASSWORD is required")


@dataclass
class Result:
    status: int
    data: Any
    text: str


class Client:
    def __init__(self) -> None:
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
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
            with self.opener.open(request, timeout=180) as response:
                text = response.read().decode(errors="replace")
                try:
                    data = json.loads(text) if text else None
                except json.JSONDecodeError:
                    data = None
                return Result(response.status, data, text)
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return Result(error.code, data, text)


def require_status(result: Result, expected: int, action: str) -> Any:
    if result.status != expected:
        raise RuntimeError(f"{action} returned HTTP {result.status}, expected {expected}")
    return result.data


def list_data(value: Any, action: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [item for item in value["data"] if isinstance(item, dict)]
    raise RuntimeError(f"{action} returned an unexpected response shape")


def find_by_name(items: list[dict[str, Any]], name: str, action: str) -> dict[str, Any]:
    item = next((candidate for candidate in items if candidate.get("name") == name), None)
    if item is None:
        raise RuntimeError(f"{action}: {name!r} was not found")
    return item


def sign_in(client: Client, email: str, password: str) -> None:
    require_status(
        client.call(
            "/api/auth/sign-in/email",
            "POST",
            {"email": email, "password": password},
        ),
        200,
        "sign in",
    )


def main() -> int:
    admin = Client()
    user = Client()
    suffix = uuid.uuid4().hex[:12]
    user_email = f"gateway-acceptance-{suffix}@example.invalid"
    user_password = secrets.token_urlsafe(32) + "Aa1!"
    invitation_id: str | None = None
    organization_id: str | None = None
    user_id: str | None = None
    membership_id: str | None = None
    accidental_agent_id: str | None = None
    cleanup_errors: list[str] = []
    acceptance_summary: dict[str, Any] | None = None

    try:
        sign_in(admin, ADMIN_EMAIL, ADMIN_PASSWORD)

        organizations = list_data(
            require_status(
                admin.call("/api/auth/organization/list"),
                200,
                "list organizations",
            ),
            "list organizations",
        )
        if len(organizations) != 1 or not isinstance(organizations[0].get("id"), str):
            raise RuntimeError("acceptance requires exactly one active organization")
        organization_id = organizations[0]["id"]

        teams = list_data(
            require_status(admin.call("/api/teams?limit=100"), 200, "list teams"),
            "list teams",
        )
        team = find_by_name(teams, TEAM_NAME, "team lookup")
        team_id = team.get("id")
        if not isinstance(team_id, str):
            raise RuntimeError("managed team has no stable ID")

        invitation = require_status(
            admin.call(
                "/api/auth/organization/invite-member",
                "POST",
                {"email": user_email, "role": ROLE, "organizationId": organization_id},
            ),
            200,
            "create invitation",
        )
        if not isinstance(invitation, dict) or not isinstance(invitation.get("id"), str):
            raise RuntimeError("invitation response did not contain an ID")
        invitation_id = invitation["id"]

        require_status(
            user.call(
                "/api/auth/sign-up/email",
                "POST",
                {
                    "name": "Gateway Acceptance User",
                    "email": user_email,
                    "password": user_password,
                    "callbackURL": "/chat",
                    "invitationId": invitation_id,
                },
            ),
            200,
            "invitation signup",
        )

        session = require_status(user.call("/api/auth/get-session"), 200, "get session")
        if not isinstance(session, dict) or not isinstance(session.get("user"), dict):
            raise RuntimeError("signup did not produce an authenticated session")
        user_id = session["user"].get("id")
        if not isinstance(user_id, str):
            raise RuntimeError("authenticated user has no stable ID")
        session_state = session.get("session")
        active_organization_id = (
            session_state.get("activeOrganizationId")
            if isinstance(session_state, dict)
            else None
        )
        if active_organization_id != organization_id:
            require_status(
                user.call(
                    "/api/auth/organization/set-active",
                    "POST",
                    {"organizationId": organization_id},
                ),
                200,
                "set end-user active organization",
            )

        member_rows = list_data(
            require_status(
                admin.call(
                    "/api/members?name="
                    + urllib.parse.quote(user_email, safe="")
                    + "&limit=10"
                ),
                200,
                "find invited member",
            ),
            "find invited member",
        )
        member = next(
            (candidate for candidate in member_rows if candidate.get("email") == user_email),
            None,
        )
        if not isinstance(member, dict) or member.get("role") != ROLE:
            raise RuntimeError("invited account did not receive the restricted role")
        membership_id = member.get("id")
        if not isinstance(membership_id, str):
            raise RuntimeError("invited account has no organization membership ID")

        require_status(
            admin.call(
                f"/api/teams/{team_id}/members",
                "POST",
                {"userId": user_id, "role": "member"},
            ),
            200,
            "add acceptance user to managed team",
        )

        active_role = require_status(
            user.call("/api/auth/organization/get-active-member-role"),
            200,
            "resolve end-user active role",
        )
        if not isinstance(active_role, dict) or active_role.get("role") != ROLE:
            raise RuntimeError("end-user session did not resolve the restricted role")

        agents = list_data(
            require_status(user.call("/api/agents?limit=100"), 200, "list agents"),
            "list agents",
        )
        visible_ids = {item.get("id") for item in agents}
        if AGENT_ID not in visible_ids:
            raise RuntimeError("managed team agent is not visible to the end user")
        if HIDDEN_AGENT_ID in visible_ids:
            raise RuntimeError("personal Guardrail Canary leaked to the end user")

        provider_keys = user.call("/api/llm-provider-api-keys")
        if provider_keys.status != 403:
            raise RuntimeError(
                f"provider credential listing returned HTTP {provider_keys.status}, expected 403"
            )

        create_agent = user.call(
            "/api/agents",
            "POST",
            {"scope": "personal", "name": "Acceptance Must Not Create"},
        )
        if create_agent.status in (200, 201) and isinstance(create_agent.data, dict):
            accidental_agent_id = create_agent.data.get("id")
        if create_agent.status != 403:
            raise RuntimeError(
                f"agent creation returned HTTP {create_agent.status}, expected 403"
            )

        admin_conversations = list_data(
            require_status(
                admin.call("/api/chat/conversations?limit=1"),
                200,
                "list administrator conversations",
            ),
            "list administrator conversations",
        )
        if admin_conversations:
            admin_conversation_id = admin_conversations[0].get("id")
            if isinstance(admin_conversation_id, str):
                other_chat = user.call(
                    f"/api/chat/conversations/{admin_conversation_id}"
                )
                if other_chat.status not in (403, 404):
                    raise RuntimeError(
                        "end user could read another user's conversation: "
                        f"HTTP {other_chat.status}"
                    )

        conversation = require_status(
            user.call(
                "/api/chat/conversations",
                "POST",
                {"agentId": AGENT_ID, "title": "Ephemeral end-user acceptance"},
            ),
            200,
            "create end-user conversation",
        )
        conversation_id = conversation.get("id") if isinstance(conversation, dict) else None
        if not isinstance(conversation_id, str):
            raise RuntimeError("conversation response did not contain an ID")

        proof = "END_USER_CHAT_OK"
        chat = user.call(
            "/api/chat",
            "POST",
            {
                "id": conversation_id,
                "trigger": "submit-message",
                "messages": [
                    {
                        "id": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [
                            {
                                "type": "text",
                                "text": f"Reply with exactly {proof} and nothing else.",
                            }
                        ],
                    }
                ],
            },
        )
        if chat.status != 200 or proof not in chat.text:
            raise RuntimeError(
                f"end-user chat proof failed with HTTP {chat.status}"
            )

        acceptance_summary = {
            "status": "PASS",
            "role": ROLE,
            "team": TEAM_NAME,
            "managed_agent_visible": True,
            "personal_agent_hidden": True,
            "provider_credentials_denied": True,
            "agent_creation_denied": True,
            "other_user_chat_denied": True,
            "managed_chat": proof,
            "account_cleanup": "pending",
        }
        return 0
    finally:
        if accidental_agent_id:
            cleanup = admin.call(f"/api/agents/{accidental_agent_id}", "DELETE")
            if cleanup.status not in (200, 204, 404):
                cleanup_errors.append(
                    f"accidental agent cleanup returned HTTP {cleanup.status}"
                )
        if user_id and organization_id:
            if membership_id is None:
                lookup = admin.call(
                    "/api/members?name="
                    + urllib.parse.quote(user_email, safe="")
                    + "&limit=10"
                )
                if lookup.status == 200:
                    for candidate in list_data(lookup.data, "cleanup member lookup"):
                        if candidate.get("email") == user_email and isinstance(
                            candidate.get("id"), str
                        ):
                            membership_id = candidate["id"]
                            break
            if membership_id is None:
                cleanup_errors.append("acceptance membership ID could not be resolved")
            else:
                cleanup = admin.call(
                    "/api/auth/organization/remove-member",
                    "POST",
                    {"memberIdOrEmail": membership_id},
                )
                if cleanup.status != 200:
                    cleanup_errors.append(
                        f"acceptance user cleanup returned HTTP {cleanup.status}"
                    )
            remaining = admin.call(
                "/api/members?name="
                + urllib.parse.quote(user_email, safe="")
                + "&limit=10"
            )
            if remaining.status != 200:
                cleanup_errors.append(
                    f"acceptance cleanup verification returned HTTP {remaining.status}"
                )
            elif any(
                item.get("email") == user_email
                for item in list_data(remaining.data, "cleanup verification")
            ):
                cleanup_errors.append("synthetic acceptance user still exists")
        elif invitation_id:
            cleanup = admin.call(
                "/api/auth/organization/cancel-invitation",
                "POST",
                {"invitationId": invitation_id},
            )
            if cleanup.status != 200:
                cleanup_errors.append(
                    f"invitation cleanup returned HTTP {cleanup.status}"
                )
        if cleanup_errors:
            print("CLEANUP FAILURE: " + "; ".join(cleanup_errors), file=sys.stderr)
            if sys.exc_info()[0] is None:
                raise RuntimeError("; ".join(cleanup_errors))
        elif acceptance_summary is not None:
            acceptance_summary["account_cleanup"] = "completed"
            print(json.dumps(acceptance_summary, separators=(",", ":")))


if __name__ == "__main__":
    raise SystemExit(main())
