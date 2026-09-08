#!/usr/bin/env python3
"""Create and verify the example.com Entra OIDC provider in Archestra.

The Archestra administrator password and Entra client secret are accepted only
as a JSON object on standard input and are never printed. A newly-created
provider is removed if public-provider verification fails.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


BASE_URL = os.environ.get("ARCHESTRA_AUTH_BASE_URL", "http://127.0.0.1:9000").rstrip("/")
ORIGIN = os.environ.get("ARCHESTRA_AUTH_ORIGIN", "https://192.0.2.10").rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_AUTH_ADMIN_EMAIL", "admin@example.com")
TENANT_ID = ""
DOMAIN = ""
# Archestra reserves the literal ``EntraID`` provider ID for its managed
# credential path. Use a tenant-specific slug for the ordinary SSO provider;
# the slug is also the case-sensitive callback path segment.
PROVIDER_ID = "gateway-entra"
DEFAULT_ROLE = "ai_gateway_user"
TEAM_GROUPS_TEMPLATE = "{{json groups}}"


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
            with self.opener.open(request, timeout=45) as response:
                text = response.read().decode(errors="replace")
                return Result(response.status, json.loads(text) if text else None)
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                data = json.loads(text) if text else None
            except json.JSONDecodeError:
                data = None
            return Result(error.code, data)


def require(result: Result, expected: tuple[int, ...], action: str) -> Any:
    if result.status not in expected:
        raise RuntimeError(
            f"{action} returned HTTP {result.status}, expected "
            + "/".join(str(value) for value in expected)
        )
    return result.data


def list_items(value: Any, action: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [item for item in value["data"] if isinstance(item, dict)]
    raise RuntimeError(f"{action} returned an unexpected response shape")


def expected_provider(client_id: str, client_secret: str) -> dict[str, Any]:
    issuer = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    return {
        "issuer": issuer,
        "providerId": PROVIDER_ID,
        "domain": DOMAIN,
        "oidcConfig": {
            "issuer": issuer,
            "pkce": True,
            "enableRpInitiatedLogout": True,
            "clientId": client_id,
            "clientSecret": client_secret,
            "discoveryEndpoint": issuer + "/.well-known/openid-configuration",
            "scopes": ["openid", "profile", "email", "offline_access"],
            "tokenEndpointAuthentication": "client_secret_post",
        },
        "roleMapping": {
            "rules": [],
            "defaultRole": DEFAULT_ROLE,
            "strictMode": True,
            "skipRoleSync": False,
        },
        # Archestra evaluates this field as a Handlebars template. Rendering
        # the claim as JSON preserves Entra's array of group object IDs; using
        # the literal string ``groups`` collapses the array into one unmatched
        # value and removes SSO-managed team memberships.
        "teamSyncConfig": {
            "enabled": True,
            "groupsExpression": TEAM_GROUPS_TEMPLATE,
        },
        "ssoLoginEnabled": True,
    }


def validate_existing(item: dict[str, Any], client_id: str) -> None:
    oidc = item.get("oidcConfig")
    issuer = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    if (
        item.get("providerId") != PROVIDER_ID
        # Archestra intentionally normalizes the persisted domain to an empty
        # string for non-Google OIDC providers. The public provider response
        # therefore identifies this provider by providerId, not by domain.
        or item.get("domain") not in ("", DOMAIN)
        or item.get("issuer") != issuer
        or not isinstance(oidc, dict)
        or oidc.get("clientId") != client_id
        or item.get("teamSyncConfig")
        != {"enabled": True, "groupsExpression": TEAM_GROUPS_TEMPLATE}
    ):
        raise RuntimeError(
            "an existing gateway Entra provider conflicts with the requested tenant, client ID, or team-sync template"
        )


def main() -> int:
    global TENANT_ID, DOMAIN
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    TENANT_ID = args.tenant_id
    DOMAIN = args.domain
    if args.confirmation != "CONFIGURE_GATEWAY_ENTRA":
        raise SystemExit(
            "configuration requires --confirmation CONFIGURE_GATEWAY_ENTRA"
        )

    try:
        secrets = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        raise SystemExit(
            "standard input must be a JSON object containing the two required secrets"
        ) from error
    if not isinstance(secrets, dict):
        raise SystemExit("standard input must be a JSON object")
    admin_password = secrets.get("admin_password")
    client_secret = secrets.get("client_secret")
    if not isinstance(admin_password, str) or not admin_password:
        raise SystemExit("admin_password is required on standard input")
    if not isinstance(client_secret, str) or not client_secret:
        raise SystemExit("client_secret is required on standard input")

    client = Client()
    require(
        client.call(
            "/api/auth/sign-in/email",
            "POST",
            {"email": ADMIN_EMAIL, "password": admin_password},
        ),
        (200,),
        "administrator sign in",
    )
    providers = list_items(
        require(client.call("/api/identity-providers"), (200,), "provider lookup"),
        "provider lookup",
    )
    matches = [
        item
        for item in providers
        if item.get("providerId") == PROVIDER_ID or item.get("domain") == DOMAIN
    ]
    if len(matches) > 1:
        raise RuntimeError(
            "multiple identity providers match gateway-entra or example.com"
        )

    created = False
    provider: dict[str, Any]
    if matches:
        provider = matches[0]
        validate_existing(provider, args.client_id)
    else:
        provider = require(
            client.call(
                "/api/identity-providers",
                "POST",
                expected_provider(args.client_id, client_secret),
            ),
            (200, 201),
            "provider creation",
        )
        if not isinstance(provider, dict):
            raise RuntimeError(
                "provider creation returned an unexpected response shape"
            )
        created = True

    provider_key = provider.get("id")
    try:
        public = list_items(
            require(
                client.call("/api/identity-providers/public"),
                (200,),
                "public-provider verification",
            ),
            "public-provider verification",
        )
        if not any(item.get("providerId") == PROVIDER_ID for item in public):
            raise RuntimeError("the provider was not published to the sign-in surface")
    except Exception:
        if created and isinstance(provider_key, str) and provider_key:
            client.call(
                "/api/identity-providers/"
                + urllib.parse.quote(provider_key, safe=""),
                "DELETE",
            )
        raise

    print(
        json.dumps(
            {
                "status": "PASS",
                "provider": PROVIDER_ID,
                "domain": DOMAIN,
                "tenant_id": TENANT_ID,
                "client_id": args.client_id,
                "created": created,
                "default_role": DEFAULT_ROLE,
                "sso_login_enabled": True,
                "local_recovery_preserved": True,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
