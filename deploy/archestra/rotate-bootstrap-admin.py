#!/usr/bin/env python3
"""Rotate the AI Gateway bootstrap administrator password through Better Auth.

Secrets are accepted only through standard input. The script authenticates the
current password, requires the bootstrap/default credential to still be
enabled, changes the password with other-session revocation, then proves a new
login and the disabled bootstrap flag. Neither password is printed.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
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
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


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
            with self.opener.open(request, timeout=30) as response:
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


def sign_in(client: Client, password: str, action: str) -> None:
    require(
        client.call(
            "/api/auth/sign-in/email",
            "POST",
            {"email": ADMIN_EMAIL, "password": password},
        ),
        (200, 201),
        action,
    )


def bootstrap_enabled(client: Client) -> bool:
    status = require(
        client.call("/api/auth/default-credentials-status"),
        (200,),
        "read bootstrap credential status",
    )
    if not isinstance(status, dict) or not isinstance(status.get("enabled"), bool):
        raise RuntimeError("bootstrap credential status returned an unexpected shape")
    return status["enabled"]


def validate_password(password: str, label: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise RuntimeError(
            f"{label} must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters"
        )
    if "\x00" in password or "\n" in password or "\r" in password:
        raise RuntimeError(f"{label} cannot contain NUL or newline characters")


def preflight(current_password: str) -> None:
    validate_password(current_password, "current password")
    client = Client()
    sign_in(client, current_password, "authenticate current administrator password")
    if not bootstrap_enabled(client):
        raise RuntimeError("bootstrap administrator password is already rotated")


def rotate(current_password: str, new_password: str) -> None:
    validate_password(current_password, "current password")
    validate_password(new_password, "new password")
    if current_password == new_password:
        raise RuntimeError("new password must differ from the current password")

    client = Client()
    sign_in(client, current_password, "authenticate current administrator password")
    if not bootstrap_enabled(client):
        raise RuntimeError("bootstrap administrator password is already rotated")

    require(
        client.call(
            "/api/auth/change-password",
            "POST",
            {
                "currentPassword": current_password,
                "newPassword": new_password,
                "revokeOtherSessions": True,
            },
        ),
        (200, 201),
        "change administrator password",
    )

    verification = Client()
    sign_in(verification, new_password, "verify the rotated administrator password")
    if bootstrap_enabled(verification):
        raise RuntimeError("password changed but bootstrap credential remains enabled")


def read_preflight_password() -> str:
    value = sys.stdin.read()
    return value[:-2] if value.endswith("\r\n") else value[:-1] if value.endswith("\n") else value


def read_rotation_payload() -> tuple[str, str]:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        raise RuntimeError("standard input is not valid commissioning JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("standard input must be a JSON object")
    current_password = payload.get("current_password")
    new_password = payload.get("new_password")
    if not isinstance(current_password, str) or not isinstance(new_password, str):
        raise RuntimeError("rotation JSON requires current_password and new_password strings")
    return current_password, new_password


def redacted(message: str, secrets: tuple[str, ...]) -> str:
    result = message
    for secret in secrets:
        if secret:
            result = result.replace(secret, "[REDACTED]")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rotate the AI Gateway bootstrap administrator credential."
    )
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()

    secrets: tuple[str, ...] = ()
    try:
        if args.preflight_only:
            current_password = read_preflight_password()
            secrets = (current_password,)
            preflight(current_password)
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "action": "preflight-bootstrap-admin-rotation",
                        "current_password_verified": True,
                        "bootstrap_credential_enabled": True,
                        "secret_input_retained": False,
                    },
                    separators=(",", ":"),
                )
            )
            return 0

        if args.confirm != "ROTATE_BOOTSTRAP_ADMIN":
            raise RuntimeError("use --confirm ROTATE_BOOTSTRAP_ADMIN to rotate the credential")
        current_password, new_password = read_rotation_payload()
        secrets = (current_password, new_password)
        rotate(current_password, new_password)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "action": "rotate-bootstrap-admin",
                    "administrator": ADMIN_EMAIL,
                    "new_password_verified": True,
                    "bootstrap_credential_enabled": False,
                    "other_sessions_revoked": True,
                    "secret_input_retained": False,
                },
                separators=(",", ":"),
            )
        )
        return 0
    except RuntimeError as error:
        print(f"ERROR: {redacted(str(error), secrets)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
