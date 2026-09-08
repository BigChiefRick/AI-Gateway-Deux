#!/usr/bin/env python3
"""Recover the local Archestra administrator from a trusted secret value.

This is a root-only break-glass transaction for a vault/database mismatch. The
replacement password is accepted only through standard input. The helper
requires exactly one credential account for the expected administrator, hashes
the replacement with the Better Auth version bundled in the running Archestra
container, updates only that account, proves a fresh administrator login,
revokes prior sessions, and proves login again. A failed verification restores
the original password hash.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


CONTAINER = os.environ.get("ARCHESTRA_CONTAINER", "archestra")
DATABASE = os.environ.get("ARCHESTRA_DATABASE", "archestra_dev")
BASE_URL = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_URL", "https://192.0.2.10"
).rstrip("/")
ORIGIN = os.environ.get(
    "ARCHESTRA_ACCEPTANCE_ORIGIN", "https://192.0.2.10"
).rstrip("/")
ADMIN_EMAIL = os.environ.get("ARCHESTRA_ACCEPTANCE_ADMIN_EMAIL", "admin@example.com")
EXPECTED_ROLE = "admin"
EXPECTED_PROVIDER = "credential"
MIN_PASSWORD_LENGTH = 16
MAX_PASSWORD_LENGTH = 128


@dataclass(frozen=True)
class AdminState:
    account_id: str
    user_id: str
    role: str
    provider_id: str
    password_hash: str


@dataclass(frozen=True)
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


def sql_literal(value: str) -> str:
    if "\x00" in value:
        raise RuntimeError("database value contains a prohibited NUL character")
    return "'" + value.replace("'", "''") + "'"


def psql(sql: str) -> list[str]:
    completed = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            "postgres",
            CONTAINER,
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            DATABASE,
        ],
        input=sql,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"administrator recovery database operation failed{suffix}")
    return [line for line in completed.stdout.splitlines() if line]


def load_state() -> AdminState:
    email = sql_literal(ADMIN_EMAIL)
    rows = psql(
        f"""
select json_build_object(
  'account_id', a.id,
  'user_id', u.id,
  'role', m.role,
  'provider_id', a.provider_id,
  'password_hash', a.password
)::text
from "user" u
join account a on a.user_id = u.id
join member m on m.user_id = u.id
where lower(u.email) = lower({email})
  and a.provider_id = 'credential';
"""
    )
    if len(rows) != 1:
        raise RuntimeError(
            "recovery requires exactly one administrator credential account and membership"
        )
    try:
        data = json.loads(rows[0])
    except json.JSONDecodeError as error:
        raise RuntimeError("administrator recovery query returned invalid JSON") from error
    required = ("account_id", "user_id", "role", "provider_id", "password_hash")
    if not isinstance(data, dict) or any(
        not isinstance(data.get(key), str) or not data[key] for key in required
    ):
        raise RuntimeError("administrator recovery query returned an unexpected shape")
    state = AdminState(**{key: data[key] for key in required})
    if state.role != EXPECTED_ROLE:
        raise RuntimeError(
            f"refusing recovery because administrator role is {state.role!r}, "
            f"expected {EXPECTED_ROLE!r}"
        )
    if state.provider_id != EXPECTED_PROVIDER:
        raise RuntimeError(
            f"refusing recovery because provider is {state.provider_id!r}, "
            f"expected {EXPECTED_PROVIDER!r}"
        )
    return state


def hash_password(password: str) -> str:
    script = (
        "import fs from 'node:fs'; "
        "import { hashPassword } from 'better-auth/crypto'; "
        "const password=fs.readFileSync(0,'utf8'); "
        "process.stdout.write(await hashPassword(password));"
    )
    completed = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            "-w",
            "/app/backend",
            CONTAINER,
            "node",
            "--input-type=module",
            "-e",
            script,
        ],
        input=password,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    password = ""
    if completed.returncode != 0:
        raise RuntimeError("Better Auth password hashing failed")
    value = completed.stdout.strip()
    if len(value) < 64 or "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimeError("Better Auth returned an invalid password hash")
    return value


def replace_hash(account_id: str, expected_hash: str, replacement_hash: str) -> None:
    rows = psql(
        f"""
begin;
with changed as (
  update account
  set password = {sql_literal(replacement_hash)}, updated_at = now()
  where id = {sql_literal(account_id)}
    and password = {sql_literal(expected_hash)}
  returning 1
)
select count(*) from changed;
commit;
"""
    )
    if rows != ["1"]:
        raise RuntimeError("administrator password hash changed concurrently; no update applied")


def revoke_sessions(user_id: str) -> None:
    rows = psql(
        f"""
with removed as (
  delete from session where user_id = {sql_literal(user_id)} returning 1
)
select count(*) >= 0 from removed;
"""
    )
    if rows != ["t"]:
        raise RuntimeError("administrator session revocation did not complete")


def verify_admin(password: str) -> None:
    client = Client()
    login = client.call(
        "/api/auth/sign-in/email",
        "POST",
        {"email": ADMIN_EMAIL, "password": password},
    )
    if login.status not in (200, 201):
        raise RuntimeError(f"fresh administrator login returned HTTP {login.status}")
    providers = client.call("/api/identity-providers?limit=1")
    if providers.status != 200:
        raise RuntimeError(
            "fresh session lacks administrator identity-provider access "
            f"(HTTP {providers.status})"
        )
    status = client.call("/api/auth/default-credentials-status")
    if status.status != 200 or not isinstance(status.data, dict):
        raise RuntimeError("default credential status was not readable")
    if status.data.get("enabled") is not False:
        raise RuntimeError("recovered password unexpectedly matches the default credential")


def validate_password(password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise RuntimeError(
            f"replacement password must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters"
        )
    if "\x00" in password or "\n" in password or "\r" in password:
        raise RuntimeError("replacement password cannot contain NUL or newline characters")


def recover(password: str) -> None:
    validate_password(password)
    state = load_state()
    replacement_hash = hash_password(password)
    updated = False
    try:
        replace_hash(state.account_id, state.password_hash, replacement_hash)
        updated = True
        verify_admin(password)
        revoke_sessions(state.user_id)
        verify_admin(password)
    except Exception as error:
        if updated:
            try:
                replace_hash(state.account_id, replacement_hash, state.password_hash)
            except Exception as rollback_error:
                raise RuntimeError(
                    "administrator recovery failed and automatic hash rollback also failed"
                ) from rollback_error
        raise RuntimeError(
            f"administrator recovery verification failed: {error}"
        ) from error


def read_password() -> str:
    value = sys.stdin.read()
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recover the local gateway administrator from a trusted secret."
    )
    parser.add_argument("--confirm")
    args = parser.parse_args()
    password = ""
    try:
        if args.confirm != "RECOVER_GATEWAY_ADMIN":
            raise RuntimeError(
                "use --confirm RECOVER_GATEWAY_ADMIN for break-glass recovery"
            )
        password = read_password()
        recover(password)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "action": "recover-gateway-admin",
                    "administrator": ADMIN_EMAIL,
                    "administrator_role_verified": True,
                    "credential_provider": EXPECTED_PROVIDER,
                    "fresh_login_verified": True,
                    "prior_sessions_revoked": True,
                    "default_credentials_enabled": False,
                    "secret_input_retained": False,
                },
                separators=(",", ":"),
            )
        )
        return 0
    except RuntimeError as error:
        message = str(error).replace(password, "[REDACTED]") if password else str(error)
        print(f"ERROR: {message}", file=sys.stderr)
        return 1
    finally:
        password = ""


if __name__ == "__main__":
    raise SystemExit(main())
