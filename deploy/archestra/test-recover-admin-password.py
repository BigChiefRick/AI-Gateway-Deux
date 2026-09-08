#!/usr/bin/env python3
"""Isolated behavior tests for guarded administrator recovery."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("recover-admin-password.py")
SPEC = importlib.util.spec_from_file_location("recover_admin_password", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load administrator recovery module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PASSWORD = "vault-recovery-test-password-123!"
STATE = MODULE.AdminState(
    account_id="account-1",
    user_id="user-1",
    role="admin",
    provider_id="credential",
    password_hash="old-hash",
)


def main() -> None:
    replacements: list[tuple[str, str, str]] = []
    with (
        patch.object(MODULE, "load_state", return_value=STATE),
        patch.object(MODULE, "hash_password", return_value="new-hash"),
        patch.object(
            MODULE,
            "replace_hash",
            side_effect=lambda *args: replacements.append(args),
        ),
        patch.object(MODULE, "verify_admin") as verify,
        patch.object(MODULE, "revoke_sessions") as revoke,
    ):
        MODULE.recover(PASSWORD)
        if replacements != [("account-1", "old-hash", "new-hash")]:
            raise AssertionError(replacements)
        if verify.call_count != 2:
            raise AssertionError("fresh login was not verified before and after revocation")
        revoke.assert_called_once_with("user-1")

    replacements.clear()
    with (
        patch.object(MODULE, "load_state", return_value=STATE),
        patch.object(MODULE, "hash_password", return_value="new-hash"),
        patch.object(
            MODULE,
            "replace_hash",
            side_effect=lambda *args: replacements.append(args),
        ),
        patch.object(MODULE, "verify_admin", side_effect=RuntimeError("injected")),
        patch.object(MODULE, "revoke_sessions"),
    ):
        try:
            MODULE.recover(PASSWORD)
        except RuntimeError as error:
            if "verification failed" not in str(error):
                raise
        else:
            raise AssertionError("failed recovery unexpectedly succeeded")
        if replacements != [
            ("account-1", "old-hash", "new-hash"),
            ("account-1", "new-hash", "old-hash"),
        ]:
            raise AssertionError("failed recovery did not restore the original hash")

    try:
        MODULE.validate_password("too-short")
    except RuntimeError:
        pass
    else:
        raise AssertionError("short recovery password was accepted")

    print("RECOVER_ADMIN_PASSWORD_TRANSACTION_TEST_OK")


if __name__ == "__main__":
    main()
