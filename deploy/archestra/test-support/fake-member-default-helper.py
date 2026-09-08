#!/usr/bin/env python3
"""Deterministic helper used only by the isolated manage-end-user test."""

import json
import sys


action, email = sys.argv[1:3]
managed = action == "grant"
print(
    json.dumps(
        {
            "status": "PASS",
            "action": action,
            "email": email,
            "default_agent_id": (
                "00000000-0000-4000-8000-000000001003" if managed else "personal"
            ),
            "default_agent_name": "AI Gateway Assistant" if managed else "My Assistant",
            "managed_default": managed,
            "changed": action != "status",
        }
    )
)
