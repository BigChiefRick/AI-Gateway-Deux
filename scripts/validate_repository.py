"""Validate documentation links and reject inherited organization/personal identifiers."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
TEXT_SUFFIXES = {
    ".caddyfile",
    ".conf",
    ".env",
    ".example",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

# Split strings keep the validation source from matching its own deny list.
FORBIDDEN = {
    "organization abbreviation": "US" + "MR",
    "organization domain": "money" + "reserve",
    "prior personal domain": "netand" + "vet",
    "prior personal branding": "Big Chief" + " Rick",
    "prior gateway address": "192.168" + ".0.213",
    "prior gateway hostname": "ai" + ".bcr.local",
}


def tracked_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        text=True,
    )
    return [ROOT / line for line in output.splitlines() if line]


def is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "Caddyfile",
        "Dockerfile",
        "Makefile",
    }


def validate_forbidden(paths: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if not path.is_file() or not is_text(path):
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for label, value in FORBIDDEN.items():
            if value.lower() in content.lower():
                errors.append(f"{path.relative_to(ROOT)}: contains {label}")
    return errors


def validate_links(paths: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if path.suffix.lower() != ".md" or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for target in MARKDOWN_LINK.findall(content):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local_target = target.split("#", 1)[0]
            if local_target and not (path.parent / local_target).resolve().exists():
                errors.append(
                    f"{path.relative_to(ROOT)}: broken local link {local_target}"
                )
    return errors


def main() -> int:
    paths = tracked_files()
    errors = validate_forbidden(paths) + validate_links(paths)
    if errors:
        print("Repository validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
