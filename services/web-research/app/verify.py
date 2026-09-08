from __future__ import annotations

import json
import os
import urllib.request


BASE_URL = os.environ.get("WEB_RESEARCH_VERIFY_URL", "http://127.0.0.1:8000/mcp")
PROTOCOL_VERSION = "2025-11-25"
EXPECTED_TOOLS = {
    "search_web",
    "fetch_webpage",
    "scrape_webpage",
    "get_weather",
    "ocr_document",
    "scan_qr_codes",
}


def call(method: str, params: dict, request_id: int) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        BASE_URL,
        data=body,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"MCP request returned HTTP {response.status}")
        content_type = response.headers.get("Content-Type", "")
        raw = response.read().decode()
    if "text/event-stream" in content_type:
        data_lines = [line[6:] for line in raw.splitlines() if line.startswith("data: ")]
        if not data_lines:
            raise RuntimeError("MCP event stream contained no data")
        raw = data_lines[-1]
    payload = json.loads(raw)
    if "error" in payload:
        raise RuntimeError(f"MCP error: {payload['error'].get('message', 'unknown error')}")
    return payload.get("result", {})


def main() -> int:
    initialized = call(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "gateway-web-research-verifier", "version": "1.0"},
        },
        1,
    )
    if initialized.get("serverInfo", {}).get("name") != "Gateway Web Research":
        raise RuntimeError("unexpected MCP server identity")
    tools = call("tools/list", {}, 2).get("tools", [])
    names = {item.get("name") for item in tools if isinstance(item, dict)}
    if names != EXPECTED_TOOLS:
        raise RuntimeError(f"unexpected MCP tool set: {sorted(names)}")
    print("WEB_RESEARCH_MCP_PROTOCOL_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
