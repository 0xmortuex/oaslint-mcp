"""MCP stdio smoke test: spawns the real server over stdio, lists tools, calls them, and attacks it."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "spec_overview", "lint_spec", "diff_specs", "changelog_markdown",
    "find_endpoints", "describe_operation", "validate_example",
}
FIX = os.path.join(os.path.dirname(__file__), "fixtures")
TOKEN = "sk-live-" + "Zq9Xw8Vu7Ts6" * 4
PASSWORD = "hunter2-Sup3rS3cret"


def params(directory: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "oaslint_mcp", "--dir", directory], env={**os.environ, "PYTHONIOENCODING": "utf-8"})


async def call(session: ClientSession, name: str, args: dict[str, Any]) -> tuple[bool, str]:
    res = await session.call_tool(name, args)
    return bool(res.is_error), "\n".join(getattr(c, "text", "") for c in res.content)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_tools_and_a_real_session_over_stdio(tmp_path: Path) -> None:
    for name in ("petstore_v1.yaml", "bad_api.yaml"):
        shutil.copy(os.path.join(FIX, name), tmp_path / name)
    new = (tmp_path / "petstore_v1.yaml").read_text(encoding="utf-8").replace("        name:\n          type: string\n          minLength: 1\n          maxLength: 80\n", "        name:\n          type: string\n          minLength: 5\n          maxLength: 80\n").replace("      required: [name]\n      properties:\n        name:", "      required: [name, tag]\n      properties:\n        name:", 1)
    (tmp_path / "petstore_v2.yaml").write_text(new, encoding="utf-8", newline="\n")
    async with stdio_client(params(str(tmp_path))) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "oaslint"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED_TOOLS, (names - EXPECTED_TOOLS, EXPECTED_TOOLS - names)

        err, text = await call(session, "spec_overview", {"spec": "petstore_v1.yaml"})
        assert not err and "OpenAPI 3.0.3" in text and "Operations: 4" in text
        err, text = await call(session, "lint_spec", {"spec": "bad_api.yaml"})
        assert not err and "OAS1006" in text and "line " in text and "fix:" in text
        err, text = await call(session, "diff_specs", {"old": "petstore_v1.yaml", "new": "petstore_v2.yaml"})
        assert not err and "Verdict: BREAKING" in text and "request-bound-tightened" in text and "request-property-now-required" in text
        err, text = await call(session, "changelog_markdown", {"old": "petstore_v1.yaml", "new": "petstore_v2.yaml"})
        assert not err and text.startswith("# API changelog") and "## Breaking changes" in text
        err, text = await call(session, "find_endpoints", {"spec": "petstore_v1.yaml", "path_glob": "/pets/*"})
        assert not err and "getPet" in text
        err, text = await call(session, "describe_operation", {"spec": "petstore_v1.yaml", "path": "/pets", "method": "post"})
        assert not err and "name*: string" in text
        err, text = await call(session, "validate_example", {"spec": "petstore_v1.yaml", "path": "/pets", "method": "post", "kind": "request", "json": '{"name": 5}'})
        assert not err and "/name: [type]" in text


@pytest.mark.anyio
async def test_errors_reach_the_agent_with_actionable_text(tmp_path: Path) -> None:
    (tmp_path / "ok.yaml").write_bytes(b"openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\n")
    async with stdio_client(params(str(tmp_path))) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        err, text = await call(session, "spec_overview", {"spec": "missing.yaml"})
        assert err and "no such file" in text
        err, text = await call(session, "diff_specs", {"old": "ok.yaml", "new": "missing.yaml"})
        assert err and "new spec: no such file" in text
        err, text = await call(session, "describe_operation", {"spec": "ok.yaml", "path": "/x", "method": "get"})
        assert err and "no operation GET /x" in text
        err, text = await call(session, "validate_example", {"spec": "ok.yaml", "path": "/x", "method": "get", "kind": "request", "json": "{"})
        assert err


@pytest.mark.anyio
async def test_hostile_inputs_over_stdio(tmp_path: Path) -> None:
    inner = tmp_path / "sandbox"
    inner.mkdir()
    (tmp_path / "outside.yaml").write_bytes(b"openapi: 3.0.3\ninfo: {title: OUTSIDE-TITLE, version: '1'}\npaths: {}\n")
    (inner / "bomb.yaml").write_bytes(
        ("openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\na0: &a0 [x,x,x,x,x,x,x,x,x,x]\n" + "".join(f"a{i}: &a{i} [" + ",".join([f"*a{i - 1}"] * 10) + "]\n" for i in range(1, 12))).encode()
    )
    (inner / "deep.yaml").write_bytes(b"openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\nx: " + b"[" * 200_000 + b"]" * 200_000 + b"\n")
    (inner / "deep.json").write_bytes(b'{"openapi": "3.0.3", "x": ' + b"[" * 200_000 + b"]" * 200_000 + b"}")
    (inner / "regex.yaml").write_bytes(
        b"openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      description: " + b"a1 " * 300_000 + b"\n      deprecated: true\n      responses:\n        '200': {description: " + b"x" * 500_000 + b"}\n"
    )
    async with stdio_client(params(str(inner))) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        for evil in ("../outside.yaml", str(tmp_path / "outside.yaml"), "..\\outside.yaml", "sandbox/../../outside.yaml"):
            err, text = await call(session, "spec_overview", {"spec": evil})
            assert err and "OUTSIDE-TITLE" not in text, (evil, text)
        err, text = await call(session, "spec_overview", {"spec": "a" * 100_000})
        assert err
        for name in ("bomb.yaml", "deep.yaml", "deep.json"):
            err, text = await call(session, "lint_spec", {"spec": name})
            assert err, name
        err, text = await call(session, "lint_spec", {"spec": "regex.yaml"})
        assert not err and "OAS1023" in text
        err, text = await call(session, "describe_operation", {"spec": "regex.yaml", "path": "/a", "method": "get"})
        assert not err
        # server still alive after all of that
        err, text = await call(session, "find_endpoints", {"spec": "regex.yaml"})
        assert not err and "/a" in text


@pytest.mark.anyio
async def test_planted_secrets_never_appear_in_any_output(tmp_path: Path) -> None:
    spec = {
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"},
        "servers": [{"url": f"http://admin:{PASSWORD}@api.prod-secret.com/v1?api_key={TOKEN}"}],
        "paths": {"/login": {"post": {
            "operationId": "login", "summary": "Create a session", "description": "deprecated",
            "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}},
            "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}},
        }}},
        "components": {"schemas": {"Login": {"type": "object", "properties": {
            "password": {"type": "string", "default": PASSWORD, "example": PASSWORD, "enum": [PASSWORD, "x"], "format": "email"},
            "token": {"type": "integer", "enum": [TOKEN], "default": TOKEN, "example": TOKEN},
            "ok": {"type": "string", "example": 5},
        }}}},
    }
    new = json.loads(json.dumps(spec))
    new["components"]["schemas"]["Login"]["properties"]["token"]["enum"] = ["other"]
    new["components"]["schemas"]["Login"]["properties"]["token"]["default"] = "other"
    new["servers"] = [{"url": f"http://admin2:{PASSWORD}2@api.prod-secret.com/v2"}]
    (tmp_path / "a.json").write_text(json.dumps(spec), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(new), encoding="utf-8")
    async with stdio_client(params(str(tmp_path))) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        outputs = []
        for tool, args in (
            ("spec_overview", {"spec": "a.json"}),
            ("lint_spec", {"spec": "a.json"}),
            ("diff_specs", {"old": "a.json", "new": "b.json"}),
            ("changelog_markdown", {"old": "a.json", "new": "b.json"}),
            ("describe_operation", {"spec": "a.json", "path": "/login", "method": "post"}),
            ("validate_example", {"spec": "a.json", "path": "/login", "method": "post", "kind": "request", "json": json.dumps({"password": TOKEN, "token": PASSWORD})}),
            ("find_endpoints", {"spec": "a.json", "text": "login"}),
        ):
            err, text = await call(session, tool, args)
            assert not err, (tool, text)
            outputs.append((tool, text))
        for tool, text in outputs:
            assert PASSWORD not in text and TOKEN not in text, f"{tool} leaked a secret:\n{text}"
        joined = "\n".join(t for _, t in outputs)
        assert "<redacted>" in joined
