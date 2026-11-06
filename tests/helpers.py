"""Tiny builders so every diff test reads as 'old spec, new spec, expected classifications'."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from oaslint_mcp.diff import BREAKING, INFO, NONBREAKING, POTENTIAL, DiffResult, diff_specs
from oaslint_mcp.spec import Sandbox, Spec, load_spec

B, P, N, I = BREAKING, POTENTIAL, NONBREAKING, INFO  # noqa: E741

STR_SCHEMA: dict[str, Any] = {"type": "string"}
SANDBOX = Sandbox(tempfile.gettempdir())
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def doc(paths: dict[str, Any], schemas: dict[str, Any] | None = None, version: str = "3.0.3", **top: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"openapi": version, "info": {"title": "t", "version": "1"}, "paths": paths}
    if schemas:
        d["components"] = {"schemas": schemas}
    d.update(top)
    return d


def load(d: dict[str, Any] | str, sandbox: Sandbox = SANDBOX) -> Spec:
    text = d if isinstance(d, str) else json.dumps(d)
    return load_spec(sandbox, text)


def resp(schema: Any = None, code: str = "200", mime: str = "application/json", **extra: Any) -> dict[str, Any]:
    r: dict[str, Any] = {"description": "d", **extra}
    if schema is not None:
        r["content"] = {mime: {"schema": schema}}
    return {code: r}


def op(responses: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
    o: dict[str, Any] = {"operationId": kw.pop("operationId", "op"), "responses": responses if responses is not None else resp({"type": "string"})}
    o.update(kw)
    return o


def body(schema: Any, required: bool = True, mime: str = "application/json") -> dict[str, Any]:
    return {"required": required, "content": {mime: {"schema": schema}}}


def obj(props: dict[str, Any], required: tuple[str, ...] | list[str] = (), **kw: Any) -> dict[str, Any]:
    o: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        o["required"] = list(required)
    o.update(kw)
    return o


def q(name: str, schema: Any = None, required: bool = False, loc: str = "query", **kw: Any) -> dict[str, Any]:
    return {"name": name, "in": loc, "required": required, "schema": schema if schema is not None else {"type": "string"}, **kw}


def get_doc(operation: dict[str, Any], path: str = "/t", method: str = "get", schemas: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    return doc({path: {method: operation}}, schemas, **top)


def response_doc(schema: Any, schemas: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    return get_doc(op(resp(schema)), schemas=schemas, **top)


def request_doc(schema: Any, required: bool = True, schemas: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    return get_doc(op(resp({"type": "string"}), requestBody=body(schema, required)), method="post", schemas=schemas, **top)


def diff(old: dict[str, Any] | str, new: dict[str, Any] | str) -> DiffResult:
    return diff_specs(load(old), load(new))


def classes(old: dict[str, Any] | str, new: dict[str, Any] | str) -> set[tuple[str, str]]:
    return {(c.severity, c.code) for c in diff(old, new).changes}
