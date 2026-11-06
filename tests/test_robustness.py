"""Malformed specs must raise SpecError (a clear message) or work; never an AttributeError/TypeError."""

from __future__ import annotations

import copy
import json
import os
import random
from typing import Any

import pytest
import yaml
from helpers import FIXTURES, load

from oaslint_mcp import describe
from oaslint_mcp.diff import diff_specs
from oaslint_mcp.errors import SpecError
from oaslint_mcp.lint import lint
from oaslint_mcp.report import changelog, diff_report, lint_report

JUNK: list[Any] = [
    None, 5, -1, 2.5, "x", "", True, False, [], {}, [1, "a"], {"$ref": "#/components/schemas/Pet"},
    {"$ref": "#/nope"}, {"type": "array"}, {"type": ["a", 3]}, {"allOf": [{"$ref": "#/components/schemas/Pet"}]},
    {"oneOf": 5}, {"properties": []}, {"required": "x"}, {"$ref": 5}, {"enum": 5}, {"items": []},
    {"type": "object", "additionalProperties": []},
]


def read(name: str) -> dict[str, Any]:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return data


def walk(node: Any, p: tuple[Any, ...] = ()) -> Any:
    yield p
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk(v, p + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, p + (i,))


def mutate(doc: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    d = copy.deepcopy(doc)
    ps = [p for p in walk(d) if p]
    for _ in range(rng.randint(1, 4)):
        p = rng.choice(ps)
        parent: Any = d
        try:
            for k in p[:-1]:
                parent = parent[k]
            if rng.random() < 0.2:
                del parent[p[-1]]
            else:
                parent[p[-1]] = copy.deepcopy(rng.choice(JUNK))
        except (KeyError, IndexError, TypeError):
            pass
    return d


def exercise(a_text: str, b_text: str) -> None:
    try:
        a = load(a_text)
        b = load(b_text)
        describe.overview(a)
        lint_report(a, lint(a))
        describe.find_endpoints(a, "/p*", "get", "pets", "x")
        describe.describe(a, "/pets", "post")
        describe.describe(a, "/pets/{petId}", "get")
        describe.validate_op_example(a, "/pets", "post", "request", "", '{"name": 1}')
        res = diff_specs(a, b)
        diff_report(res, a, b)
        changelog(res, a, b)
    except SpecError:
        pass


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_mutated_specs_never_crash(seed: int) -> None:
    rng = random.Random(seed)
    sources = [read("petstore_v1.yaml"), read("bad_api.yaml")]
    for _ in range(120):
        src = rng.choice(sources)
        exercise(json.dumps(mutate(src, rng)), json.dumps(mutate(src, rng)))


def test_non_mapping_security_flows_and_scopes() -> None:
    d = read("petstore_v1.yaml")
    d["components"]["securitySchemes"]["oauth"]["flows"] = 5
    exercise(json.dumps(d), json.dumps(d))
    d["components"]["securitySchemes"]["oauth"]["flows"] = {"implicit": {"scopes": 1.5}}
    exercise(json.dumps(d), json.dumps(d))
    d["components"]["securitySchemes"] = [1, 2]
    exercise(json.dumps(d), json.dumps(d))


def test_swagger2_with_non_list_schemes_and_consumes() -> None:
    sw = {"swagger": "2.0", "info": {"title": "t", "version": "1"}, "schemes": "https", "consumes": 5, "produces": {"a": 1},
          "paths": {"/p": {"get": {"consumes": "x", "produces": 3, "responses": {"200": {"description": "ok"}}}}}}
    exercise(json.dumps(sw), json.dumps(sw))
