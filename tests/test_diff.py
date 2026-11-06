"""Diff classification tests: every case asserts the EXACT set of (severity, code)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from helpers import B, I, N, P, classes, diff, doc, get_doc, obj, op, q, request_doc, resp, response_doc

STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer"}


def mod(d: dict[str, Any], fn: Any) -> dict[str, Any]:
    c = copy.deepcopy(d)
    fn(c)
    return c


CASES: list[tuple[str, dict[str, Any], dict[str, Any], set[tuple[str, str]]]] = []


def case(name: str, old: dict[str, Any], new: dict[str, Any], expected: set[tuple[str, str]]) -> None:
    CASES.append((name, old, new, expected))


# ---------------------------------------------------------------- operations
two = doc({"/a": {"get": op(), "post": op(operationId="p")}, "/b": {"get": op(operationId="b")}})
case("path removed", two, doc({"/a": two["paths"]["/a"]}), {(B, "operation-removed")})
case("method removed", two, doc({"/a": {"get": op()}, "/b": two["paths"]["/b"]}), {(B, "operation-removed")})
case("operation added", doc({"/a": {"get": op()}}), two, {(N, "operation-added")})
case("operationId changed", get_doc(op(operationId="x")), get_doc(op(operationId="y")), {(N, "operation-id-changed")})
case("deprecated added", get_doc(op()), get_doc(op(deprecated=True)), {(I, "operation-deprecated")})
case("deprecated removed", get_doc(op(deprecated=True)), get_doc(op()), {(I, "operation-undeprecated")})
case(
    "path parameter renamed",
    get_doc(op(parameters=[q("id", INT, True, "path")]), path="/pets/{id}"),
    get_doc(op(parameters=[q("petId", INT, True, "path")]), path="/pets/{petId}"),
    {(N, "path-param-renamed")},
)
case("info.version bump", get_doc(op()), mod(get_doc(op()), lambda d: d["info"].update(version="2")), {(I, "api-version-changed")})
case("summary and description only", get_doc(op(summary="a", description="b")), get_doc(op(summary="c", description="d")), set())

# ---------------------------------------------------------------- parameters
base_q = get_doc(op(parameters=[q("limit", INT)]))
case("required query param added", get_doc(op()), get_doc(op(parameters=[q("k", STR, True)])), {(B, "parameter-added-required")})
case("optional query param added", get_doc(op()), get_doc(op(parameters=[q("k", STR)])), {(N, "parameter-added")})
case("param optional to required", base_q, get_doc(op(parameters=[q("limit", INT, True)])), {(B, "parameter-now-required")})
case("param required to optional", get_doc(op(parameters=[q("limit", INT, True)])), base_q, {(N, "parameter-now-optional")})
case("optional param removed", base_q, get_doc(op()), {(P, "parameter-removed")})
case("param moved query to header", base_q, get_doc(op(parameters=[q("limit", INT, False, "header")])), {(B, "parameter-location-changed")})
case("param type string to integer", get_doc(op(parameters=[q("k", STR)])), get_doc(op(parameters=[q("k", INT)])), {(B, "request-type-changed")})
case("param integer to number", base_q, get_doc(op(parameters=[q("limit", {"type": "number"})])), {(N, "request-type-widened")})
case("param number to integer", get_doc(op(parameters=[q("limit", {"type": "number"})])), base_q, {(B, "request-type-narrowed")})
enum_p = lambda *v: get_doc(op(parameters=[q("s", {"type": "string", "enum": list(v)})]))  # noqa: E731
case("param enum value removed", enum_p("a", "b"), enum_p("a"), {(B, "request-enum-removed-values")})
case("param enum value added", enum_p("a"), enum_p("a", "b"), {(N, "request-enum-added-values")})
mx = lambda v: get_doc(op(parameters=[q("n", {"type": "integer", "maximum": v})]))  # noqa: E731
case("param maximum lowered", mx(100), mx(10), {(B, "request-bound-tightened")})
case("param maximum raised", mx(10), mx(100), {(N, "request-bound-loosened")})
arr = lambda **kw: get_doc(op(parameters=[q("ids", {"type": "array", "items": STR}, **kw)]))  # noqa: E731
case("array param explode changed", arr(), arr(explode=False), {(B, "parameter-style-changed")})
case(
    "primitive param style change is invisible",
    get_doc(op(parameters=[q("k", STR)])),
    get_doc(op(parameters=[q("k", STR, style="form", explode=False)])),
    set(),
)
case("param pattern added", get_doc(op(parameters=[q("k", STR)])), get_doc(op(parameters=[q("k", {"type": "string", "pattern": "^a"})])), {(B, "request-pattern-added")})
fm = lambda f: get_doc(op(parameters=[q("n", {"type": "integer", "format": f})]))  # noqa: E731
case("param int32 to int64", fm("int32"), fm("int64"), {(N, "request-format-widened")})
case("param int64 to int32", fm("int64"), fm("int32"), {(B, "request-format-changed")})
case(
    "header name case is not a change",
    get_doc(op(parameters=[q("X-Token", STR, False, "header")])),
    get_doc(op(parameters=[q("x-token", STR, False, "header")])),
    set(),
)
case(
    "param moved from path level to operation level",
    doc({"/a": {"parameters": [q("k", STR)], "get": op()}}),
    doc({"/a": {"get": op(parameters=[q("k", STR)])}}),
    set(),
)
case("param marked deprecated", base_q, get_doc(op(parameters=[q("limit", INT, deprecated=True)])), {(I, "parameter-deprecated-changed")})
case(
    "operation parameter overrides path parameter",
    doc({"/a": {"parameters": [q("k", STR)], "get": op(parameters=[q("k", INT)])}}),
    doc({"/a": {"parameters": [q("k", INT)], "get": op()}}),
    set(),
)

# ---------------------------------------------------------------- request bodies
case("required body added", get_doc(op(), method="post"), request_doc(obj({"a": STR})), {(B, "request-body-added-required")})
case("optional body added", get_doc(op(), method="post"), request_doc(obj({"a": STR}), False), {(N, "request-body-added")})
case("body optional to required", request_doc(obj({"a": STR}), False), request_doc(obj({"a": STR}), True), {(B, "request-body-now-required")})
case("body required to optional", request_doc(obj({"a": STR}), True), request_doc(obj({"a": STR}), False), {(N, "request-body-now-optional")})
case("body removed", request_doc(obj({"a": STR})), get_doc(op(), method="post"), {(P, "request-body-removed")})
case("new required request property", request_doc(obj({"a": STR})), request_doc(obj({"a": STR, "b": STR}, ["b"])), {(B, "request-property-added-required")})
case("new optional request property", request_doc(obj({"a": STR})), request_doc(obj({"a": STR, "b": STR})), {(N, "request-property-added")})
case("request property became required", request_doc(obj({"a": STR})), request_doc(obj({"a": STR}, ["a"])), {(B, "request-property-now-required")})
case("request property became optional", request_doc(obj({"a": STR}, ["a"])), request_doc(obj({"a": STR})), {(N, "request-property-now-optional")})
case("request property removed", request_doc(obj({"a": STR, "b": STR})), request_doc(obj({"a": STR})), {(P, "request-property-removed")})
case(
    "request property removed under additionalProperties false",
    request_doc(obj({"a": STR, "b": STR}, additionalProperties=False)),
    request_doc(obj({"a": STR}, additionalProperties=False)),
    {(B, "request-property-removed")},
)
case("request property type changed", request_doc(obj({"a": STR})), request_doc(obj({"a": INT})), {(B, "request-type-changed")})
case("request additionalProperties tightened", request_doc(obj({"a": STR})), request_doc(obj({"a": STR}, additionalProperties=False)), {(B, "request-additional-properties-tightened")})
case("request additionalProperties loosened", request_doc(obj({"a": STR}, additionalProperties=False)), request_doc(obj({"a": STR})), {(N, "request-additional-properties-loosened")})
ct = lambda *m: get_doc(op(requestBody={"content": {x: {"schema": STR} for x in m}}), method="post")  # noqa: E731
case("request content type removed", ct("application/json", "application/xml"), ct("application/json"), {(B, "request-content-type-removed")})
case("request content type added", ct("application/json"), ct("application/json", "application/xml"), {(N, "request-content-type-added")})
case("request nullable removed", request_doc({"type": "string", "nullable": True}), request_doc(STR), {(B, "request-nullable-removed")})
case("request nullable added", request_doc(STR), request_doc({"type": "string", "nullable": True}), {(N, "request-nullable-added")})
case("request minLength raised", request_doc({"type": "string", "minLength": 1}), request_doc({"type": "string", "minLength": 5}), {(B, "request-bound-tightened")})
case("request enum introduced", request_doc(STR), request_doc({"type": "string", "enum": ["a"]}), {(B, "request-enum-added")})
A_, B_, C_ = obj({"a": STR}, ["a"], title="A"), obj({"b": INT}, ["b"], title="B"), obj({"c": STR}, ["c"], title="C")
case("request oneOf option removed", request_doc({"oneOf": [A_, B_]}), request_doc({"oneOf": [A_]}), {(B, "request-variant-removed")})
case("request oneOf option added", request_doc({"oneOf": [A_]}), request_doc({"oneOf": [A_, B_]}), {(N, "request-variant-added")})
case(
    "server-generated readOnly property made required in a request",
    request_doc(obj({"id": {"type": "integer", "readOnly": True}, "a": STR})),
    request_doc(obj({"id": {"type": "integer", "readOnly": True}, "a": STR}, ["id"])),
    set(),
)
case("request uniqueItems added", request_doc({"type": "array", "items": STR}), request_doc({"type": "array", "items": STR, "uniqueItems": True}), {(B, "request-unique-items-added")})

# ---------------------------------------------------------------- responses
case("response property removed", response_doc(obj({"a": STR, "b": STR})), response_doc(obj({"a": STR})), {(B, "response-property-removed")})
case("response property added", response_doc(obj({"a": STR})), response_doc(obj({"a": STR, "b": STR})), {(N, "response-property-added")})
case("response required to optional", response_doc(obj({"a": STR}, ["a"])), response_doc(obj({"a": STR})), {(B, "response-property-now-optional")})
case("response optional to required", response_doc(obj({"a": STR})), response_doc(obj({"a": STR}, ["a"])), {(N, "response-property-now-required")})
case("response type changed", response_doc(obj({"a": STR})), response_doc(obj({"a": INT})), {(B, "response-type-changed")})
case("response nullable added", response_doc(STR), response_doc({"type": "string", "nullable": True}), {(B, "response-nullable-added")})
case("response nullable removed", response_doc({"type": "string", "nullable": True}), response_doc(STR), {(N, "response-nullable-removed")})
case("response enum value added", response_doc({"type": "string", "enum": ["a"]}), response_doc({"type": "string", "enum": ["a", "b"]}), {(P, "response-enum-added-values")})
case("response enum value removed", response_doc({"type": "string", "enum": ["a", "b"]}), response_doc({"type": "string", "enum": ["a"]}), {(N, "response-enum-removed-values")})
case("success code removed", get_doc(op(resp(STR, "200"))), get_doc(op(resp(STR, "201"))), {(B, "response-removed"), (N, "response-added")})
case("200 replaced by 2XX is not a removal", get_doc(op(resp(STR, "200"))), get_doc(op(resp(STR, "2XX"))), {(N, "response-added")})
case("error code removed", get_doc(op({**resp(STR), **resp(STR, "404")})), get_doc(op(resp(STR))), {(N, "response-error-removed")})
case("error code added", get_doc(op(resp(STR))), get_doc(op({**resp(STR), **resp(STR, "404")})), {(N, "response-added")})
case(
    "response content type removed",
    get_doc(op({"200": {"description": "d", "content": {"application/json": {"schema": STR}, "text/csv": {"schema": STR}}}})),
    get_doc(op(resp(STR))),
    {(B, "response-content-type-removed")},
)
case(
    "response content type added",
    get_doc(op(resp(STR))),
    get_doc(op({"200": {"description": "d", "content": {"application/json": {"schema": STR}, "text/csv": {"schema": STR}}}})),
    {(N, "response-content-type-added")},
)
case("response oneOf variant added", response_doc({"oneOf": [A_]}), response_doc({"oneOf": [A_, B_]}), {(P, "response-variant-added")})
case("response oneOf variant removed", response_doc({"oneOf": [A_, B_]}), response_doc({"oneOf": [A_]}), {(N, "response-variant-removed")})
mxl = lambda v: response_doc({"type": "string", "maxLength": v})  # noqa: E731
case("response maxLength raised", mxl(10), mxl(20), {(P, "response-bound-loosened")})
case("response maxLength lowered", mxl(20), mxl(10), {(N, "response-bound-tightened")})
case(
    "optional response header removed",
    get_doc(op(resp(STR, headers={"X-A": {"schema": STR}}))),
    get_doc(op(resp(STR))),
    {(P, "response-header-removed")},
)
case(
    "required response header removed",
    get_doc(op(resp(STR, headers={"X-A": {"required": True, "schema": STR}}))),
    get_doc(op(resp(STR))),
    {(B, "response-header-removed")},
)
case("response integer to number", response_doc(INT), response_doc({"type": "number"}), {(B, "response-type-widened")})
case("response number to integer", response_doc({"type": "number"}), response_doc(INT), {(N, "response-type-narrowed")})
rf = lambda f: response_doc({"type": "integer", "format": f})  # noqa: E731
case("response int32 to int64", rf("int32"), rf("int64"), {(B, "response-format-widened")})
case("response additionalProperties loosened", response_doc(obj({"a": STR}, additionalProperties=False)), response_doc(obj({"a": STR})), {(P, "response-additional-properties-loosened")})
case("response array item type changed", response_doc({"type": "array", "items": STR}), response_doc({"type": "array", "items": INT}), {(B, "response-type-changed")})
case(
    "response array item property removed",
    response_doc({"type": "array", "items": obj({"a": STR, "b": STR})}),
    response_doc({"type": "array", "items": obj({"a": STR})}),
    {(B, "response-property-removed")},
)
case(
    "write-only property absent from a response is not a change",
    response_doc(obj({"a": STR, "pw": {"type": "string", "writeOnly": True}}, ["pw"])),
    response_doc(obj({"a": STR})),
    set(),
)
case(
    "added response property when old schema forbade extras",
    response_doc(obj({"a": STR}, additionalProperties=False)),
    response_doc(obj({"a": STR, "b": STR}, additionalProperties=False)),
    {(P, "response-property-added")},
)

# ---------------------------------------------------------------- security
oauth = {"securitySchemes": {"s": {"type": "http", "scheme": "bearer"}, "o": {"type": "oauth2", "flows": {"implicit": {"authorizationUrl": "https://x/a", "scopes": {"r": "r", "w": "w"}}}}}}


def secured(sec: Any, glob: Any = None) -> dict[str, Any]:
    d = get_doc(op(security=sec) if sec is not None else op())
    d["components"] = oauth
    if glob is not None:
        d["security"] = glob
    return d


case("auth added to a public operation", secured(None), secured([{"s": []}]), {(B, "auth-added")})
case("auth removed", secured([{"s": []}]), secured(None), {(N, "auth-removed")})
case("scope added", secured([{"o": ["r"]}]), secured([{"o": ["r", "w"]}]), {(B, "auth-tightened")})
case("scope removed", secured([{"o": ["r", "w"]}]), secured([{"o": ["r"]}]), {(N, "auth-loosened")})
case("alternative scheme added", secured([{"s": []}]), secured([{"s": []}, {"o": ["r"]}]), {(N, "auth-loosened")})
case("scheme replaced", secured([{"s": []}]), secured([{"o": ["r"]}]), {(B, "auth-tightened")})
case("one of two alternatives dropped", secured([{"s": []}, {"o": ["r"]}]), secured([{"s": []}]), {(P, "auth-option-removed")})
case("global security added", secured(None), secured(None, [{"s": []}]), {(B, "auth-added")})
case("explicit empty security equals none", secured([]), secured(None), set())
case(
    "scheme type changed while in use",
    secured([{"s": []}]),
    mod(secured([{"s": []}]), lambda d: d["components"]["securitySchemes"].update(s={"type": "apiKey", "in": "header", "name": "X"})),
    {(B, "scheme-changed")},
)

# ---------------------------------------------------------------- servers, composition, misc
case("base path changed", get_doc(op(), servers=[{"url": "https://x/v1"}]), get_doc(op(), servers=[{"url": "https://x/v2"}]), {(B, "base-path-changed")})
case("host changed only", get_doc(op(), servers=[{"url": "https://x/v1"}]), get_doc(op(), servers=[{"url": "https://y/v1"}]), {(I, "servers-changed")})
case("oneOf changed to anyOf", response_doc({"oneOf": [A_, B_]}), response_doc({"anyOf": [A_, B_]}), {(P, "composition-kind-changed")})
disc = lambda m: response_doc({"oneOf": [A_, B_], "discriminator": {"propertyName": "k", "mapping": m}})  # noqa: E731
case("discriminator mapping changed", disc({"a": "x"}), disc({"a": "y"}), {(P, "discriminator-changed")})
case("callback removed", get_doc(op(callbacks={"cb": {"{$request.body#/u}": {"post": {"responses": {"200": {"description": "d"}}}}}})), get_doc(op()), {(P, "callback-removed")})
case(
    "webhook removed",
    doc({}, version="3.1.0", webhooks={"w": {"post": op()}}),
    doc({}, version="3.1.0"),
    {(P, "webhook-removed")},
)
case("default value changed", response_doc({"type": "string", "default": "a"}), response_doc({"type": "string", "default": "b"}), {(I, "default-changed")})
case("schema newly deprecated", response_doc({"type": "string"}), response_doc({"type": "string", "deprecated": True}), {(I, "schema-deprecated-changed")})
case("opaque keyword changed", request_doc({"type": "object", "not": {"required": ["a"]}}), request_doc({"type": "object", "not": {"required": ["b"]}}), {(P, "keyword-changed")})

# ------------------------------------------- equivalent specs: NO changes allowed
PET = obj({"id": INT, "name": STR, "tag": STR}, ["id", "name"])
case(
    "$ref versus inline",
    response_doc({"$ref": "#/components/schemas/Pet"}, {"Pet": PET}),
    response_doc(PET),
    set(),
)
case(
    "renamed component with identical content",
    response_doc({"$ref": "#/components/schemas/Pet"}, {"Pet": PET}),
    response_doc({"$ref": "#/components/schemas/Animal"}, {"Animal": PET}),
    set(),
)
case(
    "reordered properties and required",
    response_doc(obj({"id": INT, "name": STR}, ["id", "name"])),
    response_doc(obj({"name": STR, "id": INT}, ["name", "id"])),
    set(),
)
case(
    "3.0 nullable versus 3.1 type array",
    response_doc({"type": "string", "nullable": True}),
    response_doc({"type": ["string", "null"]}, version="3.1.0"),
    set(),
)
case(
    "3.1 oneOf with null versus nullable",
    response_doc({"oneOf": [STR, {"type": "null"}]}, version="3.1.0"),
    response_doc({"type": "string", "nullable": True}),
    set(),
)
case(
    "allOf split versus flat object",
    response_doc({"allOf": [obj({"a": STR}, ["a"]), obj({"b": INT})]}),
    response_doc(obj({"a": STR, "b": INT}, ["a"])),
    set(),
)
case("const versus one-value enum", response_doc({"type": "string", "const": "x"}, version="3.1.0"), response_doc({"type": "string", "enum": ["x"]}), set())
case(
    "exclusiveMinimum boolean versus numeric",
    request_doc({"type": "integer", "minimum": 5, "exclusiveMinimum": True}),
    request_doc({"type": "integer", "exclusiveMinimum": 5}, version="3.1.0"),
    set(),
)
case("oneOf options reordered", response_doc({"oneOf": [A_, B_, C_]}), response_doc({"oneOf": [C_, A_, B_]}), set())
case(
    "examples and descriptions ignored",
    response_doc({"type": "string", "example": "a", "description": "x", "title": "T"}),
    response_doc({"type": "string", "example": "zzz", "description": "completely different", "title": "U"}),
    set(),
)
case("enum order ignored", response_doc({"type": "string", "enum": ["a", "b"]}), response_doc({"type": "string", "enum": ["b", "a"]}), set())
case("integer-valued response key order", get_doc(op({**resp(STR, "200"), **resp(STR, "400")})), get_doc(op({**resp(STR, "400"), **resp(STR, "200")})), set())
REC = {"Node": obj({"v": INT, "next": {"$ref": "#/components/schemas/Node"}}, ["v"])}
case(
    "recursive schema compared with itself",
    response_doc({"$ref": "#/components/schemas/Node"}, REC),
    response_doc({"$ref": "#/components/schemas/Node"}, copy.deepcopy(REC)),
    set(),
)


@pytest.mark.parametrize("name,old,new,expected", CASES, ids=[c[0] for c in CASES])
def test_classification(name: str, old: dict[str, Any], new: dict[str, Any], expected: set[tuple[str, str]]) -> None:
    assert classes(old, new) == expected


def test_case_count_is_at_least_sixty() -> None:
    assert len(CASES) >= 60
    assert len({c[0] for c in CASES}) == len(CASES)


# ------------------------------------------------------ cases needing more than a class set
def test_recursive_schema_change_found_once_per_location() -> None:
    new_rec = {"Node": obj({"v": STR, "next": {"$ref": "#/components/schemas/Node"}}, ["v"])}
    res = diff(response_doc({"$ref": "#/components/schemas/Node"}, REC), response_doc({"$ref": "#/components/schemas/Node"}, new_rec))
    assert {(c.severity, c.code) for c in res.changes} == {(B, "response-type-changed")}
    assert len(res.changes) == 1


def test_change_reports_operation_schema_path_and_pointer() -> None:
    res = diff(
        response_doc(obj({"a": obj({"b": STR, "c": STR})})),
        response_doc(obj({"a": obj({"b": STR})})),
    )
    (c,) = res.changes
    assert c.where == "GET /t"
    assert c.at == "response 200 application/json $.a.c"
    assert c.pointer == "/paths/~1t/get/responses/200/content/application~1json/schema/properties/a/properties/c"
    assert c.side == "old"


def test_line_numbers_come_from_the_source_file() -> None:
    old = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /t:\n    get:\n      operationId: g\n      responses:\n        '200':\n          description: d\n          content:\n            application/json:\n              schema:\n                type: object\n                properties:\n                  a: {type: string}\n                  b: {type: string}\n"
    new = old.replace("                  b: {type: string}\n", "")
    from helpers import load
    from oaslint_mcp.diff import diff_specs

    res = diff_specs(load(old), load(new))
    (c,) = res.changes
    assert c.side == "old" and c.line == 16


def test_swagger2_and_openapi3_equivalent_specs_show_no_changes() -> None:
    sw = {
        "swagger": "2.0", "info": {"title": "t", "version": "1"}, "host": "x.example", "basePath": "/v1", "schemes": ["https"],
        "consumes": ["application/json"], "produces": ["application/json"],
        "paths": {"/pets/{id}": {"post": {
            "operationId": "upd",
            "parameters": [
                {"name": "id", "in": "path", "required": True, "type": "integer", "format": "int64"},
                {"name": "dry", "in": "query", "type": "boolean"},
                {"name": "b", "in": "body", "required": True, "schema": {"$ref": "#/definitions/Pet"}},
            ],
            "responses": {"200": {"description": "ok", "schema": {"$ref": "#/definitions/Pet"}}},
        }}},
        "definitions": {"Pet": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "n": {"type": "string", "x-nullable": True}}}},
    }
    oa = {
        "openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "servers": [{"url": "https://x.example/v1"}],
        "paths": {"/pets/{id}": {"post": {
            "operationId": "upd",
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "format": "int64"}},
                {"name": "dry", "in": "query", "schema": {"type": "boolean"}},
            ],
            "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}},
            "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}},
        }}},
        "components": {"schemas": {"Pet": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "n": {"type": "string", "nullable": True}}}}},
    }
    assert classes(sw, oa) == set()
    assert classes(oa, sw) == set()


def test_swagger2_breaking_change_is_found() -> None:
    sw = {
        "swagger": "2.0", "info": {"title": "t", "version": "1"},
        "paths": {"/p": {"get": {"responses": {"200": {"description": "ok", "schema": {"type": "object", "properties": {"a": {"type": "string"}}}}}}}},
    }
    sw2 = copy.deepcopy(sw)
    sw2["paths"]["/p"]["get"]["responses"]["200"]["schema"]["properties"] = {}
    assert classes(sw, sw2) == {(B, "response-property-removed")}


def test_allof_with_conflicting_part_is_flattened_before_comparison() -> None:
    old = response_doc({"allOf": [{"$ref": "#/components/schemas/Base"}, obj({"x": STR}, ["x"])]}, {"Base": obj({"id": INT}, ["id"])})
    new = response_doc({"allOf": [{"$ref": "#/components/schemas/Base"}, obj({"x": STR})]}, {"Base": obj({"id": INT}, ["id"])})
    assert classes(old, new) == {(B, "response-property-now-optional")}


def test_oneof_pair_with_same_name_is_compared_deeply() -> None:
    schemas_old = {"Cat": obj({"meow": STR}, ["meow"]), "Dog": obj({"bark": STR})}
    schemas_new = {"Cat": obj({"meow": INT}, ["meow"]), "Dog": obj({"bark": STR})}
    one = {"oneOf": [{"$ref": "#/components/schemas/Cat"}, {"$ref": "#/components/schemas/Dog"}]}
    assert classes(response_doc(one, schemas_old), response_doc(one, schemas_new)) == {(B, "response-type-changed")}


def test_remote_ref_in_new_spec_is_reported_not_fetched() -> None:
    res = diff(response_doc(STR), response_doc({"$ref": "https://example.invalid/x.yaml#/Pet"}))
    assert [(c.severity, c.code) for c in res.changes] == [(I, "unresolved-ref")]
    assert "never fetches" in res.changes[0].message


def test_diff_reports_when_two_paths_collapse_to_one_shape() -> None:
    d = doc({"/p/{a}": {"get": op()}, "/p/{b}": {"get": op(operationId="o2")}})
    res = diff(d, d)
    assert any("same shape" in n for n in res.notes)


def test_json_roundtrip_of_key_order_is_a_noop() -> None:
    d = response_doc(obj({"id": INT, "name": STR}, ["id", "name"]))
    shuffled = json.dumps(d, sort_keys=True)
    assert classes(json.dumps(d), shuffled) == set()
