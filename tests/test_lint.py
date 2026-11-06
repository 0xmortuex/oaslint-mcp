"""Lint corpus: each expectation is (rule id, severity, JSON pointer)."""

from __future__ import annotations

import pytest
from helpers import FIXTURES, body, get_doc, load, obj, op, q, resp

from oaslint_mcp.lint import RULES, lint
from oaslint_mcp.spec import Sandbox, load_spec


@pytest.fixture(scope="module")
def bad() -> list[tuple[str, str, str, int | None]]:
    s = load_spec(Sandbox(FIXTURES), "bad_api.yaml")
    return [(f.rule, f.severity, f.pointer, f.line) for f in lint(s)]


EXPECTED = [
    ("OAS1001", "warning", "/paths/~1users~1/get"),
    ("OAS1002", "error", "/paths/~1users~1{id}/delete/operationId"),
    ("OAS1003", "error", "/paths/~1items/get/responses"),
    ("OAS1004", "warning", "/paths/~1no2xx/get/responses"),
    ("OAS1005", "info", "/paths/~1users~1/get/responses"),
    ("OAS1006", "error", "/paths/~1users~1{id}/get"),
    ("OAS1006", "error", "/paths/~1widgets~1{wid}/get"),
    ("OAS1007", "error", "/paths/~1widgets~1{wid}/get/parameters/0"),
    ("OAS1008", "error", "/paths/~1widgets~1{wid}/get/parameters/1"),
    ("OAS1009", "warning", "/paths/~1items/get/parameters/1"),
    ("OAS1009", "warning", "/paths/~1items/get/parameters/2"),
    ("OAS1010", "warning", "/components/schemas/Unused"),
    ("OAS1011", "info", "/components/schemas/Item/properties/free"),
    ("OAS1012", "warning", "/components/schemas/Item/required"),
    ("OAS1013", "error", "/components/schemas/Item/properties/id/enum"),
    ("OAS1014", "error", "/components/schemas/Item/properties/count/default"),
    ("OAS1015", "warning", "/components/schemas/Item/properties/name/example"),
    ("OAS1016", "info", "/paths/~1users~1/get"),
    ("OAS1017", "warning", "/paths/~1items/post/responses/200"),
    ("OAS1018", "error", "/paths/~1items/post/security/0"),
    ("OAS1019", "warning", "/servers/0/url"),
    ("OAS1020", "info", "/paths/~1items/post/responses/200"),
    ("OAS1021", "warning", "/paths/~1users~1"),
    ("OAS1022", "error", "/paths/~1users~1{userId}"),
    ("OAS1023", "info", "/paths/~1users~1{id}/delete/deprecated"),
    ("OAS1024", "error", "/components/schemas/Item/properties/ghost/$ref"),
    ("OAS1024", "warning", "/components/schemas/Item/properties/remote/$ref"),
]


@pytest.mark.parametrize("rule,sev,ptr", EXPECTED, ids=[f"{r}@{p}" for r, _, p in EXPECTED])
def test_corpus_finding(bad: list[tuple[str, str, str, int | None]], rule: str, sev: str, ptr: str) -> None:
    hits = [b for b in bad if b[0] == rule and b[2] == ptr]
    assert hits, f"{rule} not reported at {ptr}; got {[b for b in bad if b[0] == rule]}"
    assert hits[0][1] == sev
    assert hits[0][3] is not None, "a line number should be derivable for this pointer"


def test_corpus_has_no_false_positives_on_clean_parts(bad: list[tuple[str, str, str, int | None]]) -> None:
    flagged = {(r, p) for r, _, p, _ in bad}
    assert ("OAS1019", "/servers/1/url") not in flagged  # localhost is not production-looking
    assert not any(p.startswith("/paths/~1users~1{userId}/get/parameters") for _, p in flagged)
    assert {b[0] for b in bad} <= set(RULES)
    assert len({r for r, *_ in bad}) >= 24


def test_every_rule_has_a_fix_and_message() -> None:
    s = load_spec(Sandbox(FIXTURES), "bad_api.yaml")
    for f in lint(s):
        assert f.message and f.fix and f.rule in RULES


def test_clean_petstore_has_no_errors_or_warnings() -> None:
    s = load_spec(Sandbox(FIXTURES), "petstore_v1.yaml")
    assert [f for f in lint(s) if f.severity in ("error", "warning")] == []


def test_unused_components_are_found_transitively() -> None:
    d = get_doc(op(resp({"$ref": "#/components/schemas/Used"})),
                schemas={"Used": {"type": "string"}, "A": {"$ref": "#/components/schemas/B"}, "B": {"type": "string"}})
    ptrs = {f.pointer for f in lint(load(d)) if f.rule == "OAS1010"}
    assert ptrs == {"/components/schemas/A", "/components/schemas/B"}


def test_swagger2_lint_unused_definition_and_missing_scheme() -> None:
    sw = {
        "swagger": "2.0", "info": {"title": "t", "version": "1"}, "security": [{"nope": []}],
        "paths": {"/p": {"get": {"operationId": "g", "summary": "s", "responses": {"200": {"description": "ok"}, "404": {"description": "nf"}}}}},
        "definitions": {"Orphan": {"type": "string"}},
    }
    got = {(f.rule, f.pointer) for f in lint(load(sw))}
    assert ("OAS1010", "/definitions/Orphan") in got
    assert ("OAS1018", "/security/0") in got


def test_example_validation_in_media_type_and_3_1_examples() -> None:
    schema = obj({"n": {"type": "integer"}}, ["n"])
    d = get_doc(op({"200": {"description": "d", "content": {"application/json": {
        "schema": schema, "example": {"n": "x"}, "examples": {"ok": {"value": {"n": 1}}, "bad": {"value": {}}}}}}}))
    ptrs = {f.pointer for f in lint(load(d)) if f.rule == "OAS1015"}
    assert ptrs == {
        "/paths/~1t/get/responses/200/content/application~1json/example",
        "/paths/~1t/get/responses/200/content/application~1json/examples/bad/value",
    }


def test_post_creating_with_200_but_201_present_is_fine() -> None:
    d = get_doc(op({**resp({"type": "string"}, "200"), **resp({"type": "string"}, "201")}, summary="Create thing"), method="post")
    assert "OAS1020" not in {f.rule for f in lint(load(d))}


def test_https_and_templated_servers_are_not_flagged() -> None:
    d = get_doc(op(), servers=[{"url": "https://api.example.com"}, {"url": "http://{env}.example.com", "variables": {"env": {"default": "staging"}}},
                               {"url": "http://api.prod-example.com"}])
    ptrs = {f.pointer for f in lint(load(d)) if f.rule == "OAS1019"}
    assert ptrs == {"/servers/2/url"}


def test_trailing_slash_majority_rules() -> None:
    d = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
         "paths": {"/a": {"get": op()}, "/b": {"get": op(operationId="b")}, "/c/": {"get": op(operationId="c")}}}
    ptrs = {f.pointer for f in lint(load(d)) if f.rule == "OAS1021"}
    assert ptrs == {"/paths/~1c~1"}


def test_naming_consistency_ignores_single_word_names() -> None:
    d = get_doc(op(parameters=[q("limit"), q("offset"), q("page_size"), q("sort_order")]))
    assert not [f for f in lint(load(d)) if f.rule == "OAS1009"]


def test_callbacks_and_webhooks_are_linted_shallowly() -> None:
    d = get_doc(op(callbacks={"cb": {"{$request.body#/url}": {"post": {"summary": "no responses"}}}}), version="3.1.0",
                webhooks={"newPet": {"post": {"summary": "x"}}})
    ptrs = {f.pointer for f in lint(load(d)) if f.rule == "OAS1003"}
    assert "/webhooks/newPet/post" in ptrs
    assert any("callbacks/cb" in p for p in ptrs)


def test_required_property_defined_in_an_allof_part_is_not_flagged() -> None:
    schemas = {"Base": obj({"id": {"type": "integer"}}), "Child": {"allOf": [{"$ref": "#/components/schemas/Base"}, {"type": "object", "required": ["id"]}]}}
    d = get_doc(op(resp({"$ref": "#/components/schemas/Child"})), schemas=schemas)
    assert not [f for f in lint(load(d)) if f.rule == "OAS1012"]


def test_request_body_default_and_enum_mismatch_inline() -> None:
    d = get_doc(op(resp({"type": "string"}), requestBody=body({"type": "string", "enum": ["a", "b"], "default": "c"})), method="post")
    got = {(f.rule, f.pointer) for f in lint(load(d))}
    assert ("OAS1014", "/paths/~1t/post/requestBody/content/application~1json/schema/default") in got
