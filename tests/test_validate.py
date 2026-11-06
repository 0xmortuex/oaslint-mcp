"""Example validation (the JSON-Schema subset) and describe_operation / find_endpoints."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from helpers import FIXTURES, body, doc, get_doc, load, obj, op, resp

from oaslint_mcp import describe
from oaslint_mcp.errors import SpecError
from oaslint_mcp.spec import Sandbox, load_spec
from oaslint_mcp.validate import validate


def v(schema: Any, instance: Any, schemas: dict[str, Any] | None = None, mode: str = "any", version: str = "3.0.3") -> list[tuple[str, str]]:
    s = load(get_doc(op(resp(schema)), schemas=schemas, version=version))
    return [(x.pointer, x.keyword) for x in validate(s, schema, instance, mode).violations]


def test_type_checks_and_integer_rules() -> None:
    assert v({"type": "integer"}, 3) == []
    assert v({"type": "integer"}, 3.0) == []
    assert v({"type": "integer"}, 3.5) == [("", "type")]
    assert v({"type": "integer"}, True) == [("", "type")]
    assert v({"type": "number"}, 3) == []
    assert v({"type": "string"}, None) == [("", "type")]
    assert v({"type": "string", "nullable": True}, None) == []
    assert v({"type": ["string", "null"]}, None, version="3.1.0") == []


def test_object_violations_carry_json_pointers() -> None:
    schema = obj({"a": {"type": "string"}, "tags": {"type": "array", "items": {"type": "integer"}}, "n": obj({"x": {"type": "string", "minLength": 2}})}, ["a"], additionalProperties=False)
    got = v(schema, {"tags": [1, "x", 3], "n": {"x": "z"}, "extra": 1})
    assert ("", "required") in got
    assert ("/tags/1", "type") in got
    assert ("/n/x", "minLength") in got
    assert ("/extra", "additionalProperties") in got


def test_pointer_escaping_in_property_names() -> None:
    got = v(obj({"a/b": {"type": "integer"}, "c~d": {"type": "integer"}}), {"a/b": "x", "c~d": "y"})
    assert ("/a~1b", "type") in got and ("/c~0d", "type") in got


def test_enum_const_format_pattern_bounds() -> None:
    assert v({"type": "string", "enum": ["a", "b"]}, "c") == [("", "enum")]
    assert v({"type": "string", "const": "k"}, "j", version="3.1.0") == [("", "enum")]
    assert v({"type": "string", "format": "date-time"}, "2024-01-02T03:04:05Z") == []
    assert v({"type": "string", "format": "date-time"}, "yesterday") == [("", "format")]
    assert v({"type": "string", "format": "date"}, "2024-02-30") == [("", "format")]
    assert v({"type": "string", "format": "email"}, "a@b.co") == []
    assert v({"type": "string", "format": "uuid"}, "nope") == [("", "format")]
    assert v({"type": "string", "pattern": "^[A-Z]{3}$"}, "abc") == [("", "pattern")]
    assert v({"type": "integer", "minimum": 1, "maximum": 5}, 0) == [("", "minimum")]
    assert v({"type": "integer", "minimum": 1, "exclusiveMinimum": True}, 1) == [("", "minimum")]
    assert v({"type": "integer", "format": "int32"}, 2**31) == [("", "format")]
    assert v({"type": "integer", "multipleOf": 5}, 7) == [("", "multipleOf")]
    assert v({"type": "array", "items": {"type": "integer"}, "uniqueItems": True}, [1, 2, 1]) == [("/2", "uniqueItems")]
    assert v({"type": "array", "items": {"type": "integer"}, "minItems": 2}, [1]) == [("", "minItems")]


def test_composition_keywords() -> None:
    cat, dog = obj({"meow": {"type": "string"}}, ["meow"]), obj({"bark": {"type": "string"}}, ["bark"])
    assert v({"oneOf": [cat, dog]}, {"meow": "x"}) == []
    assert v({"oneOf": [cat, dog]}, {}) == [("", "oneOf")]
    assert v({"oneOf": [{"type": "integer"}, {"type": "number"}]}, 3) == [("", "oneOf")]
    assert v({"anyOf": [cat, dog]}, {"bark": "x"}) == []
    assert v({"anyOf": [cat, dog]}, {"zzz": 1}) == [("", "anyOf")]
    assert v({"allOf": [cat, obj({"age": {"type": "integer"}}, ["age"])]}, {"meow": "x"}) == [("", "required")]


def test_recursive_schemas_validate_without_hanging() -> None:
    schemas = {"Node": obj({"v": {"type": "integer"}, "next": {"$ref": "#/components/schemas/Node"}}, ["v"])}
    node = {"$ref": "#/components/schemas/Node"}
    deep: dict[str, Any] = {"v": "bad"}
    for _ in range(50):
        deep = {"v": 1, "next": deep}
    assert v(node, deep, schemas) == [("/next" * 50 + "/v", "type")]


def test_read_only_and_write_only_required_semantics() -> None:
    schema = obj({"id": {"type": "integer", "readOnly": True}, "pw": {"type": "string", "writeOnly": True}}, ["id", "pw"])
    assert v(schema, {"pw": "x"}, mode="request") == []
    assert v(schema, {"id": 1}, mode="response") == []
    assert v(schema, {}, mode="any") == [("", "required"), ("", "required")]


def test_catastrophic_pattern_is_skipped_with_a_note() -> None:
    s = load(get_doc(op(resp({"type": "string"}))))
    t0 = time.monotonic()
    res = validate(s, {"type": "string", "pattern": "^(a+)+$"}, "a" * 40 + "!")
    assert time.monotonic() - t0 < 5
    assert res.violations == [] and any("catastrophically" in n for n in res.notes)


def test_unevaluated_keywords_are_reported_as_notes() -> None:
    s = load(get_doc(op(resp({"type": "string"}))))
    res = validate(s, {"type": "object", "not": {"required": ["a"]}}, {})
    assert any("'not' is not evaluated" in n for n in res.notes)


def test_violation_values_do_not_echo_secrets() -> None:
    s = load(get_doc(op(resp({"type": "string"}))))
    token = "sk-live-" + "A1b2C3d4" * 6
    res = validate(s, obj({"api_key": {"type": "string", "enum": ["a"]}, "mail": {"type": "string", "format": "email"}}), {"api_key": token, "mail": token})
    text = json.dumps([x.message for x in res.violations])
    assert token not in text and "<redacted>" in text


# ------------------------------------------------------------ tool-level
def petstore() -> Any:
    return load_spec(Sandbox(FIXTURES), "petstore_v1.yaml")


def test_validate_example_request_and_response() -> None:
    s = petstore()
    ok = describe.validate_op_example(s, "/pets", "post", "request", "", '{"name": "Rex"}')
    assert ok.endswith("VALID") and "INVALID" not in ok
    bad = describe.validate_op_example(s, "/pets", "post", "request", "", '{"name": "", "status": "lost"}')
    assert "INVALID" in bad and "/name: [minLength]" in bad and "/status: [enum]" in bad
    resp_bad = describe.validate_op_example(s, "/pets/{id}", "get", "response", "200", '{"name": "x", "owner": {"pets": [{"id": "z"}]}}')
    assert "/owner/name" not in resp_bad or "required" in resp_bad
    assert "[required]" in resp_bad and "/owner/pets/0/id: [type]" in resp_bad


def test_validate_example_errors_are_actionable() -> None:
    s = petstore()
    with pytest.raises(SpecError, match="not valid JSON"):
        describe.validate_op_example(s, "/pets", "post", "request", "", "{nope")
    with pytest.raises(SpecError, match="no request body"):
        describe.validate_op_example(s, "/pets/{petId}", "get", "request", "", "{}")
    with pytest.raises(SpecError, match="documented"):
        describe.validate_op_example(s, "/pets", "post", "response", "418", "{}")
    with pytest.raises(SpecError, match="kind must be"):
        describe.validate_op_example(s, "/pets", "post", "both", "", "{}")
    with pytest.raises(SpecError, match="nothing to validate"):
        describe.validate_op_example(s, "/pets/{petId}", "get", "response", "404", "{}")


def test_describe_operation_outline() -> None:
    out = describe.describe(petstore(), "/pets", "post")
    assert "POST /pets   operationId: createPet" in out
    assert "name*: string {minLength=1, maxLength=80}" in out
    assert "Security (any one of): oauth[write:pets]" in out
    assert "201 - Created" in out
    out1 = describe.describe(petstore(), "/pets/{petId}", "get", depth=1)
    assert "depth limit 1" in out1


def test_describe_operation_errors() -> None:
    s = petstore()
    with pytest.raises(SpecError, match="has no PUT"):
        describe.describe(s, "/pets", "put")
    with pytest.raises(SpecError, match="no operation GET /nothing"):
        describe.describe(s, "/nothing", "get")
    with pytest.raises(SpecError, match="depth"):
        describe.describe(s, "/pets", "get", depth=99)


def test_path_level_and_operation_level_parameters_merge() -> None:
    d = doc({"/a/{id}": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}, {"name": "v", "in": "query", "schema": {"type": "string"}}],
                         "get": op(parameters=[{"name": "v", "in": "query", "required": True, "schema": {"type": "integer"}}])}})
    out = describe.describe(load(d), "/a/{id}", "get")
    assert "- id (path, required): integer" in out
    assert "- v (query, required): integer" in out and out.count("- v (") == 1


def test_find_endpoints_filters() -> None:
    s = petstore()
    assert "4 endpoint(s) matched" in describe.find_endpoints(s)
    assert "2 endpoint(s)" in describe.find_endpoints(s, path_glob="/pets/*")
    out = describe.find_endpoints(s, method="delete")
    assert "DELETE" in out and "DEPRECATED" in out and "1 endpoint" in out
    assert "createPet" in describe.find_endpoints(s, text="create")
    assert "1 endpoint" in describe.find_endpoints(s, tag="PETS", method="post")
    assert describe.find_endpoints(s, text="zzz").startswith("No endpoints matched")
    with pytest.raises(SpecError, match="unknown method"):
        describe.find_endpoints(s, method="fetch")


def test_swagger2_describe_shows_body_and_formdata() -> None:
    sw = {
        "swagger": "2.0", "info": {"title": "t", "version": "1"}, "consumes": ["application/json"],
        "paths": {"/u": {"post": {"consumes": ["multipart/form-data"], "parameters": [
            {"name": "file", "in": "formData", "type": "file", "required": True},
            {"name": "note", "in": "formData", "type": "string"}], "responses": {"200": {"description": "ok"}}}}},
    }
    out = describe.describe(load(sw), "/u", "post")
    assert "multipart/form-data" in out and "file*: string (binary)" in out and "note: string" in out
    _ = body
