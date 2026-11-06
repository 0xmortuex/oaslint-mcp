"""Loading, version detection, $ref resolution, sandboxing, and hostile-input guards."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest
from helpers import FIXTURES, STR_SCHEMA, doc, get_doc, load, op, resp

from oaslint_mcp import describe, loader
from oaslint_mcp.errors import RefError, SpecError
from oaslint_mcp.lint import lint
from oaslint_mcp.spec import Sandbox, load_spec


def write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return str(path)


MIN_YAML = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths: {}\n"


# --------------------------------------------------------------- versions
def test_versions_are_detected_and_reported(tmp_path: Path) -> None:
    sb = Sandbox(str(tmp_path))
    write(tmp_path / "a.yaml", MIN_YAML)
    write(tmp_path / "b.yaml", MIN_YAML.replace("3.0.3", "3.1.0"))
    write(tmp_path / "c.json", json.dumps({"swagger": "2.0", "info": {"title": "t", "version": "1"}, "paths": {}}))
    assert load_spec(sb, "a.yaml").label == "OpenAPI 3.0.3"
    assert load_spec(sb, "b.yaml").label == "OpenAPI 3.1.0"
    assert load_spec(sb, "c.json").label == "Swagger 2.0"
    assert "OpenAPI 3.1.0" in describe.overview(load_spec(sb, "b.yaml"))


def test_unsupported_and_non_spec_documents_are_rejected(tmp_path: Path) -> None:
    sb = Sandbox(str(tmp_path))
    write(tmp_path / "x.yaml", MIN_YAML.replace("3.0.3", "4.0.0"))
    with pytest.raises(SpecError, match="unsupported OpenAPI version"):
        load_spec(sb, "x.yaml")
    write(tmp_path / "y.yaml", "foo: bar\n")
    with pytest.raises(SpecError, match="not an OpenAPI/Swagger document"):
        load_spec(sb, "y.yaml")
    write(tmp_path / "z.yaml", "- a\n- b\n")
    with pytest.raises(SpecError, match="top level must be an object"):
        load_spec(sb, "z.yaml")
    write(tmp_path / "bad.json", "{not json")
    with pytest.raises(SpecError, match="invalid JSON"):
        load_spec(sb, "bad.json")
    write(tmp_path / "bad.yaml", "a: [1, 2\nb: : :\n")
    with pytest.raises(SpecError, match="invalid YAML"):
        load_spec(sb, "bad.yaml")


def test_missing_file_error_is_actionable(tmp_path: Path) -> None:
    with pytest.raises(SpecError, match="no such file"):
        load_spec(Sandbox(str(tmp_path)), "nope.yaml")


# ------------------------------------------------------------ yaml / json details
def test_yaml_quirks_are_neutralised() -> None:
    text = (
        "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n"
        "        200:\n          description: ok\n"
        "components:\n  schemas:\n    S:\n      type: object\n      properties:\n"
        "        no: {type: string}\n        on: {type: string}\n"
        "      example: {created: 2024-01-02}\n"
    )
    s = load(text)
    assert "200" in s.doc["paths"]["/a"]["get"]["responses"]
    props = s.doc["components"]["schemas"]["S"]["properties"]
    assert set(props) == {"no", "on"}
    assert s.doc["components"]["schemas"]["S"]["example"] == {"created": "2024-01-02"}


def test_yaml_anchors_and_merge_keys_work() -> None:
    text = MIN_YAML.replace("paths: {}", "x-base: &b {type: string, minLength: 2}\nx-other:\n  <<: *b\n  maxLength: 5\npaths: {}")
    s = load(text)
    assert s.doc["x-other"] == {"type": "string", "minLength": 2, "maxLength": 5}


def test_unicode_and_turkish_text_roundtrip(tmp_path: Path) -> None:
    text = MIN_YAML + "x-note: 'Çalışan İstanbul şğüöı – 日本語 🚀'\n"
    write(tmp_path / "t.yaml", text)
    s = load_spec(Sandbox(str(tmp_path)), "t.yaml")
    assert s.doc["x-note"].startswith("Çalışan İstanbul")
    d = get_doc(op(summary="Kullanıcı listesi", description="Eski uç nokta, yerine /v2 kullanın."), deprecated=None)
    d["paths"]["/t"]["get"]["deprecated"] = True
    findings = lint(load(d))
    assert "OAS1023" not in {f.rule for f in findings}  # Turkish 'yerine' counts as a replacement note


def test_duplicate_keys_warn_in_json_and_yaml_with_lines() -> None:
    j = '{\n "openapi": "3.0.3",\n "info": {"title": "t", "version": "1"},\n "paths": {},\n "paths": {}\n}'
    s = load(j)
    assert any("duplicate key 'paths' at line 5" in w for w in s.warnings)
    y = MIN_YAML + "paths: {}\n"
    s = load(y)
    assert any("duplicate key 'paths'" in w and "line 4" in w for w in s.warnings)
    assert "OAS1025" in {f.rule for f in lint(s)}


def test_line_map_json_and_yaml_agree_on_pointers() -> None:
    d = get_doc(op(resp({"type": "string"})))
    pretty = json.dumps(d, indent=2)
    sj = load(pretty)
    sy = load("openapi: 3.0.3\ninfo:\n  title: t\n  version: '1'\npaths:\n  /t:\n    get:\n      operationId: op\n      responses:\n        '200':\n          description: d\n")
    idx = next(i for i, ln in enumerate(pretty.splitlines(), 1) if ln.strip().startswith('"get"'))
    assert sj.line_for("/paths/~1t/get") == idx
    assert sy.line_for("/paths/~1t/get/responses/200") == 10
    assert sy.line_for("/paths/~1t/get/responses/404") == 9  # nearest existing node


# --------------------------------------------------------------- hostile input
def test_yaml_billion_laughs_is_refused_quickly() -> None:
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 12):
        refs = ", ".join([f"*a{i - 1}"] * 10)
        lines.append(f"a{i}: &a{i} [{refs}]")
    text = MIN_YAML.replace("paths: {}", "paths: {}\n" + "\n".join("x-" + ln for ln in lines))
    t0 = time.monotonic()
    with pytest.raises(SpecError, match="alias bomb"):
        load(text)
    assert time.monotonic() - t0 < 10


def test_json_and_yaml_deep_nesting_are_refused() -> None:
    with pytest.raises(SpecError, match="too deep|deeper than"):
        loader.parse_text("[" * 100_000 + "]" * 100_000, "deep.json", "json")
    with pytest.raises(SpecError, match="too deep|deeper than"):
        loader.parse_text("[" * 100_000, "deep.yaml", "yaml")
    nested = "x"
    for _ in range(loader.MAX_DEPTH + 5):
        nested = f"{{a: {nested}}}"
    with pytest.raises(SpecError, match="deeper than|too deep"):
        loader.parse_text(nested, "deep2.yaml", "yaml")


def test_size_and_line_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = write(tmp_path / "big.yaml", MIN_YAML + "x-pad: " + "a" * 5000 + "\n")
    monkeypatch.setattr(loader, "MAX_BYTES", 1000)
    with pytest.raises(SpecError, match="limit"):
        loader.read_text(p)
    monkeypatch.setattr(loader, "MAX_LINES", 3)
    with pytest.raises(SpecError, match="lines"):
        loader.parse_text("a: 1\n" * 10, "x.yaml", "yaml")


def test_non_utf8_file_is_a_clear_error(tmp_path: Path) -> None:
    p = tmp_path / "latin.yaml"
    p.write_bytes(b"openapi: 3.0.3\n# caf\xe9\n")
    with pytest.raises(SpecError, match="not valid UTF-8"):
        load_spec(Sandbox(str(tmp_path)), "latin.yaml")


def test_unsafe_yaml_tags_are_not_executed() -> None:
    text = MIN_YAML + "x-evil: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(SpecError, match="unsupported YAML|invalid YAML"):
        load(text)


def test_quadratic_regex_style_inputs_stay_fast(tmp_path: Path) -> None:
    long_desc = "a1b2 " * 40_000
    d = get_doc(op(summary="s", description=long_desc, deprecated=True))
    d["paths"]["/t"]["get"]["parameters"] = [{"name": "x" * 50_000 + "_" + "Y" * 50_000, "in": "query", "schema": {"type": "string", "pattern": "(a+)+$"}}]
    d["paths"]["/t"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {"type": "string", "pattern": "(a+)+$", "example": "a" * 40 + "!"}
    t0 = time.monotonic()
    findings = lint(load(d))
    assert time.monotonic() - t0 < 20
    assert findings  # ran to completion


def test_huge_flat_json_loads_with_line_map(tmp_path: Path) -> None:
    d = doc({f"/p{i}": {"get": op(operationId=f"o{i}")} for i in range(2000)})
    write(tmp_path / "many.json", json.dumps(d, indent=1))
    t0 = time.monotonic()
    s = load_spec(Sandbox(str(tmp_path)), "many.json")
    assert time.monotonic() - t0 < 20
    assert s.line_for("/paths/~1p1999/get") is not None


# --------------------------------------------------------------- refs
def test_local_refs_cycles_and_definitions() -> None:
    node = {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}
    s = load(get_doc(op(resp({"$ref": "#/components/schemas/Node"})), schemas={"Node": node}))
    text = describe.describe(s, "/t", "get")
    assert "<cycle: Node>" in text
    sw = {
        "swagger": "2.0", "info": {"title": "t", "version": "1"},
        "paths": {"/p": {"get": {"responses": {"200": {"description": "ok", "schema": {"$ref": "#/definitions/D"}}}}}},
        "definitions": {"D": {"type": "object", "properties": {"d": {"$ref": "#/definitions/D"}}}},
    }
    assert "<cycle: D>" in describe.describe(load(sw), "/p", "get")


def test_ref_chain_loop_is_an_error_not_a_hang() -> None:
    d = get_doc(op(resp({"$ref": "#/components/schemas/A"})), schemas={"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}})
    s = load(d)
    with pytest.raises(RefError, match="circular"):
        s.deref({"$ref": "#/components/schemas/A"})
    assert "<unresolved" in describe.describe(s, "/t", "get")


def test_allof_cycle_is_an_error_not_a_hang() -> None:
    schemas = {"A": {"allOf": [{"$ref": "#/components/schemas/B"}]}, "B": {"allOf": [{"$ref": "#/components/schemas/A"}]}}
    s = load(get_doc(op(resp({"$ref": "#/components/schemas/A"})), schemas=schemas))
    assert "<unresolved" in describe.describe(s, "/t", "get")


def test_escaped_and_percent_encoded_pointers() -> None:
    d = get_doc(op(resp({"$ref": "#/components/schemas/a~1b%20c"})), schemas={"a/b c": {"type": "string"}})
    assert "string" in describe.describe(load(d), "/t", "get")


def test_external_relative_refs_inside_the_sandbox(tmp_path: Path) -> None:
    write(tmp_path / "main.yaml", MIN_YAML.replace("paths: {}", "paths:\n  /p:\n    get:\n      operationId: g\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema:\n                $ref: 'schemas/pet.yaml#/Pet'\n"))
    write(tmp_path / "schemas" / "pet.yaml", "Pet:\n  type: object\n  required: [name]\n  properties:\n    name: {type: string}\n    err:\n      $ref: '../common/err.yaml#/Err'\n    self:\n      $ref: '#/Pet'\n")
    write(tmp_path / "common" / "err.yaml", "Err:\n  type: object\n  properties:\n    code: {type: integer}\n")
    s = load_spec(Sandbox(str(tmp_path)), "main.yaml")
    text = describe.describe(s, "/p", "get")
    assert "name*: string" in text and "code: integer" in text and "<cycle: Pet>" in text
    assert s.check_refs() == []
    assert "External files referenced: 2" in describe.overview(s)


def test_path_traversal_refs_are_blocked(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    write(outside, "Secret:\n  type: string\n  description: TOP-SECRET-CONTENT\n")
    inner = tmp_path / "inner"
    write(inner / "main.yaml", MIN_YAML.replace("paths: {}", "paths:\n  /p:\n    get:\n      responses:\n        '200':\n          description: ok\n          content:\n            application/json:\n              schema:\n                $ref: '../outside.yaml#/Secret'\n"))
    s = load_spec(Sandbox(str(inner)), "main.yaml")
    bad = s.check_refs()
    assert len(bad) == 1 and "outside the allowed directory" in bad[0][1]
    out = describe.overview(s)
    assert "TOP-SECRET-CONTENT" not in out and "Unresolved refs: 1" in out
    assert "TOP-SECRET-CONTENT" not in str(describe.describe(s, "/p", "get"))
    abs_ref = MIN_YAML.replace("paths: {}", "x: {$ref: '" + str(outside).replace("\\", "/") + "#/Secret'}\npaths: {}")
    write(inner / "abs.yaml", abs_ref)
    assert "outside the allowed directory" in load_spec(Sandbox(str(inner)), "abs.yaml").check_refs()[0][1]


def test_spec_argument_cannot_escape_the_sandbox(tmp_path: Path) -> None:
    write(tmp_path / "secret.yaml", MIN_YAML)
    inner = tmp_path / "in"
    inner.mkdir()
    sb = Sandbox(str(inner))
    with pytest.raises(SpecError, match="outside the allowed directory"):
        load_spec(sb, "../secret.yaml")
    with pytest.raises(SpecError, match="outside the allowed directory"):
        load_spec(sb, str(tmp_path / "secret.yaml"))


@pytest.mark.skipif(sys.platform == "win32", reason="creating symlinks needs privileges on Windows")
def test_symlink_escape_is_blocked(tmp_path: Path) -> None:
    write(tmp_path / "secret.yaml", MIN_YAML)
    inner = tmp_path / "in"
    inner.mkdir()
    os.symlink(tmp_path / "secret.yaml", inner / "link.yaml")
    with pytest.raises(SpecError, match="outside the allowed directory"):
        load_spec(Sandbox(str(inner)), "link.yaml")


def test_remote_refs_are_never_fetched_and_reported(tmp_path: Path) -> None:
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    try:
        d = get_doc(op(resp({"$ref": f"http://127.0.0.1:{port}/spec.yaml#/X"})))
        s = load(d)
        bad = s.check_refs()
        assert len(bad) == 1 and "never fetches" in bad[0][1]
        try:
            srv.accept()
            connected = True
        except OSError:
            connected = False
        assert not connected, "a remote $ref triggered a network connection"
    finally:
        srv.close()


def test_very_long_path_is_a_clean_error(tmp_path: Path) -> None:
    sb = Sandbox(str(tmp_path))
    with pytest.raises(SpecError):
        load_spec(sb, "a" * 100_000)
    with pytest.raises(SpecError):
        load_spec(sb, ("a" * 200 + os.sep) * 500 + "x.yaml")
    with pytest.raises(SpecError, match="NUL"):
        load_spec(sb, "a\x00b.yaml")


def test_inline_spec_text_is_accepted_and_relative_refs_use_the_sandbox(tmp_path: Path) -> None:
    write(tmp_path / "s.yaml", "S: {type: string}\n")
    text = MIN_YAML.replace("paths: {}", "paths: {}\nx: {$ref: 's.yaml#/S'}")
    s = load_spec(Sandbox(str(tmp_path)), text)
    assert s.source == "<inline>" and s.check_refs() == []


def test_fixture_directory_loads() -> None:
    s = load_spec(Sandbox(FIXTURES), "petstore_v1.yaml")
    assert STR_SCHEMA["type"] == "string"
    assert describe.overview(s).startswith("Format read: OpenAPI 3.0.3")


def test_overview_counts_and_unresolved(tmp_path: Path) -> None:
    s = load_spec(Sandbox(FIXTURES), "bad_api.yaml")
    out = describe.overview(s)
    assert "Unresolved refs: 2" in out
    assert "never fetches" in out
    assert "Paths: 6" in out
