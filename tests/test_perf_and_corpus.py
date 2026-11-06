"""A 300-path generated spec (performance + correctness at scale) and a hand-written 2.0/3.1 pair."""

from __future__ import annotations

import time
from pathlib import Path

from oaslint_mcp import describe
from oaslint_mcp.diff import BREAKING, NONBREAKING, POTENTIAL, diff_specs
from oaslint_mcp.lint import lint
from oaslint_mcp.report import changelog, diff_report
from oaslint_mcp.spec import Sandbox, load_spec


def generate(n: int, variant: str) -> str:
    out = [
        "openapi: 3.0.3", "info: {title: Big, version: '1'}", "servers: [{url: 'https://api.big.example/v1'}]",
        "paths:",
    ]
    for i in range(n):
        out += [
            f"  /resource{i}/{{id}}:",
            "    parameters:",
            "      - {name: id, in: path, required: true, schema: {type: integer, format: int64}}",
            "    get:",
            f"      operationId: getResource{i}",
            f"      summary: Get resource {i}",
            "      parameters:",
            "        - {name: expand, in: query, description: expand, schema: {type: boolean}}",
            "      responses:",
            "        '200':",
            "          description: ok",
            "          content:",
            "            application/json:",
            f"              schema: {{$ref: '#/components/schemas/R{i % 25}'}}",
            "        '404': {description: not found}",
            f"  /resource{i}:",
            "    post:",
            f"      operationId: createResource{i}",
            f"      summary: Create resource {i}",
            "      requestBody:",
            "        required: true",
            "        content:",
            "          application/json:",
            f"            schema: {{$ref: '#/components/schemas/R{i % 25}'}}",
            "      responses:",
            "        '201':",
            "          description: created",
            "          content:",
            "            application/json:",
            f"              schema: {{$ref: '#/components/schemas/R{i % 25}'}}",
            "        '400': {description: bad}",
        ]
    out.append("components:\n  schemas:")
    for k in range(25):
        removed_prop = "" if (variant == "new" and k == 3) else "        extra: {type: string}\n"
        out.append(
            f"    R{k}:\n      type: object\n      required: [id]\n      properties:\n        id: {{type: integer}}\n"
            f"        name: {{type: string, maxLength: {100 if variant == 'old' or k != 4 else 50}}}\n"
            f"        next: {{$ref: '#/components/schemas/R{(k + 1) % 25}'}}\n"
            + removed_prop.rstrip("\n")
        )
    if variant == "new":
        out.insert(4, "  /brand-new:\n    get:\n      operationId: brandNew\n      summary: x\n      responses:\n        '200': {description: ok}\n        '500': {description: err}")
    return "\n".join(out) + "\n"


def test_three_hundred_paths_lint_and_diff(tmp_path: Path) -> None:
    (tmp_path / "old.yaml").write_bytes(generate(300, "old").encode("utf-8"))
    (tmp_path / "new.yaml").write_bytes(generate(300, "new").encode("utf-8"))
    sb = Sandbox(str(tmp_path))
    t0 = time.monotonic()
    old, new = load_spec(sb, "old.yaml"), load_spec(sb, "new.yaml")
    assert "Paths: 600" in describe.overview(old)
    findings = lint(old)
    assert not [f for f in findings if f.severity in ("error", "warning")]
    res = diff_specs(old, new)
    text = diff_report(res, old, new)
    md = changelog(res, old, new)
    assert time.monotonic() - t0 < 120, "300-path spec should be processed in seconds, not minutes"
    counts = res.counts()
    # R3 lost 'extra' (response: breaking, request: potentially breaking) at every operation that uses it (12 each way)
    assert counts[BREAKING] >= 12 and counts[POTENTIAL] >= 12
    # R4 maxLength 100 -> 50: requests tightened (breaking), responses tightened (non-breaking)
    assert any(c.code == "request-bound-tightened" for c in res.changes)
    assert any(c.code == "response-bound-tightened" and c.severity == NONBREAKING for c in res.changes)
    assert any(c.code == "operation-added" for c in res.changes)
    assert text.startswith("Comparing OLD OpenAPI 3.0.3") and "Verdict: BREAKING" in text
    assert "## Breaking changes" in md and "### GET /resource" in md or "### POST /resource" in md


def test_swagger2_to_openapi31_real_world_style_pair(tmp_path: Path) -> None:
    (tmp_path / "v1.yaml").write_bytes(
        b"""swagger: '2.0'
info: {title: Orders, version: '1.0'}
host: orders.example.com
basePath: /api
schemes: [https]
consumes: [application/json]
produces: [application/json]
securityDefinitions:
  key: {type: apiKey, in: header, name: X-Key}
paths:
  /orders:
    get:
      operationId: listOrders
      security: [{key: []}]
      parameters:
        - {name: status, in: query, type: string, enum: [open, closed]}
        - {name: ids, in: query, type: array, items: {type: integer}, collectionFormat: csv}
      responses:
        200:
          description: ok
          schema:
            type: array
            items: {$ref: '#/definitions/Order'}
  /orders/{id}:
    get:
      operationId: getOrder
      security: [{key: []}]
      parameters:
        - {name: id, in: path, required: true, type: integer}
      responses:
        200: {description: ok, schema: {$ref: '#/definitions/Order'}}
        404: {description: nf}
definitions:
  Order:
    type: object
    required: [id, total]
    properties:
      id: {type: integer}
      total: {type: number}
      note: {type: string, x-nullable: true}
      state: {type: string, enum: [open, closed]}
"""
    )
    (tmp_path / "v2.yaml").write_bytes(
        """openapi: 3.1.0
info: {title: Orders, version: '2.0'}
servers: [{url: 'https://orders.example.com/api'}]
components:
  securitySchemes:
    key: {type: apiKey, in: header, name: X-Key}
  schemas:
    Order:
      type: object
      required: [id]
      properties:
        id: {type: integer}
        total: {type: [number, 'null']}
        note: {type: [string, 'null']}
        state: {type: string, enum: [open, closed, refunded]}
        currency: {type: string}
paths:
  /orders:
    get:
      operationId: listOrders
      security: [{key: []}]
      parameters:
        - {name: status, in: query, schema: {type: string, enum: [open, closed]}}
        - {name: ids, in: query, explode: false, schema: {type: array, items: {type: integer}}}
        - {name: since, in: query, required: true, schema: {type: string, format: date}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items: {$ref: '#/components/schemas/Order'}
  /orders/{orderId}:
    get:
      operationId: getOrder
      security: [{key: []}]
      parameters:
        - {name: orderId, in: path, required: true, schema: {type: integer}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Order'}
""".encode("utf-8")
    )
    sb = Sandbox(str(tmp_path))
    old, new = load_spec(sb, "v1.yaml"), load_spec(sb, "v2.yaml")
    assert old.label == "Swagger 2.0" and new.label == "OpenAPI 3.1.0"
    res = diff_specs(old, new)
    got = {(c.severity, c.code) for c in res.changes}
    assert got == set([
        ("INFO", "api-version-changed"),
        ("BREAKING", "parameter-added-required"),       # since
        ("BREAKING", "response-property-now-optional"),  # total no longer required
        ("BREAKING", "response-nullable-added"),         # total may be null
        ("POTENTIALLY_BREAKING", "response-enum-added-values"),  # refunded
        ("NON_BREAKING", "path-param-renamed"),
        ("NON_BREAKING", "response-property-added"),     # currency
        ("NON_BREAKING", "response-error-removed"),      # 404 dropped
    ])
    # Order is used by two operations, so its schema changes are reported at both
    assert sum(c.code == "response-nullable-added" for c in res.changes) == 2
    # csv array in 2.0 equals explode:false in 3.1, so the ids parameter is NOT reported
    assert not any("ids" in c.message for c in res.changes)
    out = changelog(res, old, new)
    assert out.index("## Breaking changes") < out.index("## Non-breaking changes")
    assert "Swagger 2.0" in out and "OpenAPI 3.1.0" in out
