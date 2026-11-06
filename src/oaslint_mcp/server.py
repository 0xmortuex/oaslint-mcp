"""oaslint-mcp: an MCP server that lints OpenAPI specs and detects breaking changes."""

from __future__ import annotations

import argparse
import functools
import os
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import describe as desc
from .diff import diff_specs as run_diff
from .errors import SpecError
from .lint import lint
from .report import changelog, diff_report, lint_report
from .spec import Sandbox, Spec, load_spec

mcp = MCPServer(
    "oaslint",
    instructions=(
        "Lint OpenAPI 3.0 / 3.1 / Swagger 2.0 specs and, above all, find BREAKING CHANGES between "
        "two versions of a spec. Offline and read-only: remote $refs are never fetched. Every "
        "`spec`/`old`/`new` argument is a path to a .yaml/.yml/.json file inside the allowed "
        "directory (relative paths are fine), or the spec text pasted inline. Start with "
        "spec_overview, then lint_spec; before releasing an API change run diff_specs(old, new) "
        "and read the BREAKING and POTENTIALLY_BREAKING sections; changelog_markdown writes the "
        "release notes. find_endpoints, describe_operation and validate_example help you work "
        "with one operation at a time."
    ),
)

_sandbox: Sandbox | None = None
F = TypeVar("F", bound=Callable[..., Any])


def sandbox() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = Sandbox(os.environ.get("OASLINT_DIR") or os.getcwd())
    return _sandbox


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except SpecError as e:
            raise ToolError(str(e)) from e
        except RecursionError as e:
            raise ToolError("the spec is nested too deeply to process safely") from e

    mcp.tool()(wrapper)
    return fn


def _load(spec: str, role: str = "spec") -> Spec:
    try:
        return load_spec(sandbox(), spec)
    except SpecError as e:
        if role == "spec":
            raise
        raise SpecError(f"{role} spec: {e}") from e


@tool
def spec_overview(spec: str) -> str:
    """Summarise an API description: format/version read, title, servers, number of tags,
    paths and operations (by method), auth schemes, schema count, deprecated count and any
    unresolved $refs (remote refs are reported, never fetched).

    `spec` is a path inside the allowed directory (.yaml/.yml/.json; OpenAPI 3.0.x, 3.1.x or
    Swagger 2.0), or the spec text itself."""
    return desc.overview(_load(spec))


@tool
def lint_spec(spec: str) -> str:
    """Lint a spec. Findings have a rule id (OAS1001+), severity (error/warning/info), a JSON
    pointer, the source line when known, and a concrete fix. Rules cover operationIds, missing
    or non-2xx responses, path parameters vs the URL template, parameter naming, unused
    components, untyped schemas, required-not-in-properties, enum/default/example mismatches
    (checked with a built-in JSON Schema validator), missing descriptions, undefined security
    schemes, http:// production servers, POST-200 on creation, trailing slashes, duplicate
    paths and deprecations without a replacement note.

    `spec` is a path inside the allowed directory, or the spec text itself."""
    s = _load(spec)
    return lint_report(s, lint(s))


@tool
def diff_specs(old: str, new: str) -> str:
    """Compare two versions of an API and classify every change as BREAKING, POTENTIALLY_BREAKING
    (needs a human look), NON_BREAKING or INFO, with the reason and exact location (operation,
    schema path, JSON pointer, line).

    Rules follow request/response variance: in a request, tightening is breaking (new required
    parameter or property, narrower type, removed enum value, stricter min/max/pattern); in a
    response, loosening or removing guarantees is breaking (property removed or made optional,
    type changed, nullable added, success code removed). Also checks auth changes, content
    types, parameter style/location, oneOf/anyOf/allOf and discriminator. Equivalent specs
    written differently (reordered keys, $ref vs inline, nullable vs type [x,'null'], Swagger 2.0
    vs OpenAPI 3) report no changes.

    `old` and `new` are paths inside the allowed directory, or spec text."""
    o, n = _load(old, "old"), _load(new, "new")
    return diff_report(run_diff(o, n), o, n)


@tool
def changelog_markdown(old: str, new: str) -> str:
    """Write a human-readable markdown changelog for the move from `old` to `new`, grouped into
    breaking / potentially breaking / non-breaking / notes and then by operation. Returns text;
    nothing is written to disk."""
    o, n = _load(old, "old"), _load(new, "new")
    return changelog(run_diff(o, n), o, n)


@tool
def find_endpoints(spec: str, path_glob: str = "", method: str = "", tag: str = "", text: str = "") -> str:
    """List operations of a spec, optionally filtered. `path_glob` uses * and ? (e.g.
    '/pets/*'), `method` is get/post/..., `tag` is an exact tag name, `text` is a
    case-insensitive substring searched in path, operationId, summary, description and tags.
    Filters combine with AND."""
    return desc.find_endpoints(_load(spec), path_glob, method, tag, text)


@tool
def describe_operation(spec: str, path: str, method: str, depth: int = 4) -> str:
    """Describe one operation: parameters (merged path-level + operation-level), the request
    body and every response with their schemas fully resolved and shown as a compact outline
    (`*` = required property, `?` = nullable, recursive schemas end in a <cycle: Name> marker).
    `path` may use any parameter names (/pets/{id} matches /pets/{petId}). `depth` limits the
    outline nesting (1-12)."""
    return desc.describe(_load(spec), path, method, depth)


@tool
def validate_example(
    spec: str, path: str, method: str, kind: str, json: str, status: str = "200", content_type: str = ""
) -> str:
    """Check a JSON document against the resolved schema of an operation. `kind` is 'request'
    (validates against the request body) or 'response' (against the response for `status`,
    default 200; falls back to 2XX then default). `json` is the document as JSON text.
    Violations are reported with a JSON pointer into the document. Optionally pick a
    `content_type`; otherwise application/json (or the first JSON type) is used."""
    return desc.validate_op_example(_load(spec), path, method, kind, status, json, content_type)


def main() -> None:
    global _sandbox
    ap = argparse.ArgumentParser(prog="oaslint-mcp", description="MCP server: lint OpenAPI specs and find breaking changes.")
    ap.add_argument(
        "--dir", default=None,
        help="Only read spec files inside this directory (default: $OASLINT_DIR, else the current directory).",
    )
    args = ap.parse_args()
    _sandbox = Sandbox(args.dir or os.environ.get("OASLINT_DIR") or os.getcwd())
    mcp.run()


if __name__ == "__main__":
    main()
