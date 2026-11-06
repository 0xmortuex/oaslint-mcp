"""Read-only inspection helpers: overview, endpoint search, operation outline, example validation."""

from __future__ import annotations

import fnmatch
import json
from typing import Any

from .errors import RefError, SpecError
from .redact import redact_url, shown
from .model import METHODS, Model, Operation, build_model, norm_mime, norm_path
from .schema import Flat, flatten, ident
from .spec import Spec
from .validate import validate

MAX_FIND = 200


def _component_count(spec: Spec, kind: str) -> int:
    doc = spec.doc
    if spec.family == "2.0":
        node = doc.get("definitions" if kind == "schemas" else kind)
    else:
        comps = doc.get("components")
        node = comps.get(kind) if isinstance(comps, dict) else None
    return len(node) if isinstance(node, dict) else 0


def _schema_nodes(spec: Spec) -> dict[str, Any]:
    if spec.family == "2.0":
        d = spec.doc.get("definitions")
    else:
        comps = spec.doc.get("components")
        d = comps.get("schemas") if isinstance(comps, dict) else None
    return d if isinstance(d, dict) else {}


def overview(spec: Spec) -> str:
    m = build_model(spec)
    doc = spec.doc
    info: dict[str, Any] = doc["info"] if isinstance(doc.get("info"), dict) else {}
    out: list[str] = []
    out.append(f"Format read: {spec.label} ({spec.source})")
    out.append(f"Title: {info.get('title', '(none)')}   Version: {info.get('version', '(none)')}")
    out.append("Servers: " + (", ".join(redact_url(u) for u in m.servers) if m.servers else "(none)"))
    by_method: dict[str, int] = {}
    paths = {op.path for op in m.ops}
    for op in m.ops:
        by_method[op.method.upper()] = by_method.get(op.method.upper(), 0) + 1
    methods = ", ".join(f"{k} {v}" for k, v in sorted(by_method.items())) or "none"
    out.append(f"Paths: {len(paths)}   Operations: {len(m.ops)} ({methods})")
    tags: set[str] = set()
    for op in m.ops:
        tags.update(op.tags)
    declared = doc.get("tags")
    if isinstance(declared, list):
        tags.update(t["name"] for t in declared if isinstance(t, dict) and isinstance(t.get("name"), str))
    out.append(f"Tags: {len(tags)}" + (f" ({', '.join(sorted(tags)[:15])}{', ...' if len(tags) > 15 else ''})" if tags else ""))
    schemes = []
    for name, s in m.schemes.items():
        t = s.get("type")
        extra = s.get("scheme") or (f"in {s.get('in')}" if s.get("in") else "") or ""
        schemes.append(f"{name} ({t}{' ' + str(extra) if extra else ''})")
    out.append("Auth schemes: " + (", ".join(schemes) if schemes else "none defined"))
    out.append(f"Schemas: {_component_count(spec, 'schemas')}")
    dep_ops = sum(1 for op in m.ops if op.deprecated)
    dep_schemas = 0
    for s in _schema_nodes(spec).values():
        if isinstance(s, dict) and s.get("deprecated") is True:
            dep_schemas += 1
    out.append(f"Deprecated: {dep_ops} operation(s), {dep_schemas} schema(s)")
    if m.webhooks:
        out.append(f"Webhooks: {len(m.webhooks)} ({', '.join(m.webhooks[:10])})")
    n_cb = sum(len(op.callbacks) for op in m.ops)
    if n_cb:
        out.append(f"Callbacks: {n_cb}")
    if spec.ext:
        out.append(f"External files referenced: {len(spec.ext)}")
    bad = spec.check_refs()
    if bad:
        out.append(f"Unresolved refs: {len(bad)}")
        for ref, why, _raw in bad[:10]:
            out.append(f"  - {ref}: {why}")
        if len(bad) > 10:
            out.append(f"  ... and {len(bad) - 10} more")
    else:
        out.append("Unresolved refs: 0")
    for w in spec.warnings[:10]:
        out.append(f"Warning: {w}")
    return "\n".join(out)


def find_endpoints(spec: Spec, path_glob: str = "", method: str = "", tag: str = "", text: str = "") -> str:
    m = build_model(spec)
    meth = method.strip().lower()
    if meth and meth not in METHODS:
        raise SpecError(f"unknown method {method!r}; use one of {', '.join(METHODS)}")
    glob = path_glob.strip().lower()
    tg = tag.strip().lower()
    tx = text.strip().lower()
    rows: list[str] = []
    total = 0
    for op in m.ops:
        if meth and op.method != meth:
            continue
        if glob and not fnmatch.fnmatchcase(op.path.lower(), glob):
            continue
        if tg and tg not in (t.lower() for t in op.tags):
            continue
        if tx:
            hay = " ".join(
                [op.path, op.op_id or "", op.summary or "", op.description or "", " ".join(op.tags)]
            ).lower()
            if tx not in hay:
                continue
        total += 1
        if len(rows) < MAX_FIND:
            bits = [f"{op.method.upper():7} {op.path}"]
            if op.op_id:
                bits.append(f"[{op.op_id}]")
            if op.tags:
                bits.append("tags=" + ",".join(op.tags))
            if op.deprecated:
                bits.append("DEPRECATED")
            if op.summary:
                bits.append("- " + op.summary[:100])
            rows.append("  ".join(bits))
    if total == 0:
        return "No endpoints matched. Path globs use * and ? (e.g. '/pets/*'); text matches path, operationId, summary, description and tags."
    head = f"{total} endpoint(s) matched" + (f" (showing first {MAX_FIND})" if total > MAX_FIND else "")
    return head + "\n" + "\n".join(rows)


def find_operation(spec: Spec, path: str, method: str) -> Operation:
    m = build_model(spec)
    meth = method.strip().lower()
    cands = [op for op in m.ops if op.path == path and op.method == meth]
    if not cands:
        cands = [op for op in m.ops if norm_path(op.path) == norm_path(path) and op.method == meth]
    if cands:
        return cands[0]
    same_path = [op for op in m.ops if norm_path(op.path) == norm_path(path)]
    if same_path:
        raise SpecError(
            f"{path} exists but has no {meth.upper()} operation; it has: "
            + ", ".join(sorted(op.method.upper() for op in same_path))
        )
    close = sorted({op.path for op in m.ops if path.strip("/").split("/")[0] in op.path})[:8]
    raise SpecError(
        f"no operation {meth.upper()} {path} in {spec.source}."
        + (f" Similar paths: {', '.join(close)}" if close else " Use find_endpoints to list paths.")
    )


# ------------------------------------------------------------------ outline
def _label(f: Flat, name: str = "") -> str:
    types = sorted(t for t in (f.types or ()) if t != "null")
    base = "|".join(types) if f.types is not None else "any"
    if f.types is not None and not types:
        base = "null" if "null" in f.types else "nothing"
    if f.types is not None and "null" in f.types and types:
        base += "?"
    bits = [base]
    if f.format:
        bits.append(f"({f.format})")
    if f.enum is not None:
        vals = ", ".join(shown(v, 40, name) for v in f.enum[:8]) + (", ..." if len(f.enum) > 8 else "")
        bits.append(f"enum[{vals}]")
    cons: list[str] = []
    for k, (v, ex) in sorted(f.lo.items()) + sorted(f.hi.items()):
        cons.append(f"{k}{'(excl)' if ex else ''}={v:g}")
    if f.pattern:
        cons.append(f"pattern={f.pattern[:40]}")
    if f.multiple_of is not None:
        cons.append(f"multipleOf={f.multiple_of}")
    if f.unique_items:
        cons.append("uniqueItems")
    if f.has_default:
        cons.append(f"default={shown(f.default, 30, name)}")
    if f.read_only:
        cons.append("readOnly")
    if f.write_only:
        cons.append("writeOnly")
    if f.deprecated:
        cons.append("deprecated")
    if cons:
        bits.append("{" + ", ".join(cons) + "}")
    if f.additional is False:
        bits.append("[no extra props]")
    return " ".join(bits)


def outline(spec: Spec, schema: Any, depth_limit: int = 4, lines: list[str] | None = None) -> list[str]:
    lines = [] if lines is None else lines

    def render(s: Any, label: str, indent: int, depth: int, stack: tuple[Any, ...], pname: str = "") -> None:
        pad = "  " * indent
        try:
            node, ref = spec.deref(s)
            name = ref.rsplit("/", 1)[-1] if ref else ""
            if isinstance(node, dict) and ident(node) in stack:
                lines.append(f"{pad}{label}<cycle: {name or 'recursive schema'}>")
                return
            f = flatten(spec, s)
        except RefError as e:
            lines.append(f"{pad}{label}<unresolved: {e}>")
            return
        head = _label(f, pname)
        if name:
            head += f"  <{name}>"
        lines.append(f"{pad}{label}{head}")
        st = (*stack, ident(node)) if isinstance(node, dict) else stack
        kids = bool(f.properties or f.items is not None or isinstance(f.additional, dict) or f.one_of or f.any_of)
        if not kids:
            return
        if depth >= depth_limit:
            lines.append(f"{pad}  ... (depth limit {depth_limit}; raise depth to see more)")
            return
        for pname, psch in f.properties.items():
            render(psch, f"{pname}{'*' if pname in f.required else ''}: ", indent + 1, depth + 1, st, pname)
        if isinstance(f.additional, dict):
            render(f.additional, "[any key]: ", indent + 1, depth + 1, st)
        if f.items is not None and not isinstance(f.items, bool):
            render(f.items, "[items]: ", indent + 1, depth + 1, st)
        for kw, branches in (("oneOf", f.one_of), ("anyOf", f.any_of)):
            for i, b in enumerate(branches or []):
                render(b, f"{kw}[{i}]: ", indent + 1, depth + 1, st)

    render(schema, "", 0, 0, ())
    return lines


def describe(spec: Spec, path: str, method: str, depth: int = 4) -> str:
    op = find_operation(spec, path, method)
    if depth < 1 or depth > 12:
        raise SpecError("depth must be between 1 and 12")
    out: list[str] = [f"{op.key}" + (f"   operationId: {op.op_id}" if op.op_id else "") + ("   DEPRECATED" if op.deprecated else "")]
    if op.summary:
        out.append(op.summary)
    if op.description and op.description != op.summary:
        out.append(op.description[:600])
    if op.tags:
        out.append("Tags: " + ", ".join(op.tags))
    out.append("(* marks a required property; ? marks nullable)")
    out.append("")
    out.append("Parameters:" + ("" if op.params else " none"))
    for p in op.params.values():
        try:
            f = flatten(spec, p.schema)
            lab = _label(f, p.name)
        except RefError as e:
            lab = f"<unresolved: {e}>"
        out.append(f"  - {p.name} ({p.loc}{', required' if p.required else ''}{', deprecated' if p.deprecated else ''}): {lab}"
                   + (f" - {p.description[:80]}" if p.description else ""))
    out.append("")
    if op.body is None:
        out.append("Request body: none")
    else:
        out.append(f"Request body{' (required)' if op.body.required else ''}:")
        if not op.body.content:
            out.append("  (no content types declared)")
        for mime, sch in op.body.content.items():
            out.append(f"  {mime}:")
            out.extend("    " + ln for ln in outline(spec, sch, depth))
    out.append("")
    out.append("Responses:")
    for code, r in op.responses.items():
        out.append(f"  {code}" + (f" - {r.description[:100]}" if r.description else ""))
        for mime, sch in r.content.items():
            out.append(f"    {mime}:")
            out.extend("      " + ln for ln in outline(spec, sch, depth))
        for h, (req, hs) in r.headers.items():
            try:
                hl = _label(flatten(spec, hs))
            except RefError as e:
                hl = f"<unresolved: {e}>"
            out.append(f"    header {h}{'*' if req else ''}: {hl}")
    if not op.responses:
        out.append("  none documented")
    out.append("")
    if op.security:
        alts = [" + ".join(f"{s}[{','.join(sorted(sc))}]" if sc else s for s, sc in sorted(a)) or "(anonymous)" for a in op.security]
        out.append("Security (any one of): " + " | ".join(alts))
    else:
        out.append("Security: none")
    return "\n".join(out)


# --------------------------------------------------------- example validation
def validate_op_example(
    spec: Spec, path: str, method: str, kind: str, status: str, text: str, content_type: str = ""
) -> str:
    op = find_operation(spec, path, method)
    kind = kind.strip().lower()
    if kind not in ("request", "response"):
        raise SpecError("kind must be 'request' or 'response'")
    try:
        instance = json.loads(text)
    except json.JSONDecodeError as e:
        raise SpecError(f"the example is not valid JSON: {e.msg} (line {e.lineno}, column {e.colno})") from e
    except RecursionError as e:
        raise SpecError("the example is nested too deeply") from e
    content: dict[str, Any]
    if kind == "request":
        if op.body is None:
            raise SpecError(f"{op.key} has no request body to validate against")
        content, where = op.body.content, "request body"
    else:
        st = status.strip().upper() or "200"
        resp = op.responses.get(st) or op.responses.get(st[:1] + "XX") or op.responses.get("default")
        if resp is None:
            raise SpecError(f"{op.key} has no response {status!r}; documented: {', '.join(op.responses) or 'none'}")
        content, where = resp.content, f"response {st}"
    if not content:
        raise SpecError(f"{op.key} {where} declares no content/schema, so there is nothing to validate against")
    if content_type:
        ct = norm_mime(content_type)
        if ct not in content:
            raise SpecError(f"{where} has no content type {ct!r}; available: {', '.join(content)}")
    else:
        ct = next((m for m in content if m == "application/json"), None) or next(
            (m for m in content if "json" in m), None
        ) or next(iter(content))
    res = validate(spec, content[ct], instance, "request" if kind == "request" else "response")
    head = f"{op.key} {where} ({ct}): "
    if not res.violations:
        msg = head + "VALID"
    else:
        lines = [head + f"INVALID, {len(res.violations)} violation(s)" + (" (truncated)" if res.truncated else "")]
        for v in res.violations:
            lines.append(f"  {v.pointer or '(root)'}: [{v.keyword}] {v.message}")
        msg = "\n".join(lines)
    if res.notes:
        msg += "\nNotes: " + "; ".join(res.notes)
    return msg


__all__ = ["overview", "find_endpoints", "describe", "validate_op_example", "find_operation", "outline", "Model"]
