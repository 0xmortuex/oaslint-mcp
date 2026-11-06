"""Schema normalisation: turn any 2.0 / 3.0 / 3.1 schema into one comparable shape.

`flatten` resolves $ref, merges allOf, folds `nullable` / `type: [x, "null"]` /
`oneOf: [x, {type: null}]` into one type set, turns `const` into a one-value enum,
and turns 3.0 boolean exclusive bounds and 3.1 numeric ones into the same form.
Two specs that say the same thing in different words flatten to equal objects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .errors import RefError
from .spec import Spec

OPAQUE_KEYS = (
    "not", "if", "then", "else", "patternProperties", "prefixItems", "contains",
    "dependentSchemas", "dependentRequired", "propertyNames", "unevaluatedProperties",
    "unevaluatedItems", "minContains", "maxContains",
)
_SCHEMA_WORDS = {
    "type", "enum", "const", "properties", "required", "items", "allOf", "oneOf", "anyOf",
    "additionalProperties", "format", "pattern", "minimum", "maximum", "minLength", "maxLength",
    "minItems", "maxItems", "nullable", "not",
}
MAX_ALLOF_DEPTH = 60


class Merged(dict):  # type: ignore[type-arg]
    """A synthesised allOf node (used when two parts both define the same property)."""

    def __init__(self, parts: list[Any]) -> None:
        super().__init__({"allOf": parts})
        self.parts = parts


def ident(node: Any) -> Any:
    if isinstance(node, Merged):
        return tuple(ident(p) for p in node.parts)
    return id(node)


def canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


@dataclass
class Flat:
    types: frozenset[str] | None = None
    enum: list[Any] | None = None
    format: str | None = None
    pattern: str | None = None
    lo: dict[str, tuple[Any, bool]] = field(default_factory=dict)
    hi: dict[str, tuple[Any, bool]] = field(default_factory=dict)
    multiple_of: Any = None
    unique_items: bool = False
    properties: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    additional: Any = True  # True | False | schema
    items: Any = None
    one_of: list[Any] | None = None
    any_of: list[Any] | None = None
    discriminator: dict[str, Any] | None = None
    read_only: bool = False
    write_only: bool = False
    deprecated: bool = False
    default: Any = None
    has_default: bool = False
    opaque: dict[str, str] = field(default_factory=dict)
    description: str | None = None
    title: str | None = None


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _stricter_lo(a: tuple[Any, bool] | None, b: tuple[Any, bool]) -> tuple[Any, bool]:
    if a is None:
        return b
    if b[0] > a[0] or (b[0] == a[0] and b[1] and not a[1]):
        return b
    return a


def _stricter_hi(a: tuple[Any, bool] | None, b: tuple[Any, bool]) -> tuple[Any, bool]:
    if a is None:
        return b
    if b[0] < a[0] or (b[0] == a[0] and b[1] and not a[1]):
        return b
    return a


def _own(spec: Spec, node: dict[str, Any]) -> Flat:
    f = Flat()
    t = node.get("type")
    if isinstance(t, str):
        f.types = frozenset([t])
    elif isinstance(t, list):
        f.types = frozenset(x for x in t if isinstance(x, str))
    nullable = node.get("nullable") is True or (spec.family == "2.0" and node.get("x-nullable") is True)
    if nullable and f.types is not None:
        f.types = f.types | {"null"}
    enum: list[Any] | None = None
    if isinstance(node.get("enum"), list):
        enum = list(node["enum"])
    if "const" in node:
        c = [node["const"]]
        enum = c if enum is None else [v for v in enum if canon(v) == canon(node["const"])]
    f.enum = enum
    if isinstance(node.get("format"), str):
        f.format = node["format"]
    if isinstance(node.get("pattern"), str):
        f.pattern = node["pattern"]
    for key in ("minimum", "maximum"):
        v = node.get(key)
        ex = node.get("exclusiveMinimum" if key == "minimum" else "exclusiveMaximum")
        if _is_num(v):
            (f.lo if key == "minimum" else f.hi)[key] = (v, ex is True)
        if _is_num(ex):
            if key == "minimum":
                f.lo["minimum"] = _stricter_lo(f.lo.get("minimum"), (ex, True))
            else:
                f.hi["maximum"] = _stricter_hi(f.hi.get("maximum"), (ex, True))
    for key in ("minLength", "minItems", "minProperties"):
        if _is_num(node.get(key)):
            f.lo[key] = (node[key], False)
    for key in ("maxLength", "maxItems", "maxProperties"):
        if _is_num(node.get(key)):
            f.hi[key] = (node[key], False)
    if _is_num(node.get("multipleOf")):
        f.multiple_of = node["multipleOf"]
    f.unique_items = node.get("uniqueItems") is True
    props = node.get("properties")
    if isinstance(props, dict):
        f.properties = dict(props)
    req = node.get("required")
    if isinstance(req, list):
        f.required = [r for r in req if isinstance(r, str)]
    ap = node.get("additionalProperties")
    if ap is False:
        f.additional = False
    elif isinstance(ap, dict) and ap:
        f.additional = ap
    items = node.get("items")
    if isinstance(items, (dict, bool)):
        f.items = items
    for kw, attr in (("oneOf", "one_of"), ("anyOf", "any_of")):
        lst = node.get(kw)
        if isinstance(lst, list):
            setattr(f, attr, list(lst))
    if isinstance(node.get("discriminator"), dict):
        f.discriminator = node["discriminator"]
    f.read_only = node.get("readOnly") is True
    f.write_only = node.get("writeOnly") is True
    f.deprecated = node.get("deprecated") is True
    if "default" in node:
        f.default, f.has_default = node["default"], True
    for kw in OPAQUE_KEYS:
        if kw in node:
            f.opaque[kw] = canon(node[kw])
    if isinstance(node.get("description"), str):
        f.description = node["description"]
    if isinstance(node.get("title"), str):
        f.title = node["title"]
    return f


def _merge(a: Flat, b: Flat) -> Flat:
    r = Flat()
    if a.types is None:
        r.types = b.types
    elif b.types is None:
        r.types = a.types
    else:
        both = a.types & b.types
        # integer is a kind of number
        if "integer" in a.types and "number" in b.types:
            both |= {"integer"}
        if "number" in a.types and "integer" in b.types:
            both |= {"integer"}
        r.types = frozenset(both)
    if a.enum is None:
        r.enum = b.enum
    elif b.enum is None:
        r.enum = a.enum
    else:
        keep = {canon(v) for v in b.enum}
        r.enum = [v for v in a.enum if canon(v) in keep]
    r.format = a.format or b.format
    r.pattern = a.pattern or b.pattern
    r.lo = dict(a.lo)
    for bk, bv in b.lo.items():
        r.lo[bk] = _stricter_lo(r.lo.get(bk), bv)
    r.hi = dict(a.hi)
    for bk, bv in b.hi.items():
        r.hi[bk] = _stricter_hi(r.hi.get(bk), bv)
    r.multiple_of = a.multiple_of if a.multiple_of is not None else b.multiple_of
    r.unique_items = a.unique_items or b.unique_items
    r.properties = dict(a.properties)
    for pk, pv in b.properties.items():
        r.properties[pk] = Merged([r.properties[pk], pv]) if pk in r.properties else pv
    r.required = list(a.required) + [x for x in b.required if x not in a.required]
    if a.additional is False or b.additional is False:
        r.additional = False
    elif a.additional is True:
        r.additional = b.additional
    elif b.additional is True:
        r.additional = a.additional
    else:
        r.additional = Merged([a.additional, b.additional])
    if a.items is None:
        r.items = b.items
    elif b.items is None:
        r.items = a.items
    else:
        r.items = Merged([a.items, b.items])
    r.opaque = dict(a.opaque)
    for ok, ov in b.opaque.items():
        if ok in r.opaque and r.opaque[ok] != ov:
            r.opaque[ok + "#allOf"] = ov
        else:
            r.opaque.setdefault(ok, ov)
    for attr in ("one_of", "any_of"):
        av, bv = getattr(a, attr), getattr(b, attr)
        if av is None:
            setattr(r, attr, bv)
        else:
            setattr(r, attr, av)
            if bv is not None:
                r.opaque[attr + "#allOf"] = canon(bv)
    r.discriminator = a.discriminator or b.discriminator
    r.read_only = a.read_only or b.read_only
    r.write_only = a.write_only or b.write_only
    r.deprecated = a.deprecated or b.deprecated
    r.has_default = a.has_default or b.has_default
    r.default = a.default if a.has_default else b.default
    r.description = a.description or b.description
    r.title = a.title or b.title
    return r


def _is_null_branch(spec: Spec, raw: Any) -> bool:
    try:
        node, _ = spec.deref(raw)
    except RefError:
        return False
    if not isinstance(node, dict):
        return False
    t = node.get("type")
    return (t == "null" or t == ["null"]) and set(node) <= {"type", "description", "title"}


def flatten(spec: Spec, schema: Any, _depth: int = 0) -> Flat:
    if _depth > MAX_ALLOF_DEPTH:
        raise RefError("allOf/$ref nesting is too deep (cycle through allOf?)")
    if schema is True or schema is None:
        return Flat()
    if schema is False:
        return Flat(types=frozenset())
    if (
        spec.family == "3.1"
        and isinstance(schema, dict)
        and isinstance(schema.get("$ref"), str)
        and any(k in _SCHEMA_WORDS for k in schema)
    ):
        sib = {k: v for k, v in schema.items() if k != "$ref"}
        return _merge(flatten(spec, {"$ref": schema["$ref"]}, _depth + 1), _own(spec, sib))
    node, _ref = spec.deref(schema)
    if not isinstance(node, (dict, bool)):
        return Flat()
    if isinstance(node, bool):
        return flatten(spec, node)
    if not isinstance(node, Merged):
        hit = spec._flat.get(id(node))
        if hit is not None and hit[0] is node:
            flat: Flat = hit[1]
            return flat
    result = _own(spec, node)
    allof = node.get("allOf")
    if isinstance(allof, list):
        for part in allof:
            result = _merge(result, flatten(spec, part, _depth + 1))
    # fold single-branch / nullable oneOf-anyOf into the schema itself
    for attr in ("one_of", "any_of"):
        branches = getattr(result, attr)
        if not branches:
            continue
        real = [b for b in branches if not _is_null_branch(spec, b)]
        has_null = len(real) != len(branches)
        if len(real) == 1:
            setattr(result, attr, None)
            folded = flatten(spec, real[0], _depth + 1)
            if has_null and folded.types is not None:
                folded = _copy_with_types(folded, folded.types | {"null"})
            disc = result.discriminator
            result = _merge(result, folded)
            result.discriminator = disc
    if not isinstance(node, Merged):
        spec._flat[id(node)] = (node, result)
    return result


def _copy_with_types(f: Flat, types: frozenset[str]) -> Flat:
    import copy

    g = copy.copy(f)
    g.types = types
    return g


def branch_name(raw: Any, index: int) -> str:
    if isinstance(raw, dict):
        ref = raw.get("$ref")
        if isinstance(ref, str):
            return ref.rsplit("/", 1)[-1].split("#")[-1] or f"#{index}"
        if isinstance(raw.get("title"), str):
            return str(raw["title"])
    return f"#{index}"


def fingerprint(spec: Spec, schema: Any, depth: int = 0, stack: tuple[Any, ...] = (),
                budget: list[int] | None = None) -> str:
    """Canonical text of a fully expanded schema (cycles cut), for matching oneOf options."""
    if budget is None:
        budget = [3000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 8:
        return '"<trunc>"'
    try:
        node, _ = spec.deref(schema)
        f = flatten(spec, schema)
    except RefError:
        return '"<unresolved>"'
    key = ident(node) if isinstance(node, dict) else None
    if key is not None:
        if key in stack:
            return '"<cycle>"'
        stack = (*stack, key)

    def sub(s: Any) -> str:
        return fingerprint(spec, s, depth + 1, stack, budget)

    obj: dict[str, Any] = {
        "t": sorted(f.types) if f.types is not None else None,
        "e": sorted(canon(v) for v in f.enum) if f.enum is not None else None,
        "f": f.format, "p": f.pattern, "lo": sorted(f.lo.items()), "hi": sorted(f.hi.items()),
        "m": f.multiple_of, "u": f.unique_items,
        "r": sorted(f.required),
        "props": {k: sub(v) for k, v in sorted(f.properties.items())},
        "ap": f.additional if isinstance(f.additional, bool) else sub(f.additional),
        "items": sub(f.items) if f.items is not None else None,
        "one": sorted(sub(b) for b in f.one_of) if f.one_of else None,
        "any": sorted(sub(b) for b in f.any_of) if f.any_of else None,
        "op": f.opaque,
    }
    return canon(obj)


def type_text(types: frozenset[str] | None) -> str:
    if types is None:
        return "any"
    if not types:
        return "nothing"
    return " | ".join(sorted(types))
