"""A JSON-Schema-subset validator (OpenAPI 3.0 / 3.1 / Swagger 2.0 flavours).

Evaluated: type (with nullable), enum/const, format (common ones), pattern, numeric and
length/size bounds, multipleOf, uniqueItems, required, properties, additionalProperties,
items, allOf, oneOf, anyOf. Not evaluated (reported as a note): not, if/then/else,
patternProperties, prefixItems, contains, unevaluated*, dependent*.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import RefError, SpecError
from .loader import esc
from .redact import shown
from .schema import Flat, canon, flatten, type_text
from .spec import Spec

MAX_VIOLATIONS = 100
MAX_STEPS = 400_000
MAX_INSTANCE_DEPTH = 150
MAX_STR_FOR_PATTERN = 200_000

_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S*$")
_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
_NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")


@dataclass
class Violation:
    pointer: str
    message: str
    keyword: str


@dataclass
class Result:
    violations: list[Violation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    truncated: bool = False


def json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "integer" if v.is_integer() else "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def type_ok(inst: Any, types: frozenset[str]) -> bool:
    t = json_type(inst)
    if t in types:
        return True
    return t == "integer" and "number" in types


def format_ok(fmt: str, v: str) -> bool | None:
    """True/False, or None when the format is not one we check."""
    if fmt == "date-time":
        if not _DATE_TIME.match(v):
            return False
        try:
            datetime.datetime.fromisoformat(v.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return False
        return True
    if fmt == "date":
        try:
            datetime.date.fromisoformat(v)
        except ValueError:
            return False
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}$", v))
    if fmt == "time":
        return bool(re.match(r"^\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$", v))
    if fmt == "email":
        return bool(_EMAIL.match(v))
    if fmt == "uuid":
        return bool(_UUID.match(v))
    if fmt in ("uri", "uri-reference", "iri"):
        return bool(_URI.match(v)) if fmt != "uri-reference" else " " not in v
    if fmt == "ipv4":
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            return False
        return True
    if fmt == "ipv6":
        try:
            ipaddress.IPv6Address(v)
        except ValueError:
            return False
        return True
    if fmt == "hostname":
        return bool(_HOST.match(v))
    if fmt == "byte":
        try:
            base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            return False
        return True
    return None


def _last(ptr: str) -> str:
    return ptr.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")


class _Validator:
    def __init__(self, spec: Spec, mode: str, root_name: str = "") -> None:
        self.root_name = root_name
        self.spec = spec
        self.mode = mode  # "request" | "response" | "any"
        self.steps = 0
        self.notes: list[str] = []

    def add(self, out: list[Violation], ptr: str, kw: str, msg: str) -> None:
        out.append(Violation(ptr or "", msg, kw))

    def check(self, schema: Any, inst: Any, ptr: str, out: list[Violation], depth: int) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise SpecError("validation aborted: the schema/instance combination is too large")
        if depth > MAX_INSTANCE_DEPTH:
            self.add(out, ptr, "depth", f"instance nested deeper than {MAX_INSTANCE_DEPTH} levels")
            return
        try:
            f = flatten(self.spec, schema)
        except RefError as e:
            self.note(f"skipped a schema that could not be resolved: {e}")
            return
        for kw in f.opaque:
            self.note(f"keyword '{kw.split('#')[0]}' is not evaluated")
        if f.types is not None and not type_ok(inst, f.types):
            got = json_type(inst)
            hint = ""
            if inst is None:
                hint = " (the schema is not nullable)"
            self.add(out, ptr, "type", f"expected {type_text(f.types)}, got {got}{hint}")
            return
        if f.enum is not None and canon(inst) not in {canon(v) for v in f.enum}:
            allowed = ", ".join(shown(v, 40, self.name(ptr)) for v in f.enum[:8]) + (", ..." if len(f.enum) > 8 else "")
            self.add(out, ptr, "enum", f"{shown(inst, 40, self.name(ptr))} is not one of the allowed values [{allowed}]")
        if isinstance(inst, str):
            self.check_string(f, inst, ptr, out)
        elif isinstance(inst, (int, float)) and not isinstance(inst, bool):
            self.check_number(f, inst, ptr, out)
        elif isinstance(inst, list):
            self.check_array(f, inst, ptr, out, depth)
        elif isinstance(inst, dict):
            self.check_object(f, inst, ptr, out, depth)
        self.check_composition(f, inst, ptr, out, depth)

    def name(self, ptr: str) -> str:
        return _last(ptr) if ptr else self.root_name

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)

    def check_string(self, f: Flat, s: str, ptr: str, out: list[Violation]) -> None:
        if "minLength" in f.lo and len(s) < f.lo["minLength"][0]:
            self.add(out, ptr, "minLength", f"string is {len(s)} characters, minimum is {f.lo['minLength'][0]:g}")
        if "maxLength" in f.hi and len(s) > f.hi["maxLength"][0]:
            self.add(out, ptr, "maxLength", f"string is {len(s)} characters, maximum is {f.hi['maxLength'][0]:g}")
        if f.format:
            ok = format_ok(f.format, s)
            if ok is False:
                self.add(out, ptr, "format", f"{shown(s, 60, self.name(ptr))} is not a valid {f.format}")
        if f.pattern:
            if len(f.pattern) > 1000 or _NESTED_QUANT.search(f.pattern):
                self.note(f"pattern {f.pattern[:40]!r} looks like it could backtrack catastrophically; not evaluated")
            elif len(s) > MAX_STR_FOR_PATTERN:
                self.note("a very long string was not matched against its pattern")
            else:
                try:
                    if re.search(f.pattern, s) is None:
                        self.add(out, ptr, "pattern", f"{shown(s, 60, self.name(ptr))} does not match pattern {f.pattern[:80]!r}")
                except re.error:
                    self.note(f"pattern {f.pattern[:40]!r} is not a valid Python regex; not evaluated")

    def check_number(self, f: Flat, n: float, ptr: str, out: list[Violation]) -> None:
        lo, hi = f.lo.get("minimum"), f.hi.get("maximum")
        if lo and (n < lo[0] or (lo[1] and n == lo[0])):
            self.add(out, ptr, "minimum", f"{n} is {'not above' if lo[1] else 'below'} the minimum {lo[0]:g}")
        if hi and (n > hi[0] or (hi[1] and n == hi[0])):
            self.add(out, ptr, "maximum", f"{n} is {'not below' if hi[1] else 'above'} the maximum {hi[0]:g}")
        if f.multiple_of and isinstance(f.multiple_of, (int, float)) and f.multiple_of > 0:
            q = n / f.multiple_of
            if abs(q - round(q)) > 1e-9:
                self.add(out, ptr, "multipleOf", f"{n} is not a multiple of {f.multiple_of:g}")
        if f.format in ("int32", "int64") and float(n).is_integer():
            bits = 31 if f.format == "int32" else 63
            if not -(2**bits) <= n < 2**bits:
                self.add(out, ptr, "format", f"{n} does not fit in {f.format}")

    def check_array(self, f: Flat, arr: list[Any], ptr: str, out: list[Violation], depth: int) -> None:
        if "minItems" in f.lo and len(arr) < f.lo["minItems"][0]:
            self.add(out, ptr, "minItems", f"array has {len(arr)} items, minimum is {f.lo['minItems'][0]:g}")
        if "maxItems" in f.hi and len(arr) > f.hi["maxItems"][0]:
            self.add(out, ptr, "maxItems", f"array has {len(arr)} items, maximum is {f.hi['maxItems'][0]:g}")
        if f.unique_items:
            seen: set[str] = set()
            for i, v in enumerate(arr):
                c = canon(v)
                if c in seen:
                    self.add(out, f"{ptr}/{i}", "uniqueItems", "duplicate item (uniqueItems is true)")
                seen.add(c)
        if f.items is not None:
            for i, v in enumerate(arr):
                if len(out) >= MAX_VIOLATIONS:
                    return
                self.check(f.items, v, f"{ptr}/{i}", out, depth + 1)

    def check_object(self, f: Flat, obj: dict[str, Any], ptr: str, out: list[Violation], depth: int) -> None:
        if "minProperties" in f.lo and len(obj) < f.lo["minProperties"][0]:
            self.add(out, ptr, "minProperties", f"object has {len(obj)} properties, minimum is {f.lo['minProperties'][0]:g}")
        if "maxProperties" in f.hi and len(obj) > f.hi["maxProperties"][0]:
            self.add(out, ptr, "maxProperties", f"object has {len(obj)} properties, maximum is {f.hi['maxProperties'][0]:g}")
        for name in f.required:
            if name not in obj and not self._skip_required(f, name):
                self.add(out, ptr, "required", f"missing required property {name!r}")
        for name, val in obj.items():
            if len(out) >= MAX_VIOLATIONS:
                return
            child = f"{ptr}/{esc(name)}"
            if name in f.properties:
                self.check(f.properties[name], val, child, out, depth + 1)
            elif f.additional is False:
                self.add(out, child, "additionalProperties", f"property {name!r} is not allowed (additionalProperties is false)")
            elif f.additional is not True:
                self.check(f.additional, val, child, out, depth + 1)

    def _skip_required(self, f: Flat, name: str) -> bool:
        if self.mode == "any":
            return False
        try:
            sub = flatten(self.spec, f.properties[name]) if name in f.properties else None
        except RefError:
            return False
        if sub is None:
            return False
        return (self.mode == "request" and sub.read_only) or (self.mode == "response" and sub.write_only)

    def check_composition(self, f: Flat, inst: Any, ptr: str, out: list[Violation], depth: int) -> None:
        if f.one_of:
            matches: list[int] = []
            firsts: list[str] = []
            for i, b in enumerate(f.one_of):
                sub: list[Violation] = []
                self.check(b, inst, ptr, sub, depth + 1)
                if not sub:
                    matches.append(i)
                else:
                    firsts.append(f"option {i}: {sub[0].message}")
            if len(matches) != 1:
                detail = "; ".join(firsts[:4]) if not matches else f"options {matches} all match"
                self.add(out, ptr, "oneOf", f"must match exactly one of {len(f.one_of)} oneOf options, matches {len(matches)} ({detail})")
        if f.any_of:
            firsts = []
            ok = False
            for i, b in enumerate(f.any_of):
                sub = []
                self.check(b, inst, ptr, sub, depth + 1)
                if not sub:
                    ok = True
                    break
                firsts.append(f"option {i}: {sub[0].message}")
            if not ok:
                self.add(out, ptr, "anyOf", f"matches none of {len(f.any_of)} anyOf options ({'; '.join(firsts[:4])})")


def validate(spec: Spec, schema: Any, instance: Any, mode: str = "any", root_name: str = "") -> Result:
    v = _Validator(spec, mode, root_name)
    out: list[Violation] = []
    try:
        v.check(schema, instance, "", out, 0)
    except RecursionError as e:
        raise SpecError("validation aborted: nesting too deep") from e
    res = Result(notes=v.notes)
    if len(out) > MAX_VIOLATIONS:
        res.truncated = True
        out = out[:MAX_VIOLATIONS]
    res.violations = out
    return res
