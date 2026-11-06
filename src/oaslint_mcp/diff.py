"""Breaking-change detection between two API descriptions.

The core idea is variance. A schema in a REQUEST is an input the server validates, so a
change is safe when the new schema accepts everything the old one did (loosening is fine,
tightening breaks clients). A schema in a RESPONSE is an output clients rely on, so a change
is safe when everything the new server can emit already fit the old schema (tightening is
fine, loosening or removing a guarantee breaks clients). Every rule below is one of those two
questions asked about one keyword.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import RefError
from .loader import esc
from .redact import redact_url, shown
from .model import (
    Body, Model, Operation, Param, Resp, base_path_of, build_model, norm_path, path_vars,
)
from .schema import Flat, branch_name, canon, fingerprint, flatten, ident, type_text
from .spec import Spec

BREAKING = "BREAKING"
POTENTIAL = "POTENTIALLY_BREAKING"
NONBREAKING = "NON_BREAKING"
INFO = "INFO"
SEVERITY_ORDER = [BREAKING, POTENTIAL, NONBREAKING, INFO]
REQ = "request"
RES = "response"
MAX_DIFF_DEPTH = 40

_RANK = {"int32": ("int", 1), "int64": ("int", 2), "float": ("fl", 1), "double": ("fl", 2)}


@dataclass
class Change:
    severity: str
    code: str
    message: str
    where: str
    at: str
    pointer: str
    side: str  # "old" or "new": which spec the pointer/line refer to
    line: int | None = None


@dataclass
class DiffResult:
    old_label: str
    new_label: str
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for c in self.changes:
            out[c.severity] += 1
        return out


@dataclass(frozen=True)
class Loc:
    where: str
    ctx: str
    sp: str
    po: str
    pn: str

    def at(self) -> str:
        return f"{self.ctx} {self.sp}".strip()

    def sub(self, sp_suffix: str, seg: str, old_seg: str | None = None) -> Loc:
        return Loc(self.where, self.ctx, self.sp + sp_suffix, self.po + seg, self.pn + (seg if old_seg is None else old_seg))

    def prop(self, name: str) -> Loc:
        seg = "/properties/" + esc(name)
        return self.sub("." + name, seg)

    def with_ctx(self, ctx: str, po: str, pn: str) -> Loc:
        return Loc(self.where, ctx, "$", po, pn)


def _bound(o: tuple[float, bool] | None, n: tuple[float, bool] | None, lower: bool) -> str | None:
    if o == n:
        return None
    if o is None:
        return "tighter"
    if n is None:
        return "looser"
    (ov, oe), (nv, ne) = o, n
    if lower:
        if nv > ov or (nv == ov and ne and not oe):
            return "tighter"
        if nv < ov or (nv == ov and oe and not ne):
            return "looser"
    else:
        if nv < ov or (nv == ov and ne and not oe):
            return "tighter"
        if nv > ov or (nv == ov and oe and not ne):
            return "looser"
    return None


def _covers(a: frozenset[str] | None, t: str) -> bool:
    return a is None or t in a or (t == "integer" and "number" in a)


def _accepts(a: frozenset[str] | None, b: frozenset[str] | None) -> bool:
    """True if every value type allowed by b is allowed by a."""
    if a is None:
        return True
    if b is None:
        return False
    return all(_covers(a, t) for t in b)


def _fmt_bound(v: tuple[float, bool] | None) -> str:
    if v is None:
        return "none"
    return f"{v[0]:g}" + (" (exclusive)" if v[1] else "")


class Differ:
    def __init__(self, old: Spec, new: Spec) -> None:
        self.o = old
        self.n = new
        self.changes: list[Change] = []
        self._dedupe: set[tuple[str, str, str, str, str]] = set()
        self.notes: list[str] = []

    # --------------------------------------------------------------- emit
    def emit(self, sev: str, code: str, msg: str, loc: Loc, side: str = "new") -> None:
        key = (sev, code, loc.where, loc.at(), msg)
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        ptr = loc.pn if side == "new" else loc.po
        spec = self.n if side == "new" else self.o
        self.changes.append(
            Change(sev, code, msg, loc.where, loc.at(), ptr, side, spec.line_for(ptr))
        )

    # ------------------------------------------------------------- schemas
    def cmp_schema(self, o: Any, n: Any, d: str, loc: Loc, depth: int = 0, stack: tuple[Any, ...] = ()) -> None:
        if depth > MAX_DIFF_DEPTH:
            self.emit(INFO, "depth-limit", f"comparison stopped at depth {MAX_DIFF_DEPTH}", loc)
            return
        try:
            od, _ = self.o.deref(o)
            nd, _ = self.n.deref(n)
            if isinstance(od, bool) or isinstance(nd, bool):
                od, nd = (od if not isinstance(od, bool) else {}), (nd if not isinstance(nd, bool) else {})
            key = (ident(od), ident(nd), d)
            if key in stack:
                return
            stack = (*stack, key)
            fo = flatten(self.o, o)
            fn = flatten(self.n, n)
        except RefError as e:
            self.emit(INFO, "unresolved-ref", f"not compared, {e}", loc)
            return
        if self._branch_mode(o, n, fo, fn, d, loc, depth, stack):
            return
        if not self._cmp_types(fo, fn, d, loc):
            return
        self._cmp_enum(fo, fn, d, loc)
        self._cmp_format(fo, fn, d, loc)
        self._cmp_simple("pattern", "pattern", fo.pattern, fn.pattern, d, loc)
        self._cmp_simple("multipleOf", "multiple-of", fo.multiple_of, fn.multiple_of, d, loc)
        if fo.unique_items != fn.unique_items:
            self._cmp_simple("uniqueItems", "unique-items", True if fo.unique_items else None,
                             True if fn.unique_items else None, d, loc)
        self._cmp_bounds(fo, fn, d, loc)
        self._cmp_object(fo, fn, d, loc, depth, stack)
        if fo.items is not None or fn.items is not None:
            self.cmp_schema(fo.items if fo.items is not None else {}, fn.items if fn.items is not None else {},
                            d, loc.sub("[]", "/items"), depth + 1, stack)
        self._cmp_composition(fo, fn, d, loc, depth, stack)
        self._cmp_misc(fo, fn, d, loc)

    def _cmp_types(self, fo: Flat, fn: Flat, d: str, loc: Loc) -> bool:
        to, tn = fo.types, fn.types
        if to == tn:
            return True
        o_text, n_text = type_text(to), type_text(tn)
        null_only = (
            to is not None and tn is not None and (to ^ tn) == {"null"}
        )
        if d == REQ:
            if _accepts(tn, to):  # new accepts everything old did
                if null_only:
                    self.emit(NONBREAKING, "request-nullable-added", "request now accepts null", loc)
                else:
                    self.emit(NONBREAKING, "request-type-widened", f"request type widened: {o_text} -> {n_text}", loc)
                return True
            if null_only:
                self.emit(BREAKING, "request-nullable-removed", "request no longer accepts null (nullable removed)", loc)
            elif _accepts(to, tn):
                self.emit(BREAKING, "request-type-narrowed", f"request type narrowed: {o_text} -> {n_text}", loc)
            else:
                self.emit(BREAKING, "request-type-changed", f"request type changed: {o_text} -> {n_text}", loc)
            return _accepts(to, tn) or bool((to or frozenset()) & (tn or frozenset()))
        # response
        if _accepts(to, tn):  # everything new can emit fit the old promise
            if null_only:
                self.emit(NONBREAKING, "response-nullable-removed", "response can no longer be null", loc)
            else:
                self.emit(NONBREAKING, "response-type-narrowed", f"response type narrowed: {o_text} -> {n_text}", loc)
            return True
        if null_only:
            self.emit(BREAKING, "response-nullable-added", "response may now be null (nullable added)", loc)
        elif _accepts(tn, to):
            self.emit(BREAKING, "response-type-widened", f"response type widened: {o_text} -> {n_text}", loc)
        else:
            self.emit(BREAKING, "response-type-changed", f"response type changed: {o_text} -> {n_text}", loc)
        return _accepts(tn, to) or bool((to or frozenset()) & (tn or frozenset()))

    def _cmp_enum(self, fo: Flat, fn: Flat, d: str, loc: Loc) -> None:
        eo = None if fo.enum is None else {canon(v): v for v in fo.enum}
        en = None if fn.enum is None else {canon(v): v for v in fn.enum}
        if eo is None and en is None:
            return
        if eo is None and en is not None:
            if d == REQ:
                self.emit(BREAKING, "request-enum-added", "request value is now restricted to an enum: " + _vals(en, _hint(loc)), loc)
            else:
                self.emit(NONBREAKING, "response-enum-added", "response value is now restricted to an enum: " + _vals(en, _hint(loc)), loc)
            return
        if eo is not None and en is None:
            if d == REQ:
                self.emit(NONBREAKING, "request-enum-removed", "request enum restriction removed", loc)
            else:
                self.emit(POTENTIAL, "response-enum-removed", "response enum restriction removed: any value may now be returned", loc)
            return
        assert eo is not None and en is not None
        removed = {k: v for k, v in eo.items() if k not in en}
        added = {k: v for k, v in en.items() if k not in eo}
        if d == REQ:
            if removed:
                self.emit(BREAKING, "request-enum-removed-values", "enum values removed from request: " + _vals(removed, _hint(loc)), loc)
            if added:
                self.emit(NONBREAKING, "request-enum-added-values", "enum values added to request: " + _vals(added, _hint(loc)), loc)
        else:
            if added:
                self.emit(POTENTIAL, "response-enum-added-values",
                          "enum values added to response: " + _vals(added, _hint(loc)) + " (strict clients that switch over the enum may fail)", loc)
            if removed:
                self.emit(NONBREAKING, "response-enum-removed-values", "enum values removed from response: " + _vals(removed, _hint(loc)), loc)

    def _cmp_format(self, fo: Flat, fn: Flat, d: str, loc: Loc) -> None:
        o, n = fo.format, fn.format
        if o == n:
            return
        if o is None:
            if d == REQ:
                self.emit(BREAKING, "request-format-added", f"request format constraint added: {n}", loc)
            else:
                self.emit(NONBREAKING, "response-format-added", f"response format added: {n}", loc)
            return
        if n is None:
            if d == REQ:
                self.emit(NONBREAKING, "request-format-removed", f"request format constraint removed (was {o})", loc)
            else:
                self.emit(POTENTIAL, "response-format-removed", f"response format guarantee removed (was {o})", loc)
            return
        ro, rn = _RANK.get(o), _RANK.get(n)
        widening = ro is not None and rn is not None and ro[0] == rn[0] and rn[1] > ro[1]
        narrowing = ro is not None and rn is not None and ro[0] == rn[0] and rn[1] < ro[1]
        if d == REQ:
            if widening:
                self.emit(NONBREAKING, "request-format-widened", f"request format widened: {o} -> {n}", loc)
            else:
                self.emit(BREAKING, "request-format-changed", f"request format changed: {o} -> {n}", loc)
        else:
            if widening:
                self.emit(BREAKING, "response-format-widened", f"response format widened: {o} -> {n} (values may no longer fit the old type)", loc)
            elif narrowing:
                self.emit(NONBREAKING, "response-format-narrowed", f"response format narrowed: {o} -> {n}", loc)
            else:
                self.emit(POTENTIAL, "response-format-changed", f"response format changed: {o} -> {n}", loc)

    def _cmp_simple(self, kw: str, code: str, o: Any, n: Any, d: str, loc: Loc) -> None:
        if o == n:
            return
        if o is None:
            if d == REQ:
                self.emit(BREAKING, f"request-{code}-added", f"request {kw} constraint added: {n!r}", loc)
            else:
                self.emit(NONBREAKING, f"response-{code}-added", f"response {kw} guarantee added: {n!r}", loc)
        elif n is None:
            if d == REQ:
                self.emit(NONBREAKING, f"request-{code}-removed", f"request {kw} constraint removed (was {o!r})", loc)
            else:
                self.emit(POTENTIAL, f"response-{code}-removed", f"response {kw} guarantee removed (was {o!r})", loc)
        else:
            self.emit(POTENTIAL, f"{d}-{code}-changed", f"{d} {kw} changed: {o!r} -> {n!r} (cannot tell if looser or tighter)", loc)

    def _cmp_bounds(self, fo: Flat, fn: Flat, d: str, loc: Loc) -> None:
        for lower, name_o, name_n in ((True, fo.lo, fn.lo), (False, fo.hi, fn.hi)):
            for kw in sorted(set(name_o) | set(name_n)):
                rel = _bound(name_o.get(kw), name_n.get(kw), lower)
                if rel is None:
                    continue
                msg = f"{kw} changed: {_fmt_bound(name_o.get(kw))} -> {_fmt_bound(name_n.get(kw))}"
                if d == REQ:
                    if rel == "tighter":
                        self.emit(BREAKING, "request-bound-tightened", f"request {msg} (tightened)", loc)
                    else:
                        self.emit(NONBREAKING, "request-bound-loosened", f"request {msg} (loosened)", loc)
                else:
                    if rel == "looser":
                        self.emit(POTENTIAL, "response-bound-loosened", f"response {msg} (loosened: values outside the old range may be returned)", loc)
                    else:
                        self.emit(NONBREAKING, "response-bound-tightened", f"response {msg} (tightened)", loc)

    def _visible(self, spec: Spec, schema: Any, d: str) -> bool:
        f = flatten(spec, schema)
        return not ((d == REQ and f.read_only) or (d == RES and f.write_only))

    def _cmp_object(self, fo: Flat, fn: Flat, d: str, loc: Loc, depth: int, stack: tuple[Any, ...]) -> None:
        po = {k: v for k, v in fo.properties.items() if self._visible(self.o, v, d)}
        pn = {k: v for k, v in fn.properties.items() if self._visible(self.n, v, d)}
        ro = {r for r in fo.required if r in po or r not in fo.properties}
        rn = {r for r in fn.required if r in pn or r not in fn.properties}
        for name in sorted(set(po) | set(pn)):
            sub = loc.prop(name)
            if name in po and name in pn:
                if d == REQ:
                    if name in rn and name not in ro:
                        self.emit(BREAKING, "request-property-now-required", f"request property '{name}' became required", sub)
                    elif name in ro and name not in rn:
                        self.emit(NONBREAKING, "request-property-now-optional", f"request property '{name}' became optional", sub)
                else:
                    if name in ro and name not in rn:
                        self.emit(BREAKING, "response-property-now-optional", f"response property '{name}' is no longer guaranteed (required -> optional)", sub)
                    elif name in rn and name not in ro:
                        self.emit(NONBREAKING, "response-property-now-required", f"response property '{name}' is now always present", sub)
                self.cmp_schema(po[name], pn[name], d, sub, depth + 1, stack)
            elif name in po:
                if d == REQ:
                    if fn.additional is False:
                        self.emit(BREAKING, "request-property-removed", f"request property '{name}' removed and additionalProperties is false, so clients still sending it are rejected", sub, "old")
                    else:
                        self.emit(POTENTIAL, "request-property-removed", f"request property '{name}' removed; clients still sending it may be rejected or silently lose behaviour", sub, "old")
                else:
                    self.emit(BREAKING, "response-property-removed", f"response property '{name}' removed" + (" (it was required)" if name in ro else ""), sub, "old")
            else:
                if d == REQ:
                    if name in rn:
                        self.emit(BREAKING, "request-property-added-required", f"new required request property '{name}'", sub)
                    else:
                        self.emit(NONBREAKING, "request-property-added", f"optional request property '{name}' added", sub)
                else:
                    if fo.additional is False:
                        self.emit(POTENTIAL, "response-property-added", f"response property '{name}' added but the old schema forbade extra properties (strict clients may reject it)", sub)
                    else:
                        self.emit(NONBREAKING, "response-property-added", f"response property '{name}' added", sub)
        # additionalProperties
        ao, an = fo.additional, fn.additional
        if ao is True and an is True:
            return
        if ao is False and an is False:
            return
        if isinstance(ao, dict) and isinstance(an, dict):
            self.cmp_schema(ao, an, d, loc.sub("{*}", "/additionalProperties"), depth + 1, stack)
            return
        sub = loc.sub("{*}", "/additionalProperties")
        # rank openness: False < schema < True
        def rank(v: Any) -> int:
            return 0 if v is False else (2 if v is True else 1)
        if rank(ao) == rank(an):
            return
        tighter = rank(an) < rank(ao)
        what = f"additionalProperties {_ap(ao)} -> {_ap(an)}"
        if d == REQ:
            if tighter:
                self.emit(BREAKING, "request-additional-properties-tightened", f"request {what} (tightened)", sub)
            else:
                self.emit(NONBREAKING, "request-additional-properties-loosened", f"request {what} (loosened)", sub)
        else:
            if tighter:
                self.emit(NONBREAKING, "response-additional-properties-tightened", f"response {what} (tightened)", sub)
            else:
                self.emit(POTENTIAL, "response-additional-properties-loosened", f"response {what} (loosened: extra properties may now appear)", sub)

    def _branch_mode(self, o: Any, n: Any, fo: Flat, fn: Flat, d: str, loc: Loc, depth: int, stack: tuple[Any, ...]) -> bool:
        """oneOf/anyOf on one side only (a one-branch union collapses to its branch): compare as variant lists."""
        for spec, raw in ((self.o, o), (self.n, n)):
            node, _ = spec.deref(raw)
            if isinstance(node, dict) and (node.get("properties") or node.get("allOf")):
                return False
        comp_o, comp_n = fo.one_of or fo.any_of, fn.one_of or fn.any_of
        if comp_o is None and comp_n is None:
            return False
        if comp_o is not None and comp_n is not None:
            if (fo.one_of is not None) != (fn.one_of is not None):
                kw_o, kw_n = ("oneOf", "anyOf") if fo.one_of is not None else ("anyOf", "oneOf")
                self.emit(POTENTIAL, "composition-kind-changed", f"{kw_o} changed to {kw_n}: the set of accepted/returned variants may differ", loc)
                return True
            return False
        kw = "oneOf" if (fo.one_of or fn.one_of) else "anyOf"
        bo = comp_o if comp_o is not None else [o]
        bn = comp_n if comp_n is not None else [n]
        self._match_branches(kw, bo, bn, d, loc, depth, stack)
        return True

    def _cmp_composition(self, fo: Flat, fn: Flat, d: str, loc: Loc, depth: int, stack: tuple[Any, ...]) -> None:
        for kw, attr in (("oneOf", "one_of"), ("anyOf", "any_of")):
            bo, bn = getattr(fo, attr), getattr(fn, attr)
            other_o = fo.any_of if attr == "one_of" else fo.one_of
            other_n = fn.any_of if attr == "one_of" else fn.one_of
            if bo is None and bn is None:
                continue
            if bo is not None and bn is None:
                if other_n is not None and other_o is None:
                    other_kw = "anyOf" if kw == "oneOf" else "oneOf"
                    self.emit(POTENTIAL, "composition-kind-changed", f"{kw} changed to {other_kw}: the set of accepted/returned variants may differ", loc)
                else:
                    self.emit(POTENTIAL, "composition-removed", f"{kw} removed from the schema; variants can no longer be compared", loc, "old")
                continue
            if bo is None and bn is not None:
                if other_o is not None and other_n is None:
                    continue  # reported from the other side
                self.emit(POTENTIAL, "composition-added", f"{kw} introduced where the schema had none; may narrow or reshape the {d}", loc)
                continue
            assert bo is not None and bn is not None
            self._match_branches(kw, bo, bn, d, loc, depth, stack)
        do, dn = fo.discriminator, fn.discriminator
        if do != dn:
            if do is None:
                self.emit(INFO, "discriminator-added", "discriminator added", loc)
            elif dn is None:
                self.emit(POTENTIAL, "discriminator-removed", "discriminator removed", loc)
            else:
                self.emit(POTENTIAL, "discriminator-changed", f"discriminator changed: {shown(do, 100)} -> {shown(dn, 100)}", loc)

    def _match_branches(self, kw: str, bo: list[Any], bn: list[Any], d: str, loc: Loc, depth: int, stack: tuple[Any, ...]) -> None:
        fo = [(i, b, fingerprint(self.o, b)) for i, b in enumerate(bo)]
        fn = [(i, b, fingerprint(self.n, b)) for i, b in enumerate(bn)]
        used: set[int] = set()
        left_o: list[tuple[int, Any, str]] = []
        for item in fo:
            hit = next((x for x in fn if x[0] not in used and x[2] == item[2]), None)
            if hit is None:
                left_o.append(item)
            else:
                used.add(hit[0])
        left_n = [x for x in fn if x[0] not in used]
        pairs: list[tuple[tuple[int, Any, str], tuple[int, Any, str]]] = []
        for item in list(left_o):
            name = branch_name(item[1], item[0])
            if name.startswith("#"):
                continue
            hit = next((x for x in left_n if branch_name(x[1], x[0]) == name), None)
            if hit is not None:
                pairs.append((item, hit))
                left_o.remove(item)
                left_n.remove(hit)
        if len(left_o) == 1 and len(left_n) == 1:
            pairs.append((left_o.pop(), left_n.pop()))
        for (io, bo_, _), (jn, bn_, _) in pairs:
            name = branch_name(bn_, jn)
            sub = Loc(loc.where, loc.ctx, f"{loc.sp}|{kw}[{name}]", f"{loc.po}/{kw}/{io}", f"{loc.pn}/{kw}/{jn}")
            self.cmp_schema(bo_, bn_, d, sub, depth + 1, stack)
        for io, b, _ in left_o:
            name = branch_name(b, io)
            sub = Loc(loc.where, loc.ctx, f"{loc.sp}|{kw}[{name}]", f"{loc.po}/{kw}/{io}", f"{loc.pn}")
            if d == REQ:
                self.emit(BREAKING, "request-variant-removed", f"{kw} option '{name}' removed: requests of that shape are no longer accepted", sub, "old")
            else:
                self.emit(NONBREAKING, "response-variant-removed", f"{kw} option '{name}' removed from the response", sub, "old")
        for jn, b, _ in left_n:
            name = branch_name(b, jn)
            sub = Loc(loc.where, loc.ctx, f"{loc.sp}|{kw}[{name}]", f"{loc.po}", f"{loc.pn}/{kw}/{jn}")
            if d == REQ:
                self.emit(NONBREAKING, "request-variant-added", f"{kw} option '{name}' added to the request", sub)
            else:
                self.emit(POTENTIAL, "response-variant-added", f"{kw} option '{name}' added to the response; clients that only know the old variants may fail", sub)

    def _cmp_misc(self, fo: Flat, fn: Flat, d: str, loc: Loc) -> None:
        for kw in sorted(set(fo.opaque) | set(fn.opaque)):
            a, b = fo.opaque.get(kw), fn.opaque.get(kw)
            if a != b:
                self.emit(POTENTIAL, "keyword-changed", f"'{kw.split('#')[0]}' changed; this keyword is not analysed in detail", loc)
        if fo.read_only != fn.read_only:
            self.emit(POTENTIAL, "read-only-changed", f"readOnly changed: {fo.read_only} -> {fn.read_only}", loc)
        if fo.write_only != fn.write_only:
            self.emit(POTENTIAL, "write-only-changed", f"writeOnly changed: {fo.write_only} -> {fn.write_only}", loc)
        if fo.deprecated != fn.deprecated:
            self.emit(INFO, "schema-deprecated-changed", "schema marked deprecated" if fn.deprecated else "schema no longer deprecated", loc)
        if (fo.has_default, canon(fo.default)) != (fn.has_default, canon(fn.default)):
            self.emit(INFO, "default-changed", f"default changed: {shown(fo.default, 60, _hint(loc)) if fo.has_default else 'none'} -> {shown(fn.default, 60, _hint(loc)) if fn.has_default else 'none'}", loc)

    # ---------------------------------------------------------- operations
    def run(self) -> DiffResult:
        mo, mn = build_model(self.o), build_model(self.n)
        base = Loc("API", "", "", "", "")
        vo, vn = self.o.doc.get("info", {}), self.n.doc.get("info", {})
        if isinstance(vo, dict) and isinstance(vn, dict) and vo.get("version") != vn.get("version"):
            self.emit(INFO, "api-version-changed", f"info.version {vo.get('version')!r} -> {vn.get('version')!r}", Loc("API", "", "", "/info/version", "/info/version"))
        self._servers(mo, mn, base)
        old_by = self._index(mo, self.o, "old")
        new_by = self._index(mn, self.n, "new")
        for k, op in old_by.items():
            if k not in new_by:
                where = op.key
                self.emit(BREAKING, "operation-removed", f"operation removed: {op.key}", Loc(where, "", "", op.ptr, op.ptr), "old")
        for k, op in new_by.items():
            if k not in old_by:
                self.emit(NONBREAKING, "operation-added", f"operation added: {op.key}", Loc(op.key, "", "", op.ptr, op.ptr))
        for k, nop in new_by.items():
            oop = old_by.get(k)
            if oop is not None:
                self._cmp_op(oop, nop, mo, mn)
        self._schemes(mo, mn)
        self._webhooks(mo, mn)
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        self.changes.sort(key=lambda c: order[c.severity])
        return DiffResult(self.o.label, self.n.label, self.changes, self.notes)

    def _index(self, m: Model, spec: Spec, which: str) -> dict[tuple[str, str], Operation]:
        out: dict[tuple[str, str], Operation] = {}
        for op in m.ops:
            k = (norm_path(op.path), op.method)
            if k in out:
                self.notes.append(f"{which} spec: {op.key} has the same shape as {out[k].key}; only the first is compared")
                continue
            out[k] = op
        return out

    def _servers(self, mo: Model, mn: Model, base: Loc) -> None:
        bo = {base_path_of(u) for u in mo.servers}
        bn = {base_path_of(u) for u in mn.servers}
        loc = Loc("API", "servers", "", "/servers", "/servers")
        if bo != bn:
            if bo.isdisjoint(bn):
                self.emit(BREAKING, "base-path-changed",
                          f"base path changed: {sorted(p or '/' for p in bo)} -> {sorted(p or '/' for p in bn)}; every URL clients call moves", loc)
            elif not bo <= bn:
                self.emit(POTENTIAL, "base-path-removed", f"base path(s) no longer served: {sorted(p or '/' for p in bo - bn)}", loc, "old")
            else:
                self.emit(NONBREAKING, "base-path-added", f"base path(s) added: {sorted(p or '/' for p in bn - bo)}", loc)
        elif set(mo.servers) != set(mn.servers):
            self.emit(INFO, "servers-changed", f"server list changed: {[redact_url(u) for u in mo.servers]} -> {[redact_url(u) for u in mn.servers]}", loc)

    def _cmp_op(self, oo: Operation, on: Operation, mo: Model, mn: Model) -> None:
        where = on.key
        loc = Loc(where, "", "", oo.ptr, on.ptr)
        if oo.op_id != on.op_id:
            self.emit(NONBREAKING, "operation-id-changed",
                      f"operationId changed: {oo.op_id!r} -> {on.op_id!r} (notable: generated client method names change)", loc)
        if oo.deprecated != on.deprecated:
            self.emit(INFO, "operation-deprecated" if on.deprecated else "operation-undeprecated",
                      "operation marked deprecated" if on.deprecated else "operation no longer deprecated", loc)
        # path parameter renames (wire-compatible)
        rename: dict[str, str] = {}
        for a, b in zip(path_vars(oo.path), path_vars(on.path)):
            if a != b:
                rename[a] = b
                self.emit(NONBREAKING, "path-param-renamed", f"path parameter renamed {a!r} -> {b!r} (same position in the URL, wire-compatible)", loc)
        self._params(oo, on, rename, loc)
        self._body(oo.body, on.body, loc)
        self._responses(oo, on, loc)
        self._security(oo, on, loc)
        co, cn = set(oo.callbacks), set(on.callbacks)
        for name in sorted(co - cn):
            self.emit(POTENTIAL, "callback-removed", f"callback '{name}' removed: receivers may stop being notified", loc, "old")
        for name in sorted(cn - co):
            self.emit(INFO, "callback-added", f"callback '{name}' added", loc)

    def _params(self, oo: Operation, on: Operation, rename: dict[str, str], loc: Loc) -> None:
        po: dict[tuple[str, str], Param] = {}
        for (loc_in, name), p in oo.params.items():
            key = (loc_in, rename.get(name, name)) if loc_in == "path" else (loc_in, name)
            po[key] = p
        pn = dict(on.params)
        only_o = [k for k in po if k not in pn]
        only_n = [k for k in pn if k not in po]
        for ko in list(only_o):
            match = next((kn for kn in only_n if kn[1].lower() == ko[1].lower()), None)
            if match is not None:
                p = pn[match]
                sub = Loc(loc.where, f"parameter {p.loc}:{p.name}", "", po[ko].ptr, p.ptr)
                self.emit(BREAKING, "parameter-location-changed",
                          f"parameter '{p.name}' moved from {ko[0]} to {match[0]}", sub)
                only_o.remove(ko)
                only_n.remove(match)
        for k in only_o:
            p = po[k]
            sub = Loc(loc.where, f"parameter {p.loc}:{p.name}", "", p.ptr, loc.pn)
            self.emit(POTENTIAL, "parameter-removed",
                      f"{'required ' if p.required else ''}{p.loc} parameter '{p.name}' removed; clients still sending it may be rejected or silently lose behaviour", sub, "old")
        for k in only_n:
            p = pn[k]
            sub = Loc(loc.where, f"parameter {p.loc}:{p.name}", "", loc.po, p.ptr)
            if p.required:
                self.emit(BREAKING, "parameter-added-required", f"new required {p.loc} parameter '{p.name}'", sub)
            else:
                self.emit(NONBREAKING, "parameter-added", f"optional {p.loc} parameter '{p.name}' added", sub)
        for k in po:
            if k not in pn:
                continue
            a, b = po[k], pn[k]
            sub = Loc(loc.where, f"parameter {b.loc}:{b.name}", "$", a.ptr, b.ptr)
            if b.required and not a.required:
                self.emit(BREAKING, "parameter-now-required", f"{b.loc} parameter '{b.name}' became required", sub)
            elif a.required and not b.required:
                self.emit(NONBREAKING, "parameter-now-optional", f"{b.loc} parameter '{b.name}' became optional", sub)
            if a.deprecated != b.deprecated:
                self.emit(INFO, "parameter-deprecated-changed",
                          f"parameter '{b.name}' " + ("marked deprecated" if b.deprecated else "no longer deprecated"), sub)
            try:
                structured = any(
                    (f.types is None or bool(f.types & {"array", "object"}))
                    for f in (flatten(self.o, a.schema), flatten(self.n, b.schema))
                    if f.types is not None
                )
            except RefError:
                structured = False
            if structured and (a.style, a.explode) != (b.style, b.explode):
                self.emit(BREAKING, "parameter-style-changed",
                          f"parameter '{b.name}' serialisation changed: style={a.style}/explode={str(a.explode).lower()} -> style={b.style}/explode={str(b.explode).lower()}", sub)
            self.cmp_schema(a.schema, b.schema, REQ, sub)

    def _body(self, bo: Body | None, bn: Body | None, loc: Loc) -> None:
        if bo is None and bn is None:
            return
        if bo is None and bn is not None:
            sub = Loc(loc.where, "request body", "", loc.po, bn.ptr)
            if bn.required:
                self.emit(BREAKING, "request-body-added-required", "a required request body was added", sub)
            else:
                self.emit(NONBREAKING, "request-body-added", "an optional request body was added", sub)
            return
        if bo is not None and bn is None:
            self.emit(POTENTIAL, "request-body-removed", "request body removed; clients still sending it may be rejected",
                      Loc(loc.where, "request body", "", bo.ptr, loc.pn), "old")
            return
        assert bo is not None and bn is not None
        base = Loc(loc.where, "request body", "", bo.ptr, bn.ptr)
        if bn.required and not bo.required:
            self.emit(BREAKING, "request-body-now-required", "request body became required", base)
        elif bo.required and not bn.required:
            self.emit(NONBREAKING, "request-body-now-optional", "request body became optional", base)
        for mime in bo.content:
            if not _mime_covered(mime, bn.content):
                self.emit(BREAKING, "request-content-type-removed", f"request content type '{mime}' no longer accepted",
                          Loc(loc.where, f"request body {mime}", "", f"{bo.ptr}/content/{esc(mime)}", bn.ptr), "old")
        for mime in bn.content:
            if not _mime_covered(mime, bo.content):
                self.emit(NONBREAKING, "request-content-type-added", f"request content type '{mime}' now accepted",
                          Loc(loc.where, f"request body {mime}", "", bo.ptr, f"{bn.ptr}/content/{esc(mime)}"))
        for mime in bo.content:
            if mime in bn.content:
                sub = Loc(loc.where, f"request body {mime}", "$",
                          f"{bo.ptr}/content/{esc(mime)}/schema", f"{bn.ptr}/content/{esc(mime)}/schema")
                self.cmp_schema(bo.content[mime], bn.content[mime], REQ, sub)

    def _responses(self, oo: Operation, on: Operation, loc: Loc) -> None:
        ro, rn = oo.responses, on.responses
        for code, r in ro.items():
            if _code_covered(code, rn):
                continue
            sub = Loc(loc.where, f"response {code}", "", r.ptr, on.ptr)
            if code[:1] in ("2", "3"):
                self.emit(BREAKING, "response-removed", f"success response {code} removed; clients rely on it", sub, "old")
            else:
                self.emit(NONBREAKING, "response-error-removed", f"response {code} removed", sub, "old")
        for code, r in rn.items():
            if _code_covered(code, ro):
                continue
            sub = Loc(loc.where, f"response {code}", "", oo.ptr, r.ptr)
            self.emit(NONBREAKING, "response-added", f"response {code} added", sub)
        for code in ro:
            if code not in rn:
                continue
            a, b = ro[code], rn[code]
            self._resp(code, a, b, loc)

    def _resp(self, code: str, a: Resp, b: Resp, loc: Loc) -> None:
        for mime in a.content:
            if not _mime_covered(mime, b.content):
                self.emit(BREAKING, "response-content-type-removed", f"response {code} no longer offers content type '{mime}'",
                          Loc(loc.where, f"response {code} {mime}", "", f"{a.ptr}/content/{esc(mime)}", b.ptr), "old")
        for mime in b.content:
            if not _mime_covered(mime, a.content):
                self.emit(NONBREAKING, "response-content-type-added", f"response {code} now also offers '{mime}'",
                          Loc(loc.where, f"response {code} {mime}", "", a.ptr, f"{b.ptr}/content/{esc(mime)}"))
        for mime in a.content:
            if mime in b.content:
                sub = Loc(loc.where, f"response {code} {mime}", "$",
                          f"{a.ptr}/content/{esc(mime)}/schema", f"{b.ptr}/content/{esc(mime)}/schema")
                self.cmp_schema(a.content[mime], b.content[mime], RES, sub)
        for h, (req, sch) in a.headers.items():
            sub = Loc(loc.where, f"response {code} header {h}", "$", f"{a.ptr}/headers/{esc(h)}", f"{b.ptr}/headers/{esc(h)}")
            if h not in b.headers:
                sev = BREAKING if req else POTENTIAL
                self.emit(sev, "response-header-removed", f"response header '{h}' removed" + (" (it was required)" if req else ""), sub, "old")
            else:
                nreq, nsch = b.headers[h]
                if req and not nreq:
                    self.emit(BREAKING, "response-header-now-optional", f"response header '{h}' is no longer guaranteed", sub)
                self.cmp_schema(sch, nsch, RES, sub)
        for h in b.headers:
            if h not in a.headers:
                sub = Loc(loc.where, f"response {code} header {h}", "$", a.ptr, f"{b.ptr}/headers/{esc(h)}")
                self.emit(NONBREAKING, "response-header-added", f"response header '{h}' added", sub)

    def _security(self, oo: Operation, on: Operation, loc: Loc) -> None:
        so, sn = oo.security, on.security
        if set(so) == set(sn):
            return
        pub_o = not so or any(len(a) == 0 for a in so)
        pub_n = not sn or any(len(a) == 0 for a in sn)
        sub = Loc(loc.where, "security", "", f"{oo.ptr}/security", f"{on.ptr}/security")
        if pub_o and pub_n:
            return
        if pub_o:
            self.emit(BREAKING, "auth-added", f"authentication now required: {_alts(sn)} (the operation was public)", sub)
            return
        if pub_n:
            self.emit(NONBREAKING, "auth-removed", "authentication no longer required (the operation is now public)", sub)
            return

        def satisfied(alt: frozenset[tuple[str, frozenset[str]]]) -> bool:
            for cand in sn:
                if all(any(s == s2 and sc <= sc2 for s2, sc2 in alt) for s, sc in cand):
                    return True
            return False

        broken = [a for a in so if not satisfied(a)]
        if not broken:
            self.emit(NONBREAKING, "auth-loosened", f"accepted authentication widened: {_alts(so)} -> {_alts(sn)}", sub)
        else:
            reason = _auth_reason(broken[0], sn)
            if len(broken) == len(so):
                self.emit(BREAKING, "auth-tightened", f"authentication tightened: {_alts(so)} -> {_alts(sn)} ({reason})", sub)
            else:
                self.emit(POTENTIAL, "auth-option-removed",
                          f"one accepted authentication option no longer works: {reason}; was {_alts(so)}, now {_alts(sn)}", sub)

    def _schemes(self, mo: Model, mn: Model) -> None:
        used = {s for op in mo.ops for alt in op.security for s, _ in alt}
        for name, so in mo.schemes.items():
            sn = mn.schemes.get(name)
            loc = Loc("API", f"securityScheme {name}", "", f"/components/securitySchemes/{esc(name)}", f"/components/securitySchemes/{esc(name)}")
            if self.o.family == "2.0":
                loc = Loc("API", f"securityScheme {name}", "", f"/securityDefinitions/{esc(name)}", f"/securityDefinitions/{esc(name)}")
            if sn is None:
                if name in used:
                    self.emit(INFO, "scheme-removed", f"security scheme '{name}' removed (operations using it are reported separately)", loc, "old")
                continue
            if sn == so:
                continue
            core_o = {k: so.get(k) for k in ("type", "scheme", "in", "name")}
            core_n = {k: sn.get(k) for k in ("type", "scheme", "in", "name")}
            if core_o != core_n:
                sev = BREAKING if name in used else INFO
                self.emit(sev, "scheme-changed", f"security scheme '{name}' changed: {core_o} -> {core_n}", loc)
            elif so.get("flows") != sn.get("flows"):
                self.emit(POTENTIAL, "scheme-flows-changed", f"oauth2 flows of '{name}' changed (URLs or scopes)", loc)
            else:
                self.emit(INFO, "scheme-changed", f"security scheme '{name}' changed", loc)

    def _webhooks(self, mo: Model, mn: Model) -> None:
        for w in sorted(set(mo.webhooks) - set(mn.webhooks)):
            self.emit(POTENTIAL, "webhook-removed", f"webhook '{w}' removed: subscribers will stop receiving it", Loc("webhooks", w, "", f"/webhooks/{esc(w)}", "/webhooks"), "old")
        for w in sorted(set(mn.webhooks) - set(mo.webhooks)):
            self.emit(INFO, "webhook-added", f"webhook '{w}' added", Loc("webhooks", w, "", "/webhooks", f"/webhooks/{esc(w)}"))


# ------------------------------------------------------------------ helpers
def _hint(loc: Loc) -> str:
    last = loc.sp.rsplit(".", 1)[-1]
    return last.split("[")[0].split("{")[0].split("|")[0]


def _vals(d: dict[str, Any], name: str = "") -> str:
    items = list(d.values())
    text = ", ".join(shown(v, 40, name) for v in items[:8])
    return text + (f", ... (+{len(items) - 8})" if len(items) > 8 else "")


def _ap(v: Any) -> str:
    return "false" if v is False else ("true" if v is True else "schema")


def _mime_covered(m: str, others: dict[str, Any]) -> bool:
    if m in others or "*/*" in others:
        return True
    if "/" in m and (m.split("/")[0] + "/*") in others:
        return True
    return False


def _code_covered(code: str, others: dict[str, Any]) -> bool:
    if code in others:
        return True
    if code[:1].isdigit() and f"{code[0]}XX" in others:
        return True
    if code == "default":
        return False
    if code[:1] in ("4", "5") and "default" in others:
        return True
    return False


def _alts(alts: list[frozenset[tuple[str, frozenset[str]]]]) -> str:
    def one(a: frozenset[tuple[str, frozenset[str]]]) -> str:
        if not a:
            return "(none)"
        return " + ".join(f"{s}[{','.join(sorted(sc))}]" if sc else s for s, sc in sorted(a, key=lambda x: x[0]))

    return " OR ".join(one(a) for a in alts) or "(none)"


def _auth_reason(old_alt: frozenset[tuple[str, frozenset[str]]], new_alts: list[frozenset[tuple[str, frozenset[str]]]]) -> str:
    old_names = {s for s, _ in old_alt}
    for cand in new_alts:
        names = {s for s, _ in cand}
        if names == old_names:
            extra: list[str] = []
            for s, sc in cand:
                have = next((sc2 for s2, sc2 in old_alt if s2 == s), frozenset())
                extra += sorted(sc - have)
            if extra:
                return "now requires additional scope(s): " + ", ".join(extra)
        elif old_names < names:
            return "now also requires: " + ", ".join(sorted(names - old_names))
    return "scheme(s) " + ", ".join(sorted(old_names)) + " are no longer accepted"


def diff_specs(old: Spec, new: Spec) -> DiffResult:
    return Differ(old, new).run()
