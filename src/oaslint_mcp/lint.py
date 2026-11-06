"""Lint rules OAS1001+. Each finding has a rule id, severity, JSON pointer, line and a fix."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .errors import RefError, SpecError
from .loader import esc
from .redact import redact_url, shown
from .model import METHODS, build_model, norm_path, path_vars
from .schema import flatten
from .spec import Spec, walk_dicts
from .validate import type_ok, validate

ERROR, WARNING, INFO = "error", "warning", "info"
MAX_SCHEMA_NODES = 100_000

RULES: dict[str, str] = {
    "OAS1001": "operation has no operationId",
    "OAS1002": "duplicate operationId",
    "OAS1003": "operation has no responses",
    "OAS1004": "operation documents no 2xx response",
    "OAS1005": "operation documents no 4xx/5xx response",
    "OAS1006": "path parameter used in the URL template but not declared",
    "OAS1007": "path parameter declared but absent from the URL template",
    "OAS1008": "path parameter is not marked required: true",
    "OAS1009": "parameter naming style is inconsistent",
    "OAS1010": "unused component",
    "OAS1011": "schema has no type",
    "OAS1012": "required property is not listed in properties",
    "OAS1013": "enum value does not match the schema type",
    "OAS1014": "default value does not match the schema",
    "OAS1015": "example does not match its schema",
    "OAS1016": "missing description/summary",
    "OAS1017": "response has no description",
    "OAS1018": "security requirement references an undefined scheme",
    "OAS1019": "plain http:// server URL that looks like production",
    "OAS1020": "POST that creates a resource answers 200 instead of 201",
    "OAS1021": "trailing slash used inconsistently across paths",
    "OAS1022": "paths that differ only in parameter names",
    "OAS1023": "deprecated without a replacement note",
    "OAS1024": "unresolved $ref",
    "OAS1025": "duplicate key in the source file",
}


@dataclass
class Finding:
    rule: str
    severity: str
    pointer: str
    line: int | None
    message: str
    fix: str


class Linter:
    def __init__(self, spec: Spec) -> None:
        self.spec = spec
        self.model = build_model(spec)
        self.findings: list[Finding] = []
        self.parts: set[int] = set()

    def add(self, rule: str, sev: str, pointer: str, message: str, fix: str) -> None:
        self.findings.append(Finding(rule, sev, pointer, self.spec.line_for(pointer), message, fix))

    # ------------------------------------------------------------------ run
    def run(self) -> list[Finding]:
        self.refs_and_source()
        self.operations()
        self.paths()
        self.servers()
        self.naming()
        self.security()
        self.schemas()
        self.examples()
        self.unused()
        self.shallow_callbacks()
        order = {ERROR: 0, WARNING: 1, INFO: 2}
        self.findings.sort(key=lambda f: (order[f.severity], f.rule, f.pointer))
        return self.findings

    # ------------------------------------------------------- refs / source
    def refs_and_source(self) -> None:
        for ref, why, raw in self.spec.check_refs():
            remote = "never fetches" in why
            where = self.spec.find_ref_pointer(raw)
            self.add(
                "OAS1024", WARNING if remote else ERROR, where + "/$ref" if where else "",
                f"unresolved $ref {ref!r}: {why}",
                "Download remote files and reference them by relative path." if remote
                else "Fix the reference target or define the missing component.",
            )
        for w in self.spec.warnings:
            self.add("OAS1025", WARNING, "", w, "Remove the duplicate key; most parsers keep only the last one silently.")

    # ----------------------------------------------------------- operations
    def operations(self) -> None:
        seen_ids: dict[str, str] = {}
        for op in self.model.ops:
            if not op.op_id:
                self.add("OAS1001", WARNING, op.ptr, f"{op.key} has no operationId",
                         "Add a unique operationId; code generators and diff tools use it as the stable name.")
            elif op.op_id in seen_ids:
                self.add("OAS1002", ERROR, f"{op.ptr}/operationId",
                         f"operationId {op.op_id!r} of {op.key} is already used by {seen_ids[op.op_id]}",
                         "Make every operationId unique.")
            else:
                seen_ids[op.op_id] = op.key
            codes = list(op.responses)
            raw_resp = op.raw.get("responses")
            if not raw_resp:
                self.add("OAS1003", ERROR, f"{op.ptr}/responses" if "responses" in op.raw else op.ptr,
                         f"{op.key} has no responses", "Document at least one response, e.g. '200' plus the error cases.")
            else:
                if not any(c.startswith("2") for c in codes):
                    self.add("OAS1004", WARNING, f"{op.ptr}/responses", f"{op.key} documents no 2xx response",
                             "Add the success response (200/201/204 or 2XX).")
                if not any(c[:1] in ("4", "5") or c == "default" for c in codes):
                    self.add("OAS1005", INFO, f"{op.ptr}/responses", f"{op.key} documents no 4xx/5xx (or default) response",
                             "Describe at least the common error responses so clients can handle them.")
            for code, r in op.responses.items():
                if r.description is None:
                    self.add("OAS1017", WARNING, r.ptr, f"response {code} of {op.key} has no description",
                             "Add a description; it is required by the OpenAPI specification.")
            if not op.summary and not op.description:
                self.add("OAS1016", INFO, op.ptr, f"{op.key} has neither summary nor description",
                         "Add a one-line summary.")
            self.path_params(op)
            if op.deprecated and not _has_replacement_note(op.summary, op.description):
                self.add("OAS1023", INFO, f"{op.ptr}/deprecated", f"{op.key} is deprecated but says nothing about what to use instead",
                         "Mention the replacement operation and/or a sunset date in the description.")
            for p in op.params.values():
                if p.deprecated and not _has_replacement_note(p.description, None):
                    self.add("OAS1023", INFO, p.ptr, f"parameter {p.name!r} of {op.key} is deprecated without a replacement note",
                             "Say in the description which parameter replaces it.")
                if not p.description and p.loc != "path":
                    self.add("OAS1016", INFO, p.ptr, f"{p.loc} parameter {p.name!r} of {op.key} has no description", "Add a description.")
            if op.method == "post" and _creates(op) and "200" in op.responses and not any(c in op.responses for c in ("201", "202", "204")):
                self.add("OAS1020", INFO, f"{op.ptr}/responses/200", f"{op.key} looks like it creates a resource but answers 200",
                         "Use 201 Created (with a Location header) for resource creation, or 202 if processing is asynchronous.")

    def path_params(self, op: Any) -> None:
        template = set(path_vars(op.path))
        declared = {p.name: p for (loc, _), p in op.params.items() if loc == "path"}
        for name in sorted(template - set(declared)):
            self.add("OAS1006", ERROR, op.ptr, f"{op.key}: path parameter {{{name}}} is not declared",
                     f"Add a parameter with in: path, name: {name}, required: true.")
        for name, p in declared.items():
            if name not in template:
                self.add("OAS1007", ERROR, p.ptr, f"{op.key}: path parameter {name!r} is declared but {op.path} has no {{{name}}}",
                         "Remove the parameter or add the placeholder to the path.")
            if self._raw_required(p.ptr) is not True:
                self.add("OAS1008", ERROR, p.ptr, f"{op.key}: path parameter {name!r} must have required: true",
                         "Set required: true.")

    def _raw_required(self, ptr: str) -> Any:
        node: Any = self.spec.doc
        for seg in ptr[1:].split("/"):
            seg = seg.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and isinstance(node.get("$ref"), str) and seg not in node:
                try:
                    node, _ = self.spec.deref(node)
                except RefError:
                    return None
            if isinstance(node, dict) and seg in node:
                node = node[seg]
            elif isinstance(node, list) and seg.isdigit() and int(seg) < len(node):
                node = node[int(seg)]
            else:
                return None
        try:
            node, _ = self.spec.deref(node)
        except RefError:
            return None
        return node.get("required") if isinstance(node, dict) else None

    # ------------------------------------------------------------- paths
    def paths(self) -> None:
        paths = [p for p in self.model.paths_raw if not p.startswith("x-")]
        with_slash = [p for p in paths if p != "/" and p.endswith("/")]
        without = [p for p in paths if p != "/" and not p.endswith("/")]
        if with_slash and without:
            minority = with_slash if len(with_slash) <= len(without) else without
            for p in minority:
                self.add("OAS1021", WARNING, "/paths/" + esc(p),
                         f"path {p!r} {'ends' if p.endswith('/') else 'does not end'} with a slash, unlike most other paths",
                         "Pick one convention for all paths.")
        groups: dict[str, list[str]] = {}
        for p in paths:
            groups.setdefault(norm_path(p), []).append(p)
        for same in groups.values():
            if len(same) > 1:
                for p in same[1:]:
                    self.add("OAS1022", ERROR, "/paths/" + esc(p),
                             f"{p!r} differs from {same[0]!r} only in parameter names; they are the same URL",
                             "Merge them into one path item; OpenAPI forbids templated paths that are equivalent.")

    def servers(self) -> None:
        doc = self.spec.doc
        if self.spec.family == "2.0":
            host = doc.get("host")
            schemes = doc.get("schemes")
            if isinstance(host, str) and isinstance(schemes, list) and "http" in schemes and "https" not in schemes \
                    and _production_like(f"http://{host}"):
                self.add("OAS1019", WARNING, "/schemes", f"only plain http is offered for host {host!r}",
                         "Offer https (add it to schemes).")
            return
        servers = doc.get("servers")
        if not isinstance(servers, list):
            return
        for i, s in enumerate(servers):
            if not isinstance(s, dict) or not isinstance(s.get("url"), str):
                continue
            url = s["url"]
            variables: dict[str, Any] = s["variables"] if isinstance(s.get("variables"), dict) else {}
            for name, v in variables.items():
                if isinstance(v, dict) and "default" in v:
                    url = url.replace("{" + name + "}", str(v["default"]))
            if _production_like(url):
                self.add("OAS1019", WARNING, f"/servers/{i}/url", f"server {redact_url(s['url'])!r} uses plain http and looks like production",
                         "Use https:// for anything that is not a local/dev server.")

    def naming(self) -> None:
        for loc in ("query", "header", "cookie"):
            names: dict[str, str] = {}
            for op in self.model.ops:
                for (l2, _), p in op.params.items():
                    if l2 == loc:
                        names.setdefault(p.name, p.ptr)
            styles: dict[str, list[str]] = {}
            for n in names:
                st = _style(n.lower() if loc == "header" else n)
                if st:
                    styles.setdefault(st, []).append(n)
            if len(styles) > 1:
                dominant = max(styles, key=lambda k: len(styles[k]))
                for st, ns in styles.items():
                    if st == dominant:
                        continue
                    for n in ns:
                        self.add("OAS1009", WARNING, names[n], f"{loc} parameter {n!r} is {st} but most {loc} parameters are {dominant}",
                                 f"Rename it to {dominant} (a breaking change for existing clients) or document the exception.")

    def security(self) -> None:
        defined = set(self.model.schemes)
        reqs: list[tuple[str, Any]] = []
        if isinstance(self.spec.doc.get("security"), list):
            reqs.append(("/security", self.spec.doc["security"]))
        for op in self.model.ops:
            if isinstance(op.raw.get("security"), list):
                reqs.append((f"{op.ptr}/security", op.raw["security"]))
        for ptr, lst in reqs:
            for i, r in enumerate(lst):
                if isinstance(r, dict):
                    for name in r:
                        if name not in defined:
                            self.add("OAS1018", ERROR, f"{ptr}/{i}", f"security requirement uses scheme {name!r}, which is not defined",
                                     "Define it under components.securitySchemes (securityDefinitions in Swagger 2.0) or fix the name.")

    # ------------------------------------------------------------ schemas
    def schema_roots(self) -> list[tuple[str, Any]]:
        spec, out = self.spec, []
        if spec.family == "2.0":
            d = spec.doc.get("definitions")
            if isinstance(d, dict):
                out += [("/definitions/" + esc(k), v) for k, v in d.items()]
        else:
            comps = spec.doc.get("components")
            if isinstance(comps, dict) and isinstance(comps.get("schemas"), dict):
                out += [("/components/schemas/" + esc(k), v) for k, v in comps["schemas"].items()]
        for op in self.model.ops:
            for p in op.params.values():
                if spec.family != "2.0":
                    out.append((p.ptr + "/schema", p.schema))
            if op.body:
                for mime, sch in op.body.content.items():
                    out.append((f"{op.body.ptr}/content/{esc(mime)}/schema" if spec.family != "2.0" else op.body.ptr + "/schema", sch))
            for r in op.responses.values():
                for mime, sch in r.content.items():
                    out.append((f"{r.ptr}/content/{esc(mime)}/schema" if spec.family != "2.0" else r.ptr + "/schema", sch))
        return out

    def iter_schema_nodes(self) -> list[tuple[str, dict[str, Any]]]:
        seen: set[int] = set()
        result: list[tuple[str, dict[str, Any]]] = []
        self.parts = set()
        stack = list(reversed(self.schema_roots()))
        while stack and len(result) < MAX_SCHEMA_NODES:
            ptr, node = stack.pop()
            if not isinstance(node, dict) or id(node) in seen:
                continue
            seen.add(id(node))
            if "$ref" in node:
                continue
            result.append((ptr, node))
            for k in ("properties", "patternProperties"):
                if isinstance(node.get(k), dict):
                    for name, sub in node[k].items():
                        stack.append((f"{ptr}/{k}/{esc(name)}", sub))
            for k in ("items", "additionalProperties", "not"):
                if isinstance(node.get(k), dict):
                    stack.append((f"{ptr}/{k}", node[k]))
            for k in ("allOf", "oneOf", "anyOf"):
                if isinstance(node.get(k), list):
                    for i, sub in enumerate(node[k]):
                        stack.append((f"{ptr}/{k}/{i}", sub))
                        if isinstance(sub, dict):
                            self.parts.add(id(sub))
        return result

    def schemas(self) -> None:
        for ptr, node in self.iter_schema_nodes():
            if not any(k in node for k in ("type", "allOf", "oneOf", "anyOf", "not", "enum", "const")):
                self.add("OAS1011", INFO, ptr, "schema has no type",
                         "Add `type:` (and `format:` if relevant); untyped schemas accept anything.")
            try:
                f = flatten(self.spec, node)
            except RefError:
                continue
            missing = [] if id(node) in self.parts else [r for r in dict.fromkeys(f.required) if r not in f.properties]
            for r in missing:
                self.add("OAS1012", ERROR if f.additional is False else WARNING, ptr + "/required",
                         f"required property {r!r} is not defined in properties",
                         f"Add {r!r} under properties, or remove it from required.")
            if f.types is not None and f.enum is not None:
                for v in f.enum:
                    if not type_ok(v, f.types):
                        self.add("OAS1013", ERROR, ptr + "/enum", f"enum value {shown(v, 40, _prop_name(ptr))} is not of type {'|'.join(sorted(f.types))}",
                                 "Make the enum values match the declared type.")
            if node.get("default") is not None:
                self.check_default(ptr, node)

    def check_default(self, ptr: str, node: dict[str, Any]) -> None:
        res = validate(self.spec, {k: v for k, v in node.items() if k not in ("example", "examples", "default")}, node["default"], root_name=_prop_name(ptr))
        if res.violations:
            v = res.violations[0]
            self.add("OAS1014", ERROR, ptr + "/default", f"default value does not match the schema: {v.pointer or '(root)'} {v.message}",
                     "Change the default so it satisfies the type, enum and constraints.")

    def examples(self) -> None:
        spec = self.spec
        for ptr, node in self.iter_schema_nodes():
            if "example" in node:
                self.check_example(ptr + "/example", node, node["example"])
            if isinstance(node.get("examples"), list):
                for i, ex in enumerate(node["examples"]):
                    self.check_example(f"{ptr}/examples/{i}", node, ex)
        for op in self.model.ops:
            media: list[tuple[str, Any]] = []
            if spec.family != "2.0":
                if op.body:
                    media += [(f"{op.body.ptr}/content/{esc(m)}", s) for m, s in op.body.content.items()]
                for r in op.responses.values():
                    media += [(f"{r.ptr}/content/{esc(m)}", s) for m, s in r.content.items()]
            for ptr, sch in media:
                holder = self._node_at(ptr)
                if not isinstance(holder, dict):
                    continue
                if "example" in holder:
                    self.check_example(ptr + "/example", sch, holder["example"])
                if isinstance(holder.get("examples"), dict):
                    for name, ex in holder["examples"].items():
                        try:
                            exd, _ = spec.deref(ex)
                        except RefError:
                            continue
                        if isinstance(exd, dict) and "value" in exd:
                            self.check_example(f"{ptr}/examples/{esc(name)}/value", sch, exd["value"])

    def _node_at(self, ptr: str) -> Any:
        node: Any = self.spec.doc
        for seg in ptr[1:].split("/"):
            seg = seg.replace("~1", "/").replace("~0", "~")
            try:
                if isinstance(node, dict) and isinstance(node.get("$ref"), str) and seg not in node:
                    node, _ = self.spec.deref(node)
            except RefError:
                return None
            if isinstance(node, dict) and seg in node:
                node = node[seg]
            elif isinstance(node, list) and seg.isdigit() and int(seg) < len(node):
                node = node[int(seg)]
            else:
                return None
        try:
            node, _ = self.spec.deref(node)
        except RefError:
            return None
        return node

    def check_example(self, ptr: str, schema: Any, example: Any) -> None:
        try:
            clean = {k: v for k, v in schema.items() if k not in ("example", "examples")} if isinstance(schema, dict) else schema
            res = validate(self.spec, clean, example, root_name=_prop_name(ptr))
        except RefError:
            return
        except SpecError as e:
            self.add("OAS1015", INFO, ptr, f"example could not be checked: {e}", "Simplify the example or schema.")
            return
        if res.violations:
            shown = "; ".join(f"{v.pointer or '(root)'}: {v.message}" for v in res.violations[:3])
            more = f" (+{len(res.violations) - 3} more)" if len(res.violations) > 3 else ""
            self.add("OAS1015", WARNING, ptr, f"example does not match its schema: {shown}{more}",
                     "Fix the example or the schema so they agree.")

    # ------------------------------------------------------------ unused
    def unused(self) -> None:
        spec, doc = self.spec, self.spec.doc
        if spec.family == "2.0":
            areas = {"definitions": "definitions", "parameters": "parameters", "responses": "responses"}
            prefix = {"definitions": "#/definitions/", "parameters": "#/parameters/", "responses": "#/responses/"}
            skip_roots = {"definitions", "parameters", "responses", "securityDefinitions"}
        else:
            comps: dict[str, Any] = doc["components"] if isinstance(doc.get("components"), dict) else {}
            kinds = [k for k in comps if k not in ("securitySchemes",) and isinstance(comps[k], dict)]
            areas = {k: k for k in kinds}
            prefix = {k: f"#/components/{k}/" for k in kinds}
            skip_roots = {"components"}

        def container(kind: str) -> dict[str, Any]:
            if spec.family == "2.0":
                c = doc.get(areas[kind])
            else:
                c = doc["components"][kind]
            return c if isinstance(c, dict) else {}

        def refs_in(node: Any) -> set[tuple[str, str]]:
            found: set[tuple[str, str]] = set()
            for d in walk_dicts(node):
                v = d.get("$ref")
                if isinstance(v, str):
                    for kind, pre in prefix.items():
                        if v.startswith(pre):
                            found.add((kind, v[len(pre):].split("/")[0].replace("~1", "/").replace("~0", "~")))
            return found

        roots: set[tuple[str, str]] = set()
        for k, v in doc.items():
            if k not in skip_roots:
                roots |= refs_in(v)
        for ext in spec.ext.values():
            roots |= refs_in(ext)
        used: set[tuple[str, str]] = set()
        todo = list(roots)
        while todo:
            item = todo.pop()
            if item in used:
                continue
            used.add(item)
            kind, name = item
            sub = container(kind).get(name) if kind in areas else None
            if sub is not None:
                todo.extend(refs_in(sub) - used)
        for kind in areas:
            for name in container(kind):
                if (kind, name) not in used:
                    base = f"/{areas[kind]}/" if spec.family == "2.0" else f"/components/{kind}/"
                    self.add("OAS1010", WARNING, base + esc(name), f"{kind.rstrip('s') if kind != 'definitions' else 'schema'} {name!r} is never referenced",
                             "Delete it, or reference it from an operation.")
        # security schemes
        used_schemes: set[str] = set()
        for lst in [doc.get("security")] + [op.raw.get("security") for op in self.model.ops]:
            if isinstance(lst, list):
                for r in lst:
                    if isinstance(r, dict):
                        used_schemes.update(r)
        for name in self.model.schemes:
            if name not in used_schemes:
                base = "/securityDefinitions/" if spec.family == "2.0" else "/components/securitySchemes/"
                self.add("OAS1010", INFO, base + esc(name), f"security scheme {name!r} is defined but no security requirement uses it",
                         "Reference it in `security` or delete it.")

    # ---------------------------------------------------- callbacks/webhooks
    def shallow_callbacks(self) -> None:
        doc = self.spec.doc
        for key in ("webhooks", "x-webhooks"):
            hooks = doc.get(key)
            if isinstance(hooks, dict):
                for name, item in hooks.items():
                    self._shallow_item(f"/{key}/{esc(name)}", item, f"webhook {name!r}")
        for op in self.model.ops:
            cbs = op.raw.get("callbacks")
            if isinstance(cbs, dict):
                for cname, cb in cbs.items():
                    try:
                        cbd, _ = self.spec.deref(cb)
                    except RefError:
                        continue
                    if isinstance(cbd, dict):
                        for expr, item in cbd.items():
                            self._shallow_item(f"{op.ptr}/callbacks/{esc(cname)}/{esc(expr)}", item, f"callback {cname!r} of {op.key}")

    def _shallow_item(self, ptr: str, item: Any, label: str) -> None:
        try:
            d, _ = self.spec.deref(item)
        except RefError:
            return
        if not isinstance(d, dict):
            return
        for m in METHODS:
            o = d.get(m)
            if isinstance(o, dict) and not o.get("responses"):
                self.add("OAS1003", ERROR, f"{ptr}/{m}", f"{label}: {m.upper()} operation has no responses",
                         "Document what the receiving endpoint must answer.")


# ------------------------------------------------------------------ helpers
_REPLACEMENT = ("use ", "instead", "replace", "migrat", "superseded", "sunset", "successor", "alternative",
                "in favor", "in favour", "see ", "removed in", "yerine", "kullan", "geçin", "gecin")


def _has_replacement_note(a: str | None, b: str | None) -> bool:
    text = ((a or "")[:10_000] + " " + (b or "")[:10_000]).lower()
    return any(w in text for w in _REPLACEMENT)


_CREATE = re.compile(r"\b(creat|add|new|register|insert|submit|place|open)", re.IGNORECASE)


def _creates(op: Any) -> bool:
    blob = f"{op.op_id or ''} {op.summary or ''} {(op.description or '')[:200]}"
    if _CREATE.search(blob):
        return True
    last = [s for s in op.path.split("/") if s][-1:] or [""]
    return op.body is not None and last[0].endswith("s") and not last[0].startswith("{")


def _prop_name(ptr: str) -> str:
    """Name of the property a pointer sits under (for redaction hints), or ''."""
    segs = ptr.split("/")
    for i in range(len(segs) - 2, -1, -1):
        if segs[i] == "properties":
            return segs[i + 1].replace("~1", "/").replace("~0", "~")
    return ""


def _style(name: str) -> str | None:
    base = name.split("[", 1)[0]
    if not base or re.fullmatch(r"[a-z0-9]+", base):
        return None
    if re.fullmatch(r"[a-z0-9]+(_[a-z0-9]+)+", base):
        return "snake_case"
    if re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)+", base):
        return "kebab-case"
    if re.fullmatch(r"[a-z][a-zA-Z0-9]*", base):
        return "camelCase"
    if re.fullmatch(r"[A-Z][a-zA-Z0-9]*", base):
        return "PascalCase"
    if re.fullmatch(r"[A-Z0-9]+(_[A-Z0-9]+)+", base):
        return "SCREAMING_SNAKE"
    return None


_LOCAL_SUFFIX = (".local", ".localhost", ".test", ".example", ".internal", ".invalid", ".lan")
_NON_PROD_WORDS = ("dev", "staging", "stage", "test", "sandbox", "local", "qa", "uat", "internal", "mock", "demo")


def _production_like(url: str) -> bool:
    if not url.lower().startswith("http://"):
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host or host in ("localhost", "0.0.0.0", "::1") or host.startswith("127.") or host.endswith(_LOCAL_SUFFIX):
        return False
    if re.fullmatch(r"(10|192\.168)\.[\d.]+|172\.(1[6-9]|2\d|3[01])\.[\d.]+", host):
        return False
    if "{" in host:
        return False
    return not any(w in re.split(r"[.\-]", host) for w in _NON_PROD_WORDS)


def lint(spec: Spec) -> list[Finding]:
    return Linter(spec).run()


__all__ = ["lint", "Finding", "RULES"]
