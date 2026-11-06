"""Normalised operation model shared by diff, describe, find and validate.

Swagger 2.0 bodies/formData/produces/consumes are rewritten into the OpenAPI 3
shape (requestBody + content maps) so one comparison engine serves all versions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .errors import RefError, SpecError
from .loader import esc
from .spec import Spec

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_PARAM_SCHEMA_KEYS = (
    "type", "format", "items", "enum", "default", "minimum", "maximum", "exclusiveMinimum",
    "exclusiveMaximum", "minLength", "maxLength", "pattern", "minItems", "maxItems",
    "uniqueItems", "multipleOf", "x-nullable", "nullable",
)
_TEMPLATE_VAR = re.compile(r"\{([^{}]*)\}")


@dataclass
class Param:
    name: str
    loc: str
    required: bool
    schema: Any
    style: str
    explode: bool
    deprecated: bool
    ptr: str
    description: str | None = None


@dataclass
class Body:
    required: bool
    content: dict[str, Any]  # mime -> schema
    ptr: str


@dataclass
class Resp:
    description: str | None
    content: dict[str, Any]
    headers: dict[str, tuple[bool, Any]]
    ptr: str


Alt = frozenset  # frozenset[tuple[str, frozenset[str]]]


@dataclass
class Operation:
    path: str
    method: str
    ptr: str
    op_id: str | None
    summary: str | None
    description: str | None
    tags: list[str]
    deprecated: bool
    params: dict[tuple[str, str], Param]
    body: Body | None
    responses: dict[str, Resp]
    security: list[frozenset[tuple[str, frozenset[str]]]]
    callbacks: list[str]
    raw: dict[str, Any]
    path_item: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class Model:
    spec: Spec
    ops: list[Operation]
    servers: list[str]
    schemes: dict[str, dict[str, Any]]
    webhooks: list[str]
    paths_raw: dict[str, Any]


def norm_path(path: str) -> str:
    return _TEMPLATE_VAR.sub("{}", path)


def path_vars(path: str) -> list[str]:
    return _TEMPLATE_VAR.findall(path)


def norm_mime(m: str) -> str:
    return m.split(";", 1)[0].strip().lower()


def _m(x: Any) -> dict[str, Any]:
    """A mapping, or an empty one if the spec put something else there."""
    return x if isinstance(x, dict) else {}


def _l(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _d(spec: Spec, node: Any) -> Any:
    target, _ = spec.deref(node)
    return target


def _param_schema_2(p: dict[str, Any]) -> dict[str, Any]:
    if p.get("type") == "file":
        return {"type": "string", "format": "binary"}
    s: dict[str, Any] = {k: p[k] for k in _PARAM_SCHEMA_KEYS if k in p}
    return s


_COLLECTION = {
    "csv": ("form", False), "ssv": ("spaceDelimited", False), "pipes": ("pipeDelimited", False),
    "tsv": ("x-tsv", False), "multi": ("form", True),
}


def _style(loc: str, p: dict[str, Any], family: str) -> tuple[str, bool]:
    if family == "2.0":
        cf = str(p.get("collectionFormat", "csv"))
        style, explode = _COLLECTION.get(cf, ("form", False))
        if loc in ("path", "header"):
            return "simple", False
        return style, explode
    default = {"query": "form", "cookie": "form", "path": "simple", "header": "simple"}.get(loc, "form")
    style = str(p["style"]) if isinstance(p.get("style"), str) else default
    explode = bool(p["explode"]) if isinstance(p.get("explode"), bool) else (style == "form")
    return style, explode


def _collect_params(
    spec: Spec, lists: list[tuple[str, Any]]
) -> tuple[dict[tuple[str, str], Param], dict[str, Any] | None, list[dict[str, Any]]]:
    """Merge path-level then operation-level parameters (operation wins on (in, name))."""
    out: dict[tuple[str, str], Param] = {}
    body: dict[str, Any] | None = None
    form: list[dict[str, Any]] = []
    for base_ptr, plist in lists:
        if not isinstance(plist, list):
            continue
        for i, raw in enumerate(plist):
            p = _d(spec, raw)
            if not isinstance(p, dict) or not isinstance(p.get("name"), str):
                continue
            loc = p.get("in")
            ptr = f"{base_ptr}/{i}"
            if loc == "body" and spec.family == "2.0":
                body = {"p": p, "ptr": ptr}
                continue
            if loc == "formData" and spec.family == "2.0":
                form = [f for f in form if f.get("name") != p["name"]] + [p]
                continue
            if not isinstance(loc, str):
                continue
            name = p["name"]
            if spec.family == "2.0":
                schema: Any = _param_schema_2(p)
            elif "schema" in p:
                schema = p["schema"]
            elif isinstance(p.get("content"), dict) and p["content"]:
                first = next(iter(p["content"].values()))
                schema = first.get("schema", {}) if isinstance(first, dict) else {}
            else:
                schema = {}
            style, explode = _style(loc, p, spec.family)
            key = (loc, name.lower() if loc == "header" else name)
            out[key] = Param(
                name=name, loc=loc, required=bool(p.get("required")) or loc == "path",
                schema=schema, style=style, explode=explode,
                deprecated=p.get("deprecated") is True, ptr=ptr,
                description=p.get("description") if isinstance(p.get("description"), str) else None,
            )
    return out, body, form


def _content(spec: Spec, raw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(raw, dict):
        for mime, media in raw.items():
            m = _d(spec, media)
            out[norm_mime(mime)] = m.get("schema", {}) if isinstance(m, dict) else {}
    return out


def _requirements(raw: Any) -> list[frozenset[tuple[str, frozenset[str]]]]:
    alts: list[frozenset[tuple[str, frozenset[str]]]] = []
    if isinstance(raw, list):
        for req in raw:
            if isinstance(req, dict):
                alts.append(
                    frozenset(
                        (str(n), frozenset(str(s) for s in (sc if isinstance(sc, list) else [])))
                        for n, sc in req.items()
                    )
                )
    return alts


def norm_scheme(spec: Spec, raw: Any) -> dict[str, Any]:
    s = _d(spec, raw)
    if not isinstance(s, dict):
        return {"type": "?"}
    t = s.get("type")
    out: dict[str, Any] = {"type": t}
    if spec.family == "2.0":
        if t == "basic":
            return {"type": "http", "scheme": "basic"}
        if t == "oauth2":
            raw_flow = str(s.get("flow"))
            flow = {"accessCode": "authorizationCode", "application": "clientCredentials"}.get(raw_flow, raw_flow)
            out["flows"] = {
                str(flow): {
                    "authorizationUrl": s.get("authorizationUrl"),
                    "tokenUrl": s.get("tokenUrl"),
                    "scopes": sorted(_m(s.get("scopes")).keys()),
                }
            }
        if t == "apiKey":
            out.update({"in": s.get("in"), "name": s.get("name")})
        return out
    if t == "http":
        out["scheme"] = str(s.get("scheme", "")).lower()
    elif t == "apiKey":
        out.update({"in": s.get("in"), "name": s.get("name")})
    elif t == "oauth2":
        flows: dict[str, Any] = {}
        for fname, fv in _m(s.get("flows")).items():
            if isinstance(fv, dict):
                flows[fname] = {
                    "authorizationUrl": fv.get("authorizationUrl"),
                    "tokenUrl": fv.get("tokenUrl"),
                    "scopes": sorted(_m(fv.get("scopes")).keys()),
                }
        out["flows"] = flows
    elif t == "openIdConnect":
        out["url"] = s.get("openIdConnectUrl")
    return out


def _server_urls(spec: Spec) -> list[str]:
    doc = spec.doc
    if spec.family == "2.0":
        host: str = doc["host"] if isinstance(doc.get("host"), str) else ""
        base: str = doc["basePath"] if isinstance(doc.get("basePath"), str) else ""
        schemes = [s for s in _l(doc.get("schemes")) if isinstance(s, str)] or ([""] if host else [])
        if not host:
            return [base or "/"]
        return [(f"{s}://" if s else "//") + host + base for s in schemes]
    out: list[str] = []
    servers = doc.get("servers")
    if isinstance(servers, list):
        for s in servers:
            if isinstance(s, dict) and isinstance(s.get("url"), str):
                url = s["url"]
                vars_: dict[str, Any] = s["variables"] if isinstance(s.get("variables"), dict) else {}

                def sub(m: re.Match[str], vars_: dict[str, Any] = vars_) -> str:
                    v = vars_.get(m.group(1))
                    if isinstance(v, dict) and "default" in v:
                        return str(v["default"])
                    return m.group(0)

                out.append(_TEMPLATE_VAR.sub(sub, url))
    return out or ["/"]


def base_path_of(url: str) -> str:
    if "://" in url or url.startswith("//"):
        return urlparse(url).path.rstrip("/")
    return ("/" + url.lstrip("/")).rstrip("/")


def build_model(spec: Spec) -> Model:
    if spec._model is not None:
        m: Model = spec._model
        return m
    doc = spec.doc
    paths = doc.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        raise SpecError(f"{spec.source}: 'paths' must be an object")
    ops: list[Operation] = []
    g_consumes = [norm_mime(x) for x in _l(doc.get("consumes")) if isinstance(x, str)] if spec.family == "2.0" else []
    g_produces = [norm_mime(x) for x in _l(doc.get("produces")) if isinstance(x, str)] if spec.family == "2.0" else []
    for path, raw_item in paths.items():
        if path.startswith("x-"):
            continue
        item = _d(spec, raw_item)
        if not isinstance(item, dict):
            continue
        item_ptr = "/paths/" + esc(path)
        if isinstance(raw_item, dict) and "$ref" in raw_item:
            item_ptr = item_ptr  # logical pointer; line_for follows the $ref
        for method in METHODS:
            raw_op = item.get(method)
            if not isinstance(raw_op, dict):
                continue
            ptr = f"{item_ptr}/{method}"
            params, body_param, form = _collect_params(
                spec,
                [(f"{item_ptr}/parameters", item.get("parameters")), (f"{ptr}/parameters", raw_op.get("parameters"))],
            )
            consumes = [norm_mime(x) for x in _l(raw_op.get("consumes")) if isinstance(x, str)] or g_consumes
            produces = [norm_mime(x) for x in _l(raw_op.get("produces")) if isinstance(x, str)] or g_produces
            body: Body | None = None
            if spec.family == "2.0":
                if body_param is not None:
                    mimes = consumes or ["application/json"]
                    p = body_param["p"]
                    body = Body(bool(p.get("required")), {m: p.get("schema", {}) for m in mimes}, body_param["ptr"])
                elif form:
                    has_file = any(f.get("type") == "file" for f in form)
                    mimes = [m for m in consumes if m in ("multipart/form-data", "application/x-www-form-urlencoded")]
                    mimes = mimes or ["multipart/form-data" if has_file else "application/x-www-form-urlencoded"]
                    schema = {
                        "type": "object",
                        "properties": {f["name"]: _param_schema_2(f) for f in form},
                        "required": [f["name"] for f in form if f.get("required")],
                    }
                    body = Body(any(f.get("required") for f in form), {m: schema for m in mimes}, f"{ptr}/parameters")
            else:
                rb = _d(spec, raw_op.get("requestBody")) if raw_op.get("requestBody") is not None else None
                if isinstance(rb, dict):
                    body = Body(bool(rb.get("required")), _content(spec, rb.get("content")), f"{ptr}/requestBody")
            responses: dict[str, Resp] = {}
            raw_resps = raw_op.get("responses")
            if isinstance(raw_resps, dict):
                for code, rr in raw_resps.items():
                    if code.startswith("x-"):
                        continue
                    r = _d(spec, rr)
                    if not isinstance(r, dict):
                        continue
                    rptr = f"{ptr}/responses/{esc(code)}"
                    if spec.family == "2.0":
                        content = {m: r["schema"] for m in (produces or ["application/json"])} if "schema" in r else {}
                    else:
                        content = _content(spec, r.get("content"))
                    headers: dict[str, tuple[bool, Any]] = {}
                    if isinstance(r.get("headers"), dict):
                        for hn, hv in r["headers"].items():
                            h = _d(spec, hv)
                            if not isinstance(h, dict):
                                continue
                            hs = _param_schema_2(h) if spec.family == "2.0" else h.get("schema", {})
                            headers[hn.lower()] = (h.get("required") is True, hs)
                    responses[str(code).upper() if str(code).lower() != "default" else "default"] = Resp(
                        r.get("description") if isinstance(r.get("description"), str) else None,
                        content, headers, rptr,
                    )
            if "security" in raw_op:
                sec = _requirements(raw_op["security"])
            else:
                sec = _requirements(doc.get("security"))
            cbs = [str(k) for k in raw_op["callbacks"]] if isinstance(raw_op.get("callbacks"), dict) else []
            ops.append(
                Operation(
                    path=path, method=method, ptr=ptr,
                    op_id=raw_op.get("operationId") if isinstance(raw_op.get("operationId"), str) else None,
                    summary=raw_op.get("summary") if isinstance(raw_op.get("summary"), str) else None,
                    description=raw_op.get("description") if isinstance(raw_op.get("description"), str) else None,
                    tags=[t for t in raw_op.get("tags", []) if isinstance(t, str)] if isinstance(raw_op.get("tags"), list) else [],
                    deprecated=raw_op.get("deprecated") is True,
                    params=params, body=body, responses=responses, security=sec,
                    callbacks=cbs, raw=raw_op, path_item=item,
                )
            )
    schemes: dict[str, dict[str, Any]] = {}
    raw_schemes = (
        doc.get("securityDefinitions")
        if spec.family == "2.0"
        else _m(doc.get("components")).get("securitySchemes")
        if isinstance(doc.get("components"), dict)
        else None
    )
    if isinstance(raw_schemes, dict):
        for name, s in raw_schemes.items():
            try:
                schemes[name] = norm_scheme(spec, s)
            except RefError:
                schemes[name] = {"type": "?"}
    hooks: list[str] = []
    for k in ("webhooks", "x-webhooks"):
        if isinstance(doc.get(k), dict):
            hooks.extend(str(x) for x in doc[k])
    model = Model(spec, ops, _server_urls(spec), schemes, sorted(set(hooks)), paths)
    spec._model = model
    return model
