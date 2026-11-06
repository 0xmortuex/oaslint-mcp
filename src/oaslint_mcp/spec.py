"""A loaded API description: sandboxed file access, version detection, $ref resolution."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from . import loader
from .errors import RefError, SpecError
from .loader import esc

MAX_EXTERNAL_FILES = 200
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_NAME_MAPS = {
    "properties", "patternProperties", "definitions", "$defs", "schemas", "parameters",
    "responses", "headers", "examples", "requestBodies", "callbacks", "securitySchemes",
    "links", "pathItems", "paths", "securityDefinitions", "webhooks", "x-webhooks",
}
_DATA_KEYS = {"example", "default", "enum", "const", "value"}


def safe_realpath(path: str) -> str:
    """realpath that turns OSError/ValueError (e.g. 'path too long') into a SpecError."""
    try:
        if "\x00" in path:
            raise SpecError("path contains a NUL character")
        return os.path.realpath(path)
    except (OSError, ValueError) as e:
        raise SpecError(f"cannot resolve path ({type(e).__name__}: {str(e)[:120]})") from e


def _norm(p: str) -> str:
    return os.path.normcase(p)


class Sandbox:
    """All file access goes through here; nothing outside `root` is ever opened."""

    def __init__(self, root: str) -> None:
        self.root = safe_realpath(root)

    def inside(self, real: str) -> bool:
        r, p = _norm(self.root), _norm(real)
        if p == r:
            return True
        try:
            return os.path.commonpath([r, p]) == r
        except ValueError:  # different drives
            return False

    def resolve(self, path: str, base: str | None = None) -> str:
        if len(path) > 4096:
            raise SpecError(f"path is {len(path)} characters long; refusing it")
        joined = path if os.path.isabs(path) else os.path.join(base or self.root, path)
        real = safe_realpath(joined)
        if not self.inside(real):
            raise SpecError(
                f"{path!r} is outside the allowed directory {self.root}. "
                "Start the server with --dir pointing at the folder that holds your specs."
            )
        return real


@dataclass
class Spec:
    doc: dict[str, Any]
    family: str  # "2.0", "3.0", "3.1"
    version_text: str
    source: str  # display name
    lines: dict[str, int]
    warnings: list[str]
    sandbox: Sandbox
    main_path: str | None
    base_dir: str
    ext: dict[str, dict[str, Any]] = field(default_factory=dict)
    bad: dict[str, str] = field(default_factory=dict)
    _flat: dict[int, Any] = field(default_factory=dict)
    _model: Any = None
    _refcheck: list[tuple[str, str, str]] | None = None

    @property
    def label(self) -> str:
        return ("Swagger " if self.family == "2.0" else "OpenAPI ") + self.version_text

    # ------------------------------------------------------------- refs
    def resolve_ref(self, ref: str) -> Any:
        if ref in self.bad:
            raise RefError(f"{self.show_ref(ref)}: {self.bad[ref]}")
        if ref.startswith("@file:"):
            path, _, frag = ref[6:].partition("#")
            doc: Any = self.ext.get(path)
            if doc is None:
                raise RefError(f"{self.show_ref(ref)}: file was not loaded")
        elif ref.startswith("#"):
            doc, frag = self.doc, ref[1:]
        else:
            raise RefError(f"{ref}: unsupported reference form")
        return self._walk_pointer(doc, frag, ref)

    def show_ref(self, ref: str) -> str:
        if ref.startswith("@file:"):
            path, _, frag = ref[6:].partition("#")
            root = self.sandbox.root.replace("\\", "/")
            if _norm(path).startswith(_norm(root)):
                path = path[len(root):].lstrip("/")
            return path + ("#" + frag if frag else "")
        return ref

    def _walk_pointer(self, doc: Any, frag: str, ref: str) -> Any:
        if frag == "":
            return doc
        if not frag.startswith("/"):
            raise RefError(f"{self.show_ref(ref)}: only JSON-pointer fragments (#/...) are supported")
        node = doc
        for raw in frag[1:].split("/"):
            seg = unquote(raw).replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and seg in node:
                node = node[seg]
            elif isinstance(node, list) and seg.isdigit() and int(seg) < len(node):
                node = node[int(seg)]
            else:
                raise RefError(f"{self.show_ref(ref)}: nothing found at {frag!r}")
        return node

    def deref(self, node: Any) -> tuple[Any, str | None]:
        """Follow a chain of $refs. Returns (target, last ref string or None)."""
        last: str | None = None
        seen: set[str] = set()
        while isinstance(node, dict) and isinstance(node.get("$ref"), str):
            ref = node["$ref"]
            if ref in seen:
                raise RefError(f"{self.show_ref(ref)}: circular $ref chain with no content")
            seen.add(ref)
            last = ref
            node = self.resolve_ref(ref)
        return node, last

    # ------------------------------------------------------ canonicalise
    def _canon_ref(self, value: str, base_dir: str, doc_id: str | None, queue: list[str]) -> str:
        if value.startswith("@file:"):
            return value
        file_part, hashmark, frag = value.partition("#")
        frag = hashmark + frag if hashmark else ""
        if not file_part:
            return value if doc_id is None else f"@file:{doc_id}{frag}"
        if _SCHEME.match(file_part):
            self.bad[value] = (
                "remote reference: oaslint never fetches network resources; "
                "download the file and use a relative path"
            )
            return value
        try:
            real = self.sandbox.resolve(unquote(file_part), base_dir)
        except SpecError as e:
            self.bad[value] = str(e)
            return value
        if not os.path.isfile(real):
            self.bad[value] = "file not found inside the sandbox directory"
            return value
        if self.main_path is not None and _norm(real) == _norm(self.main_path):
            return frag if frag else "#"
        rid = real.replace("\\", "/")
        if rid not in self.ext and rid not in queue:
            if len(self.ext) + len(queue) >= MAX_EXTERNAL_FILES:
                self.bad[value] = f"more than {MAX_EXTERNAL_FILES} external files referenced"
                return value
            queue.append(rid)
        return f"@file:{rid}{frag}"

    def _rewrite(self, root: Any, base_dir: str, doc_id: str | None, queue: list[str]) -> None:
        for d in walk_dicts(root):
            v = d.get("$ref")
            if isinstance(v, str):
                new = self._canon_ref(v, base_dir, doc_id, queue)
                if new != v:
                    d["$ref"] = new

    def process_refs(self) -> None:
        queue: list[str] = []
        self._rewrite(self.doc, self.base_dir, None, queue)
        while queue:
            rid = queue.pop(0)
            if rid in self.ext:
                continue
            real = rid
            hint = loader.hint_for(real)
            parsed = loader.parse_text(loader.read_text(real), os.path.basename(real), hint)
            self.ext[rid] = parsed.data
            self._rewrite(parsed.data, os.path.dirname(real), rid, queue)

    def check_refs(self) -> list[tuple[str, str, str]]:
        """Every $ref that does not resolve: (display ref, reason, raw ref)."""
        if self._refcheck is not None:
            return self._refcheck
        out: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        roots: list[Any] = [self.doc, *self.ext.values()]
        for root in roots:
            for d in walk_dicts(root):
                v = d.get("$ref")
                if isinstance(v, str) and v not in seen:
                    seen.add(v)
                    try:
                        self.resolve_ref(v)
                    except RefError as e:
                        out.append((self.show_ref(v), str(e).split(": ", 1)[-1], v))
        self._refcheck = out
        return out

    def find_ref_pointer(self, raw: str) -> str:
        """JSON pointer of the first use of `raw` in the main document ('' if none)."""
        stack: list[tuple[Any, str]] = [(self.doc, "")]
        seen: set[int] = set()
        while stack:
            node, ptr = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            if isinstance(node, dict):
                if node.get("$ref") == raw:
                    return ptr
                for k, v in node.items():
                    if isinstance(v, (dict, list)):
                        stack.append((v, ptr + "/" + esc(k)))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    if isinstance(v, (dict, list)):
                        stack.append((v, f"{ptr}/{i}"))
        return ""

    # ------------------------------------------------------------ lines
    def line_for(self, pointer: str) -> int | None:
        """Best-effort source line for a (logical) JSON pointer in the main document.

        Follows local $refs on the way down; if the exact node is missing, returns the
        line of the deepest node that exists.
        """
        if not self.lines:
            return None
        segs = [] if pointer in ("", "/") else pointer[1:].split("/")
        node: Any = self.doc
        phys = ""
        best = self.lines.get("")
        for raw in segs:
            seg = raw.replace("~1", "/").replace("~0", "~")
            guard = 0
            while isinstance(node, dict) and isinstance(node.get("$ref"), str) and seg not in node:
                ref = node["$ref"]
                if not ref.startswith("#") or guard > 20:
                    return best
                guard += 1
                phys = ""
                tgt: Any = self.doc
                for s2 in ref[1:].split("/")[1:]:
                    s2 = unquote(s2)
                    phys += "/" + s2
                    s2 = s2.replace("~1", "/").replace("~0", "~")
                    if isinstance(tgt, dict) and s2 in tgt:
                        tgt = tgt[s2]
                    elif isinstance(tgt, list) and s2.isdigit() and int(s2) < len(tgt):
                        tgt = tgt[int(s2)]
                    else:
                        return best
                node = tgt
            if isinstance(node, dict) and seg in node:
                node = node[seg]
            elif isinstance(node, list) and seg.isdigit() and int(seg) < len(node):
                node = node[int(seg)]
            else:
                return best
            phys += "/" + esc(seg)
            ln = self.lines.get(phys)
            if ln is not None:
                best = ln
        return best


def walk_dicts(root: Any) -> Iterator[dict[str, Any]]:
    """Yield every dict that can hold a $ref, skipping example/default/enum payloads."""
    seen: set[int] = set()
    stack: list[tuple[Any, bool]] = [(root, False)]
    while stack:
        node, names = stack.pop()
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            yield node
            for k, v in node.items():
                if not names and k in _DATA_KEYS:
                    continue
                if isinstance(v, (dict, list)):
                    stack.append((v, (not names) and k in _NAME_MAPS))
        elif isinstance(node, list):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for v in node:
                if isinstance(v, (dict, list)):
                    stack.append((v, False))


def detect_version(doc: dict[str, Any], name: str) -> tuple[str, str]:
    if "swagger" in doc:
        v = str(doc["swagger"])
        if v.startswith("2."):
            return "2.0", v
        raise SpecError(f"{name}: unsupported Swagger version {v!r} (supported: 2.0)")
    if "openapi" in doc:
        v = str(doc["openapi"])
        if re.match(r"^3\.0(\.\d+)?$", v):
            return "3.0", v
        if re.match(r"^3\.1(\.\d+)?$", v):
            return "3.1", v
        raise SpecError(f"{name}: unsupported OpenAPI version {v!r} (supported: 2.0, 3.0.x, 3.1.x)")
    raise SpecError(
        f"{name}: not an OpenAPI/Swagger document (no top-level 'openapi' or 'swagger' field)"
    )


_cache: dict[tuple[str, int, int], Spec] = {}


def load_spec(sandbox: Sandbox, spec: str) -> Spec:
    """`spec` is a path inside the sandbox, or inline JSON/YAML text."""
    inline = "\n" in spec or spec.lstrip().startswith("{")
    if inline:
        if len(spec.encode("utf-8", "replace")) > loader.MAX_BYTES:
            raise SpecError("inline spec is over the size limit")
        parsed = loader.parse_text(spec, "<inline spec>")
        name, main_path, base = "<inline>", None, sandbox.root
    else:
        real = sandbox.resolve(spec)
        if not os.path.isfile(real):
            raise SpecError(
                f"no such file: {spec!r} (looked inside {sandbox.root}). "
                "Pass a path relative to that directory, or paste the spec text itself."
            )
        try:
            st = os.stat(real)
        except OSError as e:
            raise SpecError(f"cannot read {spec}: {e.strerror or e}") from e
        key = (real, st.st_mtime_ns, st.st_size)
        cached = _cache.get(key)
        if cached is not None:
            return cached
        parsed = loader.parse_text(loader.read_text(real), spec, loader.hint_for(real))
        name, main_path, base = spec, real, os.path.dirname(real)
    family, vtext = detect_version(parsed.data, name)
    s = Spec(
        doc=parsed.data, family=family, version_text=vtext, source=name, lines=parsed.lines,
        warnings=list(parsed.warnings), sandbox=sandbox, main_path=main_path, base_dir=base,
    )
    s.process_refs()
    if main_path is not None and not s.ext:
        if len(_cache) >= 8:
            _cache.pop(next(iter(_cache)))
        _cache[key] = s
    return s
