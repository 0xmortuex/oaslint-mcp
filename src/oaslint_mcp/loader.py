"""Parse JSON / YAML text into plain Python data, safely.

Guards: size cap, line cap, nesting-depth cap, YAML alias-bomb cap (the number
of nodes after expanding aliases), YAML safe tags only, duplicate-key warnings.
Also builds a JSON-pointer -> line map so findings can say where they are.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from .errors import SpecError

MAX_BYTES = 50 * 1024 * 1024
MAX_LINES = 2_000_000
MAX_DEPTH = 120
MAX_EXPANDED_NODES = 2_000_000
MAX_LINE_ENTRIES = 400_000


def esc(seg: str) -> str:
    return seg.replace("~", "~0").replace("/", "~1")


@dataclass
class Parsed:
    data: Any
    fmt: str  # "json" or "yaml"
    lines: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def read_text(path: str) -> str:
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            raise SpecError(
                f"{path}: file is {size} bytes, over the {MAX_BYTES // (1024 * 1024)} MB limit"
            )
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise SpecError(f"cannot read {path}: {e.strerror or e}") from e
    if len(raw) > MAX_BYTES:
        raise SpecError(f"{path}: file is over the {MAX_BYTES // (1024 * 1024)} MB limit")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise SpecError(f"{path}: not valid UTF-8 ({e.reason} at byte {e.start})") from e


def _measure_depth(data: Any, name: str) -> None:
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise SpecError(f"{name}: nesting deeper than {MAX_DEPTH} levels, refusing to read it")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


_TOKEN = re.compile(r'\s*(?:("(?:[^"\\]|\\.)*")|([{}\[\],:])|([^\s,:\]}\[{"]+))')


def _json_lines(text: str) -> tuple[dict[str, int], list[str]]:
    """Walk already-validated JSON once to record line numbers and duplicate keys."""
    lines: dict[str, int] = {}
    warnings: list[str] = []
    # frame: [kind, pointer, keys-set or index, pending key]
    stack: list[list[Any]] = []
    line = 1
    pos = 0
    last = 0
    expect_key = False

    def child_pointer() -> str:
        top = stack[-1]
        if top[0] == "o":
            return str(top[1]) + "/" + esc(str(top[3]))
        return str(top[1]) + "/" + str(top[2])

    def note(pointer: str, ln: int) -> None:
        if len(lines) < MAX_LINE_ENTRIES:
            lines[pointer] = ln

    while True:
        m = _TOKEN.match(text, pos)
        if not m:
            break
        tok_start = m.start(1) if m.group(1) else (m.start(2) if m.group(2) else m.start(3))
        line += text.count("\n", last, tok_start)
        last = tok_start
        pos = m.end(0)
        s, p, lit = m.group(1), m.group(2), m.group(3)
        if s is not None:
            if stack and stack[-1][0] == "o" and expect_key:
                key = json.loads(s) if "\\" in s else s[1:-1]
                top = stack[-1]
                top[3] = key
                if key in top[2]:
                    warnings.append(
                        f"duplicate key {key!r} at line {line} (the last value wins)"
                        + (f" under {top[1]}" if top[1] else "")
                    )
                top[2].add(key)
                expect_key = False
            else:
                note(child_pointer() if stack else "", line)
        elif p is not None:
            if p in "{[":
                ptr = child_pointer() if stack else ""
                note(ptr, line)
                if p == "{":
                    stack.append(["o", ptr, set(), None])
                    expect_key = True
                else:
                    stack.append(["a", ptr, 0, None])
                    expect_key = False
            elif p in "}]":
                if stack:
                    stack.pop()
                expect_key = False
            elif p == ",":
                if stack and stack[-1][0] == "a":
                    stack[-1][2] += 1
                elif stack:
                    expect_key = True
        elif lit is not None:
            note(child_pointer() if stack else "", line)
    return lines, warnings


def _parse_json(text: str, name: str) -> Parsed:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise SpecError(f"{name}: invalid JSON: {e.msg} (line {e.lineno}, column {e.colno})") from e
    except RecursionError as e:
        raise SpecError(f"{name}: JSON nesting is too deep, refusing to read it") from e
    _measure_depth(data, name)
    lines, warnings = _json_lines(text)
    return Parsed(data, "json", lines, warnings)


# --------------------------------------------------------------------- YAML

_MERGE = "tag:yaml.org,2002:merge"


class _YamlBuilder:
    def __init__(self, loader: Any, name: str) -> None:
        self.loader = loader
        self.name = name
        self.memo: dict[int, Any] = {}
        self.lines: dict[str, int] = {}
        self.warnings: list[str] = []

    @staticmethod
    def _children(node: Any) -> list[Any]:
        if isinstance(node, yaml.MappingNode):
            out: list[Any] = []
            for k, v in node.value:
                out.append(k)
                out.append(v)
            return out
        if isinstance(node, yaml.SequenceNode):
            return list(node.value)
        return []

    def check_size(self, root: Any) -> None:
        """Alias-bomb guard: size of the document once aliases are expanded."""
        sizes: dict[int, int] = {}

        def size(node: Any, depth: int) -> int:
            if depth > MAX_DEPTH:
                raise SpecError(
                    f"{self.name}: YAML nesting deeper than {MAX_DEPTH} levels, refusing to read it"
                )
            nid = id(node)
            if nid in sizes:
                return sizes[nid]
            total = 1
            for c in self._children(node):
                total += size(c, depth + 1)
                if total > MAX_EXPANDED_NODES:
                    raise SpecError(
                        f"{self.name}: YAML aliases expand to more than {MAX_EXPANDED_NODES} "
                        "nodes (alias bomb); refusing to read it"
                    )
            sizes[nid] = total
            return total

        size(root, 0)

    def build(self, node: Any, pointer: str, depth: int, line: int | None = None) -> Any:
        if depth > MAX_DEPTH:
            raise SpecError(f"{self.name}: YAML nesting deeper than {MAX_DEPTH} levels")
        if len(self.lines) < MAX_LINE_ENTRIES and pointer not in self.lines:
            self.lines[pointer] = line or node.start_mark.line + 1
        nid = id(node)
        if nid in self.memo:
            return self.memo[nid]
        result: Any
        if isinstance(node, (yaml.MappingNode, yaml.SequenceNode)) and node.tag not in (
            "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"
        ):
            raise SpecError(
                f"{self.name}: line {node.start_mark.line + 1}: unsupported YAML tag {node.tag!r}"
            )
        if isinstance(node, yaml.MappingNode):
            obj: dict[str, Any] = {}
            self.memo[nid] = obj
            merged: list[tuple[str, Any]] = []
            for knode, vnode in node.value:
                if knode.tag == _MERGE:
                    srcs = vnode.value if isinstance(vnode, yaml.SequenceNode) else [vnode]
                    for src in srcs:
                        if not isinstance(src, yaml.MappingNode):
                            raise SpecError(f"{self.name}: YAML merge key '<<' needs a mapping")
                        sub = self.build(src, pointer, depth + 1)
                        merged.extend(sub.items())
                    continue
                if not isinstance(knode, yaml.ScalarNode):
                    raise SpecError(
                        f"{self.name}: line {knode.start_mark.line + 1}: complex mapping keys "
                        "are not supported"
                    )
                key = str(knode.value)
                if key in obj:
                    self.warnings.append(
                        f"duplicate key {key!r} at line {knode.start_mark.line + 1} "
                        "(the last value wins)" + (f" under {pointer}" if pointer else "")
                    )
                obj[key] = self.build(vnode, pointer + "/" + esc(key), depth + 1, knode.start_mark.line + 1)
            for k, v in merged:
                obj.setdefault(k, v)
            return obj
        if isinstance(node, yaml.SequenceNode):
            arr: list[Any] = []
            self.memo[nid] = arr
            for i, item in enumerate(node.value):
                arr.append(self.build(item, f"{pointer}/{i}", depth + 1))
            return arr
        try:
            result = self.loader.construct_object(node, deep=True)
        except yaml.YAMLError as e:
            raise SpecError(
                f"{self.name}: line {node.start_mark.line + 1}: unsupported YAML value: {e}"
            ) from e
        if isinstance(result, (datetime.datetime, datetime.date)):
            result = result.isoformat()
        elif isinstance(result, (bytes, bytearray)):
            result = base64.b64encode(bytes(result)).decode("ascii")
        elif isinstance(result, (set, frozenset)):
            raise SpecError(f"{self.name}: YAML sets are not valid in an API description")
        self.memo[nid] = result
        return result


_BRACKETS = re.compile(r"[\[\]{}]")
_INDENT = re.compile(r"^( *)\S", re.MULTILINE)
C_SAFE_DEPTH = 400


def _shallow(text: str) -> bool:
    """True when the text cannot nest deeply enough to overflow libyaml's C recursion.

    Brackets inside quoted strings are counted too, which can only make this return False
    (the pure-Python loader is then used, which fails cleanly with RecursionError).
    """
    depth = 0
    for m in _BRACKETS.finditer(text):
        depth += 1 if m.group() in "[{" else -1
        if depth > C_SAFE_DEPTH:
            return False
    return max((len(m.group(1)) for m in _INDENT.finditer(text)), default=0) <= C_SAFE_DEPTH


def _parse_yaml(text: str, name: str) -> Parsed:
    loader_cls: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader) if _shallow(text) else yaml.SafeLoader
    loader = loader_cls(text)
    try:
        try:
            root = loader.get_single_node()
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
            problem = getattr(e, "problem", None) or str(e)
            raise SpecError(f"{name}: invalid YAML: {problem}{where}") from e
        except RecursionError as e:
            raise SpecError(f"{name}: YAML nesting is too deep, refusing to read it") from e
        if root is None:
            raise SpecError(f"{name}: the document is empty")
        builder = _YamlBuilder(loader, name)
        try:
            builder.check_size(root)
            data = builder.build(root, "", 0)
        except RecursionError as e:
            raise SpecError(f"{name}: YAML nesting is too deep, refusing to read it") from e
        return Parsed(data, "yaml", builder.lines, builder.warnings)
    finally:
        loader.dispose()


def parse_text(text: str, name: str, hint: str | None = None) -> Parsed:
    """Parse JSON or YAML. `hint` is 'json', 'yaml' or None (sniff by first character)."""
    if text.count("\n") > MAX_LINES:
        raise SpecError(f"{name}: more than {MAX_LINES} lines, refusing to read it")
    fmt = hint
    if fmt is None:
        fmt = "json" if text.lstrip()[:1] in ("{", "[") else "yaml"
    parsed = _parse_json(text, name) if fmt == "json" else _parse_yaml(text, name)
    if not isinstance(parsed.data, dict):
        raise SpecError(
            f"{name}: the top level must be an object/mapping, got {type(parsed.data).__name__}"
        )
    return parsed


def hint_for(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return "json"
    if ext in (".yaml", ".yml"):
        return "yaml"
    return None
