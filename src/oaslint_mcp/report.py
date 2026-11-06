"""Turn findings and diffs into text for the agent."""

from __future__ import annotations

from .diff import BREAKING, INFO, NONBREAKING, POTENTIAL, SEVERITY_ORDER, Change, DiffResult
from .lint import ERROR, INFO as L_INFO, RULES, WARNING, Finding
from .spec import Spec

MAX_LINT_LINES = 300
MAX_PER_SEVERITY = 150
_TITLE = {
    BREAKING: "BREAKING",
    POTENTIAL: "POTENTIALLY BREAKING (needs a human look)",
    NONBREAKING: "NON-BREAKING",
    INFO: "INFO",
}


def lint_report(spec: Spec, findings: list[Finding]) -> str:
    counts = {ERROR: 0, WARNING: 0, L_INFO: 0}
    for f in findings:
        counts[f.severity] += 1
    out = [
        f"Lint of {spec.source} ({spec.label}): {counts[ERROR]} error(s), {counts[WARNING]} warning(s), {counts[L_INFO]} info",
    ]
    if not findings:
        out.append("No findings.")
        return "\n".join(out)
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    out.append("By rule: " + ", ".join(f"{r} x{n} ({RULES.get(r, '')})" for r, n in sorted(by_rule.items())))
    out.append("")
    for f in findings[:MAX_LINT_LINES]:
        loc = f.pointer or "(document)"
        if f.line:
            loc += f"  line {f.line}"
        out.append(f"[{f.rule}] {f.severity.upper()} {loc}")
        out.append(f"    {f.message}")
        out.append(f"    fix: {f.fix}")
    if len(findings) > MAX_LINT_LINES:
        out.append(f"... {len(findings) - MAX_LINT_LINES} more finding(s) not shown (fix the above first, then re-run).")
    return "\n".join(out)


def _where(c: Change, old: Spec, new: Spec) -> str:
    spec = new if c.side == "new" else old
    ln = f", line {c.line}" if c.line else ""
    return f"{c.side} spec {c.pointer or '/'}{ln}" if spec else c.pointer


def verdict(res: DiffResult) -> str:
    n = res.counts()
    if n[BREAKING]:
        return "BREAKING: this change is not backwards compatible"
    if n[POTENTIAL]:
        return "REVIEW: no certain breaking changes, but some changes may break strict or specific clients"
    return "SAFE: no breaking changes detected"


def diff_report(res: DiffResult, old: Spec, new: Spec) -> str:
    n = res.counts()
    out = [
        f"Comparing OLD {res.old_label} ({old.source}) -> NEW {res.new_label} ({new.source})",
        f"Verdict: {verdict(res)}",
        f"Counts: {n[BREAKING]} breaking, {n[POTENTIAL]} potentially breaking, {n[NONBREAKING]} non-breaking, {n[INFO]} info",
    ]
    for note in res.notes:
        out.append(f"Note: {note}")
    for sev in SEVERITY_ORDER:
        items = [c for c in res.changes if c.severity == sev]
        if not items:
            continue
        out.append("")
        out.append(f"== {_TITLE[sev]} ({len(items)}) ==")
        for i, c in enumerate(items[:MAX_PER_SEVERITY], 1):
            at = f" > {c.at}" if c.at else ""
            out.append(f"{i}. [{c.code}] {c.where}{at}")
            out.append(f"   {c.message}")
            out.append(f"   at {_where(c, old, new)}")
        if len(items) > MAX_PER_SEVERITY:
            out.append(f"   ... {len(items) - MAX_PER_SEVERITY} more {sev} change(s) not shown")
    if not res.changes:
        out.append("")
        out.append("No differences in the API contract (descriptions, ordering and equivalent spellings are ignored).")
    return "\n".join(out)


def changelog(res: DiffResult, old: Spec, new: Spec) -> str:
    n = res.counts()
    out = [
        "# API changelog",
        "",
        f"Compared `{old.source}` ({res.old_label}) with `{new.source}` ({res.new_label}).",
        "",
        f"**{verdict(res)}.** {n[BREAKING]} breaking, {n[POTENTIAL]} potentially breaking, "
        f"{n[NONBREAKING]} non-breaking, {n[INFO]} informational.",
    ]
    sections = [
        (BREAKING, "Breaking changes"),
        (POTENTIAL, "Potentially breaking changes"),
        (NONBREAKING, "Non-breaking changes"),
        (INFO, "Notes"),
    ]
    for sev, title in sections:
        items = [c for c in res.changes if c.severity == sev]
        if not items:
            continue
        out += ["", f"## {title}"]
        groups: dict[str, list[Change]] = {}
        for c in items:
            groups.setdefault(c.where, []).append(c)
        for where, cs in groups.items():
            out += ["", f"### {where}", ""]
            for c in cs[:MAX_PER_SEVERITY]:
                at = f" ({c.at})" if c.at else ""
                out.append(f"- {c.message}{at}")
    if not res.changes:
        out += ["", "No changes to the API contract."]
    return "\n".join(out)
