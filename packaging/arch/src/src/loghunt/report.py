import json
from collections import Counter
from typing import List

from .models import Finding, SEVERITIES


def _counts(findings: List[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def _fmt(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def to_text(findings: List[Finding], stats: dict) -> str:
    out = [f"read {stats['lines']} lines, {stats['parsed']} understood", ""]
    if not findings:
        out.append("nothing suspicious found")
        return "\n".join(out) + "\n"
    c = _counts(findings)
    out.append("findings: " + ", ".join(f"{c[s]} {s}" for s in reversed(SEVERITIES) if c[s]))
    out.append("")
    for f in findings:
        out.append(f"[{f.severity.upper():8}] {f.rule}  {f.ip}")
        out.append(f"           {f.summary}")
        out.append(f"           {_fmt(f.first_seen)} -> {_fmt(f.last_seen)}   {f.mitre}")
        for line in f.evidence:
            out.append(f"           | {line}")
        out.append("")
    return "\n".join(out)


def to_markdown(findings: List[Finding], stats: dict) -> str:
    out = ["# Log analysis report", "", f"Read {stats['lines']} lines, {stats['parsed']} understood.", ""]
    if not findings:
        return "\n".join(out + ["Nothing suspicious found.", ""])
    c = _counts(findings)
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for s in reversed(SEVERITIES):
        if c[s]:
            out.append(f"| {s} | {c[s]} |")
    out += ["", "| Severity | Rule | IP | Count | First seen | Last seen | ATT&CK |", "|---|---|---|---|---|---|---|"]
    for f in findings:
        out.append(f"| {f.severity} | {f.rule} | {f.ip} | {f.count} | {_fmt(f.first_seen)} | {_fmt(f.last_seen)} | {f.mitre} |")
    out.append("")
    for f in findings:
        out += [f"## {f.rule} from {f.ip}", "", f.summary, "", "```"] + f.evidence + ["```", ""]
    return "\n".join(out)


def to_json(findings: List[Finding], stats: dict) -> str:
    data = {
        "stats": stats,
        "findings": [
            {
                "rule": f.rule, "severity": f.severity, "ip": f.ip, "count": f.count,
                "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
                "summary": f.summary, "mitre": f.mitre, "evidence": f.evidence,
            } for f in findings
        ],
    }
    return json.dumps(data, indent=2) + "\n"


def to_brief(findings: List[Finding], stats: dict) -> str:
    out = [f"{stats['parsed']} of {stats['lines']} lines understood, {len(findings)} findings", ""]
    if findings:
        out.append(f"{'LEVEL':<9}{'RULE':<30}{'ADDRESS':<17}{'COUNT':<7}ATT&CK")
    for f in findings:
        out.append(f"{f.severity:<9}{f.rule:<30}{f.ip:<17}{f.count:<7}{f.mitre.split(' ')[0]}")
    return "\n".join(out) + "\n"


RENDERERS = {"text": to_text, "markdown": to_markdown, "json": to_json, "brief": to_brief}
