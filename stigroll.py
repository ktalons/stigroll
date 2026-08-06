#!/usr/bin/env python3
"""
stigroll - roll STIG checklist and SCAP scan results up to NIST 800-53 controls.

The problem this solves: a STIG finding is technology-specific ("V-253260: Windows
Server must have the Fax Server role removed"). A control assessor doesn't think in
V-numbers, they think in 800-53 controls and families. DISA's Control Correlation
Identifiers (CCIs) are the published mapping between the two, so this reads the
CCI list, joins it against scan output, and reports findings the way an assessment
actually needs them: grouped by control family, counted by severity.

Inputs (mix and match, any number):
  *.cklb   STIG Viewer 3 checklist (JSON)
  *.ckl    STIG Viewer 2 checklist (XML)
  *.xml    XCCDF results from `oscap xccdf eval --results`

Usage:
  stigroll.py checklists/*.cklb --cci-list U_CCI_List.xml
  stigroll.py scans/results-xccdf.xml --cci-list U_CCI_List.xml --format csv
  stigroll.py checklists/*.cklb --open-only --format json

Standard library only. No install step.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Normalization tables
#
# Every input format spells these differently, so everything is normalized on
# the way in and the rest of the program only ever sees these canonical values.
# Doing this at the boundary is what keeps the aggregation code from turning
# into a pile of format-specific special cases.
# --------------------------------------------------------------------------

# DISA severity -> CAT category. This mapping is fixed by DISA, not a choice.
SEVERITY_TO_CAT = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
    "unknown": "unknown",
}

# Status vocabularies differ across .ckl, .cklb and XCCDF. Canonical set:
#   open | not_a_finding | not_applicable | not_reviewed
STATUS_ALIASES = {
    # .cklb (JSON)
    "open": "open",
    "not_a_finding": "not_a_finding",
    "not_applicable": "not_applicable",
    "not_reviewed": "not_reviewed",
    # .ckl (XML) uses title case and a different "no finding" spelling
    "notafinding": "not_a_finding",
    "not reviewed": "not_reviewed",
    # XCCDF rule-result values
    "fail": "open",
    "pass": "not_a_finding",
    "notapplicable": "not_applicable",
    "notchecked": "not_reviewed",
    "notselected": "not_applicable",
    "error": "not_reviewed",
    "unknown": "not_reviewed",
    "informational": "not_reviewed",
    "fixed": "not_a_finding",
}

# Order used for every rendered table, so output is stable and diffable
# regardless of dict insertion order or input file order.
STATUS_ORDER = ["open", "not_a_finding", "not_applicable", "not_reviewed"]
CAT_ORDER = ["CAT I", "CAT II", "CAT III", "unknown"]

CCI_PATTERN = re.compile(r"CCI-\d{6}")

# 800-53 control id, e.g. "AC-2", "AC-2(4)", "SI-4 a 1" -> family "AC", control "AC-2"
CONTROL_PATTERN = re.compile(r"\b([A-Z]{2})-(\d+)")

FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    """One rule result on one host, normalized across every input format."""

    rule_id: str  # V-number / group id, the human-facing identifier
    title: str
    severity: str  # high | medium | low | unknown
    status: str  # canonical status
    host: str
    source: str  # filename it came from, for traceability
    ccis: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)  # filled in by the CCI join

    @property
    def cat(self) -> str:
        return SEVERITY_TO_CAT.get(self.severity, "unknown")

    @property
    def families(self) -> list[str]:
        """Distinct 800-53 families this finding touches, e.g. ['AC', 'IA']."""
        return sorted({c.split("-")[0] for c in self.controls})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def localname(tag: str) -> str:
    """Strip the XML namespace from a tag.

    XCCDF ships as 1.1 and 1.2 with different namespace URIs, and .ckl files
    have no namespace at all. Rather than register three namespace maps and
    branch on version, match on local names everywhere. Slightly less strict,
    considerably less brittle.
    """
    return tag.rpartition("}")[2]


def normalize_status(raw: str) -> str:
    key = (raw or "").strip().lower().replace("-", "")
    return STATUS_ALIASES.get(key, STATUS_ALIASES.get(key.replace(" ", ""), "not_reviewed"))


def normalize_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in SEVERITY_TO_CAT:
        return s
    # XCCDF also uses "info"/"unknown"; anything unrecognized becomes unknown
    # rather than silently defaulting to a real severity, which would
    # understate or overstate risk in the rollup.
    return "unknown"


# --------------------------------------------------------------------------
# CCI list -> 800-53 control mapping
# --------------------------------------------------------------------------


def load_cci_map(path: Path, prefer_revision: str = "5") -> dict[str, list[str]]:
    """Parse DISA's U_CCI_List.xml into {CCI id: [control ids]}.

    Each cci_item carries <references> to several 800-53 revisions at once, so
    the revision has to be chosen deliberately. A CCI can point at different
    controls in different revisions, and mixing them produces a report that
    silently cites two standards at once.

    The fallback is decided for the LIST, not per item. Two situations look
    identical from inside a single cci_item and must not be treated the same:

      1. The CCI list predates the requested revision entirely. Falling back to
         the newest revision present is right; an older mapping beats none.
      2. This particular CCI was retired before the requested revision and
         superseded by a different one. Falling back is wrong, because the
         successor CCI is already referenced by the same rule and will supply
         the correct control. Falling back here imports a stale control into a
         report labelled with a newer revision.

    Case 2 is real: CCI-000795 (disable identifier after inactivity) maps to
    IA-4 through Rev 4 and has no Rev 5 reference at all. Its Rev 5 successor,
    CCI-003627, maps to AC-2 (3). A per-item fallback puts IA-4 into a Rev 5
    report. Deciding once, for the whole list, keeps the report in one standard.
    """
    tree = ET.parse(path)

    # Pass 1: bucket every item's control references by revision.
    per_item: dict[str, dict[str, list[str]]] = {}
    for item in tree.iter():
        if localname(item.tag) != "cci_item":
            continue
        cci_id = item.get("id")
        if not cci_id:
            continue

        by_revision: dict[str, list[str]] = defaultdict(list)
        for ref in item.iter():
            if localname(ref.tag) != "reference":
                continue
            for family, number in CONTROL_PATTERN.findall(ref.get("index", "")):
                by_revision[ref.get("version", "")].append(f"{family}-{number}")

        if by_revision:
            per_item[cci_id] = by_revision

    # Pass 2: does the list carry the requested revision anywhere?
    list_has_revision = any(prefer_revision in rev for rev in per_item.values())

    cci_map: dict[str, list[str]] = {}
    for cci_id, by_revision in per_item.items():
        if prefer_revision in by_revision:
            chosen = by_revision[prefer_revision]
        elif list_has_revision:
            # The list has this revision; this CCI simply does not. It was
            # retired. Contribute nothing rather than a stale control.
            continue
        else:
            chosen = by_revision[max(by_revision)]
        cci_map[cci_id] = sorted(set(chosen))

    return cci_map


def apply_cci_map(findings: list[Finding], cci_map: dict[str, list[str]]) -> None:
    """Join findings to controls in place."""
    for f in findings:
        controls: set[str] = set()
        for cci in f.ccis:
            controls.update(cci_map.get(cci, []))
        f.controls = sorted(controls)


# --------------------------------------------------------------------------
# Parsers - one per input format, all returning list[Finding]
# --------------------------------------------------------------------------


def parse_cklb(path: Path) -> list[Finding]:
    """STIG Viewer 3 checklist (JSON).

    Guards the shape as well as the syntax. Valid JSON that is not a checklist
    parses cleanly and yields zero findings, which is indistinguishable in the
    output from a host with nothing to report. Saying so explicitly is cheaper
    than letting a wrong file look like a clean result.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("stigs"):
        print(
            f"warning: {path.name} parsed as JSON but has no 'stigs' key. "
            "Is it a STIG Viewer checklist?",
            file=sys.stderr,
        )
        return []

    target = data.get("target_data") or {}
    host = target.get("host_name") or target.get("ip_address") or path.stem

    findings: list[Finding] = []
    for stig in data.get("stigs", []):
        for rule in stig.get("rules", []):
            ccis = [c for c in rule.get("ccis", []) or [] if CCI_PATTERN.fullmatch(c)]
            findings.append(
                Finding(
                    rule_id=rule.get("group_id") or rule.get("rule_id") or "?",
                    title=rule.get("rule_title") or rule.get("group_title") or "",
                    severity=normalize_severity(rule.get("severity", "")),
                    status=normalize_status(rule.get("status", "")),
                    host=host,
                    source=path.name,
                    ccis=ccis,
                )
            )
    return findings


def parse_ckl(path: Path) -> list[Finding]:
    """STIG Viewer 2 checklist (XML).

    The .ckl format stores rule metadata as repeated
    <STIG_DATA><VULN_ATTRIBUTE>name</VULN_ATTRIBUTE><ATTRIBUTE_DATA>value</ATTRIBUTE_DATA></STIG_DATA>
    pairs rather than named elements, so each VULN is flattened into a dict first.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    host = path.stem
    for el in root.iter():
        if localname(el.tag) == "HOST_NAME" and (el.text or "").strip():
            host = el.text.strip()
            break

    findings: list[Finding] = []
    for vuln in root.iter():
        if localname(vuln.tag) != "VULN":
            continue

        attrs: dict[str, list[str]] = defaultdict(list)
        status = "not_reviewed"
        for child in vuln:
            name = localname(child.tag)
            if name == "STATUS":
                status = normalize_status(child.text or "")
            elif name == "STIG_DATA":
                key = value = None
                for sub in child:
                    if localname(sub.tag) == "VULN_ATTRIBUTE":
                        key = (sub.text or "").strip()
                    elif localname(sub.tag) == "ATTRIBUTE_DATA":
                        value = (sub.text or "").strip()
                if key and value:
                    attrs[key].append(value)

        ccis = [c for v in attrs.get("CCI_REF", []) for c in CCI_PATTERN.findall(v)]
        findings.append(
            Finding(
                rule_id=(attrs.get("Vuln_Num") or ["?"])[0],
                title=(attrs.get("Rule_Title") or [""])[0],
                severity=normalize_severity((attrs.get("Severity") or [""])[0]),
                status=status,
                host=host,
                source=path.name,
                ccis=ccis,
            )
        )
    return findings


def parse_xccdf(path: Path) -> list[Finding]:
    """XCCDF results from `oscap xccdf eval --results`.

    CCI references appear as <ident> elements. Not all SCAP content carries
    them - upstream SSG profiles often reference CCEs instead - so findings
    from those profiles will have no controls attached. That is surfaced in
    the report as unmapped rather than hidden.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    host = path.stem
    for el in root.iter():
        if localname(el.tag) in {"target", "fqdn"} and (el.text or "").strip():
            host = el.text.strip()
            break

    findings: list[Finding] = []
    for rr in root.iter():
        if localname(rr.tag) != "rule-result":
            continue

        result = ""
        ccis: list[str] = []
        for child in rr:
            name = localname(child.tag)
            if name == "result":
                result = (child.text or "").strip()
            elif name == "ident":
                ccis.extend(CCI_PATTERN.findall(child.text or ""))

        idref = rr.get("idref", "?")
        findings.append(
            Finding(
                # rpartition returns the whole string when "_rule_" is absent,
                # so this both strips the SSG prefix and passes bare ids through.
                rule_id=idref.rpartition("_rule_")[2],
                title=idref,
                severity=normalize_severity(rr.get("severity", "")),
                status=normalize_status(result),
                host=host,
                source=path.name,
                ccis=ccis,
            )
        )
    return findings


def parse_any(path: Path) -> list[Finding]:
    """Dispatch on extension, then on content for the ambiguous .xml case."""
    suffix = path.suffix.lower()
    if suffix == ".cklb":
        return parse_cklb(path)
    if suffix == ".ckl":
        return parse_ckl(path)
    if suffix == ".json":
        return parse_cklb(path)
    if suffix == ".xml":
        # Both .ckl-style checklists and XCCDF results use .xml in the wild,
        # so sniff the root element rather than trusting the extension.
        root_tag = localname(ET.parse(path).getroot().tag)
        if root_tag in {"Benchmark", "TestResult", "asset-report-collection"}:
            return parse_xccdf(path)
        return parse_ckl(path)
    raise ValueError(f"unrecognized input type: {path.name}")


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def summarize(findings: list[Finding]) -> dict:
    """Build every rollup the renderers need, in one pass over the findings."""
    by_status: Counter[str] = Counter()
    open_by_cat: Counter[str] = Counter()
    by_host: dict[str, Counter[str]] = defaultdict(Counter)
    family_open: dict[str, Counter[str]] = defaultdict(Counter)
    unmapped_open = 0

    for f in findings:
        by_status[f.status] += 1
        by_host[f.host][f.status] += 1

        if f.status != "open":
            continue

        open_by_cat[f.cat] += 1
        if not f.families:
            unmapped_open += 1
        for fam in f.families:
            family_open[fam][f.cat] += 1

    return {
        "total": len(findings),
        "by_status": by_status,
        "open_by_cat": open_by_cat,
        "by_host": by_host,
        "family_open": family_open,
        "unmapped_open": unmapped_open,
        "hosts": sorted(by_host),
    }


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------


def render_markdown(findings: list[Finding], s: dict) -> str:
    out: list[str] = []
    w = out.append

    w("# STIG Findings Rollup\n")
    w(f"**Hosts:** {len(s['hosts'])} ({', '.join(s['hosts'])})  ")
    w(f"**Rules evaluated:** {s['total']}  ")
    w(f"**Open findings:** {s['by_status']['open']}\n")

    w("## Open findings by severity\n")
    w("| Category | Open |")
    w("|---|---:|")
    for cat in CAT_ORDER:
        if s["open_by_cat"][cat] or cat != "unknown":
            w(f"| {cat} | {s['open_by_cat'][cat]} |")
    w("")

    w("## All results by status\n")
    w("| Status | Count |")
    w("|---|---:|")
    for st in STATUS_ORDER:
        w(f"| {st.replace('_', ' ')} | {s['by_status'][st]} |")
    w("")

    w("## Open findings by NIST 800-53 control family\n")
    if s["family_open"]:
        w("| Family | Name | CAT I | CAT II | CAT III | Total |")
        w("|---|---|---:|---:|---:|---:|")
        for fam in sorted(s["family_open"], key=lambda f: -sum(s["family_open"][f].values())):
            counts = s["family_open"][fam]
            total = sum(counts.values())
            name = FAMILY_NAMES.get(fam, "")
            w(
                f"| {fam} | {name} | {counts['CAT I']} | {counts['CAT II']} "
                f"| {counts['CAT III']} | {total} |"
            )
        w("")
    else:
        w("_No CCI-to-control mapping applied. Pass `--cci-list U_CCI_List.xml`._\n")

    if s["unmapped_open"]:
        w(
            f"> {s['unmapped_open']} open finding(s) carry no CCI reference and could not be "
            "mapped to a control. These still require adjudication.\n"
        )

    if len(s["hosts"]) > 1:
        w("## Per-host breakdown\n")
        w("| Host | Open | Not a finding | N/A | Not reviewed |")
        w("|---|---:|---:|---:|---:|")
        for host in s["hosts"]:
            c = s["by_host"][host]
            w(
                f"| {host} | {c['open']} | {c['not_a_finding']} "
                f"| {c['not_applicable']} | {c['not_reviewed']} |"
            )
        w("")

    open_findings = [f for f in findings if f.status == "open"]
    cat1 = [f for f in open_findings if f.cat == "CAT I"]
    if cat1:
        w("## CAT I open findings\n")
        w("| Rule | Host | Controls | Title |")
        w("|---|---|---|---|")
        for f in sorted(cat1, key=lambda f: f.rule_id):
            controls = ", ".join(f.controls) or "-"
            title = f.title[:80].replace("|", "\\|")
            w(f"| {f.rule_id} | {f.host} | {controls} | {title} |")
        w("")

    return "\n".join(out)


def render_csv(findings: list[Finding]) -> str:
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["rule_id", "host", "status", "severity", "cat", "controls", "families", "title", "source"]
    )
    for f in findings:
        writer.writerow(
            [
                f.rule_id,
                f.host,
                f.status,
                f.severity,
                f.cat,
                ";".join(f.controls),
                ";".join(f.families),
                f.title,
                f.source,
            ]
        )
    return buf.getvalue()


def render_json(findings: list[Finding], s: dict) -> str:
    return json.dumps(
        {
            "summary": {
                "total": s["total"],
                "hosts": s["hosts"],
                "by_status": dict(s["by_status"]),
                "open_by_cat": dict(s["open_by_cat"]),
                "open_by_family": {k: dict(v) for k, v in s["family_open"].items()},
                "unmapped_open": s["unmapped_open"],
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "host": f.host,
                    "status": f.status,
                    "severity": f.severity,
                    "cat": f.cat,
                    "ccis": f.ccis,
                    "controls": f.controls,
                    "families": f.families,
                    "title": f.title,
                    "source": f.source,
                }
                for f in findings
            ],
        },
        indent=2,
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stigroll",
        description="Roll STIG checklists and SCAP results up to NIST 800-53 control families.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, help=".cklb, .ckl, or XCCDF results")
    parser.add_argument(
        "--cci-list",
        type=Path,
        help="DISA U_CCI_List.xml. Without it, no control mapping is produced.",
    )
    parser.add_argument(
        "--format", choices=["markdown", "csv", "json"], default="markdown", help="output format"
    )
    parser.add_argument("--open-only", action="store_true", help="report only open findings")
    parser.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")
    parser.add_argument(
        "--revision", default="5", help="800-53 revision to prefer in the CCI mapping (default 5)"
    )
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    for path in args.inputs:
        if not path.exists():
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        try:
            findings.extend(parse_any(path))
        except (ET.ParseError, json.JSONDecodeError, ValueError) as exc:
            # One malformed file shouldn't sink an assessment covering 40 hosts,
            # so report it and keep going rather than aborting the whole run.
            print(f"warning: could not parse {path.name}: {exc}", file=sys.stderr)

    if not findings:
        print("error: no findings parsed from any input", file=sys.stderr)
        return 1

    if args.cci_list:
        if not args.cci_list.exists():
            print(f"error: CCI list not found: {args.cci_list}", file=sys.stderr)
            return 1
        apply_cci_map(findings, load_cci_map(args.cci_list, args.revision))

    # Summarize the FULL set before filtering. --open-only narrows what gets
    # listed, not what gets counted: a status table built from open findings
    # alone would report "not a finding: 0" and read as a much worse posture
    # than the assessment actually found.
    summary = summarize(findings)

    if args.open_only:
        findings = [f for f in findings if f.status == "open"]

    if args.format == "markdown":
        text = render_markdown(findings, summary)
    elif args.format == "csv":
        text = render_csv(findings)
    else:
        text = render_json(findings, summary)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# --------------------------------------------------------------------------
# DESIGN NOTES
#
# Every decision below trades something away. They are recorded here because a
# reviewer should not have to reverse-engineer intent from behaviour. Fuller
# reasoning sits in the docstring of the function each one belongs to.
#
# 1. Tolerant XML parsing over strict. localname() strips namespaces instead of
#    registering maps for XCCDF 1.1, 1.2 and namespace-free .ckl. An assessment
#    tool ingests whatever the client hands it, so tolerance wins. Cost: a
#    structurally wrong file parses into garbage rather than erroring.
#
# 2. Findings count in every control family they touch. One rule can reference
#    CCIs spanning AC and IA, and the family table counts it under both, so
#    family totals legitimately exceed the finding count. The assessment
#    question is "what evidence do I have for AC," not "how many unique
#    findings exist." The status table is the one that reconciles to a true
#    total.
#
# 3. Unknown severity is its own bucket, never defaulted to CAT II. Defaulting
#    produces a tidier report that misstates risk. "unknown: 3" tells an
#    assessor to go look; a silent reclassification does not.
#
# 4. Unmapped findings are surfaced, not dropped. SCAP content referencing CCEs
#    instead of CCIs yields no control mapping, and hiding those would make the
#    rollup look complete when it is not.
#
# 5. Parse errors warn and continue. One corrupt checklist should not cost you
#    the other 39 hosts in an engagement. The warning goes to stderr so a pipe
#    cannot swallow it: stdout is data, stderr is commentary.
#
# 6. Control granularity is the base control, not the enhancement. "AC-2 (3)(a)"
#    is reported as AC-2. Keeping enhancements would fragment the family view
#    into dozens of near-empty rows. A --granularity flag would cover both.
#
# ROADMAP
#   - POA&M-shaped CSV export
#   - delta between two runs, to show remediation progress over time
#   - --fail-on CAT I, so it can gate a pipeline
#   - pluggable mappings beyond CCI, since the join is not STIG-specific
# --------------------------------------------------------------------------
