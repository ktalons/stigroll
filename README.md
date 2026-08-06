# stigroll

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](stigroll.py)
[![Walkthrough](https://img.shields.io/badge/video-3%20min%20walkthrough-red.svg)](https://youtu.be/V9yN8JgrrxU)

Roll DISA STIG checklist and SCAP scan results up to NIST SP 800-53 control families.

> A STIG finding is technology-specific: *"V-253370, Credential Guard must be running."* A control
assessor does not report in V-numbers, they report in 800-53 controls. DISA publishes the mapping
between the two as Control Correlation Identifiers, and `stigroll` applies it, so the output
answers **"show me the evidence for AU-12"** instead of handing someone a list of rule IDs.

**[Watch the 3 minute walkthrough](https://youtu.be/V9yN8JgrrxU)** or read it in
[`DEMO.md`](DEMO.md): three input formats, three output formats, and a real assessment.

## Why it exists

STIG Viewer resolves the CCI to a control on screen, then drops it on export. Check any saved
checklist:

```bash
grep -c 'CCI-000381' examples/sample-checklist.cklb   # 29
grep -c 'CM-7'       examples/sample-checklist.cklb   # 0
```

Twenty-nine rules in that checklist reference `CCI-000381`. Not one of them carries `CM-7`, the
control it maps to. The CCI survives the export and the control does not, so every consumer
downstream has to redo the join, which is why the question an auditor actually asks is the one
the tooling cannot answer.

## What it does

| Stage | Detail |
|---|---|
| **Ingest** | `.cklb` (STIG Viewer 3, JSON), `.ckl` (STIG Viewer 2, XML), XCCDF results from `oscap xccdf eval --results` |
| **Normalize** | Every format's status and severity vocabulary converted to one canonical set at the boundary |
| **Join** | Each finding's CCIs resolved against DISA's `U_CCI_List.xml` to 800-53 controls |
| **Report** | Markdown, CSV or JSON. Grouped by control family, counted by CAT severity |

Standard library only. One file. No install step, which matters on a hardened assessor
workstation where installing a package is a change request.

> Nothing about the shape is STIG-specific. It is **scan output, plus a published mapping, equals
framework-level rollup.** Swap the mapping file and the same three stages produce evidence against
a different control framework. Any workflow that currently moves scanner results into a control
matrix by hand is the same problem.

## Usage

Python 3.10 or newer. Nothing to install.

### Try it in about a minute

```bash
git clone https://github.com/ktalons/stigroll && cd stigroll

# DISA's CCI list. Public, no account required.
# The browse page at public.cyber.mil/stigs/cci/ currently redirects behind a
# login; this direct file URL is open.
curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
unzip U_CCI_List.zip

# Run it against the real assessment included in this repo
python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml
```

That should reproduce [`examples/sample-output.md`](examples/sample-output.md) exactly, so you can
diff your run against a known-good result.

### Against your own data

```bash
# One file, a glob, or several files of mixed formats in a single pass
python3 stigroll.py my-host.cklb --cci-list U_CCI_List.xml
python3 stigroll.py /path/to/checklists/*.cklb --cci-list U_CCI_List.xml
python3 stigroll.py host.cklb legacy.ckl scan-results.xml --cci-list U_CCI_List.xml

# Machine-readable, for a pipeline
python3 stigroll.py my-host.cklb --cci-list U_CCI_List.xml --format json | jq '.summary'

# Write a report to a file
python3 stigroll.py my-host.cklb --cci-list U_CCI_List.xml -o rollup.md
```

Multiple hosts in one run produce a per-host breakdown alongside the totals.

### Options

| Option | Default | Notes |
|---|---|---|
| `inputs` | required | One or more `.cklb`, `.ckl`, or XCCDF results files. Mixed formats are fine |
| `--cci-list` | none | Path to `U_CCI_List.xml`. **Without it there is no control mapping**, only status and severity counts |
| `--format` | `markdown` | `markdown`, `csv`, or `json` |
| `-o`, `--output` | stdout | Write to a file |

Mapping targets **800-53 Revision 5**, which is what FedRAMP baselines are built from. That is a
constant rather than a flag: a report that silently mixes revisions is worse than one that speaks
a single standard.

Warnings go to `stderr` and data goes to `stdout`, so a malformed input cannot corrupt a piped
report. One unparseable file warns and the run continues.

## Worked example

`examples/sample-checklist.cklb` is a real assessment: a Windows 11 workstation against the
Microsoft Windows 11 STIG V2R8, 20 of 256 rules worked by hand, host identifiers replaced. Run it
yourself and you get [`examples/sample-output.md`](examples/sample-output.md).

**256 rules evaluated, 12 open.**

| Status | Count |
|---|---:|
| open | **12** |
| not a finding | 7 |
| not applicable | 1 |
| not reviewed | 236 |

| Open findings by control family | | | | | |
|---|---|---|---|---|---|
| **AU** Audit and Accountability | **CM** Configuration Mgmt | **AC** Access Control | **SI** System Integrity | **MA** Maintenance | **SC** Comms Protection |
| 5 | 3 | 2 | 1 | 1 | 1 |

CAT I 2, CAT II 10, CAT III 0.

That last table is the point. The same twelve findings, expressed in the language an assessment
reports in rather than the language the scanner speaks.

> *Note: `not reviewed: 236`. The checklist covers the full benchmark and only 20 rules were assessed,
so the artifact states its own completeness rather than presenting a sample as a whole.

## Design

```
3 input formats          1 internal shape         1 aggregation      3 output formats
─────────────────        ────────────────         ─────────────      ────────────────
.cklb  (JSON)  ─┐                                                    ┌─ markdown
.ckl   (XML)   ─┼──> parse_*() ──> Finding ──> summarize() ──> dict ─┼─ csv
XCCDF  (XML)   ─┘                  dataclass                         └─ json
                     ▲
              normalize HERE
```

### The revision is chosen once, for the whole CCI list

A CCI can map to different controls in different 800-53 revisions, and some are retired between
them. `CCI-000795` maps to IA-4 through Rev 4 and has no Rev 5 reference at all; its successor
`CCI-003627` maps to AC-2 (3). Falling back per item would quietly put an IA control into a report
labelled Rev 5, so the fallback is decided once for the whole list instead.

`examples/ubuntu-host.cklb` carries a rule referencing both halves of that pair, so the behaviour
is checkable against real published data rather than taken on trust.

## Scope and limits

- **Base control granularity by design.** `AC-2 (3)(a)` is reported as `AC-2`. Keeping
  enhancements fragments the family view into dozens of near-empty rows. A `--granularity` flag
  would cover both cases.
- **Everything is held in memory.** Fine at engagement scale, tens of hosts. A very large estate
  would want streaming or a database.
- **XCCDF content referencing CCEs rather than CCIs yields no mapping.** Reported as unmapped
  rather than silently omitted.
- **Tolerant XML parsing.** Namespaces are stripped rather than registered, so a structurally
  wrong file can parse into garbage instead of erroring. That trade favours ingesting whatever a
  client hands you.

Design notes and a roadmap are at the bottom of [`stigroll.py`](stigroll.py).

## License

MIT. See [LICENSE](LICENSE).

Built by [Kyle Versluis](https://github.com/ktalons). More at <https://ktalons.github.io/>.
