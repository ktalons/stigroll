# Demo

Three input formats, three output formats, one real assessment at the end.

[![stigroll walkthrough](https://img.youtube.com/vi/V9yN8JgrrxU/hqdefault.jpg)](https://youtu.be/V9yN8JgrrxU)

**[Watch the walkthrough](https://youtu.be/V9yN8JgrrxU)** (< 3 minutes)

Every command below runs against files checked into this repo and DISA's published CCI list, so
you can follow along rather than take any of it on trust.

## Setup

```bash
git clone https://github.com/ktalons/stigroll && cd stigroll

# DISA's CCI list. Public, no account required. The browse page at
# public.cyber.mil/stigs/cci/ currently redirects behind a login;
# this direct file URL is open.
curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
unzip U_CCI_List.zip
```

## The gap this closes

```bash
grep -c 'CCI-000381' examples/sample-checklist.cklb    # 29
grep -c 'CM-7'       examples/sample-checklist.cklb    # 0
```

Twenty-nine rules in that checklist reference `CCI-000381`. **Zero of them carry `CM-7`**, the
NIST 800-53 control that CCI maps to. STIG Viewer resolves the mapping while you work and does not
write it into the export, so every consumer downstream has to redo the join.

## The example files

| File | Format | Produced by | Host |
|---|---|---|---|
| `examples/ubuntu-host.cklb` | JSON | STIG Viewer 3 | `lab-ubuntu-01` |
| `examples/windows-host.ckl` | XML | STIG Viewer 2 (legacy) | `lab-win-01` |
| `examples/openscap-results.xml` | XCCDF | `oscap xccdf eval --results` | `lab-ubuntu-02` |
| `examples/sample-checklist.cklb` | JSON | STIG Viewer 3.7 | a real 256-rule assessment |

The first three are small on purpose. Three different vendors, three different vocabularies for
the same ideas, and one consistent output.

## Every input, every output

### CSV

One row per finding. The flattest view, and the one that goes into a spreadsheet.

```bash
python3 stigroll.py examples/ubuntu-host.cklb      --cci-list U_CCI_List.xml --format csv
python3 stigroll.py examples/windows-host.ckl      --cci-list U_CCI_List.xml --format csv
python3 stigroll.py examples/openscap-results.xml  --cci-list U_CCI_List.xml --format csv
```

Same nine columns every time, regardless of which format went in.

### JSON

For a pipeline. The `summary` object carries the rollup; `findings` carries every record.

```bash
python3 stigroll.py examples/ubuntu-host.cklb      --cci-list U_CCI_List.xml --format json | jq '.summary'
python3 stigroll.py examples/windows-host.ckl      --cci-list U_CCI_List.xml --format json | jq '.summary'
python3 stigroll.py examples/openscap-results.xml  --cci-list U_CCI_List.xml --format json | jq '.summary'
```

### Markdown

The default. A report you can paste into a ticket or a wiki without reformatting.

```bash
python3 stigroll.py examples/ubuntu-host.cklb      --cci-list U_CCI_List.xml
python3 stigroll.py examples/windows-host.ckl      --cci-list U_CCI_List.xml
python3 stigroll.py examples/openscap-results.xml  --cci-list U_CCI_List.xml
```

### All three at once

Mixed formats in a single invocation produce one report with a per-host breakdown:

```bash
python3 stigroll.py examples/*.cklb examples/*.ckl examples/*.xml --cci-list U_CCI_List.xml
```

## The real assessment

`examples/sample-checklist.cklb` is a genuine assessment. A Windows 11 workstation against the
Microsoft Windows 11 STIG V2R8, 20 of 256 rules worked by hand in STIG Viewer 3.7. Host name, IP
and MAC were replaced before publishing; nothing else was altered.

```bash
python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml -o rollup.md
code rollup.md
```

Then open the preview in VS Code with `Cmd + Shift + V` (`Ctrl + Shift + V` on Windows and Linux).

The output is markdown on purpose. The tool writes a report, not a data dump, and it renders as a
finished document without anyone reformatting it.

The part that matters:

```
## Open findings by NIST 800-53 control family

| Family | Name | CAT I | CAT II | CAT III | Total |
|---|---|---:|---:|---:|---:|
| AU | Audit and Accountability | 0 | 5 | 0 | 5 |
| CM | Configuration Management | 1 | 2 | 0 | 3 |
| AC | Access Control | 0 | 2 | 0 | 2 |
| SI | System and Information Integrity | 0 | 1 | 0 | 1 |
| MA | Maintenance | 1 | 0 | 0 | 1 |
| SC | System and Communications Protection | 0 | 1 | 0 | 1 |
```

Twelve open findings, grouped by control family instead of by rule number. That block is raw
stdout, unedited.

The report also carries `not reviewed: 236`, because the checklist covers the full benchmark and
only 20 rules were assessed. The artifact states its own completeness rather than presenting a
sample as though it were the whole.

Expected output is checked in at [`examples/sample-output.md`](examples/sample-output.md), so you
can diff your run against a known-good result.

## What the sample data shows

Ten of the twelve open findings are an **absent** registry value rather than a wrong one. Nothing
on that host was misconfigured. Settings had simply never been configured at all.

That is what an unmanaged endpoint looks like, and it is the argument for CM-6 in one sentence.
