# Demo

Ninety seconds, terminal only. The gap first, then the fix.

<!-- VIDEO: uncomment and replace VIDEO_ID in both places once the recording is uploaded.
[![stigroll walkthrough](https://img.youtube.com/vi/VIDEO_ID/maxresdefault.jpg)](https://youtu.be/VIDEO_ID)
-->

Every command below runs against data checked into this repo, so you can follow along rather than
take any of it on trust.

## Setup, about a minute

```bash
git clone https://github.com/ktalons/stigroll && cd stigroll

# DISA's CCI list. Public, no account required. The browse page at
# public.cyber.mil/stigs/cci/ currently redirects behind a login;
# this direct file URL is open.
curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
unzip U_CCI_List.zip
```

## 1. The input

```bash
ls examples/
```

```
sample-checklist.cklb   sample-output.md
```

`sample-checklist.cklb` is a real assessment. A Windows 11 workstation against the Microsoft
Windows 11 STIG V2R8, 20 of 256 rules worked by hand in STIG Viewer 3.7. Host name, IP and MAC
were replaced before publishing. Nothing else was altered.

## 2. The gap

```bash
grep -c 'CCI-000381' examples/sample-checklist.cklb
grep -c 'CM-7'       examples/sample-checklist.cklb
```

```
29
0
```

Twenty-nine rules in that file reference `CCI-000381`. **Zero of them carry `CM-7`**, the NIST
800-53 control that CCI maps to.

STIG Viewer resolves that mapping and displays it on screen while you work. It does not write it
into the export. So the checklist tells you which Control Correlation Identifier applies and never
which control, and every consumer downstream has to redo the join to get back to control language.

Which means the question an assessor is actually asked, *"show me the evidence for AU-12,"* is the
one question this artifact cannot answer.

## 3. The join

```bash
python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml
```

Runs in about a tenth of a second and prints the full report. The part that matters:

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

That block is the tool's raw stdout, unedited. It is markdown on purpose, so a report can be
pasted straight into a ticket or a wiki without reformatting.

Same twelve findings. Expressed in the language an assessment reports in, instead of the language
the scanner speaks.

The report also carries `not reviewed: 236`, because the checklist covers the full benchmark and
only 20 rules were assessed. The artifact states its own completeness rather than presenting a
sample as though it were the whole.

Full expected output is checked in at [`examples/sample-output.md`](examples/sample-output.md), so
you can diff your run against a known-good result.

## What the sample data shows

Ten of the twelve open findings are an **absent** registry value rather than a wrong one. Nothing
on that host was misconfigured. Settings had simply never been configured at all.

That is what an unmanaged endpoint looks like, and it is the argument for CM-6 in one sentence.
