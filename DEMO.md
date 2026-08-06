# Demo

Ninety seconds, terminal only. The gap first, then the fix.

<!-- VIDEO: uncomment and replace VIDEO_ID in both places once the recording is uploaded.
[![stigroll walkthrough](https://img.youtube.com/vi/VIDEO_ID/maxresdefault.jpg)](https://youtu.be/VIDEO_ID)
-->

The written walkthrough below covers the same ground, and every command is reproducible against
the sample data checked into this repo.

---

## What it shows

**1. A real checklist export.** A Windows 11 workstation assessed against the Microsoft Windows 11
STIG V2R8. Twenty of 256 rules worked by hand, twelve came back open.

**2. The gap.** The export carries the Control Correlation Identifier and not the control it maps
to:

```bash
grep -c 'CCI-000381' examples/sample-checklist.cklb   # 29 -> the CCI is there
grep -c 'CM-7'       examples/sample-checklist.cklb   # 0  -> the control it maps to is not
```

STIG Viewer resolves that mapping on screen and discards it on export. So an auditor asking *"show
me the evidence for AU-12"* cannot be answered from this file, and every downstream consumer has
to redo the join.

**3. The fix.**

```bash
python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml --format markdown
```

Twelve open findings, expressed by control family instead of by rule number:

| Family | Name | Open |
|---|---|---:|
| AU | Audit and Accountability | 5 |
| CM | Configuration Management | 3 |
| AC | Access Control | 2 |
| SI | System and Information Integrity | 1 |
| MA | Maintenance | 1 |
| SC | System and Communications Protection | 1 |

Same twelve findings. The language an assessment actually reports in.

---

## Reproduce it yourself

Everything below is public content and takes about a minute.

```bash
git clone https://github.com/ktalons/stigroll
cd stigroll

# DISA's CCI list. Public, no account required.
# Note: the browse page at public.cyber.mil/stigs/cci/ currently redirects behind
# a login. The direct file URL is open.
curl -LO https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip
unzip U_CCI_List.zip

python3 stigroll.py examples/sample-checklist.cklb --cci-list U_CCI_List.xml --format markdown
```

Expected output is checked in at [`examples/sample-output.md`](examples/sample-output.md), so you
can diff your run against it.

## About the sample data

`examples/sample-checklist.cklb` is a genuine assessment rather than invented data. The
determinations, comments and finding details are real. Host name, IP and MAC have been replaced;
nothing else was altered.

Ten of the twelve open findings are an **absent** registry value rather than a wrong one. Nothing
was misconfigured on that host. Settings had simply never been configured, which is what an
unmanaged endpoint looks like and is the argument for CM-6 in a sentence.
